//! End-to-end regression tests for `roottrace root`'s handling of a read
//! that reports **Interrupted**, and of a fatal read error arriving AFTER
//! some file bytes were already read. The existing multi-read regressions
//! pin batches split across several successful reads; this file pins what
//! happens *during* the file reads themselves.
//!
//! Recoverable interruption (EINTR / `ErrorKind::Interrupted`):
//!   * an interrupted read is retried and the SAME batch keeps being
//!     processed: the bytes already obtained are neither lost nor counted a
//!     second time, and the interruption must never be mistaken for EOF or
//!     reported as a failure;
//!   * the interruption can land while one record is still incomplete or
//!     immediately after the LF that separates records - in both places the
//!     root is the fixed root of the complete original record sequence,
//!     identical to a run with no interruption;
//!   * an interruption on the read that would otherwise return zero (EOF) is
//!     retried too;
//!   * recovery trims nothing - CR, NUL and non-UTF-8 bytes cross the resume
//!     point verbatim, a read end is not turned into a record end, and the
//!     trailing-LF / no-trailing-LF byte rule is unchanged.
//!
//! Fatal error after partial input:
//!   * once bytes have been read successfully, a later non-retryable read
//!     failure fails the whole root computation: exit status 1, stdout
//!     completely empty, stderr naming both the input path and the read
//!     reason;
//!   * this holds even when the bytes already read happen to end on an LF
//!     (several complete records, even the whole file ending in LF), and
//!     when they end inside a record - already-read records are never
//!     emitted as a partial root, an open fragment is never treated as a
//!     final record, and the empty-tree root is never substituted;
//!   * it is a file-read failure (exit 1, "cannot read ..."), not a usage
//!     error (exit 2).
//!
//! Faults are injected deterministically by `common::read_fault` (an
//! LD_PRELOAD interposer, see `tests/common/read_fault_shim.c`) at exact
//! file offsets and at natural 64 KiB buffer boundaries; nothing inside
//! roottrace is stubbed. Expected roots are the same FIXED constants used by
//! `root_regression.rs` (B9) and `multi_read_regression.rs` (MREAD),
//! independently produced by `tests/reference/rfc6962_vectors.py` and
//! `tests/reference/rfc6962_multiread_vectors.py`.

mod common;

use std::path::PathBuf;
use std::process::Output;

use common::read_fault::{self, ReadAction, READ_BUF};
use common::{join_lf, TempFile};

// ---------------------------------------------------------------------------
// Small fixed batch: B9 from root_regression.rs (nine records, crosses the
// eight-record power-of-two boundary). It packs empty records, a duplicate,
// a trailing CR, NUL and non-UTF-8 bytes into 59 LF-terminated bytes, so a
// handful of bytes separates every interesting byte rule.
// ---------------------------------------------------------------------------

const B9: &[&[u8]] = &[
    b"alpha",
    b"beta",
    b"",
    b"gamma",
    b"alpha",
    b"delta\r",
    b"\xff\xfe\x00binary",
    b"epsilon",
    b"zeta\x01tail",
];

// Independently fixed RFC 6962 root (tests/reference/rfc6962_vectors.py).
const ROOT_B9: &str = "a8a3e76ecf28b850e84cb5465729921212ffd07de3c0e6e170cd233bf723adc3";

// Byte offsets in the LF-terminated B9 file (documented and asserted below):
//
//   0.. 5 "alpha"      5 LF
//   6..10 "beta"      10 LF
//  11     LF           (r2 is empty)
//  12..16 "gamma"     17 LF
//  18..22 "alpha"     23 LF
//  24..29 "delta\r"   30 LF   (CR is content at byte 29)
//  31..39 ff fe 00 "binary"   (9 bytes)  40 LF
//  41..47 "epsilon"   48 LF
//  49..57 "zeta\x01tail"      (9 bytes)  58 LF ; file length 59
const SZ_B9_LF: usize = 59; // trailing LF present
const SZ_B9_NO_LF: usize = 58;

// Split points for the deliberately short first read (see ReadAction::Short):
const SPLIT_AFTER_TWO_RECORDS: usize = 11; // buffered bytes end on LF 10, next byte LF 11
const SPLIT_INSIDE_GAMMA: usize = 14; // next byte ('m') is mid-record content
const SPLIT_AFTER_CR_BEFORE_LF: usize = 30; // buffered tail is CR (byte 29), next byte LF
const SPLIT_RIGHT_AFTER_LF: usize = 31; // next byte is 0xff starting the binary record
const SPLIT_RESUME_AT_NUL: usize = 33; // bytes 31..33 = ff fe, next byte NUL
const SPLIT_INSIDE_BINARY_RECORD: usize = 34; // ff fe 00 already read, next byte 'b'
const SPLIT_AFTER_EIGHT_RECORDS: usize = 49; // next byte begins the ninth record
const SPLIT_INSIDE_LAST_RECORD: usize = 52; // inside "zeta\x01tail"

/// Run `roottrace root` on one B9 file form under a per-read fault script.
/// Returns the input path alongside the output, or `None` when the fault
/// harness is unavailable (the calling test then soft-skips). The temp file
/// is removed on return; only its path string is needed for diagnostics.
fn run_b9(trailing_lf: bool, script: &[ReadAction]) -> Option<(PathBuf, Output)> {
    if !read_fault::available() {
        return None;
    }
    let tmp = TempFile::create(&join_lf(B9, trailing_lf));
    let path = tmp.path.clone();
    let out = read_fault::root_under_faults(&tmp.path, script)?;
    Some((path, out))
}

// ---------------------------------------------------------------------------
// Large fixed batch: the multi-read batch from multi_read_regression.rs
// (205567 LF-terminated bytes, one 140000-byte record). The construction is
// byte-for-byte the deterministic one used by that test and the reference
// generator, so natural 64 KiB buffer boundaries fall on documented bytes.
// ---------------------------------------------------------------------------

const LONG_LEN: usize = 140_000;
const PAD_LEN: usize = READ_BUF - 1 - 7; // 65528

// Independently fixed RFC 6962 root
// (tests/reference/rfc6962_multiread_vectors.py).
const ROOT_MREAD: &str = "dca3d078542c8497a09302a4a0cd3b521a498ce3bffbe29bf9f510f2d1203304";

/// Deterministic pseudo-random content byte; identical to `fill_byte` in
/// `multi_read_regression.rs` and in the reference generator.
fn fill_byte(i: usize) -> u8 {
    let b = ((i as u32).wrapping_mul(2_654_435_761) >> 13) as u8;
    if b == b'\n' {
        0x0b
    } else {
        b
    }
}

fn long_record() -> Vec<u8> {
    let mut rec: Vec<u8> = (0..LONG_LEN).map(fill_byte).collect();
    rec[..13].copy_from_slice(b"MREAD\x00\xff\xfe\rHEAD");
    let mid = LONG_LEN / 2;
    let marker = b"\x00\xff\rSECOND-HALF";
    rec[mid..mid + marker.len()].copy_from_slice(marker);
    let tail = b"\x00TAIL\r\xff";
    rec[LONG_LEN - tail.len()..].copy_from_slice(tail);
    rec
}

fn pad_record() -> Vec<u8> {
    let mut p = b"pad:".to_vec();
    p.resize(PAD_LEN, b'p');
    p
}

fn mread_bytes(trailing_lf: bool) -> Vec<u8> {
    let pad = pad_record();
    let long = long_record();
    let recs: Vec<&[u8]> = vec![
        b"alpha",
        b"",
        &pad,
        b"",
        &long,
        b"beta\r",
        b"alpha",
        b"",
        b"\xff\x00z",
        b"end-record\x01",
    ];
    join_lf(&recs, trailing_lf)
}

fn run_mread(trailing_lf: bool, script: &[ReadAction]) -> Option<(PathBuf, Output)> {
    if !read_fault::available() {
        return None;
    }
    let data = mread_bytes(trailing_lf);
    let tmp = TempFile::create(&data);
    let path = tmp.path.clone();
    let out = read_fault::root_under_faults(&tmp.path, script)?;
    Some((path, out))
}

/// Print a soft-skip note (the test still passes) when the shim cannot be
/// built, e.g. a statically linked toolchain or no C compiler.
fn skip_without_harness() {
    eprintln!(
        "skipping read-fault regression: fault-injection harness unavailable \
         (needs Linux, a dynamic roottrace binary and a C compiler)"
    );
}

// === Interrupted reads: retry and complete the same batch ==================

#[test]
fn small_batch_layout_places_each_split_on_a_documented_byte() {
    // Pin the B9 file layout the split constants below rely on, so a future
    // edit to the batch moves the splits deliberately.
    let data = join_lf(B9, true);
    assert_eq!(data.len(), SZ_B9_LF);
    assert_eq!(join_lf(B9, false).len(), SZ_B9_NO_LF);
    assert_eq!(&data[5..6], b"\n");
    // Bytes 10 and 11 are two consecutive LFs (beta's and the empty record's).
    assert_eq!(&data[10..12], b"\n\n");
    assert_eq!(&data[12..17], b"gamma");
    assert_eq!(data[29], b'\r');
    assert_eq!(data[30], b'\n');
    assert_eq!(&data[31..34], b"\xff\xfe\x00");
    assert_eq!(&data[41..48], b"epsilon");
    assert_eq!(data[48], b'\n');
    assert_eq!(&data[49..58], b"zeta\x01tail");
    assert_eq!(data[58], b'\n');
    // The documented split points really fall right after an LF, inside a
    // record, on a CR, or resuming at a NUL.
    assert_eq!(data[SPLIT_AFTER_TWO_RECORDS - 1], b'\n');
    assert_eq!(data[SPLIT_AFTER_TWO_RECORDS], b'\n');
    assert_eq!(data[SPLIT_INSIDE_GAMMA], b'm');
    assert_eq!(data[SPLIT_AFTER_CR_BEFORE_LF - 1], b'\r');
    assert_eq!(data[SPLIT_AFTER_CR_BEFORE_LF], b'\n');
    assert_eq!(data[SPLIT_RIGHT_AFTER_LF - 1], b'\n');
    assert_eq!(data[SPLIT_RIGHT_AFTER_LF], 0xff);
    assert_eq!(data[SPLIT_RESUME_AT_NUL], 0x00);
    assert_eq!(data[SPLIT_INSIDE_BINARY_RECORD], b'b');
    assert_eq!(data[SPLIT_INSIDE_LAST_RECORD], b'a');
}

#[test]
fn interrupted_reads_are_retried_and_the_full_batch_root_is_unchanged() {
    let i = ReadAction::Interrupt;
    let p = ReadAction::Pass;
    // (description, trailing LF?, script)
    let cases: &[(&str, bool, Vec<ReadAction>)] = &[
        // EINTR before any byte was obtained.
        ("interrupted before the first byte", true, vec![i]),
        // Interruption while a record is still incomplete.
        (
            "interrupted inside 'gamma'",
            true,
            vec![ReadAction::Short(SPLIT_INSIDE_GAMMA), i],
        ),
        // Interruption immediately following the LF that separates records:
        // the next byte starts a brand-new record (the binary one at 0xff).
        (
            "interrupted right after a separator LF",
            true,
            vec![ReadAction::Short(SPLIT_RIGHT_AFTER_LF), i],
        ),
        // Buffered bytes end right after an LF and the resume byte is the
        // second of two consecutive LFs (the empty record's terminator).
        (
            "interrupted between two consecutive LFs",
            true,
            vec![ReadAction::Short(SPLIT_AFTER_TWO_RECORDS), i],
        ),
        // Three consecutive interruptions at the same mid-record point: the
        // retry repeats until real bytes arrive, without duplicating the 14
        // already-read bytes.
        (
            "three consecutive interruptions mid-record",
            true,
            vec![ReadAction::Short(SPLIT_INSIDE_GAMMA), i, i, i],
        ),
        // Interruption on the read that, uninterrupted, returns zero: EINTR
        // must be retried into EOF, not itself taken as end of file.
        (
            "interrupted on the EOF read (trailing LF form)",
            true,
            vec![p, i],
        ),
        (
            "interrupted on the EOF read (no trailing LF form)",
            false,
            vec![p, i],
        ),
        // The same mid-record interruption in the file form without the
        // terminating LF: identical nine records, identical root.
        (
            "interrupted inside a record, no trailing LF",
            false,
            vec![ReadAction::Short(SPLIT_INSIDE_GAMMA), i],
        ),
    ];

    let mut any = false;
    for (desc, trailing_lf, script) in cases {
        let Some((_, out)) = run_b9(*trailing_lf, script) else {
            continue;
        };
        any = true;
        read_fault::assert_root_success(&out, ROOT_B9, desc);
    }
    if !any {
        skip_without_harness();
    }
}

#[test]
fn recovery_keeps_cr_nul_and_non_utf8_bytes_across_the_resume_point() {
    let i = ReadAction::Interrupt;
    let cases: &[(&str, usize)] = &[
        // Last buffered byte is CR content, the resumed read starts on that
        // record's terminating LF: CR must not be trimmed or replayed.
        ("resume on LF after a buffered CR", SPLIT_AFTER_CR_BEFORE_LF),
        // The bytes already read end exactly on a separator LF and the
        // resumed stream starts with 0xff: non-UTF-8 content is not dropped.
        ("resume starts on a non-UTF-8 byte", SPLIT_RIGHT_AFTER_LF),
        // ff fe already read, the resumed read starts at NUL.
        ("resume starts on NUL inside binary record", SPLIT_RESUME_AT_NUL),
        // Mid-record resume inside a record that also ends in CR later.
        ("resume on ASCII inside the binary record", SPLIT_INSIDE_BINARY_RECORD),
    ];

    let mut any = false;
    for (desc, split) in cases {
        for trailing_lf in [true, false] {
            let Some((_, out)) = run_b9(
                trailing_lf,
                &[ReadAction::Short(*split), i],
            ) else {
                continue;
            };
            any = true;
            read_fault::assert_root_success(
                &out,
                ROOT_B9,
                &format!("{desc} (trailing_lf={trailing_lf})"),
            );
        }
    }
    if !any {
        skip_without_harness();
    }
}

#[test]
fn interruption_output_is_byte_identical_to_the_uninterrupted_run() {
    // Not just equal to the fixed constant: faulted and unfaulted stdout must
    // be the exact same 65 bytes, and both trailing-LF file forms agree.
    let Some(()) = read_fault::available().then_some(()) else {
        skip_without_harness();
        return;
    };

    let mut baseline: Option<Vec<u8>> = None;
    for trailing_lf in [true, false] {
        let data = join_lf(B9, trailing_lf);
        let plain = TempFile::create(&data);
        let unfaulted = std::process::Command::new(common::bin())
            .arg("root")
            .arg(&plain.path)
            .output()
            .unwrap();
        assert_eq!(unfaulted.status.code(), Some(0));
        assert!(unfaulted.stderr.is_empty());

        for script in [
            vec![ReadAction::Interrupt],
            vec![ReadAction::Short(SPLIT_INSIDE_GAMMA), ReadAction::Interrupt],
            vec![ReadAction::Short(SPLIT_RIGHT_AFTER_LF), ReadAction::Interrupt],
            vec![ReadAction::Pass, ReadAction::Interrupt],
        ] {
            let (_, out) = run_b9(trailing_lf, &script).unwrap();
            read_fault::assert_root_success(&out, ROOT_B9, "faulted run matches fixed root");
            assert_eq!(
                out.stdout, unfaulted.stdout,
                "interrupted run must be byte-identical to the uninterrupted run"
            );
        }

        if let Some(prev) = &baseline {
            assert_eq!(
                prev, &unfaulted.stdout,
                "trailing/no-trailing-LF forms encode the same records"
            );
        } else {
            baseline = Some(unfaulted.stdout);
        }
    }
}

#[test]
fn interruptions_at_natural_64kib_boundaries_complete_the_multi_read_batch() {
    let data = mread_bytes(true);
    // The first natural buffer ends on PAD's terminating LF and the second
    // buffer starts with the empty record's LF: the boundary straddles two
    // consecutive separator LFs.
    assert!(data.len() > 3 * READ_BUF);
    assert_eq!(data[READ_BUF - 1], b'\n');
    assert_eq!(data[READ_BUF], b'\n');

    let p = ReadAction::Pass;
    let i = ReadAction::Interrupt;
    let cases: &[(&str, bool, Vec<ReadAction>)] = &[
        // Interruption on the second read: the first 64 KiB (ending on LF) are
        // in hand and the resumed read begins on another LF.
        (
            "interrupted right after the first 64 KiB boundary LFs",
            true,
            vec![p, i],
        ),
        // Interruption on the third read, 128 KiB in - strictly inside the
        // 140000-byte record spanning several reads.
        (
            "interrupted inside the long record at the 128 KiB boundary",
            true,
            vec![p, p, i],
        ),
        // Interruption on the final EOF read after four data reads
        // (205567 = 65536*3 + 8959), with and without the terminating LF.
        ("interrupted on the multi-read EOF call", true, vec![p, p, p, p, i]),
        (
            "interrupted on the multi-read EOF call (no trailing LF)",
            false,
            vec![p, p, p, p, i],
        ),
    ];

    let mut any = false;
    for (desc, trailing_lf, script) in cases {
        let Some((_, out)) = run_mread(*trailing_lf, script) else {
            continue;
        };
        any = true;
        read_fault::assert_root_success(&out, ROOT_MREAD, desc);
    }
    if !any {
        skip_without_harness();
    }
}

// === Fatal read errors after partial bytes: failure, never a partial root ==

#[test]
fn fatal_error_after_lf_ended_prefix_fails_without_any_root() {
    let e = ReadAction::ReadError;
    let i = ReadAction::Interrupt;
    let cases: &[(&str, bool, Vec<ReadAction>)] = &[
        // Two complete records ("alpha", "beta") already read, prefix ending
        // exactly on an LF - and nothing follows.
        (
            "error after two LF-terminated records",
            true,
            vec![ReadAction::Short(SPLIT_AFTER_TWO_RECORDS), e],
        ),
        // Eight complete records (a power of two): an especially tempting
        // partial result, still forbidden.
        (
            "error after eight LF-terminated records",
            true,
            vec![ReadAction::Short(SPLIT_AFTER_EIGHT_RECORDS), e],
        ),
        // The ENTIRE file, including its terminating LF, was read
        // successfully; the next read returns EIO instead of zero. The full
        // root must not be emitted.
        (
            "error on the EOF read after a fully read LF-terminated file",
            true,
            vec![ReadAction::Short(SZ_B9_LF), e],
        ),
        // Same, last record without a trailing LF: its bytes were all read
        // but EOF never arrived, so even that final record is not confirmed.
        (
            "error after all bytes of the no-trailing-LF file",
            false,
            vec![ReadAction::Short(SZ_B9_NO_LF), e],
        ),
        // A recovered interruption (prefix ending on LF), then the fatal
        // error: retry success does not commit any partial result.
        (
            "recovered interruption followed by a fatal error",
            true,
            vec![ReadAction::Short(SPLIT_AFTER_TWO_RECORDS), i, e],
        ),
    ];

    let mut any = false;
    for (desc, trailing_lf, script) in cases {
        let Some((path, out)) = run_b9(*trailing_lf, script) else {
            continue;
        };
        any = true;
        read_fault::assert_read_failure(&out, &path, desc);
    }
    if !any {
        skip_without_harness();
    }
}

#[test]
fn fatal_error_inside_a_record_fails_without_any_root() {
    let e = ReadAction::ReadError;
    // Each prefix ends in the MIDDLE of an open record: the fragment must not
    // be treated as a completed final record.
    let cases: &[(&str, bool, usize)] = &[
        ("error inside 'gamma'", true, SPLIT_INSIDE_GAMMA),
        ("error inside the binary record", true, SPLIT_INSIDE_BINARY_RECORD),
        ("error inside the final record", true, SPLIT_INSIDE_LAST_RECORD),
        // Same final-record fragment in the file without a trailing LF.
        ("error inside the final record, no trailing LF", false, SPLIT_INSIDE_LAST_RECORD),
    ];

    let mut any = false;
    for (desc, trailing_lf, split) in cases {
        let Some((path, out)) = run_b9(*trailing_lf, &[ReadAction::Short(*split), e]) else {
            continue;
        };
        any = true;
        read_fault::assert_read_failure(&out, &path, desc);
    }
    if !any {
        skip_without_harness();
    }
}

#[test]
fn fatal_error_at_natural_64kib_boundary_fails_the_whole_multi_read_batch() {
    let e = ReadAction::ReadError;
    let p = ReadAction::Pass;
    // Second read fails: a full 64 KiB ending on an LF is already committed
    // (several complete records), spanning the exact read boundary.
    let Some((path, out)) = run_mread(true, &[p, e]) else {
        skip_without_harness();
        return;
    };
    read_fault::assert_read_failure(
        &out,
        &path,
        "error after the first full 64 KiB (LF-ended) read",
    );

    // Third read fails with the 140000-byte record open across reads.
    let (path2, out) = run_mread(true, &[p, p, e]).expect("harness was available above");
    read_fault::assert_read_failure(&out, &path2, "error inside the long record");

    // A partial prefix must not masquerade as the fixed full-batch root: the
    // failure assertions above already pin stdout to empty; make the contrast
    // explicit.
    assert!(out.stdout.is_empty());
    assert_ne!(String::from_utf8_lossy(&out.stdout).as_ref(), ROOT_MREAD);
}
