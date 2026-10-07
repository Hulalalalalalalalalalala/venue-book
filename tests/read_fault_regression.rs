//! End-to-end regression tests for the way `roottrace root` handles errors
//! reported WHILE the batch file is being read.
//!
//! Two outcomes are pinned against the real binary:
//!
//!   * A read that reports Interrupted (EINTR) but can be retried must keep
//!     processing the SAME batch: the bytes already read are neither lost nor
//!     fed in twice, whether the interruption lands inside the long record or
//!     immediately after the record-separating LF (and including the read
//!     attempt that otherwise reports end of file). The recovered root is
//!     exactly the uninterrupted one, stdout stays one 64-lowercase-hex line
//!     plus LF, stderr stays empty and the exit status is 0.
//!   * A read error (here EIO) after some bytes have already been read must
//!     fail the whole computation: exit status 1, stdout EMPTY (no root for
//!     the already-complete prefix, no empty-tree root, no partial result),
//!     stderr naming the input path and the read reason. This is a read
//!     failure (exit 1), not a usage error (exit 2).
//!
//! Recovered reads keep the batch file's existing byte rules: LF only
//! separates records, the trailing LF adds no empty record, a final record
//! without a trailing LF still participates in full, and CR/NUL/non-UTF-8
//! bytes are never trimmed; the end of one read is never the end of a record.
//!
//! Faults are injected with the LD_PRELOAD shim in tests/common/
//! read_fault_shim.c, built on the fly (Linux + a C compiler; the tests skip
//! where that is unavailable). The shim only touches read() attempts on one
//! descriptor - the batch file, matched through /proc/self/fd - and scripts
//! each successive attempt as a normal (size-capped) read, EINTR, EIO or a
//! premature EOF. Reads are capped to READ_CAP bytes so interruption/error
//! points land exactly on the documented offsets; nothing here simulates the
//! read loop in Rust, so the command's actual src/main.rs loop is exercised.
//!
//! Expected roots are FIXED constants produced independently of roottrace by
//! tests/reference/rfc6962_read_interrupt_vectors.py (Python hashlib, RFC 6962
//! recursion and an order-sensitive stack fold agreeing); they are copied
//! below and never derived from roottrace output. A recoverable interruption
//! changes only read chunking, not the bytes, so its root is the same fixed
//! root as an uninterrupted read.

mod common;

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

use common::{bin, join_lf, TempFile};

// --- Fixed batch and vectors -----------------------------------------------
//
// File layout (forced read size READ_CAP = 8), trailing-LF form:
//
//   0..4   b"alpha"          record 0
//   5      LF
//   6      LF                record 1 = ""
//   7      LF                record 2 = ""; LAST byte of the first 8-byte
//                             read, so the next attempt comes right after a
//                             separating LF
//   8..33  LONG (26 bytes)   record 3, spanning several forced reads; NUL, CR
//                             and non-UTF-8 bytes in both halves, final byte
//                             0xfe; contains no LF
//   34     LF
//   35..40 b"end\x01\xffz"   record 4, the final short record
//   41     LF                trailing-LF form only

const READ_CAP: usize = 8;
const LONG_LEN: usize = 26;
const MOD_INDEX: usize = 20;
const OFF_R2_LF: usize = 7; // LF ending the first forced read
const LONG_START: usize = 8;
const LONG_END: usize = 33;
const OFF_LONG_LF: usize = 34;
const R4_START: usize = 35;
const OFF_TRAILING_LF: usize = 41;
const TRAILING_FILE_LEN: usize = 42;
const NOTRAILING_FILE_LEN: usize = 41;

const ROOT_IREC: &str = "8ee1f04edea76548cf86c83bd8edeb1777f3f38f4c770d120771ac870ac3cc9b";
const ROOT_IREC_M: &str = "181ec9faa6256e48dc1d8ec07cdcf3477060a45719fbf36143ab257d70087ea1";

const LONG_REC: &[u8] = b"LO\x00\xff\rRECqqqqqqqqqqqqqqqqq\xfe";
const LONG_REC_M: &[u8] = b"LO\x00\xff\rRECqqqqqqqqqqqqZqqqq\xfe";
const R4_REC: &[u8] = b"end\x01\xffz";

fn records(long: &'static [u8]) -> Vec<&'static [u8]> {
    vec![b"alpha", b"", b"", long, R4_REC]
}

// --- Fault-injection shim ---------------------------------------------------

static SHIM_COUNTER: AtomicU64 = AtomicU64::new(0);

/// A compiled read-fault preload shared object, deleted when the test ends.
struct FaultShim {
    path: PathBuf,
}

impl Drop for FaultShim {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

impl FaultShim {
    /// Compile the shipped shim. Returns None where the mechanism is
    /// unavailable (not Linux, or no C compiler); the calling test then
    /// skips. `cargo test --offline` needs no network or crate for this.
    fn compile() -> Option<Self> {
        if cfg!(not(target_os = "linux")) {
            return None;
        }
        let source = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("common")
            .join("read_fault_shim.c");
        if !source.exists() {
            return None;
        }
        let cc = ["cc", "gcc", "clang"]
            .iter()
            .find(|c| which(c).is_some())?;
        let id = SHIM_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "roottrace-readfault-{}-{id}.so",
            std::process::id()
        ));
        let status = Command::new(cc)
            .arg("-shared")
            .arg("-fPIC")
            .arg("-o")
            .arg(&path)
            .arg(&source)
            .status()
            .ok()?;
        if !status.success() || !path.exists() {
            return None;
        }
        Some(FaultShim { path })
    }
}

fn which(program: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(program);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// Run `roottrace root <file>` under the shim with a per-read-attempt script.
/// `script` lists actions (ok/intr/eio/eof) for successive read() ATTEMPTS on
/// the batch descriptor; an EINTR attempt consumes its own token.
fn root_with_faults(file: &Path, shim: &FaultShim, script: &str) -> Output {
    Command::new(bin())
        .arg("root")
        .arg(file)
        .env("LD_PRELOAD", &shim.path)
        // Match by the unique temp-file basename against the descriptor's
        // /proc/self/fd resolution; other descriptors are never affected.
        .env("RT_FAULT_TARGET", file.file_name().unwrap())
        .env("RT_READ_CAP", READ_CAP.to_string())
        .env("RT_FAULT_SCRIPT", script)
        .output()
        .expect("failed to execute roottrace binary")
}

/// Strict success path, matching common::assert_root for output produced via
/// the fault-injecting command: exit 0, empty stderr, stdout exactly the 64
/// lowercase hex digits of `expected` plus one LF.
fn assert_recovered_root(desc: &str, out: &Output, expected: &str) {
    if out.status.code() != Some(0) {
        panic!(
            "[{desc}] expected successful recovery (exit 0), got {:?}\n\
             stderr: {}\nstdout: {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr),
            String::from_utf8_lossy(&out.stdout),
        );
    }
    if !out.stderr.is_empty() {
        panic!(
            "[{desc}] a recoverable interruption must not be reported: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    if out.stdout.len() != 65 || out.stdout[64] != b'\n' {
        panic!("[{desc}] stdout is not 64 hex digits + LF: {:?}", out.stdout);
    }
    let hex = &out.stdout[..64];
    assert!(
        hex.iter().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
        "[{desc}] root must be lowercase hex"
    );
    assert_eq!(
        std::str::from_utf8(hex).unwrap(),
        expected,
        "[{desc}] recovered root must be the full original batch's root"
    );
}

/// Strict failure path for an unreadable-after-partial-bytes file: exit 1,
/// nothing on stdout, stderr naming the input path and the read reason.
fn assert_read_failure(desc: &str, out: &Output, path: &Path) {
    assert_eq!(
        out.status.code(),
        Some(1),
        "[{desc}] a file read failure must exit 1, got {:?}\nstderr: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr),
    );
    assert!(
        out.stdout.is_empty(),
        "[{desc}] no root (not even of the prefix read before the error) may be printed: {:?}",
        out.stdout
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains(&*path.file_name().unwrap().to_string_lossy()),
        "[{desc}] stderr must name the input path, got: {err}"
    );
    assert!(
        err.contains("cannot read"),
        "[{desc}] stderr must classify this as a read failure, got: {err}"
    );
    // The read reason: the injected EIO surfaces as an OS error rather than
    // as a usage message or a silently truncated file.
    assert!(
        err.contains("os error 5"),
        "[{desc}] stderr must state the read reason, got: {err}"
    );
}

// --- Fixed batch shape ------------------------------------------------------

#[test]
fn batch_layout_pins_interruption_points_and_byte_rules() {
    let recs = records(LONG_REC);
    assert_eq!(recs.len(), 5);
    let trail = join_lf(&recs, true);
    let notrail = join_lf(&recs, false);

    assert_eq!(trail.len(), TRAILING_FILE_LEN);
    assert_eq!(notrail.len(), NOTRAILING_FILE_LEN);

    // Three consecutive LFs: record 0 ends, then records 1 and 2 are empty.
    assert_eq!(&trail[..5], b"alpha");
    for off in [5, 6, OFF_R2_LF] {
        assert_eq!(trail[off], b'\n', "offset {off}");
    }
    // The first forced READ_CAP-byte read ends exactly on a separating LF;
    // its preceding byte is the previous separating LF (the empty record 2).
    assert_eq!(READ_CAP - 1, OFF_R2_LF);
    assert_eq!(trail[OFF_R2_LF - 1], b'\n');

    // The long record spans several forced reads and is byte-exact inside.
    assert!(LONG_LEN > 2 * READ_CAP);
    assert_eq!(&trail[LONG_START..=LONG_END], LONG_REC);
    assert_eq!(LONG_REC.len(), LONG_LEN);
    assert!(!LONG_REC.contains(&b'\n'));
    assert!(LONG_REC.contains(&0x00), "NUL participates");
    assert!(LONG_REC.contains(&0x0d), "CR is not trimmed");
    assert!(LONG_REC.iter().any(|&b| b >= 0x80), "non-UTF-8 bytes participate");
    assert_eq!(LONG_REC[0], b'L');
    assert_eq!(LONG_REC[LONG_LEN - 1], 0xfe);
    // The changed byte distinguishing ROOT_IREC_M sits in a later forced read
    // than the record's first bytes, so a prefix-only computation cannot see it.
    assert!(LONG_START + MOD_INDEX >= 2 * READ_CAP);
    assert_eq!(LONG_REC_M[MOD_INDEX], b'Z');
    assert_ne!(LONG_REC_M[MOD_INDEX], LONG_REC[MOD_INDEX]);
    assert_eq!(LONG_REC_M.len(), LONG_LEN);

    assert_eq!(trail[OFF_LONG_LF], b'\n');
    assert_eq!(&trail[R4_START..OFF_TRAILING_LF], R4_REC);
    assert_eq!(trail[OFF_TRAILING_LF], b'\n');

    // The no-trailing-LF form is the same bytes minus the final LF; its last
    // record still ends on a non-text byte and is fully present.
    assert_eq!(notrail, &trail[..OFF_TRAILING_LF]);
    assert_eq!(&notrail[R4_START..], R4_REC);
    assert_eq!(notrail[notrail.len() - 1], 0x7a);
}

#[test]
fn uninterrupted_batch_has_the_fixed_root_in_both_file_forms() {
    let recs = records(LONG_REC);
    // Without the shim, ordinary reads (the OS returns the 64 KiB buffer in
    // one go) anchor the same fixed root the interrupted runs must reproduce.
    for (desc, bytes) in [
        ("trailing LF", join_lf(&recs, true)),
        ("no trailing LF", join_lf(&recs, false)),
    ] {
        let tmp = TempFile::create(&bytes);
        let out = Command::new(bin()).arg("root").arg(&tmp.path).output().unwrap();
        assert_recovered_root(&format!("uninterrupted, {desc}"), &out, ROOT_IREC);
    }
    assert_ne!(ROOT_IREC, ROOT_IREC_M);
}

// --- Interrupted reads are recovered ----------------------------------------

#[test]
fn interruption_inside_the_long_record_loses_no_bytes() {
    let Some(shim) = FaultShim::compile() else {
        eprintln!("skipping: read-fault shim needs Linux and a C compiler");
        return;
    };
    let recs = records(LONG_REC);
    // EINTR on attempt 2, which (after two 8-byte reads) is inside the long
    // record; later attempts return the rest.
    let tmp = TempFile::create(&join_lf(&recs, true));
    let out = root_with_faults(&tmp.path, &shim, "ok,ok,intr,ok,ok,ok,ok,ok");
    assert_recovered_root("EINTR inside the long record", &out, ROOT_IREC);
}

#[test]
fn interruption_right_after_a_separating_lf_keeps_the_sequence() {
    let Some(shim) = FaultShim::compile() else {
        eprintln!("skipping: read-fault shim needs Linux and a C compiler");
        return;
    };
    let recs = records(LONG_REC);
    // The first read returns exactly offsets 0..8, whose last byte is the LF
    // closing empty record 2; the very next attempt reports EINTR. Recovery
    // must not turn that read end / LF into anything but the separator it is.
    let tmp = TempFile::create(&join_lf(&recs, true));
    let out = root_with_faults(&tmp.path, &shim, "ok,intr,ok,ok,ok,ok,ok,ok");
    assert_recovered_root("EINTR immediately after a separating LF", &out, ROOT_IREC);
}

#[test]
fn interruption_on_the_eof_attempt_is_retried_not_taken_as_eof() {
    let Some(shim) = FaultShim::compile() else {
        eprintln!("skipping: read-fault shim needs Linux and a C compiler");
        return;
    };
    let recs = records(LONG_REC);
    // Both file forms: all bytes are already in, then the attempt that should
    // return 0 instead reports EINTR once; the retry returns the real EOF.
    for (desc, bytes, script) in [
        (
            "EINTR on the EOF attempt, trailing LF",
            join_lf(&recs, true),
            "ok,ok,ok,ok,ok,ok,intr,ok",
        ),
        (
            "EINTR on the EOF attempt, no trailing LF",
            join_lf(&recs, false),
            "ok,ok,ok,ok,ok,ok,intr,ok",
        ),
    ] {
        let tmp = TempFile::create(&bytes);
        let out = root_with_faults(&tmp.path, &shim, script);
        assert_recovered_root(desc, &out, ROOT_IREC);
    }
}

#[test]
fn repeated_interruptions_including_first_attempt_still_recover() {
    let Some(shim) = FaultShim::compile() else {
        eprintln!("skipping: read-fault shim needs Linux and a C compiler");
        return;
    };
    let recs = records(LONG_REC);
    // EINTR before any byte, then two consecutive EINTRs inside the long
    // record. Each is a retry of the same position with zero bytes consumed.
    let tmp = TempFile::create(&join_lf(&recs, true));
    let out = root_with_faults(
        &tmp.path,
        &shim,
        "intr,ok,intr,intr,ok,ok,ok,ok,ok,ok",
    );
    assert_recovered_root("repeated EINTRs, including the first attempt", &out, ROOT_IREC);
}

#[test]
fn recovery_over_no_trailing_lf_and_modified_deep_byte_keeps_full_records() {
    let Some(shim) = FaultShim::compile() else {
        eprintln!("skipping: read-fault shim needs Linux and a C compiler");
        return;
    };
    // No trailing LF: interruptions in the middle of the long record and
    // right after a separating LF. The final record has no terminating LF,
    // and the long record's CR/NUL/non-UTF-8 bytes must arrive untrimmed, so
    // the root is still the fixed full-sequence root.
    let recs = records(LONG_REC);
    for script in ["ok,ok,intr,ok,ok,ok,ok", "ok,intr,ok,ok,ok,ok,ok"] {
        let tmp = TempFile::create(&join_lf(&recs, false));
        let out = root_with_faults(&tmp.path, &shim, script);
        assert_recovered_root(
            "EINTR recovery, last record without trailing LF",
            &out,
            ROOT_IREC,
        );
    }

    // A byte changed deep in the long record (a later forced read than its
    // start) changes the fixed root even through an interruption right after
    // a separating LF: bytes past the interruption point really do count.
    let recs_m = records(LONG_REC_M);
    let tmp = TempFile::create(&join_lf(&recs_m, true));
    let out = root_with_faults(&tmp.path, &shim, "ok,intr,ok,ok,ok,ok,ok,ok");
    assert_recovered_root("EINTR recovery with a deep byte changed", &out, ROOT_IREC_M);
}

// --- Read errors after some bytes fail the whole root -----------------------

#[test]
fn read_error_inside_a_record_fails_with_empty_stdout() {
    let Some(shim) = FaultShim::compile() else {
        eprintln!("skipping: read-fault shim needs Linux and a C compiler");
        return;
    };
    let recs = records(LONG_REC);
    // 16 bytes already read (inside the long record), then EIO. The partial
    // record must not be treated as a complete final record.
    for bytes in [join_lf(&recs, true), join_lf(&recs, false)] {
        let tmp = TempFile::create(&bytes);
        let out = root_with_faults(&tmp.path, &shim, "ok,ok,eio");
        assert_read_failure("EIO mid-record after partial bytes", &out, &tmp.path);
    }
}

#[test]
fn read_error_right_after_a_lf_does_not_emit_the_prefix_root() {
    let Some(shim) = FaultShim::compile() else {
        eprintln!("skipping: read-fault shim needs Linux and a C compiler");
        return;
    };
    let recs = records(LONG_REC);
    // The first read ends exactly on the LF closing empty record 2: records
    // 0..2 are fully assembled, then EIO. Even those complete records must not
    // be reported as a root, and nothing is printed to stdout.
    let tmp = TempFile::create(&join_lf(&recs, true));
    let out = root_with_faults(&tmp.path, &shim, "ok,eio");
    assert_read_failure("EIO immediately after a separating LF", &out, &tmp.path);
}

#[test]
fn read_error_after_all_bytes_are_read_still_fails() {
    let Some(shim) = FaultShim::compile() else {
        eprintln!("skipping: read-fault shim needs Linux and a C compiler");
        return;
    };
    let recs = records(LONG_REC);
    // Every file byte has already been fed successfully (including the final
    // no-trailing-LF record); the next read attempt - the one meant to return
    // EOF - reports EIO instead. The batch must still fail with empty stdout
    // rather than printing the computable root.
    for bytes in [join_lf(&recs, true), join_lf(&recs, false)] {
        let tmp = TempFile::create(&bytes);
        let out = root_with_faults(&tmp.path, &shim, "ok,ok,ok,ok,ok,ok,eio");
        assert_read_failure("EIO on the EOF attempt after all bytes", &out, &tmp.path);
    }
}

#[test]
fn first_read_error_is_classified_the_same_as_a_later_one() {
    let Some(shim) = FaultShim::compile() else {
        eprintln!("skipping: read-fault shim needs Linux and a C compiler");
        return;
    };
    let recs = records(LONG_REC);
    // Zero bytes obtained: still a read failure (exit 1, path and reason on
    // stderr), never the empty-tree root.
    let tmp = TempFile::create(&join_lf(&recs, true));
    let out = root_with_faults(&tmp.path, &shim, "eio");
    assert_read_failure("EIO on the first read", &out, &tmp.path);
}

// --- The shim really drives the read loop -----------------------------------

#[test]
fn injected_premature_eof_matches_a_genuinely_truncated_file() {
    let Some(shim) = FaultShim::compile() else {
        eprintln!("skipping: read-fault shim needs Linux and a C compiler");
        return;
    };
    // Negative control proving the faults genuinely reach the command's read
    // loop: force a premature EOF after the first 8 bytes. The result must be
    // (a) the root of a real file holding exactly those 8 bytes and (b) NOT
    // the fixed root of the complete batch. If the preload did not load, this
    // command would read the whole file and equal ROOT_IREC, failing (b).
    let recs = records(LONG_REC);
    let full = TempFile::create(&join_lf(&recs, true));
    let prefix_bytes = &join_lf(&recs, true)[..READ_CAP];
    assert_eq!(prefix_bytes, b"alpha\n\n\n");
    let truncated = TempFile::create(prefix_bytes);

    let injected = root_with_faults(&full.path, &shim, "ok,eof");
    let genuine = Command::new(bin())
        .arg("root")
        .arg(&truncated.path)
        .output()
        .unwrap();

    assert_eq!(injected.status.code(), Some(0));
    assert_eq!(genuine.status.code(), Some(0));
    assert!(injected.stderr.is_empty() && genuine.stderr.is_empty());
    assert_eq!(
        injected.stdout, genuine.stdout,
        "a forced early EOF must be indistinguishable from a genuinely short file"
    );
    assert_ne!(
        injected.stdout,
        format!("{ROOT_IREC}\n").into_bytes(),
        "the injected early EOF must change the result; is LD_PRELOAD active?"
    );
}
