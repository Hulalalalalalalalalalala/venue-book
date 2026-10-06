//! End-to-end regression tests for `roottrace root` on batches where one
//! record spans MULTIPLE reads of the file: `root` streams the file through a
//! fixed 64 KiB buffer, and the batch built here holds a 140000-byte record
//! (> 128 KiB) whose bytes arrive in several separate reads, plus two
//! record-separating LFs placed exactly on the last/first byte of a read
//! boundary. A read boundary must never become a record boundary: the long
//! record participates as its full byte sequence exactly once, and no record
//! is truncated, counted twice, or split into several positions.
//!
//! Expected roots are FIXED constants produced independently of roottrace by
//! `tests/reference/rfc6962_multiread_vectors.py` (standard-library
//! `hashlib.sha256`, the RFC 6962 recursive definition and an order-sensitive
//! stack fold agreeing); they are never derived from roottrace output. The
//! record bytes are rebuilt here with the same deterministic construction as
//! that script, so the expected root is anchored to the exact record sequence
//! documented below.
//!
//! The batch (10 records, a non-power-of-two count; RFC 6962 splits k=8, so
//! the long record at position 4 sits in the left subtree and the trailing
//! short record at position 9 in the right one):
//!
//! ```text
//!   0  "alpha"        short; duplicated byte-for-byte at position 6
//!   1  ""             empty record
//!   2  PAD            65528 bytes ("pad:" + 'p' * 65524); its terminating LF
//!                     is the LAST byte of the first 64 KiB read (offset 65535)
//!   3  ""             empty record; its LF is the FIRST byte of the second
//!                     read (offset 65536) - two consecutive LFs straddle the
//!                     read boundary and each still terminates one record
//!   4  LONG           140000 bytes (> 128 KiB), spanning reads 1..3; NUL, CR
//!                     and non-UTF-8 bytes in both halves and at the tail
//!   5  "beta\r"       short, trailing CR is content
//!   6  "alpha"        duplicate of position 0 (must not be merged)
//!   7  ""             empty record
//!   8  "\xff\x00z"    short, non-UTF-8 and NUL bytes
//!   9  "end-record\x01"  trailing short record, must reach the final root
//! ```

mod common;

use std::process::Command;

use common::{assert_root, bin, join_lf, TempFile};

/// The fixed buffer `roottrace root` reads the file through (src/main.rs).
/// The batch below is laid out against this size so that record separators
/// land exactly on a read boundary.
const READ_BUF: usize = 64 * 1024;

/// Length of the long record: > 128 KiB, so it spans several consecutive
/// reads no matter where in the file it starts.
const LONG_LEN: usize = 140_000;

/// Length of the PAD record: 7 bytes precede it in the file ("alpha\n" and
/// the empty record's "\n"), so PAD's terminating LF is the last byte of the
/// first read (offset READ_BUF - 1 = 65535).
const PAD_LEN: usize = READ_BUF - 1 - 7; // 65528

/// Position of the single changed content byte inside the long record: in
/// its second half and, as a file offset (65537 + 100000 = 165537), inside a
/// later read than the record's first bytes.
const MOD_POS: usize = 100_000;

// Independently fixed RFC 6962 roots
// (tests/reference/rfc6962_multiread_vectors.py).
const ROOT_MREAD: &str = "dca3d078542c8497a09302a4a0cd3b521a498ce3bffbe29bf9f510f2d1203304";
const ROOT_MREAD_M: &str = "93011d0e8ec828d5c3fd2698f87664fcdb9ce07f4b16bb5cac269474478d3f57";

/// Deterministic pseudo-random content byte; LF is remapped so the long
/// record never contains its own separator. Identical to `fill_byte` in
/// tests/reference/rfc6962_multiread_vectors.py.
fn fill_byte(i: usize) -> u8 {
    let b = ((i as u32).wrapping_mul(2_654_435_761) >> 13) as u8;
    if b == b'\n' {
        0x0b
    } else {
        b
    }
}

/// The 140000-byte record: pseudo-random binary fill with a distinct marker
/// spliced into the first half, the second half and the tail, so each region
/// carries content that distinguishes the original bytes.
fn long_record() -> Vec<u8> {
    let mut rec: Vec<u8> = (0..LONG_LEN).map(fill_byte).collect();
    rec[..13].copy_from_slice(b"MREAD\x00\xff\xfe\rHEAD"); // first-half marker
    let mid = LONG_LEN / 2;
    let marker = b"\x00\xff\rSECOND-HALF"; // second-half marker
    rec[mid..mid + marker.len()].copy_from_slice(marker);
    let tail = b"\x00TAIL\r\xff"; // tail marker, ends on a non-text byte
    rec[LONG_LEN - tail.len()..].copy_from_slice(tail);
    rec
}

/// The same record with exactly ONE non-LF content byte changed at MOD_POS
/// in the second half; length and every other byte are kept.
fn long_record_m() -> Vec<u8> {
    let mut rec = long_record();
    let old = rec[MOD_POS];
    rec[MOD_POS] = if old != b'A' { b'A' } else { b'B' };
    rec
}

/// The PAD record aligning the following LFs to the read boundary.
fn pad_record() -> Vec<u8> {
    let mut p = b"pad:".to_vec();
    p.resize(PAD_LEN, b'p');
    p
}

/// The 10-record sequence, with the long record (original or modified)
/// plugged in at position 4.
fn records<'a>(pad: &'a [u8], long: &'a [u8]) -> Vec<&'a [u8]> {
    vec![
        b"alpha",
        b"",
        pad,
        b"",
        long,
        b"beta\r",
        b"alpha",
        b"",
        b"\xff\x00z",
        b"end-record\x01",
    ]
}

/// Run `roottrace root` on a file holding exactly `file_bytes`.
fn run_root(file_bytes: &[u8]) -> std::process::Output {
    let tmp = TempFile::create(file_bytes);
    Command::new(bin())
        .arg("root")
        .arg(&tmp.path)
        .output()
        .expect("failed to execute roottrace binary")
}

#[test]
fn batch_shape_covers_multiple_reads_and_boundary_lfs() {
    let pad = pad_record();
    let long = long_record();
    let recs = records(&pad, &long);

    // Non-power-of-two record count with empty records, a duplicate and a
    // trailing short record.
    assert_eq!(recs.len(), 10);
    assert!(!recs.len().is_power_of_two());
    assert_eq!(recs[0], recs[6], "duplicate content must not be merged");
    assert_eq!(recs[1], b"");
    assert_eq!(recs[3], b"");
    assert_eq!(recs[7], b"");
    assert_eq!(recs[9], b"end-record\x01");

    // The long record exceeds 128 KiB and contains no LF; NUL, CR and
    // non-UTF-8 bytes appear in both halves and at the tail.
    assert!(long.len() > 128 * 1024);
    assert!(!long.contains(&b'\n'));
    let half = LONG_LEN / 2;
    for region in [&long[..half], &long[half..]] {
        assert!(region.contains(&0x00), "NUL in each half");
        assert!(region.contains(&0x0d), "CR in each half");
        assert!(region.iter().any(|&b| b >= 0x80), "non-UTF-8 in each half");
    }
    assert_eq!(&long[..13], b"MREAD\x00\xff\xfe\rHEAD");
    assert_eq!(&long[half..half + 14], b"\x00\xff\rSECOND-HALF");
    assert_eq!(&long[LONG_LEN - 7..], b"\x00TAIL\r\xff");

    // File layout against the 64 KiB read buffer: the LFs terminating
    // records 2 and 3 are consecutive bytes straddling the first read
    // boundary, and the long record spans several reads.
    let data = join_lf(&recs, true);
    assert_eq!(data.len(), 205_567);
    assert!(data.len() > 3 * READ_BUF, "the file needs several reads");
    assert_eq!(data[READ_BUF - 1], b'\n', "PAD's LF is the last byte of read 0");
    assert_eq!(data[READ_BUF], b'\n', "the empty record's LF is the first byte of read 1");
    assert_ne!(data[READ_BUF - 2], b'\n');
    assert_ne!(data[READ_BUF + 1], b'\n');
    let long_start = 7 + PAD_LEN + 1 + 1; // after PAD's LF and record 3's LF
    let long_end = long_start + LONG_LEN - 1;
    assert_eq!(long_start, READ_BUF + 1);
    assert!(
        long_end / READ_BUF - long_start / READ_BUF >= 2,
        "the long record must span at least three reads"
    );
    // The file holds exactly ten LFs: nine separators plus the terminator.
    assert_eq!(data.iter().filter(|&&b| b == b'\n').count(), 10);
}

#[test]
fn multi_read_batch_matches_fixed_root_with_and_without_trailing_lf() {
    let pad = pad_record();
    let long = long_record();
    let recs = records(&pad, &long);

    assert_root(
        "MREAD: 10 records, 140000-byte record spanning reads, trailing LF",
        &recs,
        &join_lf(&recs, true),
        ROOT_MREAD,
    );
    assert_root(
        "MREAD: same record sequence, no trailing LF",
        &recs,
        &join_lf(&recs, false),
        ROOT_MREAD,
    );

    // The two file forms encode the same record sequence, so the command
    // output must be byte-for-byte identical, not just equal to the vector.
    let with_lf = run_root(&join_lf(&recs, true));
    let without_lf = run_root(&join_lf(&recs, false));
    assert_eq!(with_lf.status.code(), Some(0));
    assert_eq!(without_lf.status.code(), Some(0));
    assert_eq!(with_lf.stdout, without_lf.stdout);
    assert_eq!(with_lf.stdout, format!("{ROOT_MREAD}\n").into_bytes());
    assert!(with_lf.stderr.is_empty() && without_lf.stderr.is_empty());
}

#[test]
fn one_byte_change_in_second_half_gives_the_modified_batchs_fixed_root() {
    let pad = pad_record();
    let long = long_record();
    let long_m = long_record_m();

    // Exactly one content byte differs, in the second half of the long
    // record; it is not an LF, and record count and order are unchanged.
    assert!(MOD_POS > LONG_LEN / 2);
    assert_eq!(long_m.len(), long.len());
    assert_eq!(long_m[..MOD_POS], long[..MOD_POS]);
    assert_eq!(long_m[MOD_POS + 1..], long[MOD_POS + 1..]);
    assert_ne!(long_m[MOD_POS], long[MOD_POS]);
    assert_ne!(long_m[MOD_POS], b'\n');

    let recs_m = records(&pad, &long_m);
    assert_eq!(recs_m.len(), 10);
    let recs = records(&pad, &long);
    for i in 0..10 {
        if i != 4 {
            assert_eq!(recs_m[i], recs[i], "only the long record changes");
        }
    }

    assert_root(
        "MREAD_M: one non-LF byte changed in the long record's second half",
        &recs_m,
        &join_lf(&recs_m, true),
        ROOT_MREAD_M,
    );
    assert_root(
        "MREAD_M: same modified batch without trailing LF",
        &recs_m,
        &join_lf(&recs_m, false),
        ROOT_MREAD_M,
    );
    assert_ne!(
        ROOT_MREAD, ROOT_MREAD_M,
        "one byte deep in the multi-read record must change the root: \
         the unmodified parts stay in the computation but cannot mask it"
    );
}

#[test]
fn cli_counts_exactly_ten_positions_for_the_multi_read_batch() {
    // The root vector above pins the full byte content; this pins the record
    // COUNT seen at the command line: positions 0..9 exist (the trailing
    // short record included), position 10 does not - the long record was not
    // split into several positions and no boundary LF was lost or invented.
    let pad = pad_record();
    let long = long_record();
    let recs = records(&pad, &long);
    let tmp = TempFile::create(&join_lf(&recs, true));

    let last = Command::new(bin())
        .arg("prove")
        .arg(&tmp.path)
        .arg("9")
        .output()
        .unwrap();
    assert_eq!(last.status.code(), Some(0));
    let json = String::from_utf8(last.stdout).unwrap();
    assert!(
        json.contains("\"tree_size\":10") && json.contains("\"leaf_index\":9"),
        "the tenth record must exist at index 9: {json}"
    );
    // The proof commits to the same root the streaming `root` prints.
    assert!(json.contains(&format!("\"root\":\"{ROOT_MREAD}\"")), "{json}");

    let beyond = Command::new(bin())
        .arg("prove")
        .arg(&tmp.path)
        .arg("10")
        .output()
        .unwrap();
    assert_eq!(beyond.status.code(), Some(1), "there is no eleventh record");
    assert!(beyond.stdout.is_empty());
}
