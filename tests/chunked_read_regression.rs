//! End-to-end regression tests for `roottrace root` on batches LARGER THAN
//! ONE READ: a record that spans several 64 KiB reads and LF separator runs
//! that straddle read boundaries.
//!
//! `root` streams the batch file through a fixed 64 KiB buffer (see
//! src/main.rs). The earlier regressions cover short batches and short
//! records; this file pins down what happens when one record is longer than
//! the read length and when separators land exactly on a read edge:
//!
//!   * a record spanning multiple reads hashes its COMPLETE bytes - a read
//!     boundary never truncates it, counts it twice or splits it into several
//!     record positions;
//!   * record order, empty records and duplicated content all keep their exact
//!     positions across reads, and a short trailing record still takes part in
//!     the root (identical content is never merged);
//!   * two files differing only in a terminating LF print byte-identical
//!     output;
//!   * consecutive LFs straddling a read boundary each introduce exactly one
//!     empty record - none lost, none added;
//!   * changing exactly one non-LF byte in the long record's SECOND half
//!     preserves the record count and order but yields the modified batch's
//!     own fixed root, while the untouched parts still participate.
//!
//! Expected roots are FIXED constants produced independently of roottrace by
//! `tests/reference/rfc6962_vectors.py` (standard-library `hashlib.sha256`,
//! the RFC's recursive definition and a structurally different stack fold
//! agreeing). The construction parameters below are copied from that
//! generator, so the file the CLI reads is exactly the fixed record sequence
//! the constants correspond to; nothing is derived from roottrace output.

mod common;

use common::{join_lf_owned, root_of_file_bytes, run_root};

/// The CLI read buffer in src/main.rs (`64 * 1024`). The fixture files are
/// several times this size, forcing multiple `read()` calls.
const CLI_READ_LEN: usize = 65536;

// --- Fixed long-record construction parameters (copied from the generator). -
const CHUNK_LONG_LEN: usize = 200_000; // > 128 KiB and > three read lengths
const CHUNK_LONG_HEAD: &[u8] = b"S200:\x00\xff\xfe\r";
const CHUNK_FILL_ALPHABET: &[u8] =
    b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const CHUNK_MARK_FIRST_OFFSET: usize = 10_000;
const CHUNK_MARK_FIRST: &[u8] = b"@FIRST-HALF@\x00\r\xff";
const CHUNK_MARK_SECOND_OFFSET: usize = 120_000;
const CHUNK_MARK_SECOND: &[u8] = b"@SECOND-HALF@\x00\r\xfe";
const CHUNK_TAIL_MARK: &[u8] = b"@TAIL-REGION@\x00\r\xfd";
/// The single changed byte: the 'S' of the second-half marker becomes 'X'.
const CHUNK_MUT_OFFSET: usize = 120_001;

// Independently fixed RFC 6962 roots (tests/reference/rfc6962_vectors.py).
const ROOT_CHUNK: &str = "3b2aa30896ceb93f2daa3b87daf413e9452037c9d005b6eb41d8f49de4bf979e";
const ROOT_CHUNK_M: &str = "bca54125a164366cf9b883f28dd84587fbfc424a1943258a100f81ef44a0f879";
const ROOT_CHUNK_NO_EMPTY: &str =
    "c8ddc949e8bc1584aed2f021e52d34eb19750fcce35230411c180c97615875fe";
const ROOT_CHUNK_NO_DUP: &str =
    "7aeba1aacb937c50ff50e324bcf38c288834a9551b02480e460ef46da5e37ab6";
const ROOT_CHUNK_NO_TAIL: &str =
    "c8410006ed5cefa8a96d716749becc67b6ce680c6f754b39826e2aac73e1159f";
const ROOT_LF_BOUNDARY: &str =
    "91d6946f1b8a7e39527dbf574828e9f27a4bea6970763bf8ac8017c6f8807fa6";

/// LF-run straddling the read boundary: fixed prefix (with NUL/CR/non-UTF-8)
/// and total length of each padding record; the rest of the record is filled
/// with `LF_BOUNDARY_FILL`. After the padding record's own LF come three LFs
/// that introduce three empty records.
const LF_BOUNDARY_FILL: u8 = b'p';
const LF_BOUNDARY_PAD: &[(&[u8], usize)] = &[
    (b"CLUSTER1-PADDING:\x00\r\xff", 65534),
    (b"CLUSTER2-PADDING:\x00\r\xff", 65532),
    (b"CLUSTER3-PADDING:\x00\r\xff", 65532),
];
/// Exact file offsets of the twelve clustered separators (four per boundary):
/// k*64KiB-2, k*64KiB-1, k*64KiB, k*64KiB+1 for k = 1, 2, 3.
const LF_BOUNDARY_SEPARATORS: &[usize] = &[
    65534, 65535, 65536, 65537, 131070, 131071, 131072, 131073, 196606, 196607, 196608, 196609,
];

// --- Fixture construction (mirrors the Python generator byte for byte). -----

/// Build the 200_000-byte long record: fixed binary head, cyclic ASCII fill,
/// distinctive markers overwritten at fixed offsets in the first half, second
/// half and tail. No byte is ever LF.
fn build_long_record() -> Vec<u8> {
    let mut rec: Vec<u8> = CHUNK_LONG_HEAD.to_vec();
    let mut i = 0usize;
    while rec.len() < CHUNK_LONG_LEN {
        rec.push(CHUNK_FILL_ALPHABET[i % CHUNK_FILL_ALPHABET.len()]);
        i += 1;
    }
    rec[CHUNK_MARK_FIRST_OFFSET..CHUNK_MARK_FIRST_OFFSET + CHUNK_MARK_FIRST.len()]
        .copy_from_slice(CHUNK_MARK_FIRST);
    rec[CHUNK_MARK_SECOND_OFFSET..CHUNK_MARK_SECOND_OFFSET + CHUNK_MARK_SECOND.len()]
        .copy_from_slice(CHUNK_MARK_SECOND);
    rec[CHUNK_LONG_LEN - CHUNK_TAIL_MARK.len()..].copy_from_slice(CHUNK_TAIL_MARK);
    assert_eq!(rec.len(), CHUNK_LONG_LEN);
    rec
}

/// The seven fixed records around one supplied (possibly mutated) long record.
fn chunk_records(long: &[u8]) -> Vec<Vec<u8>> {
    vec![
        b"before-a".to_vec(), // 0 short record before the long one
        long.to_vec(),       // 1 record spanning multiple reads
        b"".to_vec(),        // 2 empty record
        b"dup".to_vec(),     // 3 first occurrence
        b"after-b\x01".to_vec(), // 4 short record after the long one
        b"dup".to_vec(),     // 5 same bytes as position 3, own position
        b"tail-final".to_vec(), // 6 trailing short record
    ]
}

/// Keep only the CHUNK records whose indices pass `keep`, around `long`.
fn chunk_records_subset<F: Fn(usize) -> bool>(long: &[u8], keep: F) -> Vec<Vec<u8>> {
    chunk_records(long)
        .into_iter()
        .enumerate()
        .filter(|(i, _)| keep(*i))
        .map(|(_, r)| r)
        .collect()
}

/// Build the LF-run boundary batch file: three padding records, each followed
/// by three empty records, then a final `end` record.
fn boundary_file(trailing_lf: bool) -> Vec<u8> {
    let mut data: Vec<u8> = Vec::new();
    for (prefix, total_len) in LF_BOUNDARY_PAD {
        data.extend_from_slice(prefix);
        data.extend(
            std::iter::repeat(LF_BOUNDARY_FILL).take(total_len - prefix.len()),
        );
        data.push(b'\n'); // ends the padding record ...
        data.extend([b'\n'; 3]); // ... and introduces three empty records
    }
    data.extend_from_slice(b"end");
    if trailing_lf {
        data.push(b'\n');
    }
    data
}

/// Byte offset in the batch file where the long record starts: `before-a`
/// (8 bytes) plus its LF.
const LONG_RECORD_FILE_OFFSET: usize = 9;

// --- Structural invariants of the fixture itself. ---------------------------

#[test]
fn chunk_fixture_forces_multiple_reads_and_has_the_required_shape() {
    let long = build_long_record();
    assert_eq!(long.len(), CHUNK_LONG_LEN);
    assert!(long.len() > 128 * 1024, "at least one record must exceed 128 KiB");
    assert!(long.len() > CLI_READ_LEN, "the long record exceeds one read length");
    assert!(!long.contains(&b'\n'), "the long record contains no LF of its own");

    // NUL, CR and non-UTF-8 bytes occur throughout, including at the tail.
    for (name, window) in [
        ("head", &long[..CLI_READ_LEN.min(long.len())]),
        ("tail", &long[CHUNK_LONG_LEN - CHUNK_TAIL_MARK.len()..]),
    ] {
        assert!(window.contains(&0x00), "{name} keeps a NUL byte");
        assert!(window.contains(&0x0D), "{name} keeps a CR byte");
        assert!(window.iter().any(|&b| b >= 0x80), "{name} keeps a non-UTF-8 byte");
    }

    // Distinctive markers sit in the first half, second half and tail.
    assert_eq!(&long[CHUNK_MARK_FIRST_OFFSET..][..CHUNK_MARK_FIRST.len()], CHUNK_MARK_FIRST);
    assert_eq!(&long[CHUNK_MARK_SECOND_OFFSET..][..CHUNK_MARK_SECOND.len()], CHUNK_MARK_SECOND);
    assert_eq!(&long[CHUNK_LONG_LEN - CHUNK_TAIL_MARK.len()..], CHUNK_TAIL_MARK);
    assert!(CHUNK_MARK_FIRST_OFFSET < CHUNK_LONG_LEN / 2);
    assert!(CHUNK_MARK_SECOND_OFFSET > CHUNK_LONG_LEN / 2);

    // The single-byte mutation is a non-LF content byte in the SECOND half;
    // it changes the 'S' of the second-half marker to 'X'.
    assert_eq!(long[CHUNK_MUT_OFFSET], b'S');
    assert_ne!(b'S', b'\n');
    assert!(CHUNK_MUT_OFFSET > CHUNK_LONG_LEN / 2);
    let mut mutated = long.clone();
    mutated[CHUNK_MUT_OFFSET] = b'X';
    assert_eq!(mutated.len(), long.len());
    assert_eq!(&mutated[..CHUNK_MUT_OFFSET], &long[..CHUNK_MUT_OFFSET]);
    assert_eq!(&mutated[CHUNK_MUT_OFFSET + 1..], &long[CHUNK_MUT_OFFSET + 1..]);
    let mut expected_second = CHUNK_MARK_SECOND.to_vec();
    expected_second[1] = b'X'; // "@SECOND-HALF@..." -> "@XECOND-HALF@..."
    assert_eq!(
        &mutated[CHUNK_MARK_SECOND_OFFSET..][..CHUNK_MARK_SECOND.len()],
        expected_second.as_slice()
    );

    // The assembled file is a non-power-of-two 7-record batch large enough to
    // need four reads, and the long record crosses every read boundary.
    let file = join_lf_owned(&chunk_records(&long), true);
    assert_eq!(file.len(), CHUNK_LONG_LEN + 39); // 200_000 + 6 records + 7 LFs
    assert!(file.len() > 3 * CLI_READ_LEN);
    let long_end = LONG_RECORD_FILE_OFFSET + long.len();
    for k in 1..=3u32 {
        let bound = k as usize * CLI_READ_LEN;
        assert!(
            LONG_RECORD_FILE_OFFSET < bound && bound < long_end,
            "the long record must straddle the {k}*64KiB boundary ({bound})"
        );
        // The boundary lands on a long-record content byte, not a separator.
        assert_ne!(file[bound], b'\n');
    }
    // Markers fall in different physical reads of the file.
    let first_at = LONG_RECORD_FILE_OFFSET + CHUNK_MARK_FIRST_OFFSET;
    let second_at = LONG_RECORD_FILE_OFFSET + CHUNK_MARK_SECOND_OFFSET;
    let tail_at = LONG_RECORD_FILE_OFFSET + CHUNK_LONG_LEN - CHUNK_TAIL_MARK.len();
    assert!(first_at < CLI_READ_LEN);
    assert!((CLI_READ_LEN..2 * CLI_READ_LEN).contains(&second_at));
    assert!(tail_at >= 3 * CLI_READ_LEN);
    // The long record's terminating LF and the empty record's LF are adjacent.
    assert_eq!(&file[long_end..long_end + 2], b"\n\n");

    // Empty record and duplicated content are present at the fixed positions.
    let records = chunk_records(&long);
    assert_eq!(records.len(), 7, "batch is a non-power-of-two seven records");
    assert!(records[2].is_empty());
    assert_eq!(records[3], records[5]);
    assert_ne!(records[3].as_slice(), b"");
}

#[test]
fn boundary_fixture_lands_separators_exactly_on_read_edges() {
    let data = boundary_file(true);
    assert!(data.len() > 3 * CLI_READ_LEN);
    // Padding record + 3 empty records per cluster, plus the final record:
    // 3 * 4 + 1 == 13 records (non-power-of-two).
    assert_eq!(LF_BOUNDARY_PAD.len() * 4 + 1, 13);
    let lfs: Vec<usize> = data
        .iter()
        .enumerate()
        .filter_map(|(i, &b)| (b == b'\n').then_some(i))
        .collect();
    // Thirteen LFs total (twelve clustered plus the terminating one).
    assert_eq!(lfs.len(), 13);
    for &want in LF_BOUNDARY_SEPARATORS {
        assert_eq!(data[want], b'\n', "a separator must sit at offset {want}");
        assert!(lfs.binary_search(&want).is_ok(), "separator {want} missing");
    }
    // Each cluster occupies exactly boundary-2..=boundary+1: nothing adjacent.
    for k in 1..=3u32 {
        let bound = k as usize * CLI_READ_LEN;
        assert_ne!(data[bound - 3], b'\n');
        assert_ne!(data[bound + 2], b'\n');
    }
}

// --- The CLI contract over the real binary. ---------------------------------

#[test]
fn record_spanning_multiple_reads_matches_its_fixed_root() {
    let long = build_long_record();
    let records = chunk_records(&long);

    // With and without the terminating LF: one fixed record sequence, one
    // fixed root.
    let trailing = join_lf_owned(&records, true);
    let no_trailing = join_lf_owned(&records, false);
    assert_eq!(trailing.len() - 1, no_trailing.len());
    assert_eq!(&trailing[..no_trailing.len()], no_trailing.as_slice());

    root_of_file_bytes(
        "CHUNK: 7 records, 200_000-byte middle record, trailing LF",
        &trailing,
        ROOT_CHUNK,
    );
    root_of_file_bytes(
        "CHUNK: same sequence without the terminating LF",
        &no_trailing,
        ROOT_CHUNK,
    );

    // The two file forms must produce byte-identical command output.
    let a = run_root(&trailing);
    let b = run_root(&no_trailing);
    assert_eq!(a.status.code(), Some(0));
    assert_eq!(b.status.code(), Some(0));
    assert!(a.stderr.is_empty() && b.stderr.is_empty());
    assert_eq!(a.stdout, b.stdout, "trailing LF must not change the output by one byte");
    assert_eq!(a.stdout.len(), 65);
}

#[test]
fn empty_record_duplicates_and_trailing_record_keep_their_positions_across_reads() {
    let long = build_long_record();

    // Removing the empty record (position 2): six records, different fixed
    // sequence - an empty record cannot be dropped at a read boundary.
    root_of_file_bytes(
        "CHUNK_NO_EMPTY",
        &join_lf_owned(&chunk_records_subset(&long, |i| i != 2), false),
        ROOT_CHUNK_NO_EMPTY,
    );
    // Removing only the SECOND copy of the duplicated content (position 5):
    // identical bytes still present at position 3 must not be merged away.
    root_of_file_bytes(
        "CHUNK_NO_DUP",
        &join_lf_owned(&chunk_records_subset(&long, |i| i != 5), false),
        ROOT_CHUNK_NO_DUP,
    );
    // Removing the short trailing record (position 6): it sits after the
    // multi-read long record and must take part in the final root.
    root_of_file_bytes(
        "CHUNK_NO_TAIL",
        &join_lf_owned(&chunk_records_subset(&long, |i| i != 6), false),
        ROOT_CHUNK_NO_TAIL,
    );

    // All three structural edits differ from the full batch and from each
    // other: order and occurrence count, not just the byte multiset, matter.
    let roots = [
        ROOT_CHUNK,
        ROOT_CHUNK_NO_EMPTY,
        ROOT_CHUNK_NO_DUP,
        ROOT_CHUNK_NO_TAIL,
    ];
    for (i, x) in roots.iter().enumerate() {
        for y in &roots[i + 1..] {
            assert_ne!(x, y, "distinct record sequences must hash apart");
        }
    }
}

#[test]
fn one_byte_change_in_the_long_records_second_half_matches_modified_fixed_root() {
    let long = build_long_record();
    let mut mutated = long.clone();
    mutated[CHUNK_MUT_OFFSET] = b'X';
    assert_ne!(mutated[CHUNK_MUT_OFFSET], b'\n');

    // Same record count and order; only the one long record's interior byte
    // changes. The complete untouched prefix and suffix still participate.
    let records = chunk_records(&mutated);
    assert_eq!(records.len(), 7);
    let before = chunk_records(&long);
    for i in [0, 2, 3, 4, 5, 6] {
        assert_eq!(records[i], before[i], "only the long record may change");
    }
    assert_eq!(records[1].len(), long.len());

    let trailing = join_lf_owned(&records, true);
    let no_trailing = join_lf_owned(&records, false);
    root_of_file_bytes("CHUNK_M: one second-half byte changed, trailing LF", &trailing, ROOT_CHUNK_M);
    root_of_file_bytes("CHUNK_M: same modified batch without trailing LF", &no_trailing, ROOT_CHUNK_M);
    assert_ne!(ROOT_CHUNK_M, ROOT_CHUNK, "the changed byte must change the root");

    // A one-byte change that only affects bytes deep in a later read cannot
    // be hidden: run the CLI on the actual files and compare the outputs.
    assert_ne!(run_root(&trailing).stdout, run_root(&join_lf_owned(&before, true)).stdout);
}

#[test]
fn one_byte_changes_in_first_half_and_tail_also_change_the_cli_root() {
    // The fixed CHUNK root already commits to every byte, but this pins the
    // first-half and tail regions explicitly through the real binary: mutate
    // one non-LF byte in each region (both regions sit in distinct reads),
    // keep record count and order, and require a different root each time.
    let long = build_long_record();
    let original = join_lf_owned(&chunk_records(&long), true);
    let original_out = run_root(&original);
    assert_eq!(original_out.status.code(), Some(0));
    assert!(original_out.stderr.is_empty());

    // First half: the 'F' of the first-half marker (file offset 10_010, well
    // inside the first read).
    let mut first = long.clone();
    assert_eq!(first[CHUNK_MARK_FIRST_OFFSET + 1], b'F');
    first[CHUNK_MARK_FIRST_OFFSET + 1] = b'Q';
    // Tail: the leading '@' of the tail marker (inside the fourth read, near
    // the record's end, after all three 64 KiB boundaries).
    let tail_at = CHUNK_LONG_LEN - CHUNK_TAIL_MARK.len();
    let mut tail = long.clone();
    assert_eq!(tail[tail_at], b'@');
    tail[tail_at] = b'#';

    let variants = [("first-half", first), ("tail", tail)];
    let mut variant_roots: Vec<Vec<u8>> = Vec::new();
    for (label, changed) in &variants {
        assert_eq!(changed.len(), long.len(), "{label} mutation keeps the length");
        let records = chunk_records(changed);
        assert_eq!(records.len(), 7, "{label} mutation keeps the record count");
        let file = join_lf_owned(&records, true);
        let out = run_root(&file);
        assert_eq!(out.status.code(), Some(0), "{label}: {out:?}");
        assert!(out.stderr.is_empty(), "{label} run must stay silent on stderr");
        assert_eq!(out.stdout.len(), 65);
        assert_ne!(
            out.stdout, original_out.stdout,
            "{label} byte participates across the reads and must change the root"
        );
        variant_roots.push(out.stdout);
    }
    // The two regional mutations produce different roots from the original and
    // from one another.
    assert_ne!(variant_roots[0], variant_roots[1]);
    for r in &variant_roots {
        assert_ne!(r, &original_out.stdout);
    }
}

#[test]
fn consecutive_lfs_straddling_read_boundaries_keep_every_empty_record() {
    let trailing = boundary_file(true);
    let no_trailing = boundary_file(false);

    // The exact fixed root already commits to all thirteen records: the
    // twelve clustered LFs introduce nine empty records that each occupy a
    // position, with separators sitting on both sides of each read edge.
    root_of_file_bytes(
        "LF_BOUNDARY: LF runs straddling three 64 KiB read boundaries",
        &trailing,
        ROOT_LF_BOUNDARY,
    );

    // Trailing-LF equivalence stays exact when the file spans many reads.
    let a = run_root(&trailing);
    let b = run_root(&no_trailing);
    assert_eq!(a.status.code(), Some(0));
    assert_eq!(b.status.code(), Some(0));
    assert!(a.stderr.is_empty() && b.stderr.is_empty());
    assert_eq!(a.stdout, b.stdout);
    assert_eq!(&a.stdout[..64], ROOT_LF_BOUNDARY.as_bytes());
}

#[test]
fn losing_or_doubling_a_boundary_empty_record_changes_the_root() {
    // Anchor: the correct 13-record batch.
    let good = boundary_file(true);
    let good_root = run_root(&good);
    assert_eq!(good_root.status.code(), Some(0));
    assert_eq!(&good_root.stdout[..64], ROOT_LF_BOUNDARY.as_bytes());

    // Remove ONE clustered separator: two adjacent empty records merge, so
    // the file encodes twelve records - the root must change. Removing a
    // separator well inside one read (boundary-2) and one exactly on the edge
    // (boundary) are both tried.
    for &offset in &[
        CLI_READ_LEN - 2,       // first LF of a cluster, two bytes before edge
        CLI_READ_LEN,           // LF exactly on the read edge
        2 * CLI_READ_LEN - 1,   // one byte before the second edge
        3 * CLI_READ_LEN + 1,   // one byte after the third edge
    ] {
        let mut merged = good.clone();
        assert_eq!(merged[offset], b'\n');
        merged.remove(offset);
        let out = run_root(&merged);
        assert_eq!(out.status.code(), Some(0), "offset {offset}: {out:?}");
        assert_ne!(
            out.stdout, good_root.stdout,
            "removing the separator at {offset} must change the root"
        );
    }

    // Insert ONE extra LF right at a boundary: an additional empty record
    // appears (fourteen records) - the root must likewise change.
    for &offset in &[CLI_READ_LEN, 2 * CLI_READ_LEN, 3 * CLI_READ_LEN] {
        let mut added = good.clone();
        added.insert(offset, b'\n');
        let out = run_root(&added);
        assert_eq!(out.status.code(), Some(0));
        assert_ne!(
            out.stdout, good_root.stdout,
            "an extra separator at {offset} must change the root"
        );
    }
}
