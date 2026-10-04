//! End-to-end regression tests for `roottrace root` with LONG records whose
//! lengths approach and cross the SHA-256 padding/block boundaries.
//!
//! A leaf is hashed as SHA-256(0x00 || record). Record lengths 54/55/56 make
//! the leaf input 55/56/57 bytes (the 0x80 padding terminator and the 64-bit
//! length field crowd the 56-byte boundary and spill into a second block),
//! lengths 63/64/65 make it 64/65/66 bytes (exactly one block, then one and
//! two bytes into the next), and L135's leaf input is 136 bytes (content
//! reaches a third block). A block walk that drops the tail, counts a span
//! twice, pads wrong, or splits one record into several yields a different
//! root, which the fixed vectors below pin down.
//!
//! Expected roots are FIXED constants produced independently of roottrace by
//! `tests/reference/rfc6962_vectors.py` (standard-library `hashlib.sha256`,
//! recursive definition and stack fold agreeing); they are never derived
//! from roottrace output. The long record byte literals are copied from the
//! same generator, so the single-record batches and the mixed batch hash the
//! very same record bytes - a long record follows one standard on its own and
//! inside a batch.
//!
//! Every long record contains NUL, CR and non-UTF-8 bytes in its interior and
//! ends on a non-text byte, so no text decoding, CR/LF normalization or
//! NUL-based truncation can go unnoticed.

mod common;

use common::{assert_root, join_lf};

// --- Fixed long records (raw record bytes, WITHOUT the LF separator) -------
// Copied verbatim from tests/reference/rfc6962_vectors.py output.

const REC_L54: &[u8] =
    b"L54:\x00\xff\xfe\rabcdefghijklmnopqrstuvwxyz0123456789abcdefghi\x00";
const REC_L55: &[u8] =
    b"L55:\x00\xff\xfe\rabcdefghijklmnopqrstuvwxyz0123456789abcdefghij\r";
const REC_L56: &[u8] =
    b"L56:\x00\xff\xfe\rabcdefghijklmnopqrstuvwxyz0123456789abcdefghijk\xff";
const REC_L63: &[u8] =
    b"L63:\x00\xff\xfe\rabcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr\x00";
const REC_L64: &[u8] =
    b"L64:\x00\xff\xfe\rabcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrs\r";
const REC_L65: &[u8] =
    b"L65:\x00\xff\xfe\rabcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrst\xfe";
const REC_L135: &[u8] = b"L135:\x00\xff\xfe\rabcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopq\xff";

// Tail-byte variants: identical to the original except for the very last
// byte. Their fixed roots correspond to the whole MODIFIED record.
const REC_L65_M: &[u8] =
    b"L65:\x00\xff\xfe\rabcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstZ";
const REC_L135_M: &[u8] = b"L135:\x00\xff\xfe\rabcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopq~";

// Independently fixed RFC 6962 roots (tests/reference/rfc6962_vectors.py).
const ROOT_L54: &str = "c20ba1db777b396463af4e4d7defeb24472fb84a1dfcecdceebd62b05d8fbe5f";
const ROOT_L55: &str = "fea596a972f814904aac2bfaf3ed800937bc9fc7157174db9c8ac18e799635fb";
const ROOT_L56: &str = "3088506400b3153087723150df0f2368e4d476e37b2d255e0ceb43e99c830d1b";
const ROOT_L63: &str = "27e0fa0bbbdcc1e98422f0c9d5009ed6c9985492ad2ea043ef6151abbe6647df";
const ROOT_L64: &str = "cf194ddfdf737250e35d68be5a46bacb8686b83658f94c9c954389c1be083270";
const ROOT_L65: &str = "0c516c35707fdd7ce8110d5257a639e9088c51b4186dcf0e4239e043973afe2b";
const ROOT_L135: &str = "32f07c1f5187e59d842b36d33a004fcfaa70c8962d32d0e920a57051496b675e";
const ROOT_L65_M: &str = "749532458c5a679a6eeb5ddb2cbc5c2b7fe7cf961c0a9e3fe1201d727b2a1653";
const ROOT_L135_M: &str = "0f69f3b46fdb491cbd29e4ecbaa48764101d6249ab54287bc2591c18f69d4130";

/// (name, exact record bytes, fixed root of the one-record batch).
const SINGLE_LONG: &[(&str, &[u8], &str)] = &[
    ("L54", REC_L54, ROOT_L54),
    ("L55", REC_L55, ROOT_L55),
    ("L56", REC_L56, ROOT_L56),
    ("L63", REC_L63, ROOT_L63),
    ("L64", REC_L64, ROOT_L64),
    ("L65", REC_L65, ROOT_L65),
    ("L135", REC_L135, ROOT_L135),
];

/// Fixed batch of long AND short records (10 records; RFC 6962 splits k=8, so
/// long records at positions 2/4/6 land in the left subtree and the one at
/// position 8 in the right subtree). It also holds an empty record and short
/// records carrying CR, NUL and non-UTF-8 bytes.
const MIXED_RECORDS: &[&[u8]] = &[
    b"alpha",
    b"",
    REC_L54,
    b"beta\r",
    REC_L63,
    b"\xff\x00z",
    REC_L135,
    b"middle",
    REC_L65,
    b"end-record\x01",
];
const ROOT_MIXED: &str = "3a460e4bda163253da14917c2f9c63208d1b24e3d285c763d2f6c6dedec6694b";

/// MIXED with exactly one byte changed: the final byte of the L65 record at
/// position 8.
const MIXED_M_RECORDS: &[&[u8]] = &[
    b"alpha",
    b"",
    REC_L54,
    b"beta\r",
    REC_L63,
    b"\xff\x00z",
    REC_L135,
    b"middle",
    REC_L65_M,
    b"end-record\x01",
];
const ROOT_MIXED_M: &str = "71cc24ac8aa1e4e4c95ca35704b0ec4302323659479d3e46134fcb359ab2858e";

/// Structural invariants every long record must satisfy: the exact required
/// raw length (LF excluded), no LF inside, and NUL/CR/non-UTF-8 bytes in the
/// interior.
fn assert_long_record_shape(name: &str, rec: &[u8], expected_len: usize) {
    assert_eq!(
        rec.len(),
        expected_len,
        "{name}: record length is the raw byte count without the LF separator"
    );
    assert!(!rec.contains(&b'\n'), "{name}: records must not contain LF");
    assert!(rec.contains(&0x00), "{name}: NUL must appear inside the record");
    assert!(rec.contains(&0x0D), "{name}: CR must appear inside the record");
    assert!(
        rec.iter().any(|&b| b >= 0x80),
        "{name}: non-UTF-8 bytes must appear inside the record"
    );
}

#[test]
fn long_records_cover_the_required_lengths_and_binary_content() {
    let lengths: Vec<usize> = SINGLE_LONG.iter().map(|(_, rec, _)| rec.len()).collect();
    assert_eq!(lengths, vec![54, 55, 56, 63, 64, 65, 135]);
    assert!(REC_L135.len() > 128, "a record longer than 128 bytes is required");
    for (name, rec, _) in SINGLE_LONG {
        assert_long_record_shape(name, rec, rec.len());
        // Every base record also ends on a non-text byte, so binary fidelity
        // is exercised at the tail as well as in the interior.
        assert!(
            matches!(rec[rec.len() - 1], 0x00 | 0x0D | 0x80..=0xFF),
            "{name}: the record must end on a non-text byte, got {:#04x}",
            rec[rec.len() - 1]
        );
    }
    // Tail variants keep the exact same length and interior binary shape;
    // their final byte is the one deliberately changed byte (ASCII here).
    assert_long_record_shape("L65_M", REC_L65_M, 65);
    assert_long_record_shape("L135_M", REC_L135_M, 135);
    assert_eq!(REC_L65_M.last(), Some(&b'Z'));
    assert_eq!(REC_L135_M.last(), Some(&b'~'));
}

#[test]
fn each_long_record_as_a_single_record_batch_matches_its_fixed_root() {
    for (name, rec, expected) in SINGLE_LONG {
        let records: &[&[u8]] = &[*rec];
        // With and without the LF that terminates the single record: the file
        // encodes the same one-record sequence and has the same fixed root.
        assert_root(
            &format!("{name}: one {}-byte record, trailing LF", rec.len()),
            records,
            &join_lf(records, true),
            expected,
        );
        assert_root(
            &format!("{name}: one {}-byte record, no trailing LF", rec.len()),
            records,
            &join_lf(records, false),
            expected,
        );
    }
}

#[test]
fn every_boundary_length_has_its_own_distinct_fixed_root() {
    // Adjacent lengths (e.g. 63/64/65 straddling the 64-byte block) must not
    // collapse onto one another through padding or truncation.
    for (i, (n1, _, r1)) in SINGLE_LONG.iter().enumerate() {
        for (n2, _, r2) in &SINGLE_LONG[i + 1..] {
            assert_ne!(r1, r2, "{n1}-byte and {n2}-byte records need distinct roots");
        }
    }
}

#[test]
fn changing_one_byte_near_the_end_matches_the_modified_records_fixed_root() {
    // L65: only the final 0xfe byte becomes 'Z'.
    assert_eq!(REC_L65_M.len(), REC_L65.len());
    assert_eq!(REC_L65_M[..REC_L65.len() - 1], REC_L65[..REC_L65.len() - 1]);
    assert_ne!(REC_L65_M.last(), REC_L65.last());
    // L135 (>128 bytes): only the final 0xff byte becomes '~'.
    assert_eq!(REC_L135_M.len(), REC_L135.len());
    assert_eq!(REC_L135_M[..REC_L135.len() - 1], REC_L135[..REC_L135.len() - 1]);
    assert_ne!(REC_L135_M.last(), REC_L135.last());
    for (name, rec, root_modified, root_original) in [
        ("L65_M", REC_L65_M, ROOT_L65_M, ROOT_L65),
        ("L135_M", REC_L135_M, ROOT_L135_M, ROOT_L135),
    ] {
        let records: &[&[u8]] = &[rec];
        assert_root(
            &format!("{name}: full modified record, trailing LF"),
            records,
            &join_lf(records, true),
            root_modified,
        );
        assert_root(
            &format!("{name}: full modified record, no trailing LF"),
            records,
            &join_lf(records, false),
            root_modified,
        );
        assert_ne!(
            root_modified, root_original,
            "{name}: a one-byte change near the tail must change the root"
        );
    }
}

#[test]
fn fixed_mixed_long_and_short_batch_matches_its_fixed_root() {
    assert_eq!(MIXED_RECORDS.len(), 10);
    // The same long-record constants used in the single-record batches appear
    // in the batch: one standard for long records on their own and in a batch.
    assert_eq!(MIXED_RECORDS[2], REC_L54);
    assert_eq!(MIXED_RECORDS[4], REC_L63);
    assert_eq!(MIXED_RECORDS[6], REC_L135);
    assert_eq!(MIXED_RECORDS[8], REC_L65);
    let long_positions = [2usize, 4, 6, 8];
    // RFC 6962 k=8 split for 10 records: long records on both sides.
    assert!(long_positions.iter().any(|&i| i < 8));
    assert!(long_positions.iter().any(|&i| i >= 8));
    // MIXED_M differs from MIXED only at record position 8 (last byte of L65).
    assert_eq!(MIXED_M_RECORDS[8], REC_L65_M);
    for i in 0..10 {
        if i != 8 {
            assert_eq!(MIXED_M_RECORDS[i], MIXED_RECORDS[i]);
        }
    }

    // File size documents that LF bytes are separators, not record content:
    // records total 347 bytes; 9 between-record LFs give 356, terminating LF
    // gives 357.
    assert_eq!(join_lf(MIXED_RECORDS, false).len(), 356);
    assert_eq!(join_lf(MIXED_RECORDS, true).len(), 357);

    assert_root(
        "MIXED: 10 long/short records, trailing LF",
        MIXED_RECORDS,
        &join_lf(MIXED_RECORDS, true),
        ROOT_MIXED,
    );
    assert_root(
        "MIXED: 10 long/short records, no trailing LF",
        MIXED_RECORDS,
        &join_lf(MIXED_RECORDS, false),
        ROOT_MIXED,
    );
    assert_root(
        "MIXED_M: last byte of the L65 record changed inside the batch",
        MIXED_M_RECORDS,
        &join_lf(MIXED_M_RECORDS, true),
        ROOT_MIXED_M,
    );
    assert_root(
        "MIXED_M: same modified batch without trailing LF",
        MIXED_M_RECORDS,
        &join_lf(MIXED_M_RECORDS, false),
        ROOT_MIXED_M,
    );
    assert_ne!(ROOT_MIXED, ROOT_MIXED_M, "the one tail byte participates in the batch root");
    // A batch containing the long record is not the same as the record alone.
    assert_ne!(ROOT_MIXED, ROOT_L135);
    assert_ne!(ROOT_MIXED_M, ROOT_L65_M);
}
