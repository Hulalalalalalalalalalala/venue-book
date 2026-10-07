//! End-to-end regression tests pinning the AUDIT PATHS and real VERIFY
//! results for the multi-read batch: ten records where position 4 is one
//! 140000-byte record (> 128 KiB, spanning several of `root`'s 64 KiB
//! reads) carrying NUL, CR and non-UTF-8 bytes in its interior and at its
//! tail, while the batch also keeps short, empty and duplicated records.
//! The long record occupies exactly ONE position; every one of its bytes
//! takes part in its leaf hash - nothing may be truncated, split off, or
//! skipped past the read boundary.
//!
//! The expected JSON lines (roots and audit paths alike) are FIXED vectors
//! produced independently of roottrace by
//! `tests/reference/rfc6962_multiread_vectors.py`, which reuses the two
//! structurally different audit-path producers from
//! `tests/reference/rfc6962_vectors.py` (the RFC 6962 section 2.1.1
//! recursive PATH definition, and a top-down descent whose sibling subtree
//! hashes come from the stack fold) and re-hashes every path back to the
//! batch root with an independent recursive inclusion verifier. The
//! constants are copied here and are NEVER derived from roottrace output:
//! matching `prove` against `root`, or roottrace's own `verify` accepting
//! a proof, is not the basis of their correctness.
//!
//! Coverage:
//!   * `prove` at the long record (index 4) and the trailing short record
//!     (index 9): tree_size 10, the selected leaf_index, the fixed batch
//!     root and the position-bound leaf-to-root audit path, with the
//!     uneven RFC 6962 k=8 shape - no duplicated last record, no empty
//!     padding record
//!   * success output is one complete JSON line plus one LF, exit 0, empty
//!     stderr; files with and without the terminating LF encode the same
//!     ten records and produce byte-identical proofs
//!   * both generated proofs verify through the existing `verify` command
//!     against the exact raw record bytes (the 140000-byte record written
//!     with NO LF splitting or trimming) and the independently confirmed
//!     size/root, printing exactly "verified\n"
//!   * after changing one non-LF byte in the SECOND HALF of the long
//!     record (record count and positions unchanged), the regenerated
//!     proofs bind the changed root: the long record's own path is
//!     unchanged (none of its sibling subtrees moved), while the trailing
//!     short record's path changes exactly in the subtree hash covering
//!     the long record
//!   * the ORIGINAL long-record proof, paired with the modified record
//!     bytes and the ORIGINAL trusted root, fails as a VERIFICATION
//!     FAILURE: exit 1, empty stdout, "verification failed" on stderr -
//!     never classified as a malformed proof
//!
//! The record construction is byte-for-byte the same deterministic one
//! used by the reference script and by `multi_read_regression.rs`.

mod common;

use std::process::Command;

use common::{join_lf, TempFile};

/// Length of the long record (> 128 KiB) and its position in the batch.
const LONG_LEN: usize = 140_000;
const LONG_INDEX: u64 = 4;
const LAST_INDEX: u64 = 9;
const TREE_SIZE: u64 = 10;

/// Length of the PAD record at position 2, identical to
/// `multi_read_regression.rs`: seven bytes precede it ("alpha\n" and the
/// empty record's "\n"), so PAD's terminating LF lands on the last byte
/// of the first 64 KiB read.
const READ_BUF: usize = 64 * 1024;
const PAD_LEN: usize = READ_BUF - 1 - 7; // 65528

/// Position of the single changed content byte: inside the long record's
/// second half (also in a later 64 KiB read than its first file bytes).
const MOD_POS: usize = 100_000;

// Independently fixed RFC 6962 roots (tests/reference/rfc6962_multiread_vectors.py).
const ROOT_MREAD: &str = "dca3d078542c8497a09302a4a0cd3b521a498ce3bffbe29bf9f510f2d1203304";
const ROOT_MREAD_M: &str = "93011d0e8ec828d5c3fd2698f87664fcdb9ce07f4b16bb5cac269474478d3f57";

// Fixed audit paths, leaf-to-root order (same generator).
const PATH_MREAD_M4: &[&str] = &[
    "09d57080f181af9460d7806c9066e28272c282d935afead202b9ff41ad8787e4",
    "e5c500d4e9f2bd311da87658fd66f03d1aaeb85e92844381550935c5a9d99db3",
    "ecdeec636c4e6848207ef6eb558d42d68bec43ef9f8039628c9da67fdf52bdb3",
    "e2d624046d736c852bc39fd837f6020e512d0ecda2f0c7ad3b468c399b575f2c",
];
const PATH_MREAD_M9: &[&str] = &[
    "874bb321567c2878c37d117d7b4844d505bba48fb28ef79e9a384783cd83981c",
    "b5b3451f98dc0883a58aeb101c5444c11e47803cdcfff29cf2f1e289627fbdad",
];
const PATH_MREAD_M_M4: &[&str] = &[
    "09d57080f181af9460d7806c9066e28272c282d935afead202b9ff41ad8787e4",
    "e5c500d4e9f2bd311da87658fd66f03d1aaeb85e92844381550935c5a9d99db3",
    "ecdeec636c4e6848207ef6eb558d42d68bec43ef9f8039628c9da67fdf52bdb3",
    "e2d624046d736c852bc39fd837f6020e512d0ecda2f0c7ad3b468c399b575f2c",
];
const PATH_MREAD_M_M9: &[&str] = &[
    "874bb321567c2878c37d117d7b4844d505bba48fb28ef79e9a384783cd83981c",
    "c8ae53a4f10cf65e79e605c3b0d382317dc4694600f41e891dbb26f6f0c27370",
];

/// Deterministic pseudo-random fill byte; LF is remapped so the long
/// record never carries its own separator. Identical to `fill_byte` in
/// the reference generator and in `multi_read_regression.rs`.
fn fill_byte(i: usize) -> u8 {
    let b = ((i as u32).wrapping_mul(2_654_435_761) >> 13) as u8;
    if b == b'\n' { 0x0b } else { b }
}

/// The 140000-byte record: pseudo-random binary fill with distinct
/// markers in the first half, second half and tail.
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

/// The same record with exactly one non-LF content byte changed in its
/// second half; length and every other byte are preserved.
fn long_record_m() -> Vec<u8> {
    let mut rec = long_record();
    let old = rec[MOD_POS];
    rec[MOD_POS] = if old != b'A' { b'A' } else { b'B' };
    assert_ne!(rec[MOD_POS], b'\n');
    rec
}

/// The PAD record aligning the following LFs to the read boundary; its
/// content still occupies exactly one fixed position in the ten-record
/// sequence the fixed proofs are computed over.
fn pad_record() -> Vec<u8> {
    let mut p = b"pad:".to_vec();
    p.resize(PAD_LEN, b'p');
    p
}

/// The ten-record sequence, with the original or modified long record at
/// position 4.
fn batch_records<'a>(pad: &'a [u8], long: &'a [u8]) -> Vec<&'a [u8]> {
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

fn expected_json(size: u64, index: u64, root: &str, path: &[&str]) -> String {
    let mut out = format!(
        "{{\"tree_size\":{size},\"leaf_index\":{index},\"root\":\"{root}\",\"audit_path\":["
    );
    for (i, h) in path.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push('"');
        out.push_str(h);
        out.push('"');
    }
    out.push_str("]}");
    out
}

fn run_prove(file_bytes: &[u8], index: u64) -> std::process::Output {
    let tmp = TempFile::create(file_bytes);
    Command::new(common::bin())
        .arg("prove")
        .arg(&tmp.path)
        .arg(index.to_string())
        .output()
        .expect("failed to execute roottrace binary")
}

fn run_verify(
    record: &std::path::Path,
    proof: &std::path::Path,
    size: &str,
    root: &str,
) -> std::process::Output {
    Command::new(common::bin())
        .arg("verify")
        .arg(record)
        .arg(proof)
        .arg(size)
        .arg(root)
        .output()
        .expect("failed to execute roottrace binary")
}

/// Assert the documented prove success contract and return the exact
/// stdout bytes (one JSON line + LF).
fn assert_proof_line(desc: &str, file_bytes: &[u8], index: u64, expected_line: &str) -> Vec<u8> {
    let out = run_prove(file_bytes, index);
    if out.status.code() != Some(0) {
        panic!(
            "[{desc}] prove {index} failed: status={:?}\nstderr: {}\nstdout: {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr),
            String::from_utf8_lossy(&out.stdout),
        );
    }
    assert!(out.stderr.is_empty(), "[{desc}] stderr must be empty");
    let expected = format!("{expected_line}\n").into_bytes();
    assert_eq!(
        out.stdout, expected,
        "[{desc}] prove {index} must emit exactly the fixed JSON line + one LF"
    );
    // One and only one LF: a single complete line, no blank second record.
    assert_eq!(
        out.stdout.iter().filter(|&&b| b == b'\n').count(),
        1,
        "[{desc}] exactly one terminating LF"
    );
    out.stdout
}

/// Slice out the `"audit_path":[...]` substring of a JSON proof line.
fn audit_path_text(json_line: &str) -> &str {
    let key = "\"audit_path\":[";
    let start = json_line.find(key).expect("audit_path present");
    let end = json_line[start..].find(']').expect("audit_path closed") + start;
    &json_line[start..=end]
}

// --- Batch shape relevant to the proofs --------------------------------------

#[test]
fn multi_read_batch_is_ten_records_with_one_140000_byte_position() {
    let pad = pad_record();
    let long = long_record();
    let recs = batch_records(&pad, &long);
    assert_eq!(recs.len(), TREE_SIZE as usize);
    assert_eq!(recs[LONG_INDEX as usize].len(), LONG_LEN);
    assert_eq!(recs[LAST_INDEX as usize], b"end-record\x01");
    // Short, empty and duplicated records are all still present.
    assert_eq!(recs[0], recs[6]);
    for empty in [1usize, 3, 7] {
        assert!(recs[empty].is_empty(), "position {empty} is an empty record");
    }
    // The long record holds no separator LF anywhere, and its binary
    // bytes span both halves and the tail.
    assert!(!long.contains(&b'\n'));
    let half = LONG_LEN / 2;
    for region in [&long[..half], &long[half..]] {
        assert!(region.contains(&0x00) && region.contains(&0x0d));
        assert!(region.iter().any(|&b| b >= 0x80));
    }
    assert_eq!(&long[..13], b"MREAD\x00\xff\xfe\rHEAD");
    assert_eq!(&long[half..half + 14], b"\x00\xff\rSECOND-HALF");
    assert_eq!(&long[LONG_LEN - 7..], b"\x00TAIL\r\xff");

    // Nine separator LFs plus, in the terminated form, one final LF.
    assert_eq!(join_lf(&recs, true).iter().filter(|&&b| b == b'\n').count(), 10);
    assert_eq!(join_lf(&recs, false).iter().filter(|&&b| b == b'\n').count(), 9);
}

// --- Fixed prove vectors -----------------------------------------------------

#[test]
fn prove_for_long_record_and_last_record_match_fixed_vectors() {
    let pad = pad_record();
    let long = long_record();
    let recs = batch_records(&pad, &long);

    // m=4: the 140000-byte record itself, deep in the k=8 left subtree:
    // four leaf-to-root siblings (uneven tree, never padded to 16 leaves).
    assert_proof_line(
        "MREAD m=4 long record",
        &join_lf(&recs, true),
        LONG_INDEX,
        &expected_json(TREE_SIZE, LONG_INDEX, ROOT_MREAD, PATH_MREAD_M4),
    );
    // m=9: the trailing short record in the 2-record right subtree:
    // exactly two siblings, the last one being MTH of all eight left
    // records - not a copy of the last record and not an empty leaf.
    assert_proof_line(
        "MREAD m=9 last short record",
        &join_lf(&recs, true),
        LAST_INDEX,
        &expected_json(TREE_SIZE, LAST_INDEX, ROOT_MREAD, PATH_MREAD_M9),
    );
    assert_eq!(PATH_MREAD_M4.len(), 4);
    assert_eq!(PATH_MREAD_M9.len(), 2);
}

#[test]
fn terminating_lf_changes_neither_the_record_count_nor_the_proof_bytes() {
    let pad = pad_record();
    let long = long_record();
    let recs = batch_records(&pad, &long);
    for index in [LONG_INDEX, LAST_INDEX] {
        let with = run_prove(&join_lf(&recs, true), index);
        let without = run_prove(&join_lf(&recs, false), index);
        assert_eq!(with.status.code(), Some(0));
        assert_eq!(without.status.code(), Some(0));
        // The two file forms name the same ten-record sequence, so the
        // proofs must be byte-identical (no eleventh empty record).
        assert_eq!(
            with.stdout, without.stdout,
            "index {index}: trailing LF must not alter the proof"
        );
        assert!(with.stderr.is_empty() && without.stderr.is_empty());
    }

    // Position 10 must not exist in either file form.
    for trailing in [true, false] {
        let out = run_prove(&join_lf(&recs, trailing), 10);
        assert_eq!(out.status.code(), Some(1), "there is no record at index 10");
        assert!(out.stdout.is_empty());
    }
}

// --- Real verify interop with the exact raw record bytes ----------------------

#[test]
fn generated_proofs_verify_against_raw_record_bytes_and_fixed_trust() {
    let pad = pad_record();
    let long = long_record();
    let recs = batch_records(&pad, &long);

    for (index, record, fixed_path) in [
        (LONG_INDEX, long.clone(), PATH_MREAD_M4),
        (LAST_INDEX, recs[LAST_INDEX as usize].to_vec(), PATH_MREAD_M9),
    ] {
        // The target record contains no separator LF; verify reads the
        // record file verbatim, so it is written raw with no added LF.
        assert!(!record.contains(&b'\n'));
        let record_file = TempFile::create(&record);

        // (a) The proof built straight from the independently fixed
        // constants (not from roottrace prove output).
        let fixed_proof = expected_json(TREE_SIZE, index, ROOT_MREAD, fixed_path);
        let proof_file = TempFile::create(fixed_proof.as_bytes());
        let out = run_verify(&record_file.path, &proof_file.path, "10", ROOT_MREAD);
        assert_eq!(
            out.status.code(),
            Some(0),
            "fixed proof m={index}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(out.stdout, b"verified\n");
        assert!(out.stderr.is_empty());

        // (b) The proof actually emitted by `prove` for the materialised
        // batch, handed byte for byte to the existing `verify` command.
        let proved = run_prove(&join_lf(&recs, true), index);
        assert_eq!(proved.status.code(), Some(0));
        let proof_file = TempFile::create(&proved.stdout);
        let out = run_verify(&record_file.path, &proof_file.path, "10", ROOT_MREAD);
        assert_eq!(out.status.code(), Some(0));
        assert_eq!(out.stdout, b"verified\n");
        assert!(out.stderr.is_empty());
    }
}

#[test]
fn added_or_changed_bytes_of_the_long_record_are_verification_failures() {
    // No trimming/substitution at the binary tail: an appended separator
    // LF or a flipped tail byte both change the record and fail.
    let long = long_record();
    let fixed_proof = expected_json(TREE_SIZE, LONG_INDEX, ROOT_MREAD, PATH_MREAD_M4);
    let proof_file = TempFile::create(fixed_proof.as_bytes());

    let mut with_lf = long.clone();
    with_lf.push(b'\n');
    let rec = TempFile::create(&with_lf);
    let out = run_verify(&rec.path, &proof_file.path, "10", ROOT_MREAD);
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("verification failed"), "stderr: {err}");
    assert!(!err.contains("invalid proof"));

    let mut flipped = long.clone();
    let last = flipped.len() - 1;
    flipped[last] ^= 0x01;
    let rec = TempFile::create(&flipped);
    let out = run_verify(&rec.path, &proof_file.path, "10", ROOT_MREAD);
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("verification failed"), "stderr: {err}");
    assert!(!err.contains("invalid proof"));
}

// --- One-byte change deep in the long record ----------------------------------

#[test]
fn modified_batch_rebinds_both_proofs_with_the_expected_path_changes() {
    let long = long_record();
    let long_m = long_record_m();
    // Exactly one non-LF byte differs, in the second half.
    assert_eq!(long_m.len(), long.len());
    assert_eq!(long_m[..MOD_POS], long[..MOD_POS]);
    assert_eq!(long_m[MOD_POS + 1..], long[MOD_POS + 1..]);
    assert_ne!(long_m[MOD_POS], long[MOD_POS]);

    let pad = pad_record();
    let recs = batch_records(&pad, &long);
    let recs_m = batch_records(&pad, &long_m);
    assert_eq!(recs.len(), recs_m.len());
    for i in 0..10 {
        if i != LONG_INDEX as usize {
            assert_eq!(recs_m[i], recs[i], "only the long record changes");
        }
    }

    // m=4 against the changed batch: new root, same size/index, and the
    // same audit path - the changed byte is inside the proved leaf, never
    // in any of its sibling subtrees.
    let p4_orig =
        assert_proof_line("MREAD m=4", &join_lf(&recs, true), LONG_INDEX,
            &expected_json(TREE_SIZE, LONG_INDEX, ROOT_MREAD, PATH_MREAD_M4));
    let p4_mod = assert_proof_line(
        "MREAD_M m=4",
        &join_lf(&recs_m, true),
        LONG_INDEX,
        &expected_json(TREE_SIZE, LONG_INDEX, ROOT_MREAD_M, PATH_MREAD_M_M4),
    );
    assert_eq!(PATH_MREAD_M4, PATH_MREAD_M_M4, "sibling-only path is unchanged");
    let p4_orig = String::from_utf8(p4_orig).unwrap();
    let p4_mod = String::from_utf8(p4_mod).unwrap();
    assert_eq!(
        audit_path_text(&p4_orig),
        audit_path_text(&p4_mod),
        "the long record's audit path stays byte-identical after its own change"
    );
    assert_ne!(p4_orig, p4_mod, "only the root field should differ");

    // m=9 against the changed batch: the record bytes there are unchanged,
    // yet its path's root-side subtree hash (MTH of the eight left records,
    // which covers the long record) must change; its leaf-side sibling
    // (hash of position 8) does not.
    assert_proof_line(
        "MREAD_M m=9",
        &join_lf(&recs_m, true),
        LAST_INDEX,
        &expected_json(TREE_SIZE, LAST_INDEX, ROOT_MREAD_M, PATH_MREAD_M_M9),
    );
    assert_eq!(PATH_MREAD_M9[0], PATH_MREAD_M_M9[0], "sibling leaf hash unchanged");
    assert_ne!(
        PATH_MREAD_M9[1], PATH_MREAD_M_M9[1],
        "the size-8 left subtree hash must commit to the changed record"
    );
    assert_ne!(ROOT_MREAD, ROOT_MREAD_M);

    // Both modified proofs verify against the modified record bytes and
    // the independently confirmed modified size/root.
    let proof4 = TempFile::create(
        expected_json(TREE_SIZE, LONG_INDEX, ROOT_MREAD_M, PATH_MREAD_M_M4).as_bytes(),
    );
    let rec4 = TempFile::create(&long_m);
    let out = run_verify(&rec4.path, &proof4.path, "10", ROOT_MREAD_M);
    assert_eq!(out.status.code(), Some(0), "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(out.stdout, b"verified\n");
    assert!(out.stderr.is_empty());

    let proof9 = TempFile::create(
        expected_json(TREE_SIZE, LAST_INDEX, ROOT_MREAD_M, PATH_MREAD_M_M9).as_bytes(),
    );
    let rec9 = TempFile::create(recs_m[LAST_INDEX as usize]);
    let out = run_verify(&rec9.path, &proof9.path, "10", ROOT_MREAD_M);
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(out.stdout, b"verified\n");
    assert!(out.stderr.is_empty());
}

#[test]
fn stale_long_record_proof_with_modified_bytes_and_old_root_is_a_verify_failure() {
    // The ORIGINAL proof (well formed, audit path unchanged) paired with
    // the modified record and the ORIGINAL independently trusted root must
    // fail cryptographically: exit 1, nothing on stdout, classified as a
    // verification failure rather than an invalid proof.
    let long_m = long_record_m();
    let stale_proof = expected_json(TREE_SIZE, LONG_INDEX, ROOT_MREAD, PATH_MREAD_M4);
    let proof_file = TempFile::create(stale_proof.as_bytes());
    let record_file = TempFile::create(&long_m);
    let out = run_verify(&record_file.path, &proof_file.path, "10", ROOT_MREAD);
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty(), "no output on a failed verification");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("verification failed"),
        "a hash mismatch is a verification failure, got: {err}"
    );
    assert!(
        !err.contains("invalid proof"),
        "the stale proof is well formed and must not be called invalid: {err}"
    );

    // The modified root does not rescue the stale proof either, and is
    // likewise a verification failure.
    let out = run_verify(&record_file.path, &proof_file.path, "10", ROOT_MREAD_M);
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("verification failed"), "stderr: {err}");
    assert!(!err.contains("invalid proof"));
}
