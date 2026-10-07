//! End-to-end regression tests for `roottrace prove`/`roottrace verify` on
//! the MULTI-READ batch: ten records, one of them a 140000-byte record
//! (> 128 KiB) whose bytes arrive in several separate 64 KiB reads
//! (`tests/multi_read_regression.rs` pins the roots and the record count for
//! the same batch). Here the generated PROOFS are pinned, not just the root:
//! the full audit path and the actual verification outcome for the long
//! record (position 4, left k=8 subtree) and the trailing short record
//! (position 9, right subtree).
//!
//! The expected audit paths are FIXED constants produced independently of
//! roottrace by `tests/reference/rfc6962_multiread_vectors.py`: the two
//! structurally different RFC 6962 section 2.1.1 path producers from
//! `tests/reference/rfc6962_vectors.py` (the recursive PATH transcription and
//! the top-down descent whose sibling hashes come from the stack fold) must
//! agree at every position of both batches, and the independent recursive
//! inclusion verifier re-hashes every path back to the batch root before the
//! constants are printed. Nothing here is anchored by comparing `prove` with
//! `root` or by roottrace verifying its own output.
//!
//! The record bytes are rebuilt with the same deterministic construction as
//! `tests/multi_read_regression.rs` (and the reference script), so the
//! constants bind the exact same record sequence.

mod common;

use std::process::Command;

use common::{bin, join_lf, TempFile};

// --- The multi-read batch (identical construction to ------------------------
// --- tests/multi_read_regression.rs and the reference generator) ------------

const READ_BUF: usize = 64 * 1024;
const LONG_LEN: usize = 140_000;
const PAD_LEN: usize = READ_BUF - 1 - 7; // 65528
const MOD_POS: usize = 100_000;

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

fn long_record_m() -> Vec<u8> {
    let mut rec = long_record();
    let old = rec[MOD_POS];
    rec[MOD_POS] = if old != b'A' { b'A' } else { b'B' };
    rec
}

fn pad_record() -> Vec<u8> {
    let mut p = b"pad:".to_vec();
    p.resize(PAD_LEN, b'p');
    p
}

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

// --- Fixed roots and audit paths (copied from the reference generator) ------

const ROOT_MREAD: &str = "dca3d078542c8497a09302a4a0cd3b521a498ce3bffbe29bf9f510f2d1203304";
const ROOT_MREAD_M: &str = "93011d0e8ec828d5c3fd2698f87664fcdb9ce07f4b16bb5cac269474478d3f57";

// Position 4 (the long record): depth 3 inside the balanced size-8 left
// subtree, plus the right-subtree hash - four elements, leaf-to-root.
const PATH_MREAD_M4: &[&str] = &[
    "09d57080f181af9460d7806c9066e28272c282d935afead202b9ff41ad8787e4",
    "e5c500d4e9f2bd311da87658fd66f03d1aaeb85e92844381550935c5a9d99db3",
    "ecdeec636c4e6848207ef6eb558d42d68bec43ef9f8039628c9da67fdf52bdb3",
    "e2d624046d736c852bc39fd837f6020e512d0ecda2f0c7ad3b468c399b575f2c",
];
// Position 9 (the trailing short record): the sibling leaf hash of record 8,
// then MTH of the whole size-8 left subtree - two elements, no padding.
const PATH_MREAD_M9: &[&str] = &[
    "874bb321567c2878c37d117d7b4844d505bba48fb28ef79e9a384783cd83981c",
    "b5b3451f98dc0883a58aeb101c5444c11e47803cdcfff29cf2f1e289627fbdad",
];
// Modified batch (one non-LF byte changed inside the long record's second
// half): the long record's own sibling subtrees are untouched, so its path
// is identical to PATH_MREAD_M4; the trailing record's path keeps its first
// element (record 8's leaf hash) but the left-subtree hash covering the long
// record changes.
const PATH_MREAD_MOD_M4: &[&str] = &[
    "09d57080f181af9460d7806c9066e28272c282d935afead202b9ff41ad8787e4",
    "e5c500d4e9f2bd311da87658fd66f03d1aaeb85e92844381550935c5a9d99db3",
    "ecdeec636c4e6848207ef6eb558d42d68bec43ef9f8039628c9da67fdf52bdb3",
    "e2d624046d736c852bc39fd837f6020e512d0ecda2f0c7ad3b468c399b575f2c",
];
const PATH_MREAD_MOD_M9: &[&str] = &[
    "874bb321567c2878c37d117d7b4844d505bba48fb28ef79e9a384783cd83981c",
    "c8ae53a4f10cf65e79e605c3b0d382317dc4694600f41e891dbb26f6f0c27370",
];

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

fn run_prove(path: &std::path::Path, index: &str) -> std::process::Output {
    Command::new(bin())
        .arg("prove")
        .arg(path)
        .arg(index)
        .output()
        .expect("failed to execute roottrace binary")
}

fn run_verify(
    record: &std::path::Path,
    proof: &std::path::Path,
    size: &str,
    root: &str,
) -> std::process::Output {
    Command::new(bin())
        .arg("verify")
        .arg(record)
        .arg(proof)
        .arg(size)
        .arg(root)
        .output()
        .expect("failed to execute roottrace binary")
}

/// Assert the full documented prove success contract: exit 0, empty stderr,
/// exactly one LF-terminated JSON line equal to `expected`.
fn assert_proof(desc: &str, file_bytes: &[u8], index: &str, expected: &str) {
    let tmp = TempFile::create(file_bytes);
    let output = run_prove(&tmp.path, index);
    if output.status.code() != Some(0) {
        panic!(
            "[{desc}] prove {index} failed: status={:?}\n  stderr: {}\n  stdout: {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr),
            String::from_utf8_lossy(&output.stdout),
        );
    }
    if !output.stderr.is_empty() {
        panic!(
            "[{desc}] successful prove wrote stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let stdout = String::from_utf8(output.stdout.clone())
        .unwrap_or_else(|e| panic!("[{desc}] stdout is not UTF-8: {e}"));
    if !stdout.ends_with('\n')
        || stdout.len() != expected.len() + 1
        || stdout.as_bytes().iter().filter(|b| **b == b'\n').count() != 1
    {
        panic!(
            "[{desc}] stdout must be exactly one JSON line + one trailing LF, got {:?}",
            stdout.as_bytes()
        );
    }
    assert_eq!(&stdout[..stdout.len() - 1], expected, "[{desc}] proof JSON mismatch");
}

/// Assert the full documented verify success contract: exit 0, empty stderr,
/// stdout exactly "verified\n".
fn assert_verified(desc: &str, record: &[u8], proof: &[u8], size: &str, root: &str) {
    let rec = TempFile::create(record);
    let prf = TempFile::create(proof);
    let out = run_verify(&rec.path, &prf.path, size, root);
    if out.status.code() != Some(0) || out.stdout != b"verified\n" || !out.stderr.is_empty() {
        panic!(
            "[{desc}] expected verified/exit0/empty-stderr\n\
             status: {:?}\nstdout: {:?}\nstderr: {}",
            out.status.code(),
            out.stdout,
            String::from_utf8_lossy(&out.stderr),
        );
    }
}

#[test]
fn prove_long_and_trailing_records_match_fixed_vectors() {
    let pad = pad_record();
    let long = long_record();
    let recs = records(&pad, &long);
    let data = join_lf(&recs, true);

    // The long record occupies exactly one position; all of its 140000 bytes
    // take part in the proof (the root and path constants bind them).
    assert_proof(
        "MREAD m=4 (140000-byte record spanning multiple reads)",
        &data,
        "4",
        &expected_json(10, 4, ROOT_MREAD, PATH_MREAD_M4),
    );
    assert_proof(
        "MREAD m=9 (trailing short record, uneven right subtree)",
        &data,
        "9",
        &expected_json(10, 9, ROOT_MREAD, PATH_MREAD_M9),
    );
}

#[test]
fn trailing_lf_form_gives_byte_identical_proofs() {
    let pad = pad_record();
    let long = long_record();
    let recs = records(&pad, &long);
    let with_lf = TempFile::create(&join_lf(&recs, true));
    let no_lf = TempFile::create(&join_lf(&recs, false));

    for index in ["4", "9"] {
        let a = run_prove(&with_lf.path, index);
        let b = run_prove(&no_lf.path, index);
        assert_eq!(a.status.code(), Some(0));
        assert_eq!(b.status.code(), Some(0));
        assert_eq!(
            a.stdout, b.stdout,
            "index {index}: the two file forms name the same record sequence; \
             no extra empty record may appear"
        );
    }
}

#[test]
fn proofs_verify_against_record_bytes_and_independent_trusted_values() {
    let pad = pad_record();
    let long = long_record();
    let recs = records(&pad, &long);
    let batch = TempFile::create(&join_lf(&recs, true));

    // The record file handed to verify holds the record's raw bytes exactly:
    // no batch-separating LF, and the NUL/CR/non-UTF-8 bytes inside and at
    // the tail are neither trimmed nor replaced.
    assert_eq!(long.len(), LONG_LEN);
    assert!(!long.contains(&b'\n'));
    assert!(long.contains(&0x00) && long.contains(&0x0d));
    assert!(long.iter().any(|&b| b >= 0x80));
    assert_eq!(&long[LONG_LEN - 7..], b"\x00TAIL\r\xff");

    // The two proofs as actually generated by `prove` (pinned byte-for-byte
    // against the fixed vectors above), verified against the record bytes
    // and the independently fixed trusted size and root.
    let proof4 = run_prove(&batch.path, "4");
    let proof9 = run_prove(&batch.path, "9");
    assert_eq!(proof4.status.code(), Some(0));
    assert_eq!(proof9.status.code(), Some(0));
    assert_verified(
        "MREAD m=4: 140000-byte record verifies against trusted (10, ROOT_MREAD)",
        &long,
        &proof4.stdout,
        "10",
        ROOT_MREAD,
    );
    assert_verified(
        "MREAD m=9: trailing short record verifies against trusted (10, ROOT_MREAD)",
        b"end-record\x01",
        &proof9.stdout,
        "10",
        ROOT_MREAD,
    );
}

#[test]
fn one_byte_change_rebinds_root_and_only_the_covering_path_element() {
    let pad = pad_record();
    let long_m = long_record_m();
    let recs_m = records(&pad, &long_m);
    let data_m = join_lf(&recs_m, true);

    // The modified batch still has ten records in the same positions; its
    // proofs must bind ROOT_MREAD_M, not the original root.
    assert_proof(
        "MREAD_M m=4 (modified long record)",
        &data_m,
        "4",
        &expected_json(10, 4, ROOT_MREAD_M, PATH_MREAD_MOD_M4),
    );
    assert_proof(
        "MREAD_M m=9 (unchanged trailing record, changed path)",
        &data_m,
        "9",
        &expected_json(10, 9, ROOT_MREAD_M, PATH_MREAD_MOD_M9),
    );

    // The change sits inside leaf 4, so the long record's own audit path
    // (sibling subtree hashes only) keeps its original value...
    assert_eq!(
        PATH_MREAD_MOD_M4, PATH_MREAD_M4,
        "the long record's sibling subtrees are untouched by a change inside it"
    );
    // ...while the trailing record's path keeps the sibling leaf hash of
    // record 8 but must change the left-subtree hash covering the long record.
    assert_eq!(PATH_MREAD_MOD_M9.len(), PATH_MREAD_M9.len());
    assert_eq!(PATH_MREAD_MOD_M9[0], PATH_MREAD_M9[0]);
    assert_ne!(
        PATH_MREAD_MOD_M9[1], PATH_MREAD_M9[1],
        "the subtree hash covering the long record must change with its content"
    );

    // The regenerated proofs verify against the modified record bytes and
    // the independently fixed modified root.
    let proof4_m = expected_json(10, 4, ROOT_MREAD_M, PATH_MREAD_MOD_M4) + "\n";
    let proof9_m = expected_json(10, 9, ROOT_MREAD_M, PATH_MREAD_MOD_M9) + "\n";
    assert_verified(
        "MREAD_M m=4: modified long record verifies against trusted (10, ROOT_MREAD_M)",
        &long_m,
        proof4_m.as_bytes(),
        "10",
        ROOT_MREAD_M,
    );
    assert_verified(
        "MREAD_M m=9: trailing record verifies against trusted (10, ROOT_MREAD_M)",
        b"end-record\x01",
        proof9_m.as_bytes(),
        "10",
        ROOT_MREAD_M,
    );
}

#[test]
fn original_proof_fails_verification_for_modified_record_and_original_trusted_values() {
    let long_m = long_record_m();
    // The ORIGINAL long-record proof, the MODIFIED record bytes and the
    // ORIGINAL trusted size/root: the proof is well-formed but cannot match,
    // so this is a verification failure, not a malformed proof.
    let proof4 = expected_json(10, 4, ROOT_MREAD, PATH_MREAD_M4) + "\n";
    let rec = TempFile::create(&long_m);
    let prf = TempFile::create(proof4.as_bytes());
    let out = run_verify(&rec.path, &prf.path, "10", ROOT_MREAD);
    assert_eq!(out.status.code(), Some(1), "mismatched record must exit 1");
    assert!(out.stdout.is_empty(), "no success output on failure");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("verification failed"),
        "must be classified as a verification failure: {err}"
    );
    assert!(
        !err.contains("invalid proof"),
        "the proof itself is well-formed: {err}"
    );
}
