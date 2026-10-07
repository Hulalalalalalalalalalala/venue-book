//! End-to-end regression tests for verifying records that THEMSELVES contain
//! LF bytes, through both the `roottrace verify` command and the
//! `roottrace::verify_membership` library entry point.
//!
//! The record file of `verify` and the `record: &[u8]` argument of the
//! library are taken as raw bytes with no LF splitting and no trimming (the
//! LF-separated batch file is a `root`/`prove` concept). Existing coverage
//! pins that APPENDING an LF to a normal record fails; these tests pin the
//! success side: a legitimate record whose own bytes contain LF verifies as
//! one complete record. Such a record can never appear inside a batch file
//! (LF is the separator there), so the fixed proofs and trusted roots come
//! from `tests/reference/rfc6962_lf_record_vectors.py` — two structurally
//! different RFC 6962 implementations over `hashlib.sha256`, cross-checked
//! and re-verified by an independent inclusion verifier — and are never
//! derived from roottrace output.
//!
//! Coverage:
//!   * REC_LF_RICH: starts with LF, consecutive LFs inside, ends with LF,
//!     carries CR/NUL/non-UTF-8 bytes, 100 bytes long so the leaf input
//!     crosses the SHA-256 64-byte block boundary — verifies in a
//!     single-record tree (empty audit path) and in a 9-record
//!     non-power-of-two tree (position 4)
//!   * REC_ONE_LF: exactly one LF byte — verifies in both tree shapes and is
//!     neither the zero-byte empty record nor the batch-file empty record
//!   * the LFs inside the record do not change the proof's declared
//!     tree_size/leaf_index, and verification does not match any single
//!     line of the record
//!   * mutations (trailing LF removed, one internal LF changed) fail as
//!     "verification failed" — exit 1, empty stdout — never as "invalid
//!     proof" and never successfully; the library returns
//!     VerifyError::VerificationFailed
//!   * CLI success output is exactly "verified\n" with exit 0 and empty
//!     stderr; the library result carries the claimed index and the
//!     caller's trusted size and root

mod common;

use std::process::Command;

use common::TempFile;
use roottrace::{verify_membership, VerifyError};

// --- Fixed records, roots and paths (copied from the reference generator) --

// REC_LF_RICH: 100-byte record; starts with LF, consecutive LFs inside,
// ends with LF, carries CR/NUL/non-UTF-8 bytes; leaf input 101 bytes
// crosses the SHA-256 64-byte block boundary.
const REC_LF_RICH: &[u8] = b"\n\x00\xff\xfe\rlf-rich-record:\n\n\nsegment-B\r\nabcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz012\n";

// REC_ONE_LF: the record that is exactly one LF byte.
const REC_ONE_LF: &[u8] = b"\n";

// Single-record trees (tree_size 1, leaf_index 0, empty audit path):
const ROOT_LF_RICH_SINGLE: &str = "173226ff98963fba71af8e5be5a65b8801b57802a8da0f3df194630a60e3c6b4";
const ROOT_ONE_LF_SINGLE: &str = "67ebbd370daa02ba9aadd05d8e091e862d0d8bcadafdf2a22360240a42fe922e";

// LF_BATCH: 9-record (non-power-of-two) sequence with REC_LF_RICH at
// position 4 and REC_ONE_LF at position 8 (lone right subtree).
const ROOT_LF_BATCH: &str = "0da784b08ff8dc5d6ce28573aef2f1870116467b242aea9bdddc09e7878ea281";
const PATH_LF_BATCH_M4: &[&str] = &["874bb321567c2878c37d117d7b4844d505bba48fb28ef79e9a384783cd83981c", "3fc0ce0f8d78eb619bf4d612fea9ce899778ce65c0f4057ccdff93d5e5a1cb11", "24ff5ce2ca4e64d47365292c6d5408d2118f70f3eb7d4baf88caf779e61cc1c5", "67ebbd370daa02ba9aadd05d8e091e862d0d8bcadafdf2a22360240a42fe922e"];
const PATH_LF_BATCH_M8: &[&str] = &["6815e839c7f397a279197c64b82fa20441773460c830112ced04f25607a30d8f"];

// The batch-file empty record's root (SHA-256(0x00)), fixed independently in
// tests/reference/rfc6962_vectors.py and reused by verify_regression.rs: the
// one-LF record must NOT verify against it.
const ROOT_ONE_EMPTY_RECORD: &str =
    "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d";

fn proof_json(size: u64, index: u64, root: &str, path: &[&str]) -> String {
    let mut out =
        format!("{{\"tree_size\":{size},\"leaf_index\":{index},\"root\":\"{root}\",\"audit_path\":[");
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

/// Decode 64 lowercase hex characters into a 32-byte hash.
fn hash_of(hex: &str) -> [u8; 32] {
    assert_eq!(hex.len(), 64, "hash must be 64 hex chars: {hex:?}");
    let mut out = [0u8; 32];
    for (i, pair) in hex.as_bytes().chunks_exact(2).enumerate() {
        let nibble = |b: u8| -> u8 {
            match b {
                b'0'..=b'9' => b - b'0',
                b'a'..=b'f' => b - b'a' + 10,
                _ => panic!("not lowercase hex: {hex:?}"),
            }
        };
        out[i] = (nibble(pair[0]) << 4) | nibble(pair[1]);
    }
    out
}

fn run(
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

fn assert_verified(desc: &str, record: &[u8], proof: &[u8], size: &str, root: &str) {
    let rec = TempFile::create(record);
    let prf = TempFile::create(proof);
    let out = run(&rec.path, &prf.path, size, root);
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

/// The failure must be classified as a verification failure (exit 1, empty
/// stdout, "verification failed" on stderr) — never as a malformed proof.
fn assert_verification_failed(desc: &str, record: &[u8], proof: &[u8], size: &str, root: &str) {
    let rec = TempFile::create(record);
    let prf = TempFile::create(proof);
    let out = run(&rec.path, &prf.path, size, root);
    assert_eq!(out.status.code(), Some(1), "[{desc}] must exit 1");
    assert!(out.stdout.is_empty(), "[{desc}] stdout must be empty, got {:?}", out.stdout);
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("verification failed"), "[{desc}] stderr: {err}");
    assert!(!err.contains("invalid proof"), "[{desc}] must not be a format error: {err}");
}

// --- Success: LF-containing records verify as one complete record ----------

#[test]
fn lf_rich_record_verifies_as_one_record_in_both_tree_shapes() {
    // Structural requirements the whole test file relies on.
    assert_eq!(REC_LF_RICH.len(), 100);
    assert!(1 + REC_LF_RICH.len() > 64, "leaf input must cross the 64-byte block boundary");
    assert_eq!(REC_LF_RICH[0], b'\n', "starts with LF");
    assert_eq!(REC_LF_RICH[REC_LF_RICH.len() - 1], b'\n', "ends with LF");
    assert!(REC_LF_RICH.windows(3).any(|w| w == b"\n\n\n"), "consecutive LFs inside");
    assert!(REC_LF_RICH.contains(&0x00) && REC_LF_RICH.contains(&b'\r'));
    assert!(REC_LF_RICH.iter().any(|&b| b >= 0x80), "non-UTF-8 bytes inside");

    // Single-record tree: empty audit path, the record is the whole tree.
    let single = proof_json(1, 0, ROOT_LF_RICH_SINGLE, &[]);
    assert_verified(
        "LF-rich record, single-record tree",
        REC_LF_RICH,
        single.as_bytes(),
        "1",
        ROOT_LF_RICH_SINGLE,
    );

    // Non-power-of-two 9-record tree: the record sits at position 4 with the
    // audit path for that position. The LFs inside the record do not change
    // the declared tree size or position.
    let batch = proof_json(9, 4, ROOT_LF_BATCH, PATH_LF_BATCH_M4);
    assert!(
        batch.starts_with("{\"tree_size\":9,\"leaf_index\":4,"),
        "the proof declares tree_size 9 and leaf_index 4 regardless of the LFs: {batch}"
    );
    assert_verified(
        "LF-rich record, 9-record tree position 4",
        REC_LF_RICH,
        batch.as_bytes(),
        "9",
        ROOT_LF_BATCH,
    );
}

#[test]
fn one_lf_record_verifies_and_is_not_the_empty_record() {
    // Exactly one LF byte: verifies in both tree shapes.
    let single = proof_json(1, 0, ROOT_ONE_LF_SINGLE, &[]);
    assert_verified(
        "one-LF record, single-record tree",
        REC_ONE_LF,
        single.as_bytes(),
        "1",
        ROOT_ONE_LF_SINGLE,
    );
    let batch = proof_json(9, 8, ROOT_LF_BATCH, PATH_LF_BATCH_M8);
    assert_verified(
        "one-LF record, 9-record tree position 8",
        REC_ONE_LF,
        batch.as_bytes(),
        "9",
        ROOT_LF_BATCH,
    );

    // It is NOT the zero-byte empty record: the empty record's own proof
    // (tree_size 1, root SHA-256(0x00)) must reject the one-LF record...
    assert_verification_failed(
        "one-LF record against the empty-record proof",
        REC_ONE_LF,
        proof_json(1, 0, ROOT_ONE_EMPTY_RECORD, &[]).as_bytes(),
        "1",
        ROOT_ONE_EMPTY_RECORD,
    );
    // ...and the zero-byte record file must not verify against the one-LF
    // proofs, in either tree shape.
    assert_verification_failed(
        "zero-byte record file against the one-LF single proof",
        b"",
        single.as_bytes(),
        "1",
        ROOT_ONE_LF_SINGLE,
    );
    assert_verification_failed(
        "zero-byte record file against the one-LF batch proof",
        b"",
        batch.as_bytes(),
        "9",
        ROOT_LF_BATCH,
    );
    // Two LFs are yet another record; consecutive LFs are content, not
    // "two empty records".
    assert_verification_failed(
        "two-LF record file against the one-LF single proof",
        b"\n\n",
        single.as_bytes(),
        "1",
        ROOT_ONE_LF_SINGLE,
    );
}

// --- Mutations of an LF-containing record fail verification ----------------

#[test]
fn lf_rich_record_mutations_fail_verification_in_both_tree_shapes() {
    let single = proof_json(1, 0, ROOT_LF_RICH_SINGLE, &[]);
    let batch = proof_json(9, 4, ROOT_LF_BATCH, PATH_LF_BATCH_M4);

    // Only the trailing LF removed: the record becomes a different one.
    let no_trailing = &REC_LF_RICH[..REC_LF_RICH.len() - 1];
    assert_verification_failed(
        "trailing LF removed, single-record tree",
        no_trailing,
        single.as_bytes(),
        "1",
        ROOT_LF_RICH_SINGLE,
    );
    assert_verification_failed(
        "trailing LF removed, 9-record tree",
        no_trailing,
        batch.as_bytes(),
        "9",
        ROOT_LF_BATCH,
    );

    // One INTERNAL LF changed (the middle LF of the consecutive run becomes
    // a vertical tab), every other byte unchanged and the length preserved.
    assert_eq!(REC_LF_RICH[21], b'\n', "byte 21 is an internal LF");
    let mut internal_changed = REC_LF_RICH.to_vec();
    internal_changed[21] = 0x0b;
    assert_verification_failed(
        "one internal LF changed, single-record tree",
        &internal_changed,
        single.as_bytes(),
        "1",
        ROOT_LF_RICH_SINGLE,
    );
    assert_verification_failed(
        "one internal LF changed, 9-record tree",
        &internal_changed,
        batch.as_bytes(),
        "9",
        ROOT_LF_BATCH,
    );

    // Verification must not fall back to matching a single LINE of the
    // record: no LF-delimited segment of it is the record.
    for line in [
        b"\x00\xff\xfe\rlf-rich-record:".as_slice(),
        b"segment-B\r".as_slice(),
        b"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz012".as_slice(),
        b"".as_slice(),
    ] {
        assert_verification_failed(
            &format!("a single line of the record {line:?}"),
            line,
            batch.as_bytes(),
            "9",
            ROOT_LF_BATCH,
        );
    }
}

// --- Library: same byte rule through roottrace::verify_membership ----------

#[test]
fn library_verifies_lf_containing_records_with_typed_result() {
    let cases: &[(&[u8], String, u64, u64, &str)] = &[
        (REC_LF_RICH, proof_json(1, 0, ROOT_LF_RICH_SINGLE, &[]), 1, 0, ROOT_LF_RICH_SINGLE),
        (REC_LF_RICH, proof_json(9, 4, ROOT_LF_BATCH, PATH_LF_BATCH_M4), 9, 4, ROOT_LF_BATCH),
        (REC_ONE_LF, proof_json(1, 0, ROOT_ONE_LF_SINGLE, &[]), 1, 0, ROOT_ONE_LF_SINGLE),
        (REC_ONE_LF, proof_json(9, 8, ROOT_LF_BATCH, PATH_LF_BATCH_M8), 9, 8, ROOT_LF_BATCH),
    ];
    for (record, proof, size, index, root) in cases {
        let trusted_root = hash_of(root);
        let m = verify_membership(record, proof.as_bytes(), *size, &trusted_root)
            .unwrap_or_else(|e| panic!("index {index} of tree {size} must verify: {e}"));
        assert_eq!(m.leaf_index(), *index);
        assert_eq!(m.tree_size(), *size);
        assert_eq!(m.root(), &trusted_root);
    }
}

#[test]
fn library_lf_record_mutations_are_verification_failed() {
    let single = proof_json(1, 0, ROOT_LF_RICH_SINGLE, &[]);
    let batch = proof_json(9, 4, ROOT_LF_BATCH, PATH_LF_BATCH_M4);
    let single_root = hash_of(ROOT_LF_RICH_SINGLE);
    let batch_root = hash_of(ROOT_LF_BATCH);

    let no_trailing = &REC_LF_RICH[..REC_LF_RICH.len() - 1];
    let mut internal_changed = REC_LF_RICH.to_vec();
    internal_changed[21] = 0x0b;

    let one_lf_single = proof_json(1, 0, ROOT_ONE_LF_SINGLE, &[]);
    let one_lf_root = hash_of(ROOT_ONE_LF_SINGLE);

    let failures: &[(&[u8], &[u8], u64, &[u8; 32])] = &[
        (no_trailing, single.as_bytes(), 1, &single_root),
        (no_trailing, batch.as_bytes(), 9, &batch_root),
        (&internal_changed, single.as_bytes(), 1, &single_root),
        (&internal_changed, batch.as_bytes(), 9, &batch_root),
        // The one-LF record is not the empty record, and vice versa.
        (b"", one_lf_single.as_bytes(), 1, &one_lf_root),
        (b"\n\n", one_lf_single.as_bytes(), 1, &one_lf_root),
    ];
    for (record, proof, size, root) in failures {
        match verify_membership(record, proof, *size, root) {
            Err(VerifyError::VerificationFailed(_)) => {}
            other => panic!(
                "record {record:?} against tree {size} must be VerificationFailed, got {other:?}"
            ),
        }
    }
}
