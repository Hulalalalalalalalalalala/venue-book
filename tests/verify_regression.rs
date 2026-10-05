//! End-to-end regression tests for
//! `roottrace verify <record-file> <proof-file> <trusted-tree-size> <trusted-root>`.
//!
//! The record sequences, roots and audit paths are the FIXED vectors of
//! `tests/prove_regression.rs`, produced independently of roottrace by
//! `tests/reference/rfc6962_vectors.py`; they are copied here, never derived
//! from roottrace output. Where a test needs an additional proof it is
//! generated at runtime with `prove` — those proofs are themselves pinned
//! byte-for-byte by `prove_regression.rs`.
//!
//! These tests pin the whole `verify` contract:
//!   * the record file's complete bytes are the record (no LF splitting, no
//!     trimming; a zero-byte file is one empty record)
//!   * trusted tree size and root come from the command line; the proof's
//!     own tree_size/root fields must match them, never substitute for them
//!   * success is exactly "verified\n" on stdout, exit 0, empty stderr
//!   * content/trusted/path mismatches exit 1 with a failure note on stderr
//!   * malformed proofs (missing/duplicate/mistyped fields, bad integers or
//!     hex, tree_size 0, out-of-range index) exit 1 as invalid proofs
//!   * bad trusted arguments or wrong argument counts exit 2 with usage
//!   * unreadable record/proof files exit 1 with nothing on stdout

mod common;

use std::process::Command;

use common::{TempDir, TempFile};

// --- Fixed payloads and vectors (shared with prove_regression.rs) -----------

const PAYLOAD_B8: &[u8] =
    b"alpha\nbeta\n\ngamma\nalpha\ndelta\r\n\xff\xfe\x00binary\nepsilon\n";
const PAYLOAD_B9: &[u8] =
    b"alpha\nbeta\n\ngamma\nalpha\ndelta\r\n\xff\xfe\x00binary\nepsilon\nzeta\x01tail\n";
const PAYLOAD_ONE_LF: &[u8] = b"\n";

const ROOT_B8: &str = "80f3f98ae8d7d9d1d2139a6a2dc94628e02fba22e125f922ea8a4c10799cb912";
const ROOT_B9: &str = "a8a3e76ecf28b850e84cb5465729921212ffd07de3c0e6e170cd233bf723adc3";
const ROOT_ONE_EMPTY_RECORD: &str =
    "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d";

const PATH_B9_M0: &[&str] = &[
    "e23537b050e84af2cbaab46f2f83d8d3b5febc8e5ac6200d306284f687d46924",
    "ac96b46d1760957393e22a8a365d54e58645a244550bc3c566892cdbdc5d8fc1",
    "416649c1a4f116151112df7d7d3faa85d5d8c60699e153e7a3c57a1abab7a242",
    "5cc496b84d9250622d5de1219d1f156e7973503fbd80f7f3364800bbfa2947d2",
];
const PATH_B9_M4: &[&str] = &[
    "4957faa551907820ed93a476704ffd826ea5502881876c87f3acefc0a8d29bce",
    "b739bc437ae5d551d144d1478ee16d1119ba15b2198a3a8b7c47976c36cb6639",
    "6f2bd73a7406c5089558c115aaae63a717e4c6947c44898e7d9600023ff15d10",
    "5cc496b84d9250622d5de1219d1f156e7973503fbd80f7f3364800bbfa2947d2",
];
const PATH_B9_M8: &[&str] =
    &["80f3f98ae8d7d9d1d2139a6a2dc94628e02fba22e125f922ea8a4c10799cb912"];
const PATH_B8_M3: &[&str] = &[
    "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
    "983cb57c04cddd52634edab38a7bef85708a974f114bbd9aa9ec5d4ce6656b4b",
    "416649c1a4f116151112df7d7d3faa85d5d8c60699e153e7a3c57a1abab7a242",
];

fn proof_json(size: u64, index: u64, root: &str, path: &[&str]) -> String {
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

/// Assert the full documented success contract: exit 0, empty stderr, and
/// stdout is exactly "verified\n".
fn assert_verified(desc: &str, record: &[u8], proof_json_text: &str, size: &str, root: &str) {
    let rec = TempFile::create(record);
    let proof = TempFile::create(proof_json_text.as_bytes());
    let out = run_verify(&rec.path, &proof.path, size, root);
    assert_eq!(
        out.status.code(),
        Some(0),
        "[{desc}] verify failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        out.stderr.is_empty(),
        "[{desc}] successful verify wrote stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(out.stdout, b"verified\n", "[{desc}] stdout must be exactly 'verified\\n'");
}

/// Assert a verification failure: exit 1, empty stdout, and stderr explains
/// that verification failed.
fn assert_verify_failed(desc: &str, record: &[u8], proof_json_text: &str, size: &str, root: &str) {
    let rec = TempFile::create(record);
    let proof = TempFile::create(proof_json_text.as_bytes());
    let out = run_verify(&rec.path, &proof.path, size, root);
    assert_eq!(out.status.code(), Some(1), "[{desc}] must exit 1");
    assert!(out.stdout.is_empty(), "[{desc}] failure must not write stdout");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("verification failed"), "[{desc}] stderr must report the failure: {err}");
}

/// Assert an invalid proof: exit 1, empty stdout, stderr names the proof.
fn assert_invalid_proof(desc: &str, record: &[u8], proof_json_text: &str, size: &str, root: &str) {
    let rec = TempFile::create(record);
    let proof = TempFile::create(proof_json_text.as_bytes());
    let out = run_verify(&rec.path, &proof.path, size, root);
    assert_eq!(out.status.code(), Some(1), "[{desc}] must exit 1");
    assert!(out.stdout.is_empty(), "[{desc}] must not write stdout");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("invalid proof"), "[{desc}] stderr must report an invalid proof: {err}");
}

/// Run `prove` on a batch held in a temp file and return the JSON line.
fn prove_json(batch_bytes: &[u8], index: &str) -> String {
    let batch = TempFile::create(batch_bytes);
    let out = Command::new(common::bin())
        .arg("prove")
        .arg(&batch.path)
        .arg(index)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "prove {index} failed");
    String::from_utf8(out.stdout).unwrap().trim_end_matches('\n').to_string()
}

#[test]
fn fixed_vectors_verify_successfully() {
    assert_verified(
        "B9 m=0 first record",
        b"alpha",
        &proof_json(9, 0, ROOT_B9, PATH_B9_M0),
        "9",
        ROOT_B9,
    );
    assert_verified(
        "B9 m=8 last record of uneven batch (single-hash path)",
        b"zeta\x01tail",
        &proof_json(9, 8, ROOT_B9, PATH_B9_M8),
        "9",
        ROOT_B9,
    );
    assert_verified(
        "B8 m=3 balanced power-of-two batch",
        b"gamma",
        &proof_json(8, 3, ROOT_B8, PATH_B8_M3),
        "8",
        ROOT_B8,
    );
    // A zero-byte record file is one empty record and matches the proof for
    // the single-empty-record batch.
    assert_verified(
        "zero-byte record file == one empty record",
        b"",
        &proof_json(1, 0, ROOT_ONE_EMPTY_RECORD, &[]),
        "1",
        ROOT_ONE_EMPTY_RECORD,
    );
    // Records with NUL, CR and non-UTF-8 bytes verify byte-for-byte.
    assert_verified(
        "record with CR content",
        b"delta\r",
        &prove_json(PAYLOAD_B9, "5"),
        "9",
        ROOT_B9,
    );
    assert_verified(
        "record with NUL and non-UTF-8 bytes",
        b"\xff\xfe\x00binary",
        &prove_json(PAYLOAD_B9, "6"),
        "9",
        ROOT_B9,
    );
}

#[test]
fn proof_json_allows_field_order_and_whitespace_variation() {
    let fancy = format!(
        "{{\n\t\"audit_path\": [ \"{}\",\n\t\t\"{}\" ],\n\t\"root\":\t\"{ROOT_B8}\",\n\t\"leaf_index\": 3,\n\t\"tree_size\":   8\n}}\n",
        PATH_B8_M3[0], PATH_B8_M3[1]
    );
    // Note: this JSON is intentionally missing the third path element and
    // must FAIL — the whitespace/order freedom never relaxes the hash check.
    assert_verify_failed("short path in fancy formatting", b"gamma", &fancy, "8", ROOT_B8);

    let fancy_full = format!(
        "  {{\n  \"audit_path\": [\"{}\", \"{}\", \"{}\"],\n  \"root\": \"{ROOT_B8}\",\n  \"leaf_index\": 3,\n  \"tree_size\": 8\n}}\n",
        PATH_B8_M3[0], PATH_B8_M3[1], PATH_B8_M3[2]
    );
    assert_verified("reordered fields and whitespace", b"gamma", &fancy_full, "8", ROOT_B8);
}

#[test]
fn record_file_bytes_are_taken_verbatim() {
    let proof0 = proof_json(9, 0, ROOT_B9, PATH_B9_M0);
    // An extra trailing LF changes the record: must fail.
    assert_verify_failed("record with appended LF", b"alpha\n", &proof0, "9", ROOT_B9);
    // Trailing spaces and CR are content too.
    assert_verify_failed("record with trailing space", b"alpha ", &proof0, "9", ROOT_B9);
    assert_verify_failed("record with trailing CR", b"alpha\r", &proof0, "9", ROOT_B9);
    // A zero-byte record file is NOT the record b"alpha".
    assert_verify_failed("empty record file vs alpha proof", b"", &proof0, "9", ROOT_B9);
    // And a record file containing a lone LF is not the empty record.
    assert_verify_failed(
        "lone-LF record file vs empty-record proof",
        b"\n",
        &proof_json(1, 0, ROOT_ONE_EMPTY_RECORD, &[]),
        "1",
        ROOT_ONE_EMPTY_RECORD,
    );
}

#[test]
fn trusted_values_must_match_the_proof_fields() {
    let proof0 = proof_json(9, 0, ROOT_B9, PATH_B9_M0);
    // Trusted tree size disagrees with the proof.
    assert_verify_failed("trusted size too small", b"alpha", &proof0, "8", ROOT_B9);
    assert_verify_failed("trusted size too large", b"alpha", &proof0, "10", ROOT_B9);
    // Trusted root disagrees with the proof (ROOT_B8 is a real root of a
    // different batch, not a random string).
    assert_verify_failed("trusted root of another batch", b"alpha", &proof0, "9", ROOT_B8);
}

#[test]
fn audit_path_must_have_exactly_the_right_hashes_in_order() {
    // Missing hash: drop the last element of the m=0 path.
    assert_verify_failed(
        "path missing a hash",
        b"alpha",
        &proof_json(9, 0, ROOT_B9, &PATH_B9_M0[..3]),
        "9",
        ROOT_B9,
    );
    // Extra hash: append a duplicate of the last element.
    let mut longer = PATH_B9_M0.to_vec();
    longer.push(PATH_B9_M0[3]);
    assert_verify_failed(
        "path with an extra hash",
        b"alpha",
        &proof_json(9, 0, ROOT_B9, &longer),
        "9",
        ROOT_B9,
    );
    // Right hashes, wrong order.
    let swapped = [PATH_B9_M0[1], PATH_B9_M0[0], PATH_B9_M0[2], PATH_B9_M0[3]];
    assert_verify_failed(
        "path hashes out of order",
        b"alpha",
        &proof_json(9, 0, ROOT_B9, &swapped),
        "9",
        ROOT_B9,
    );
    // The uneven batch's last record pairs with exactly one sibling; padding
    // the tree out to a power of two (extra hashes) must not verify.
    let mut padded = PATH_B9_M8.to_vec();
    padded.push(PATH_B9_M0[3]);
    assert_verify_failed(
        "uneven batch proof must not be padded",
        b"zeta\x01tail",
        &proof_json(9, 8, ROOT_B9, &padded),
        "9",
        ROOT_B9,
    );
}

#[test]
fn duplicate_content_is_verified_at_the_declared_position_only() {
    // b"alpha" sits at positions 0 and 4 of B9; both proofs verify the same
    // record bytes at their own declared position.
    assert_verified(
        "duplicate at position 0",
        b"alpha",
        &proof_json(9, 0, ROOT_B9, PATH_B9_M0),
        "9",
        ROOT_B9,
    );
    assert_verified(
        "duplicate at position 4",
        b"alpha",
        &proof_json(9, 4, ROOT_B9, PATH_B9_M4),
        "9",
        ROOT_B9,
    );
    // Re-anchoring the m=0 proof to position 4 (its hashes belong to
    // position 0) must fail: positions are never searched or adjusted.
    let reanchored = proof_json(9, 4, ROOT_B9, PATH_B9_M0);
    assert_verify_failed("m=0 proof re-anchored to index 4", b"alpha", &reanchored, "9", ROOT_B9);
}

#[test]
fn invalid_proofs_exit_1_and_say_invalid_proof() {
    let valid = proof_json(9, 0, ROOT_B9, PATH_B9_M0);
    let cases: Vec<(String, String)> = vec![
        ("empty proof file".into(), String::new()),
        ("not an object".into(), "[]".into()),
        ("trailing garbage".into(), format!("{valid} x")),
        ("missing tree_size".into(), valid.replace("\"tree_size\":9,", "")),
        ("missing leaf_index".into(), valid.replace("\"leaf_index\":0,", "")),
        ("missing root".into(), valid.replace(&format!("\"root\":\"{ROOT_B9}\","), "")),
        ("missing audit_path".into(), valid.replace("\"audit_path\"", "\"audit_path_2\"")),
        ("duplicate field".into(), valid.replace("{\"tree_size\":9", "{\"tree_size\":9,\"tree_size\":9")),
        ("tree_size zero".into(), valid.replace("\"tree_size\":9", "\"tree_size\":0")),
        ("tree_size negative".into(), valid.replace("\"tree_size\":9", "\"tree_size\":-1")),
        ("tree_size fraction".into(), valid.replace("\"tree_size\":9", "\"tree_size\":9.0")),
        ("tree_size string".into(), valid.replace("\"tree_size\":9", "\"tree_size\":\"9\"")),
        ("tree_size overflow".into(), valid.replace("\"tree_size\":9", "\"tree_size\":18446744073709551616")),
        ("leaf_index out of range".into(), valid.replace("\"leaf_index\":0", "\"leaf_index\":9")),
        ("root uppercase".into(), valid.replace(ROOT_B9, &ROOT_B9.to_uppercase())),
        ("root too short".into(), valid.replace(ROOT_B9, &ROOT_B9[..63])),
        ("path element not hex".into(), valid.replace(PATH_B9_M0[0], &PATH_B9_M0[0].replacen('e', "g", 1))),
        ("path element not a string".into(), valid.replace(&format!("\"{}\"", PATH_B9_M0[0]), PATH_B9_M0[0])),
    ];
    for (desc, json) in cases {
        assert_invalid_proof(&desc, b"alpha", &json, "9", ROOT_B9);
    }
}

#[test]
fn bad_trusted_arguments_and_arity_exit_2_with_usage() {
    let rec = TempFile::create(b"alpha");
    let proof = TempFile::create(proof_json(9, 0, ROOT_B9, PATH_B9_M0).as_bytes());
    let r = rec.path.to_str().unwrap();
    let p = proof.path.to_str().unwrap();

    for bad_size in ["0", "-1", "abc", "9.0", " 9", "9 ", "", "18446744073709551616"] {
        let out = run_verify(&rec.path, &proof.path, bad_size, ROOT_B9);
        assert_eq!(out.status.code(), Some(2), "size {bad_size:?} must exit 2");
        assert!(out.stdout.is_empty());
        assert!(String::from_utf8_lossy(&out.stderr).contains("Usage"), "size {bad_size:?}");
    }
    for bad_root in [
        &ROOT_B9.to_uppercase(),
        &ROOT_B9[..63],
        "xyz",
        "",
        &ROOT_B9.replacen('a', "g", 1),
    ] {
        let out = run_verify(&rec.path, &proof.path, "9", bad_root);
        assert_eq!(out.status.code(), Some(2), "root {bad_root:?} must exit 2");
        assert!(out.stdout.is_empty());
        assert!(String::from_utf8_lossy(&out.stderr).contains("Usage"), "root {bad_root:?}");
    }
    // Missing and extra arguments.
    for args in [
        vec!["verify"],
        vec!["verify", r],
        vec!["verify", r, p],
        vec!["verify", r, p, "9"],
        vec!["verify", r, p, "9", ROOT_B9, "extra"],
    ] {
        let out = Command::new(common::bin()).args(&args).output().unwrap();
        assert_eq!(out.status.code(), Some(2), "args {args:?} must exit 2");
        assert!(out.stdout.is_empty());
        assert!(String::from_utf8_lossy(&out.stderr).contains("Usage"), "args {args:?}");
    }
}

#[test]
fn unreadable_input_files_exit_1_and_write_nothing_to_stdout() {
    let rec = TempFile::create(b"alpha");
    let proof = TempFile::create(proof_json(9, 0, ROOT_B9, PATH_B9_M0).as_bytes());
    let missing = TempFile::create(b"x");
    let missing_path = missing.path.clone();
    drop(missing);
    let dir = TempDir::create();

    for (desc, r, p) in [
        ("missing record file", missing_path.clone(), proof.path.clone()),
        ("missing proof file", rec.path.clone(), missing_path.clone()),
        ("record path is a directory", dir.path.clone(), proof.path.clone()),
        ("proof path is a directory", rec.path.clone(), dir.path.clone()),
    ] {
        let out = run_verify(&r, &p, "9", ROOT_B9);
        assert_eq!(out.status.code(), Some(1), "{desc} must exit 1");
        assert!(out.stdout.is_empty(), "{desc} must not write stdout");
        assert!(!out.stderr.is_empty(), "{desc} must explain the failure");
    }
}

#[test]
fn verify_roundtrips_prove_output_for_every_position() {
    // For both the even and the uneven batch, every position's `prove`
    // output verifies against the true root; the empty-record positions are
    // matched by a zero-byte record file.
    for (payload, size, root) in [(PAYLOAD_B8, "8", ROOT_B8), (PAYLOAD_B9, "9", ROOT_B9)] {
        let records: Vec<&[u8]> = {
            let mut v: Vec<&[u8]> = payload.split(|&b| b == b'\n').collect();
            if payload.last() == Some(&b'\n') {
                v.pop();
            }
            v
        };
        assert_eq!(records.len().to_string(), size);
        for (i, record) in records.iter().enumerate() {
            let json = prove_json(payload, &i.to_string());
            assert_verified(
                &format!("position {i} of {size}"),
                record,
                &json,
                size,
                root,
            );
        }
    }
    // The single-LF batch: one empty record, empty audit path.
    let json = prove_json(PAYLOAD_ONE_LF, "0");
    assert_verified("single empty record", b"", &json, "1", ROOT_ONE_EMPTY_RECORD);
}

#[test]
fn version_root_and_prove_behaviour_are_unchanged() {
    let out = Command::new(common::bin()).arg("--version").output().unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(out.stdout, b"roottrace 0.1.0\n");

    let tmp = TempFile::create(PAYLOAD_B9);
    let out = Command::new(common::bin()).arg("root").arg(&tmp.path).output().unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(&out.stdout[..64], ROOT_B9.as_bytes());

    let out = Command::new(common::bin()).arg("prove").arg(&tmp.path).arg("0").output().unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(
        String::from_utf8(out.stdout).unwrap(),
        format!("{}\n", proof_json(9, 0, ROOT_B9, PATH_B9_M0))
    );
}
