//! End-to-end regression tests for `roottrace inspect <proof-file>`.
//!
//! `inspect` displays the batch size, record position and root that a proof
//! itself claims, without a target record or independently trusted values.
//! These tests pin down the full contract:
//!
//!   * success stdout is exactly one LF-terminated JSON object holding only
//!     tree_size, leaf_index and root; stderr is empty; exit status is 0
//!   * the output is byte-for-byte the three claims taken from a real `prove`
//!     proof (the audit_path is parsed but not displayed)
//!   * field reordering, legal JSON whitespace and equivalent Unicode escapes
//!     in field names or hash characters display the same information
//!   * a format-VALID proof whose audit path cannot prove the claimed position
//!     (wrong count/order/content, an arbitrary root) is still displayed:
//!     inspect performs no membership check and never prints "verified"
//!   * the FULL proof format is enforced exactly as verify does, including the
//!     non-displayed audit_path: a missing field, a duplicate after
//!     interpretation, a bad hash length, an unterminated array, tree_size 0,
//!     an out-of-range index, non-integer/overflowing numbers or trailing data
//!     all exit 1 with empty stdout and a format reason on stderr
//!   * sizes and indices keep their full unsigned 64-bit meaning (u64::MAX
//!     claims need no materializable tree)
//!   * missing/directory/unreadable paths exit 1; missing/extra arguments
//!     exit 2 with the usage text
//!
//! Non-UTF-8 proof paths are covered in `non_utf8_paths.rs`.

mod common;

use std::path::Path;
use std::process::Command;

use common::{TempDir, TempFile};

// Fixed vector reused from tests/reference/rfc6962_vectors.py (see
// prove_regression.rs): the 9-record uneven batch, positions 0 and 8.
const PAYLOAD_B9: &[u8] =
    b"alpha\nbeta\n\ngamma\nalpha\ndelta\r\n\xff\xfe\x00binary\nepsilon\nzeta\x01tail\n";
const ROOT_B9: &str = "a8a3e76ecf28b850e84cb5465729921212ffd07de3c0e6e170cd233bf723adc3";
const PATH_B9_M0: &[&str] = &[
    "e23537b050e84af2cbaab46f2f83d8d3b5febc8e5ac6200d306284f687d46924",
    "ac96b46d1760957393e22a8a365d54e58645a244550bc3c566892cdbdc5d8fc1",
    "416649c1a4f116151112df7d7d3faa85d5d8c60699e153e7a3c57a1abab7a242",
    "5cc496b84d9250622d5de1219d1f156e7973503fbd80f7f3364800bbfa2947d2",
];
const PATH_B9_M8: &[&str] =
    &["80f3f98ae8d7d9d1d2139a6a2dc94628e02fba22e125f922ea8a4c10799cb912"];

const ROOT_ONE_EMPTY: &str =
    "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d";

fn run_inspect(path: &Path) -> std::process::Output {
    Command::new(common::bin())
        .arg("inspect")
        .arg(path)
        .output()
        .expect("failed to execute roottrace binary")
}

fn run_args(args: &[&str]) -> std::process::Output {
    Command::new(common::bin())
        .args(args)
        .output()
        .expect("failed to execute roottrace binary")
}

/// Produce a real `prove` proof for a payload/index into a temp file.
fn prove_to_file(payload: &[u8], index: &str) -> TempFile {
    let batch = TempFile::create(payload);
    let out = Command::new(common::bin())
        .arg("prove")
        .arg(&batch.path)
        .arg(index)
        .output()
        .expect("failed to execute roottrace binary");
    assert_eq!(out.status.code(), Some(0), "prove setup failed: {:?}", out.stderr);
    TempFile::create(&out.stdout)
}

fn proof_json(size: u64, index: u64, root: &str, path: &[&str]) -> Vec<u8> {
    let mut s = format!(
        "{{\"tree_size\":{size},\"leaf_index\":{index},\"root\":\"{root}\",\"audit_path\":["
    );
    for (i, h) in path.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push('"');
        s.push_str(h);
        s.push('"');
    }
    s.push_str("]}");
    s.into_bytes()
}

fn expected_line(size: u64, index: u64, root: &str) -> Vec<u8> {
    format!("{{\"tree_size\":{size},\"leaf_index\":{index},\"root\":\"{root}\"}}\n").into_bytes()
}

/// Full success contract: exit 0, stderr empty, stdout is exactly the expected
/// one-line JSON object.
fn assert_inspect_success(desc: &str, proof_bytes: &[u8], expected_stdout: &[u8]) {
    let tmp = TempFile::create(proof_bytes);
    let out = run_inspect(&tmp.path);
    if out.status.code() != Some(0) {
        panic!(
            "[{desc}] expected exit 0, got {:?}\nproof: {proof_bytes:?}\nstderr: {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    if !out.stderr.is_empty() {
        panic!(
            "[{desc}] successful inspect must leave stderr empty, got: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    if out.stdout != expected_stdout {
        panic!(
            "[{desc}] stdout mismatch\nproof: {proof_bytes:?}\nexpected: {:?}\nactual:   {:?}",
            String::from_utf8_lossy(expected_stdout),
            String::from_utf8_lossy(&out.stdout)
        );
    }
}

/// Full malformed-proof contract: exit 1, empty stdout, a format reason on
/// stderr (never a usage message).
fn assert_invalid(desc: &str, proof_bytes: &[u8]) {
    let tmp = TempFile::create(proof_bytes);
    let out = run_inspect(&tmp.path);
    assert_eq!(out.status.code(), Some(1), "[{desc}] expected exit 1");
    assert!(out.stdout.is_empty(), "[{desc}] stdout must be empty");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("invalid proof"),
        "[{desc}] stderr must report a format problem, got: {err}"
    );
    assert!(!err.contains("Usage"), "[{desc}] format errors are not usage errors");
}

// --- Success path ------------------------------------------------------------

#[test]
fn inspects_real_proofs_at_every_position_and_matches_root_command() {
    let batch = TempFile::create(PAYLOAD_B9);
    // Independently computed batch root via the `root` command.
    let root_out = Command::new(common::bin())
        .arg("root")
        .arg(&batch.path)
        .output()
        .unwrap();
    assert_eq!(root_out.status.code(), Some(0));
    assert_eq!(
        String::from_utf8_lossy(&root_out.stdout).trim(),
        ROOT_B9
    );

    for index in 0..9u64 {
        let proof = prove_to_file(PAYLOAD_B9, &index.to_string());
        let out = run_inspect(&proof.path);
        assert_eq!(out.status.code(), Some(0), "index {index}: {:?}", out.stderr);
        assert_eq!(out.stdout, expected_line(9, index, ROOT_B9), "index {index}");
        assert!(out.stderr.is_empty());
    }
}

#[test]
fn inspect_single_record_tree_shows_empty_path_tree_without_displaying_path() {
    // A file holding one LF is one empty record; its proof has an empty audit
    // path, which inspect must parse but omit from the output.
    let proof = prove_to_file(b"\n", "0");
    let out = run_inspect(&proof.path);
    assert_eq!(out.status.code(), Some(0), "{:?}", out.stderr);
    assert_eq!(out.stdout, expected_line(1, 0, ROOT_ONE_EMPTY));
    let line = String::from_utf8(out.stdout).unwrap();
    // The three keys are quoted twice each and only `root` carries a quoted
    // value: 8 quote characters total, and no fourth field.
    assert_eq!(line.matches('"').count(), 8, "only three key/value pairs: {line}");
    assert!(!line.contains("audit_path"));
    assert!(!line.to_lowercase().contains("verified"));
}

#[test]
fn inspect_accepts_proof_field_reordering_whitespace_and_escapes() {
    let expected = expected_line(9, 0, ROOT_B9);

    // Fields in a different order with arbitrary whitespace between tokens.
    let reordered = format!(
        " {{\n  \"audit_path\" : [\n  \"{p0}\"\n, \"{p1}\" , \"{p2}\" , \"{p3}\" ] ,\n  \"root\" : \"{root}\" ,\n  \"leaf_index\" : 0 ,\n  \"tree_size\" : 9\n}}\t\n",
        p0 = PATH_B9_M0[0],
        p1 = PATH_B9_M0[1],
        p2 = PATH_B9_M0[2],
        p3 = PATH_B9_M0[3],
        root = ROOT_B9,
    );
    assert_inspect_success("reordered+whitespace", reordered.as_bytes(), &expected);

    // Equivalent \uXXXX escapes in a field name and in hash characters decode
    // to the exact same claims.
    let escaped_root: String = ROOT_B9
        .chars()
        .map(|c| {
            if c == 'a' {
                "\\u0061".to_string()
            } else if c == 'e' {
                "\\u0065".to_string()
            } else {
                c.to_string()
            }
        })
        .collect();
    let escaped = format!(
        "{{\"tree_siz\\u0065\":9,\"leaf_index\":0,\"root\":\"{escaped_root}\",\"audit_path\":[\"{}\",\"{}\",\"{}\",\"{}\"]}}",
        PATH_B9_M0[0], PATH_B9_M0[1], PATH_B9_M0[2], PATH_B9_M0[3],
    );
    assert_inspect_success("unicode escapes", escaped.as_bytes(), &expected);

    // The raw prove output itself is accepted byte for byte.
    let proof = prove_to_file(PAYLOAD_B9, "0");
    assert_inspect_success(
        "prove output verbatim",
        &std::fs::read(&proof.path).unwrap(),
        &expected,
    );
}

// --- No membership verification ----------------------------------------------

#[test]
fn inspect_shows_claims_even_when_the_audit_path_cannot_prove_them() {
    // 3-record tree, position 1, correct claims shape but only ONE of the two
    // required sibling hashes: verify would fail this; inspect must display it.
    let short_path =
        proof_json(3, 1, ROOT_B9, &PATH_B9_M0[..1]);
    assert_inspect_success(
        "path too short",
        &short_path,
        &expected_line(3, 1, ROOT_B9),
    );

    // An empty path for a 9-record tree and a position with no real proof.
    let no_path = proof_json(9, 4, ROOT_B9, &[]);
    assert_inspect_success("empty path for big tree", &no_path, &expected_line(9, 4, ROOT_B9));

    // An arbitrary root that nothing hashes to is still merely displayed.
    let arbitrary = "0123456789abcdef".repeat(4);
    let made_up = proof_json(7, 6, &arbitrary, &PATH_B9_M8);
    assert_inspect_success(
        "arbitrary root",
        &made_up,
        &expected_line(7, 6, &arbitrary),
    );

    // Whatever the output is, it must not assert verification success.
    for bytes in [short_path, no_path, made_up] {
        let tmp = TempFile::create(&bytes);
        let out = run_inspect(&tmp.path);
        let line = String::from_utf8_lossy(&out.stdout).to_ascii_lowercase();
        assert!(!line.contains("verified"), "inspect must never say verified: {line}");
    }
}

// --- Full format enforcement (shared with verify) ----------------------------

#[test]
fn inspect_rejects_non_objects_truncation_and_trailing_data() {
    assert_invalid("empty file", b"");
    assert_invalid("null", b"null");
    assert_invalid("array", b"[]");
    assert_invalid("garbage", b"garbage");
    assert_invalid("empty object", b"{}");
    let good = proof_json(9, 8, ROOT_B9, PATH_B9_M8);
    assert_invalid("truncated mid-object", &good[..good.len() - 3]);
    let mut trailing = good.clone();
    trailing.extend_from_slice(b" x");
    assert_invalid("trailing data", &trailing);
    // Leading non-JSON whitespace is fine, but a second JSON value is not.
    let mut two = good.clone();
    two.extend_from_slice(b"{}");
    assert_invalid("second object after the first", &two);
}

#[test]
fn inspect_rejects_any_missing_field_including_audit_path() {
    let h = ROOT_B9;
    assert_invalid(
        "missing audit_path",
        format!(r#"{{"tree_size":1,"leaf_index":0,"root":"{h}"}}"#).as_bytes(),
    );
    assert_invalid(
        "missing root",
        format!(r#"{{"tree_size":1,"leaf_index":0,"audit_path":[]}}"#).as_bytes(),
    );
    assert_invalid(
        "missing leaf_index",
        format!(r#"{{"tree_size":1,"root":"{h}","audit_path":[]}}"#).as_bytes(),
    );
    assert_invalid(
        "missing tree_size",
        format!(r#"{{"leaf_index":0,"root":"{h}","audit_path":[]}}"#).as_bytes(),
    );
    // An unknown field is rejected too: only the three displayed fields plus
    // audit_path exist, and merely finding the displayed three is not enough.
    assert_invalid(
        "unknown field",
        format!(r#"{{"tree_size":1,"leaf_index":0,"root":"{h}","audit_path":[],"extra":1}}"#)
            .as_bytes(),
    );
}

#[test]
fn inspect_rejects_damage_inside_the_non_displayed_audit_path() {
    // All three displayed fields are present and valid in every case; the
    // damage is confined to audit_path.
    assert_invalid(
        "path hash wrong length",
        format!(
            r#"{{"tree_size":2,"leaf_index":0,"root":"{}","audit_path":["{}"]}}"#,
            ROOT_B9,
            &"a".repeat(63)
        )
        .as_bytes(),
    );
    assert_invalid(
        "path hash uppercase",
        format!(
            r#"{{"tree_size":2,"leaf_index":0,"root":"{}","audit_path":["{}"]}}"#,
            ROOT_B9,
            &"A".repeat(64)
        )
        .as_bytes(),
    );
    assert_invalid(
        "path hash not a string",
        format!(r#"{{"tree_size":2,"leaf_index":0,"root":"{ROOT_B9}","audit_path":[1]}}"#).as_bytes(),
    );
    assert_invalid(
        "audit_path not an array",
        format!(r#"{{"tree_size":2,"leaf_index":0,"root":"{ROOT_B9}","audit_path":{{}}}}"#)
            .as_bytes(),
    );
    assert_invalid(
        "array never closed",
        format!(
            r#"{{"tree_size":2,"leaf_index":0,"root":"{ROOT_B9}","audit_path":["{}""#,
            "0".repeat(64)
        )
        .as_bytes(),
    );
    assert_invalid(
        "missing comma between path hashes",
        format!(
            r#"{{"tree_size":3,"leaf_index":0,"root":"{ROOT_B9}","audit_path":["{}" "{}"]}}"#,
            "0".repeat(64),
            "1".repeat(64)
        )
        .as_bytes(),
    );
    // An uppercase hash character reached through a legal escape is still
    // uppercase after interpretation. Built as a plain (non-raw) format string
    // so "\\u0041" produces the six JSON bytes `\u0041`, decoding to 'A'.
    let escaped_upper = format!(
        "{{\"tree_size\":2,\"leaf_index\":0,\"root\":\"{ROOT_B9}\",\"audit_path\":[\"\\u0041{}\"]}}",
        "a".repeat(63)
    );
    assert_invalid("escaped uppercase path hash char", escaped_upper.as_bytes());
}

#[test]
fn inspect_rejects_duplicate_fields_after_interpretation() {
    let h = ROOT_B9;
    assert_invalid(
        "duplicate tree_size",
        format!(r#"{{"tree_size":1,"tree_size":1,"leaf_index":0,"root":"{h}","audit_path":[]}}"#)
            .as_bytes(),
    );
    assert_invalid(
        "duplicate leaf_index",
        format!(r#"{{"tree_size":1,"leaf_index":0,"leaf_index":0,"root":"{h}","audit_path":[]}}"#)
            .as_bytes(),
    );
    assert_invalid(
        "duplicate root",
        format!(r#"{{"tree_size":1,"leaf_index":0,"root":"{h}","root":"{h}","audit_path":[]}}"#)
            .as_bytes(),
    );
    assert_invalid(
        "duplicate audit_path",
        format!(r#"{{"tree_size":1,"leaf_index":0,"root":"{h}","audit_path":[],"audit_path":[]}}"#)
            .as_bytes(),
    );
    // The second spelling of the key escapes the final 'e' of "tree_size" as
    // a \uXXXX escape: after interpretation the keys are identical, so this is
    // still a duplicate (not two different fields).
    let dup_via_escape =
        b"{\"tree_size\":1,\"tree_siz\\u0065\":1,\"leaf_index\":0,\"root\":\"".to_vec();
    let mut dup_via_escape = dup_via_escape;
    dup_via_escape.extend_from_slice(h.as_bytes());
    dup_via_escape.extend_from_slice(br#"","audit_path":[]}"#);
    assert_invalid("duplicate tree_size via escape", &dup_via_escape);
}

#[test]
fn inspect_rejects_wrong_types_bad_numbers_zero_size_and_bad_index() {
    let h = ROOT_B9;
    assert_invalid(
        "tree_size as string",
        format!(r#"{{"tree_size":"1","leaf_index":0,"root":"{h}","audit_path":[]}}"#).as_bytes(),
    );
    assert_invalid(
        "leaf_index negative",
        format!(r#"{{"tree_size":1,"leaf_index":-1,"root":"{h}","audit_path":[]}}"#).as_bytes(),
    );
    assert_invalid(
        "root non-hex string",
        format!(r#"{{"tree_size":1,"leaf_index":0,"root":"{}","audit_path":[]}}"#, "z".repeat(64))
            .as_bytes(),
    );
    for bad_size in ["0", "01", "1.0", "1e3", "18446744073709551616"] {
        assert_invalid(
            &format!("tree_size token {bad_size}"),
            format!(r#"{{"tree_size":{bad_size},"leaf_index":0,"root":"{h}","audit_path":[]}}"#)
                .as_bytes(),
        );
    }
    // tree_size 0 and an index at/beyond the claimed size are semantic format
    // errors shared with verify.
    assert_invalid(
        "zero tree size",
        format!(r#"{{"tree_size":0,"leaf_index":0,"root":"{h}","audit_path":[]}}"#).as_bytes(),
    );
    assert_invalid(
        "index equals size",
        format!(r#"{{"tree_size":1,"leaf_index":1,"root":"{h}","audit_path":[]}}"#).as_bytes(),
    );
    assert_invalid(
        "index beyond size",
        format!(r#"{{"tree_size":2,"leaf_index":9,"root":"{h}","audit_path":[]}}"#).as_bytes(),
    );
}

// --- 64-bit integer meaning --------------------------------------------------

#[test]
fn inspect_keeps_full_unsigned_64_bit_claims() {
    // No tree of this size can exist on disk; inspect only reads the claims,
    // so an empty audit path is format-valid and the values survive intact.
    let root = "f".repeat(64);
    let max = u64::MAX;
    let proof = proof_json(max, max - 1, &root, &[]);
    assert_inspect_success("u64::MAX size", &proof, &expected_line(max, max - 1, &root));
    // index u64::MAX against size u64::MAX is out of range → malformed.
    let oob = proof_json(max, max, &root, &[]);
    assert_invalid("u64::MAX index at u64::MAX size", &oob);
}

// --- Read failures and usage --------------------------------------------------

#[test]
fn read_failures_exit_1_with_empty_stdout_and_a_reason() {
    let missing = std::env::temp_dir().join("roottrace-inspect-no-such-file-xyz");
    let _ = std::fs::remove_file(&missing);
    let out = run_inspect(&missing);
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("cannot read"),
        "got: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let dir = TempDir::create();
    let out = run_inspect(&dir.path);
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty());
    assert!(String::from_utf8_lossy(&out.stderr).contains("cannot read"));
}

#[test]
fn missing_and_extra_arguments_are_usage_errors() {
    for args in [
        vec!["inspect"],
        vec!["inspect", "a", "b"],
        vec!["inspect", "a", "b", "c"],
        vec![],
        vec!["bogus", "x"],
    ] {
        let out = run_args(&args);
        assert_eq!(out.status.code(), Some(2), "args {args:?}");
        assert!(out.stdout.is_empty(), "args {args:?}");
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("Usage"),
            "args {args:?}"
        );
    }

    // A malformed proof file must NOT be downgraded to a usage error even when
    // extra arguments accompany it: argument arity is checked first.
    let tmp = TempFile::create(b"not json at all");
    let out = Command::new(common::bin())
        .args(["inspect"])
        .arg(&tmp.path)
        .arg("extra")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty());
    assert!(String::from_utf8_lossy(&out.stderr).contains("Usage"));
}

#[test]
fn inspect_does_not_change_verify_or_version_behaviour() {
    // inspect must not relax verify: the same malformed proofs that inspect
    // rejects are still format errors for verify (exit 1, never "verified").
    let record = TempFile::create(b"alpha");
    let bad_proof = TempFile::create(b"{}");
    let out = Command::new(common::bin())
        .arg("verify")
        .arg(&record.path)
        .arg(&bad_proof.path)
        .arg("9")
        .arg(ROOT_B9)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty());
    assert!(String::from_utf8_lossy(&out.stderr).contains("invalid proof"));

    let version = run_args(&["--version"]);
    assert_eq!(version.status.code(), Some(0));
    assert_eq!(version.stdout, b"roottrace 0.1.0\n");
}
