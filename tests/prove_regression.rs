//! End-to-end regression tests for `roottrace prove <file> <record-index>`.
//!
//! The fixed audit-path vectors below were produced independently of
//! roottrace by `tests/reference/rfc6962_vectors.py`-style Python code
//! (standard-library `hashlib.sha256`, direct transcription of the RFC 6962
//! section 2.1.1 recursive PATH definition) and re-checked with the
//! section 2.1.2 iterative verifier (`fn`/`sn`). The constants are copied,
//! never derived from roottrace output.
//!
//! The batch B9 and its root are the same fixed sequence used in
//! root_regression.rs; it intentionally contains duplicate content
//! (r0 == r4 == b"alpha"), an empty record, a trailing CR and non-UTF-8 /
//! NUL bytes.

mod common;

use std::process::Command;

use common::{join_lf, TempDir, TempFile};

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

const ROOT_B9: &str = "a8a3e76ecf28b850e84cb5465729921212ffd07de3c0e6e170cd233bf723adc3";
// Independently fixed one-empty-record root (matches root_regression).
const ROOT_ONE_EMPTY_RECORD: &str =
    "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d";
// Root of the first eight B9 records (B8), also the sole audit-path hash
// for the ninth leaf because it is the complete right-hand subtree.
const ROOT_B8: &str = "80f3f98ae8d7d9d1d2139a6a2dc94628e02fba22e125f922ea8a4c10799cb912";

/// Independently fixed audit paths (leaf -> root) for selected B9 positions.
const PATH_B9_M0: &[&str] = &[
    "e23537b050e84af2cbaab46f2f83d8d3b5febc8e5ac6200d306284f687d46924",
    "ac96b46d1760957393e22a8a365d54e58645a244550bc3c566892cdbdc5d8fc1",
    "416649c1a4f116151112df7d7d3faa85d5d8c60699e153e7a3c57a1abab7a242",
    "5cc496b84d9250622d5de1219d1f156e7973503fbd80f7f3364800bbfa2947d2",
];
const PATH_B9_M1: &[&str] = &[
    "2a158d8afd48e3f88cb4195dfdb2a9e4817d95fa57fd34440d93f9aae5c4f82b",
    "ac96b46d1760957393e22a8a365d54e58645a244550bc3c566892cdbdc5d8fc1",
    "416649c1a4f116151112df7d7d3faa85d5d8c60699e153e7a3c57a1abab7a242",
    "5cc496b84d9250622d5de1219d1f156e7973503fbd80f7f3364800bbfa2947d2",
];
// m=4 holds the same record content as m=0 (b"alpha"); its path must
// nonetheless be for position 4, not a re-used "first occurrence" proof.
const PATH_B9_M4: &[&str] = &[
    "4957faa551907820ed93a476704ffd826ea5502881876c87f3acefc0a8d29bce",
    "b739bc437ae5d551d144d1478ee16d1119ba15b2198a3a8b7c47976c36cb6639",
    "6f2bd73a7406c5089558c115aaae63a717e4c6947c44898e7d9600023ff15d10",
    "5cc496b84d9250622d5de1219d1f156e7973503fbd80f7f3364800bbfa2947d2",
];
const PATH_B9_M7: &[&str] = &[
    "354d947543a0306df550c8bac298cead6634c395cf3789cd6485c73fa4d478f0",
    "480e47ed3044deb1275d9f67a813860f7efc02c782ac94752c708cb24d5b19c0",
    "6f2bd73a7406c5089558c115aaae63a717e4c6947c44898e7d9600023ff15d10",
    "5cc496b84d9250622d5de1219d1f156e7973503fbd80f7f3364800bbfa2947d2",
];

fn expected_line(size: u64, index: u64, root: &str, path: &[&str]) -> Vec<u8> {
    let joined = path
        .iter()
        .map(|h| format!("\"{h}\""))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "{{\"tree_size\":{size},\"leaf_index\":{index},\"root\":\"{root}\",\"audit_path\":[{joined}]}}\n"
    )
    .into_bytes()
}

/// Run `roottrace prove <file> <index>` and require the documented strict
/// success path: exit 0, empty stderr, stdout exactly the fixed JSON line.
fn assert_proof(desc: &str, file_bytes: &[u8], index: &str, expected_stdout: &[u8]) {
    let tmp = TempFile::create(file_bytes);
    let output = Command::new(common::bin())
        .arg("prove")
        .arg(&tmp.path)
        .arg(index)
        .output()
        .expect("failed to execute roottrace binary");
    if output.status.code() != Some(0) || !output.stderr.is_empty() {
        panic!(
            "[{desc}] prove {index:?} did not take the success path\n\
             exit status: {:?}\n\
             stderr: {}\n\
             stdout: {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr),
            String::from_utf8_lossy(&output.stdout),
        );
    }
    if output.stdout != expected_stdout {
        panic!(
            "[{desc}] prove {index:?} stdout mismatch\n\
             expected: {}\n\
             actual:   {}",
            String::from_utf8_lossy(expected_stdout),
            String::from_utf8_lossy(&output.stdout),
        );
    }
}

#[test]
fn fixed_audit_paths_for_selected_b9_positions() {
    let file = join_lf(B9, true);
    assert_proof("B9 m0", &file, "0", &expected_line(9, 0, ROOT_B9, PATH_B9_M0));
    assert_proof("B9 m1", &file, "1", &expected_line(9, 1, ROOT_B9, PATH_B9_M1));
    assert_proof("B9 m4", &file, "4", &expected_line(9, 4, ROOT_B9, PATH_B9_M4));
    assert_proof("B9 m7", &file, "7", &expected_line(9, 7, ROOT_B9, PATH_B9_M7));
    // The ninth leaf is the complete right-hand subtree: a one-hash path,
    // no copied/padded trailing leaf.
    assert_proof(
        "B9 m8 (short right-subtree path)",
        &file,
        "8",
        &expected_line(9, 8, ROOT_B9, &[ROOT_B8]),
    );
}

#[test]
fn duplicate_content_is_proved_at_the_named_position() {
    // r0 and r4 are byte-identical b"alpha"; their proofs differ and each
    // matches its own position's fixed vector.
    assert_ne!(PATH_B9_M0, PATH_B9_M4);
    let file = join_lf(B9, false); // also exercise the no-trailing-LF form
    assert_proof("dup at 0", &file, "0", &expected_line(9, 0, ROOT_B9, PATH_B9_M0));
    assert_proof("dup at 4", &file, "4", &expected_line(9, 4, ROOT_B9, PATH_B9_M4));
}

#[test]
fn proof_root_equals_the_root_command_output_for_the_same_file() {
    let file = join_lf(B9, true);
    let tmp = TempFile::create(&file);
    let root_out = Command::new(common::bin())
        .arg("root")
        .arg(&tmp.path)
        .output()
        .unwrap();
    let root_stdout = String::from_utf8_lossy(&root_out.stdout);
    let root = root_stdout.trim();
    assert_eq!(root, ROOT_B9);

    for i in 0..B9.len() {
        let out = Command::new(common::bin())
            .arg("prove")
            .arg(&tmp.path)
            .arg(i.to_string())
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(0), "position {i}");
        assert!(out.stderr.is_empty());
        let stdout = String::from_utf8(out.stdout).unwrap();
        let line = stdout.strip_suffix('\n').expect("trailing LF");
        assert_eq!(line.matches('\n').count(), 0, "exactly one output line");
        assert!(line.contains(&format!("\"tree_size\":{}", B9.len())));
        assert!(line.contains(&format!("\"leaf_index\":{i}")));
        assert!(line.contains(&format!("\"root\":\"{root}\"")));
    }
}

#[test]
fn single_record_has_an_empty_audit_path() {
    // A file containing exactly one LF holds one empty record.
    assert_proof(
        "single LF, index 0",
        b"\n",
        "0",
        &expected_line(1, 0, ROOT_ONE_EMPTY_RECORD, &[]),
    );
    // Same for a non-empty single record; the path is empty regardless.
    let tmp = TempFile::create(b"only-record");
    let out = Command::new(common::bin())
        .arg("prove")
        .arg(&tmp.path)
        .arg("0")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert!(out.stderr.is_empty());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("\"tree_size\":1"));
    assert!(stdout.contains("\"leaf_index\":0"));
    assert!(stdout.ends_with("\"audit_path\":[]}\n"));
    // The proof carries no raw record bytes.
    assert!(!stdout.contains("only-record"));
}

#[test]
fn index_out_of_range_exits_1_names_the_missing_position() {
    let tmp = TempFile::create(&join_lf(B9, true));
    for bad in ["9", "10", "18446744073709551615"] {
        let out = Command::new(common::bin())
            .arg("prove")
            .arg(&tmp.path)
            .arg(bad)
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(1), "index {bad} should exit 1");
        assert!(out.stdout.is_empty(), "index {bad} must write no proof");
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(err.contains("does not exist"), "index {bad} stderr: {err}");
    }

    // A truly empty file has no selectable record, even at index 0.
    let empty = TempFile::create(b"");
    let out = Command::new(common::bin())
        .arg("prove")
        .arg(&empty.path)
        .arg("0")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty());
    assert!(String::from_utf8_lossy(&out.stderr).contains("does not exist"));
}

#[test]
fn malformed_index_and_arg_count_errors_exit_2_with_usage() {
    let tmp = TempFile::create(&join_lf(B9, true));
    for bad in [
        "-1", "abc", "+1", "1.0", " 1", "1 ", "0x1", "18446744073709551616",
    ] {
        let out = Command::new(common::bin())
            .arg("prove")
            .arg(&tmp.path)
            .arg(bad)
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(2), "index {bad:?} should exit 2");
        assert!(out.stdout.is_empty(), "index {bad:?} must not write stdout");
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("Usage"),
            "index {bad:?} should print usage"
        );
    }

    // Missing or extra arguments, unknown command.
    for args in [
        vec!["prove"],
        vec!["prove", "path-only"],
        vec!["prove", &tmp.path.display().to_string(), "0", "extra"],
        vec!["nonsense", &tmp.path.display().to_string(), "0"],
    ] {
        let out = Command::new(common::bin()).args(&args).output().unwrap();
        assert_eq!(out.status.code(), Some(2), "args {args:?} should exit 2");
        assert!(out.stdout.is_empty());
        assert!(String::from_utf8_lossy(&out.stderr).contains("Usage"));
    }
}

#[test]
fn read_failures_exit_1_and_write_no_partial_proof() {
    let missing = TempFile::create(b"x");
    let missing_path = missing.path.clone();
    drop(missing);
    let out = Command::new(common::bin())
        .arg("prove")
        .arg(&missing_path)
        .arg("0")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty());
    assert!(!out.stderr.is_empty());

    let dir = TempDir::create();
    let out = Command::new(common::bin())
        .arg("prove")
        .arg(&dir.path)
        .arg("0")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty());
    assert!(!out.stderr.is_empty());
}
