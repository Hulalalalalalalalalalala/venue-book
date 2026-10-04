//! End-to-end regression tests for `roottrace prove <file> <record-index>`.
//!
//! The expected JSON lines are FIXED vectors produced independently of
//! roottrace by `tests/reference/rfc6962_vectors.py`, which computes RFC 6962
//! section 2.1.1 audit paths two different ways (the recursive PATH
//! definition and a top-down descent whose sibling subtree hashes come from
//! the structurally separate stack fold), then re-verifies every path with a
//! recursive inclusion verifier over `hashlib.sha256`. The constants here are
//! copied from that generator and never derived from roottrace output.
//!
//! Besides pinning the exact bytes of the success output, these tests check:
//!   * `root` equals what `roottrace root` prints for the same file
//!   * identical content at two positions yields two different proofs
//!   * trailing-LF / no-trailing-LF files give byte-identical proofs
//!   * an empty file has no selectable record; index >= size exits 1
//!   * bad or missing/extra arguments exit 2 with a usage message
//!   * unreadable files exit 1 and write nothing to stdout

mod common;

use std::process::Command;

use common::{join_lf, TempDir, TempFile};

// --- Fixed file payloads (copied from the reference generator) --------------

const PAYLOAD_B8: &[u8] =
    b"alpha\nbeta\n\ngamma\nalpha\ndelta\r\n\xff\xfe\x00binary\nepsilon\n";
const PAYLOAD_B9: &[u8] =
    b"alpha\nbeta\n\ngamma\nalpha\ndelta\r\n\xff\xfe\x00binary\nepsilon\nzeta\x01tail\n";
const PAYLOAD_ONE_LF: &[u8] = b"\n";
const PAYLOAD_EMPTY: &[u8] = b"";

const PAYLOAD_MIXED: &[u8] = b"alpha\n\nL54:\x00\xff\xfe\rabcdefghijklmnopqrstuvwxyz0123456789abcdefghi\x00\nbeta\r\nL63:\x00\xff\xfe\rabcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr\x00\n\xff\x00z\nL135:\x00\xff\xfe\rabcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopq\xff\nmiddle\nL65:\x00\xff\xfe\rabcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrst\xfe\nend-record\x01\n";

const B9_RECORDS: &[&[u8]] = &[
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

// --- Fixed inclusion-proof vectors ------------------------------------------

const ROOT_B8: &str = "80f3f98ae8d7d9d1d2139a6a2dc94628e02fba22e125f922ea8a4c10799cb912";
const ROOT_B9: &str = "a8a3e76ecf28b850e84cb5465729921212ffd07de3c0e6e170cd233bf723adc3";
const ROOT_ONE_EMPTY_RECORD: &str =
    "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d";
const ROOT_MIXED: &str = "3a460e4bda163253da14917c2f9c63208d1b24e3d285c763d2f6c6dedec6694b";

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
// m=8 of the uneven 9-record tree pairs directly with MTH of the complete
// size-8 left subtree: exactly one sibling, which must equal ROOT_B8. No
// duplicated or empty trailing leaf may be introduced.
const PATH_B9_M8: &[&str] =
    &["80f3f98ae8d7d9d1d2139a6a2dc94628e02fba22e125f922ea8a4c10799cb912"];
const PATH_B8_M3: &[&str] = &[
    "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
    "983cb57c04cddd52634edab38a7bef85708a974f114bbd9aa9ec5d4ce6656b4b",
    "416649c1a4f116151112df7d7d3faa85d5d8c60699e153e7a3c57a1abab7a242",
];
const PATH_MIXED_M8: &[&str] = &[
    "8a3600db5c87060b03bdb7b4c7b70056808cb54e5ab927b95731d6936bff303d",
    "4290a44282949b6321f1219162bb52eceb3358250c553ee76e820bea56378f49",
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

/// Run `roottrace prove <file> <index>` and return the completed output.
fn run_prove(path: &std::path::Path, index: &str) -> std::process::Output {
    Command::new(common::bin())
        .arg("prove")
        .arg(path)
        .arg(index)
        .output()
        .expect("failed to execute roottrace binary")
}

/// Assert the full documented success contract: exit 0, empty stderr, exactly
/// one LF-terminated JSON line equal to `expected`.
fn assert_proof_success(
    desc: &str,
    file_bytes: &[u8],
    index: &str,
    expected: &str,
) -> TempFile {
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
    if !stdout.ends_with('\n') || stdout.len() != expected.len() + 1 || stdout.as_bytes().iter().filter(|b| **b == b'\n').count() != 1 {
        panic!(
            "[{desc}] stdout must be exactly one JSON line + one trailing LF, got {:?}",
            stdout.as_bytes()
        );
    }
    assert_eq!(&stdout[..stdout.len() - 1], expected, "[{desc}] proof JSON mismatch");
    tmp
}

/// Extract the 64-hex `root` field value from a prove JSON line.
fn root_field(json_line: &str) -> &str {
    let key = "\"root\":\"";
    let start = json_line.find(key).expect("root field present") + key.len();
    &json_line[start..start + 64]
}

#[test]
fn fixed_proof_vectors_match_reference_constants() {
    assert_proof_success(
        "B9 m=0 (first record, uneven 9-record tree)",
        PAYLOAD_B9,
        "0",
        &expected_json(9, 0, ROOT_B9, PATH_B9_M0),
    );
    assert_proof_success(
        "B9 m=4 (byte-equal duplicate of m=0, exact position honored)",
        PAYLOAD_B9,
        "4",
        &expected_json(9, 4, ROOT_B9, PATH_B9_M4),
    );
    assert_proof_success(
        "B9 m=8 (last record; one sibling = ROOT_B8, no padding)",
        PAYLOAD_B9,
        "8",
        &expected_json(9, 8, ROOT_B9, PATH_B9_M8),
    );
    assert_proof_success(
        "B8 m=3 (balanced power-of-two tree, full-depth path)",
        PAYLOAD_B8,
        "3",
        &expected_json(8, 3, ROOT_B8, PATH_B8_M3),
    );
    assert_proof_success(
        "MIXED m=8 (long record in the k=8 right subtree, binary content)",
        PAYLOAD_MIXED,
        "8",
        &expected_json(10, 8, ROOT_MIXED, PATH_MIXED_M8),
    );
    assert_proof_success(
        "single LF m=0 (one empty record: empty path, fields still present)",
        PAYLOAD_ONE_LF,
        "0",
        &expected_json(1, 0, ROOT_ONE_EMPTY_RECORD, &[]),
    );
}

#[test]
fn proof_root_equals_root_command_for_the_same_file() {
    for (desc, bytes, index) in [
        ("B9/0", PAYLOAD_B9, "0"),
        ("B9/4", PAYLOAD_B9, "4"),
        ("B9/8", PAYLOAD_B9, "8"),
        ("MIXED/8", PAYLOAD_MIXED, "8"),
        ("ONE_LF/0", PAYLOAD_ONE_LF, "0"),
    ] {
        let tmp = TempFile::create(bytes);
        let root_out = Command::new(common::bin())
            .arg("root")
            .arg(&tmp.path)
            .output()
            .unwrap();
        assert_eq!(root_out.status.code(), Some(0), "[{desc}] root failed");
        let root_line = String::from_utf8(root_out.stdout).unwrap();
        let root_cmd = root_line.trim_end_matches('\n');

        let proof_out = run_prove(&tmp.path, index);
        assert_eq!(proof_out.status.code(), Some(0), "[{desc}] prove failed");
        let proof_line = String::from_utf8(proof_out.stdout).unwrap();
        assert_eq!(
            root_field(proof_line.trim_end_matches('\n')),
            root_cmd,
            "[{desc}] proof root must equal root-command output"
        );
    }
}

#[test]
fn duplicate_content_gets_two_distinct_position_proofs() {
    // B9 holds b"alpha" at both position 0 and position 4.
    let tmp = TempFile::create(PAYLOAD_B9);
    let p0 = String::from_utf8(run_prove(&tmp.path, "0").stdout).unwrap();
    let p4 = String::from_utf8(run_prove(&tmp.path, "4").stdout).unwrap();
    assert_ne!(p0, p4, "proofs for positions 0 and 4 must differ despite equal bytes");
    assert!(p0.contains("\"leaf_index\":0"));
    assert!(p4.contains("\"leaf_index\":4"));
    // Both roots agree and pin the whole 9-record batch.
    assert_eq!(root_field(p0.trim_end()), ROOT_B9);
    assert_eq!(root_field(p4.trim_end()), ROOT_B9);
    // The B8 batch also contains "alpha" at position 0 but is a different
    // batch, so its m=0 proof is not interchangeable with B9 m=0.
    let tmp8 = TempFile::create(PAYLOAD_B8);
    let p0_b8 = String::from_utf8(run_prove(&tmp8.path, "0").stdout).unwrap();
    assert_ne!(p0, p0_b8);
}

#[test]
fn trailing_lf_equivalence_holds_for_proofs() {
    // The trailing/no-trailing-LF forms name the same record sequence, so
    // proofs must be byte-identical (not just equally rooted).
    for (records, index) in [(B9_RECORDS, "4"), (B9_RECORDS, "8")] {
        let with_lf = TempFile::create(&join_lf(records, true));
        let no_lf = TempFile::create(&join_lf(records, false));
        let a = run_prove(&with_lf.path, index);
        let b = run_prove(&no_lf.path, index);
        assert_eq!(a.status.code(), Some(0));
        assert_eq!(a.stdout, b.stdout, "index {index} proofs differ on trailing LF");
    }
}

#[test]
fn leading_zero_indexes_are_accepted() {
    // "08" is still ASCII decimal digits and names position 8.
    let tmp = assert_proof_success(
        "B9 index 08 == 8",
        PAYLOAD_B9,
        "08",
        &expected_json(9, 8, ROOT_B9, PATH_B9_M8),
    );
    // leaf_index in the output is the canonical integer 8, not echoed text.
    let out = String::from_utf8(run_prove(&tmp.path, "08").stdout).unwrap();
    assert!(out.contains("\"leaf_index\":8"));
    assert!(!out.contains("\"leaf_index\":08"));
}

#[test]
fn out_of_range_index_exits_1_names_the_missing_position_and_writes_nothing() {
    // Empty file: zero records, nothing is selectable.
    let empty = TempFile::create(PAYLOAD_EMPTY);
    let out = run_prove(&empty.path, "0");
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty(), "no partial proof on stdout");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("does not exist"), "stderr must name the missing position: {err}");
    assert!(err.contains("index 0"), "stderr must name the requested index: {err}");
    assert!(err.contains('0'), "stderr must describe the valid range: {err}");

    // Single LF: exactly one record (index 0); index 1 is out of range.
    let one_lf = TempFile::create(PAYLOAD_ONE_LF);
    let out = run_prove(&one_lf.path, "1");
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("does not exist") && err.contains("index 1"));

    // Index equal to the size, one past it, and far beyond it, for B9.
    let b9 = TempFile::create(PAYLOAD_B9);
    for bad in ["9", "10", "18446744073709551615"] {
        let out = run_prove(&b9.path, bad);
        assert_eq!(out.status.code(), Some(1), "index {bad} must exit 1");
        assert!(out.stdout.is_empty(), "index {bad} must not touch stdout");
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(err.contains("does not exist"), "index {bad}: {err}");
    }
}

#[test]
fn malformed_index_and_bad_arguments_exit_2_with_usage() {
    let tmp = TempFile::create(PAYLOAD_B9);
    for bad in [
        "-1",            // negative
        "abc",           // non-numeric
        "1.0",           // not an integer token
        "+1",            // explicit sign rejected
        " 1",            // whitespace
        "1 ",            // trailing whitespace
        "0x9",           // hex prefix
        "9a",            // digits then junk
        "18446744073709551616", // one above u64::MAX
        "",              // empty index
    ] {
        let out = run_prove(&tmp.path, bad);
        assert_eq!(out.status.code(), Some(2), "index {bad:?} must exit 2");
        assert!(out.stdout.is_empty(), "index {bad:?} must not write stdout");
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(err.contains("Usage"), "index {bad:?} must print usage, got: {err}");
    }

    // Missing and extra arguments.
    for args in [
        vec!["prove"],
        vec!["prove", "only-one-arg"],
        vec!["prove", tmp.path.to_str().unwrap(), "0", "extra"],
        vec!["bogus"],
        vec!["root"],
        vec!["--version", "extra"],
    ] {
        let out = Command::new(common::bin()).args(&args).output().unwrap();
        assert_eq!(out.status.code(), Some(2), "args {args:?} must exit 2");
        assert!(out.stdout.is_empty(), "args {args:?} must not write stdout");
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("Usage"),
            "args {args:?} must print usage"
        );
    }
}

#[test]
fn prove_read_failures_exit_1_and_write_nothing_to_stdout() {
    let missing = TempFile::create(b"x");
    let missing_path = missing.path.clone();
    drop(missing);
    let out = Command::new(common::bin())
        .arg("prove")
        .arg(&missing_path)
        .arg("0")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1), "missing file must exit 1");
    assert!(out.stdout.is_empty(), "no partial proof when the file is unreadable");
    assert!(!out.stderr.is_empty());

    let dir = TempDir::create();
    let out = Command::new(common::bin())
        .arg("prove")
        .arg(&dir.path)
        .arg("0")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1), "directory path must exit 1");
    assert!(out.stdout.is_empty());
    assert!(!out.stderr.is_empty());
}

#[test]
fn version_and_root_behaviour_are_unchanged() {
    let out = Command::new(common::bin()).arg("--version").output().unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert!(out.stderr.is_empty());
    assert_eq!(out.stdout, b"roottrace 0.1.0\n");

    let tmp = TempFile::create(PAYLOAD_B9);
    let out = Command::new(common::bin())
        .arg("root")
        .arg(&tmp.path)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(out.stdout.len(), 65);
    assert_eq!(&out.stdout[..64], ROOT_B9.as_bytes());
}
