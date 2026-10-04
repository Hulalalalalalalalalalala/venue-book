//! End-to-end regression tests for `roottrace root`, focused on the power-of
//! two boundary in the RFC 6962 SHA-256 Merkle Tree Hash (7, 8 and 9
//! records).
//!
//! Expected roots are FIXED constants produced independently of roottrace by
//! `tests/reference/rfc6962_vectors.py`, which computes them with Python's
//! `hashlib.sha256` in two structurally different ways (the RFC's recursive
//! definition and an order-sensitive stack fold); the two implementations
//! agree for every vector, and the one-leaf/empty cases were additionally
//! cross-checked against the system `sha256sum`. The constants below are
//! copied from that generator and never derived from roottrace output.
//!
//! Each batch is spelled out as its exact record sequence so an expected root
//! can be traced back to the records it belongs to. Failures distinguish a
//! command execution failure from a root mismatch and report both the record
//! sequence and the expected root.

mod common;

use std::process::Command;

use common::{assert_root, join_lf, TempDir, TempFile};

// ---------------------------------------------------------------------------
// Fixed record sequences.
//
// The 7/8/9 batches share their first seven records. Those seven include:
//   * duplicated content at two different positions (r0 == r4 == b"alpha")
//   * an empty record (r2)
//   * a trailing CR kept as content (r5)
//   * non-UTF-8 / NUL bytes (r6)
// The eighth and ninth records are explicitly defined and distinct.
// ---------------------------------------------------------------------------

const B7: &[&[u8]] = &[
    b"alpha",
    b"beta",
    b"",
    b"gamma",
    b"alpha",
    b"delta\r",
    b"\xff\xfe\x00binary",
];

const B8: &[&[u8]] = &[
    b"alpha",
    b"beta",
    b"",
    b"gamma",
    b"alpha",
    b"delta\r",
    b"\xff\xfe\x00binary",
    b"epsilon",
];

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

// Independently fixed RFC 6962 roots (tests/reference/rfc6962_vectors.py).
const ROOT_B7: &str = "90caa8bddc2a50cf863a969533ad1700a80aeed313dcd1c7a4b46b0c93991b6e";
const ROOT_B8: &str = "80f3f98ae8d7d9d1d2139a6a2dc94628e02fba22e125f922ea8a4c10799cb912";
const ROOT_B9: &str = "a8a3e76ecf28b850e84cb5465729921212ffd07de3c0e6e170cd233bf723adc3";

// B9 with the duplicate-content position r4 changed to other bytes.
const V_DUP: &[&[u8]] = &[
    b"alpha",
    b"beta",
    b"",
    b"gamma",
    b"alpha-changed",
    b"delta\r",
    b"\xff\xfe\x00binary",
    b"epsilon",
    b"zeta\x01tail",
];
const ROOT_V_DUP: &str = "015cce68e9e800f3ff480da17c8f43f30eed95e0705b5500043c3bf74662dde0";

// B9 with two records of different content (r1 and r5) swapped. The byte
// multiset of records is unchanged, only their positions differ.
const V_SWAP: &[&[u8]] = &[
    b"alpha",
    b"delta\r",
    b"",
    b"gamma",
    b"alpha",
    b"beta",
    b"\xff\xfe\x00binary",
    b"epsilon",
    b"zeta\x01tail",
];
const ROOT_V_SWAP: &str = "3a6482dbcf43884e11018c885ff68e63717a13154217c591c8a01f6dafdb9dd9";

// B9 with the empty record r2 omitted: 8 records, but a DIFFERENT sequence
// from B8. Dropping an empty record must not be silently ignored.
const V_DROP_EMPTY: &[&[u8]] = &[
    b"alpha",
    b"beta",
    b"gamma",
    b"alpha",
    b"delta\r",
    b"\xff\xfe\x00binary",
    b"epsilon",
    b"zeta\x01tail",
];
const ROOT_V_DROP_EMPTY: &str = "918ae84b0d065be5148d048875c9f8cafb5e0ee14417cefbbbb4575631a5257a";

// B9 with one extra duplicate of r0 appended: the same record content
// included twice occupies two positions (10 records total).
const V_DUP_INSERT: &[&[u8]] = &[
    b"alpha",
    b"beta",
    b"",
    b"gamma",
    b"alpha",
    b"delta\r",
    b"\xff\xfe\x00binary",
    b"epsilon",
    b"zeta\x01tail",
    b"alpha",
];
const ROOT_V_DUP_INSERT: &str = "ae0586f6c285c304a53273198d19f5f137d1d9f546e9a74a6fd87547c09bd4e8";

// Empty file: zero records -> SHA-256(""). Single LF: one empty record ->
// SHA-256(0x00). Independently fixed (and cross-checked with sha256sum).
const ROOT_EMPTY_FILE: &str =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const ROOT_ONE_EMPTY_RECORD: &str =
    "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d";

#[test]
fn roots_for_7_8_and_9_records_match_fixed_vectors() {
    assert_root(
        "B7: seven records (largest subtree split k=4, uneven right side)",
        B7,
        &join_lf(B7, true),
        ROOT_B7,
    );
    assert_root(
        "B8: eight records exactly fills a depth-3 tree (power-of-two boundary)",
        B8,
        &join_lf(B8, true),
        ROOT_B8,
    );
    assert_root(
        "B9: nine records crosses the 8-record power-of-two boundary (k=8)",
        B9,
        &join_lf(B9, true),
        ROOT_B9,
    );
}

#[test]
fn changing_one_duplicate_position_gives_its_own_fixed_root() {
    assert_root(
        "V_DUP: r4 (byte-equal to r0) changed, exact new root",
        V_DUP,
        &join_lf(V_DUP, true),
        ROOT_V_DUP,
    );
    assert_ne!(ROOT_V_DUP, ROOT_B9, "changed record must change the root");
}

#[test]
fn swapping_two_different_records_gives_its_own_fixed_root() {
    assert_root(
        "V_SWAP: r1 and r5 swapped; same record contents, different positions",
        V_SWAP,
        &join_lf(V_SWAP, true),
        ROOT_V_SWAP,
    );
    assert_ne!(ROOT_V_SWAP, ROOT_B9, "record order participates in the hash");
    // Equal contents at different positions are not interchangeable: while the
    // swap moved r1/r5, untouched duplicate positions r0 and r4 still prove
    // per-position participation via V_DUP's fixed root above.
}

#[test]
fn omitting_the_empty_record_gives_its_own_fixed_root() {
    assert_eq!(V_DROP_EMPTY.len(), 8);
    assert_ne!(V_DROP_EMPTY, B8, "8 records here is not the B8 sequence");
    assert_root(
        "V_DROP_EMPTY: empty r2 removed; empty records occupy a real position",
        V_DROP_EMPTY,
        &join_lf(V_DROP_EMPTY, true),
        ROOT_V_DROP_EMPTY,
    );
    assert_ne!(ROOT_V_DROP_EMPTY, ROOT_B9);
    assert_ne!(ROOT_V_DROP_EMPTY, ROOT_B8, "must not collide with B8's 8-record root");
}

#[test]
fn including_a_duplicate_record_twice_gives_its_own_fixed_root() {
    assert_eq!(V_DUP_INSERT.len(), 10);
    assert_root(
        "V_DUP_INSERT: duplicate of r0 appended; duplicates are not merged",
        V_DUP_INSERT,
        &join_lf(V_DUP_INSERT, true),
        ROOT_V_DUP_INSERT,
    );
    assert_ne!(ROOT_V_DUP_INSERT, ROOT_B9);
}

#[test]
fn trailing_lf_only_terminates_the_last_record() {
    // The same fixed sequence with and without a final LF has the same fixed
    // root, on both sides of the power-of-two boundary.
    for (desc, records, expected) in [
        ("B7 trailing/no-trailing LF", B7, ROOT_B7),
        ("B8 trailing/no-trailing LF", B8, ROOT_B8),
        ("B9 trailing/no-trailing LF", B9, ROOT_B9),
    ] {
        assert_root(desc, records, &join_lf(records, true), expected);
        assert_root(desc, records, &join_lf(records, false), expected);
    }
}

#[test]
fn empty_file_is_zero_records_single_lf_is_one_empty_record() {
    assert_root("EMPTY: 0-byte file, zero records", &[], b"", ROOT_EMPTY_FILE);
    assert_root(
        "ONE_LF: one LF, a single empty record",
        &[b""],
        b"\n",
        ROOT_ONE_EMPTY_RECORD,
    );
    assert_ne!(ROOT_EMPTY_FILE, ROOT_ONE_EMPTY_RECORD);
}

#[test]
fn version_output_is_unchanged() {
    let out = Command::new(common::bin()).arg("--version").output().unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert!(out.stderr.is_empty());
    assert_eq!(out.stdout, b"roottrace 0.1.0\n");
}

#[test]
fn usage_errors_exit_2_and_write_usage_to_stderr() {
    let no_args = Command::new(common::bin()).output().unwrap();
    assert_eq!(no_args.status.code(), Some(2));
    assert!(no_args.stdout.is_empty());
    let err = String::from_utf8_lossy(&no_args.stderr);
    assert!(err.contains("Usage"), "expected usage on stderr, got: {err}");

    for args in [
        vec!["bogus"],
        vec!["root"],
        vec!["root", "a", "b"],
        vec!["--version", "extra"],
    ] {
        let out = Command::new(common::bin()).args(&args).output().unwrap();
        assert_eq!(out.status.code(), Some(2), "args {args:?} should exit 2");
        assert!(out.stdout.is_empty(), "args {args:?} must not write stdout");
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("Usage"),
            "args {args:?} should print usage to stderr"
        );
    }
}

#[test]
fn read_failures_exit_1_and_write_nothing_to_stdout() {
    let missing = TempFile::create(b"x");
    let missing_path = missing.path.clone();
    drop(missing); // delete it so the path does not exist
    let out = Command::new(common::bin())
        .arg("root")
        .arg(&missing_path)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1), "missing file should exit 1");
    assert!(out.stdout.is_empty());
    assert!(!out.stderr.is_empty());

    let dir = TempDir::create();
    let out = Command::new(common::bin()).arg("root").arg(&dir.path).output().unwrap();
    assert_eq!(out.status.code(), Some(1), "directory path should exit 1");
    assert!(out.stdout.is_empty());
    assert!(!out.stderr.is_empty());
}
