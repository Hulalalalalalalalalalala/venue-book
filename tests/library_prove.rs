//! Integration tests for the roottrace LIBRARY proof-generation entry point
//! (`roottrace::prove_membership`), called the way an external Rust program
//! would: an in-memory ordered record batch plus a 0-based record index, with
//! no batch file, no temporary files and no command line.
//!
//! The batch elements are complete records: LF (leading, interior, trailing),
//! CR, space, NUL and non-UTF-8 bytes are all content. Records that themselves
//! contain LF can never appear in an LF-separated batch file, so for those the
//! expected roots and audit paths are the independently fixed constants of
//! `tests/reference/rfc6962_lf_record_vectors.py` (two cross-checked RFC 6962
//! implementations over `hashlib.sha256`, re-verified by an independent
//! inclusion verifier) — never derived from roottrace output. For
//! file-representable batches the generated JSON is checked byte for byte
//! against the actual `roottrace prove` CLI output.
//!
//! Coverage:
//!   * generated JSON is byte-identical to `roottrace prove` output at every
//!     position of a file-representable batch, and the root matches
//!     `roottrace root`
//!   * records containing LF (and CR/NUL/non-UTF-8 bytes) generate proofs
//!     whose root and audit path match the independent fixed constants, in a
//!     single-record tree (empty path) and a 9-record non-power-of-two tree
//!   * the generated single-line JSON (no trailing newline) feeds straight
//!     into `inspect_proof` and `verify_membership` with independently
//!     trusted values
//!   * an empty byte record occupies a position; the empty batch is not one
//!     empty record and errors for every index
//!   * duplicate content stays position-specific: the later occurrence gets
//!     its own proof, never the earlier one's
//!   * odd record counts keep the RFC 6962 uneven tree shape (no duplicated
//!     last record, no padding)
//!   * an index at or past the record count is a typed
//!     `ProveError::IndexOutOfRange` carrying the requested index and the
//!     actual count; huge u64 indices are not truncated into a valid position

mod common;

use std::process::Command;

use roottrace::{inspect_proof, prove_membership, verify_membership, ProveError};

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

fn hex_of(hash: &[u8; 32]) -> String {
    hash.iter().map(|b| format!("{b:02x}")).collect()
}

/// Run a CLI subcommand and return its stdout with the trailing LF removed.
fn cli_stdout(args: &[&str]) -> Vec<u8> {
    let out = Command::new(common::bin())
        .args(args)
        .output()
        .expect("failed to execute roottrace binary");
    assert!(
        out.status.success() && out.stderr.is_empty(),
        "roottrace {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(out.stdout.last(), Some(&b'\n'), "CLI output must end in LF");
    out.stdout[..out.stdout.len() - 1].to_vec()
}

// --- byte-identical output for file-representable batches --------------------

/// A file-representable batch: duplicate content ("x" at positions 0 and 4),
/// an empty record, and a record with NUL/CR/non-UTF-8 bytes.
const BATCH_RECORDS: &[&[u8]] = &[
    b"x",
    b"alpha",
    b"",
    b"bin\x00\xff\xfe\x01",
    b"x",
    b"omega",
];

#[test]
fn generated_json_matches_cli_prove_byte_for_byte_at_every_position() {
    // Both file forms (with and without the trailing LF) name the same
    // record sequence and must give the same proofs.
    for trailing_lf in [true, false] {
        let batch = common::TempFile::create(&common::join_lf(BATCH_RECORDS, trailing_lf));
        let path = batch.path.to_str().unwrap();
        let cli_root = cli_stdout(&["root", path]);
        for (i, record) in BATCH_RECORDS.iter().enumerate() {
            let cli_proof = cli_stdout(&["prove", path, &i.to_string()]);
            let proof = prove_membership(BATCH_RECORDS, i as u64)
                .unwrap_or_else(|e| panic!("position {i} must exist: {e}"));

            // Typed accessors: tree size, position, root, leaf-to-root path.
            assert_eq!(proof.tree_size(), BATCH_RECORDS.len() as u64);
            assert_eq!(proof.leaf_index(), i as u64);
            assert_eq!(hex_of(proof.root()), String::from_utf8(cli_root.clone()).unwrap());

            // The JSON is one line WITHOUT a trailing newline and matches the
            // CLI proof object byte for byte.
            let json = proof.to_json();
            assert!(!json.ends_with('\n') && !json.contains('\n'), "single line, no LF: {json:?}");
            assert_eq!(json.as_bytes(), cli_proof.as_slice(), "position {i}, trailing_lf={trailing_lf}");

            // The generated JSON feeds straight into verification with the
            // independently obtained trusted values (the CLI root).
            let trusted_root = hash_of(std::str::from_utf8(&cli_root).unwrap());
            let m = verify_membership(record, json.as_bytes(), proof.tree_size(), &trusted_root)
                .unwrap_or_else(|e| panic!("generated proof at {i} must verify: {e}"));
            assert_eq!(m.leaf_index(), i as u64);

            // ...and into inspection, which reports the same claims.
            let claims = inspect_proof(json.as_bytes()).expect("generated proof is well-formed");
            assert_eq!(claims.tree_size(), proof.tree_size());
            assert_eq!(claims.leaf_index(), proof.leaf_index());
            assert_eq!(claims.root(), proof.root());
        }
    }
}

#[test]
fn duplicate_content_gets_position_specific_proofs() {
    // "x" sits at positions 0 and 4: asking for the later occurrence must not
    // return the earlier one's proof.
    let first = prove_membership(BATCH_RECORDS, 0).unwrap();
    let later = prove_membership(BATCH_RECORDS, 4).unwrap();
    assert_eq!(first.leaf_index(), 0);
    assert_eq!(later.leaf_index(), 4);
    assert_ne!(first.audit_path(), later.audit_path());
    assert_ne!(first.to_json(), later.to_json());
    // Same root: both proofs anchor the same batch.
    assert_eq!(first.root(), later.root());
    assert_eq!(first.tree_size(), later.tree_size());
}

// --- tree shape: single record, odd counts -----------------------------------

#[test]
fn single_record_batch_has_empty_path() {
    let proof = prove_membership(&[b"only"], 0).expect("the one position exists");
    assert_eq!(proof.tree_size(), 1);
    assert_eq!(proof.leaf_index(), 0);
    assert!(proof.audit_path().is_empty(), "single record: empty path");
    assert!(proof.to_json().contains("\"audit_path\":[]"));
    // The root is the bare leaf hash SHA-256(0x00 || "only") — verified here
    // through the CLI, which computes the same root for the one-record file.
    let batch = common::TempFile::create(b"only");
    let cli_root = cli_stdout(&["root", batch.path.to_str().unwrap()]);
    assert_eq!(hex_of(proof.root()), String::from_utf8(cli_root).unwrap());
}

#[test]
fn odd_record_counts_keep_the_rfc6962_uneven_shape() {
    // n=5: RFC split k=4, so the last record pairs directly with MTH of the
    // whole 4-record subtree — a single sibling. A padding scheme would emit
    // a longer path.
    let five: &[&[u8]] = &[b"a", b"b", b"c", b"d", b"e"];
    let last = prove_membership(five, 4).unwrap();
    assert_eq!(last.audit_path().len(), 1, "n=5, last record: one sibling");
    // n=9: RFC split k=8, the last record is the lone right subtree.
    let nine: &[&[u8]] = &[b"0", b"1", b"2", b"3", b"4", b"5", b"6", b"7", b"8"];
    let last = prove_membership(nine, 8).unwrap();
    assert_eq!(last.audit_path().len(), 1, "n=9, last record: one sibling");
    // Every position of every odd/even size generates and verifies.
    for n in 1..=12usize {
        let owned: Vec<Vec<u8>> = (0..n).map(|i| format!("record-{i:04}").into_bytes()).collect();
        let refs: Vec<&[u8]> = owned.iter().map(|r| r.as_slice()).collect();
        let root = prove_membership(&refs, 0).unwrap().root().to_owned();
        for (m, record) in refs.iter().enumerate() {
            let proof = prove_membership(&refs, m as u64).unwrap();
            assert_eq!(proof.root(), &root, "n={n}, m={m}: same root at every position");
            verify_membership(record, proof.to_json().as_bytes(), n as u64, &root)
                .unwrap_or_else(|e| panic!("n={n}, m={m} must verify: {e}"));
        }
    }
}

// --- records containing LF: independent fixed constants -----------------------
//
// From tests/reference/rfc6962_lf_record_vectors.py (shared with
// tests/verify_lf_record_regression.rs): such records cannot appear in a
// batch file, so the constants are the independent trust anchor here.

// REC_LF_RICH: 100-byte record; starts with LF, consecutive LFs inside,
// ends with LF, carries CR/NUL/non-UTF-8 bytes.
const REC_LF_RICH: &[u8] = b"\n\x00\xff\xfe\rlf-rich-record:\n\n\nsegment-B\r\nabcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz012\n";
// REC_ONE_LF: the record that is exactly one LF byte.
const REC_ONE_LF: &[u8] = b"\n";

const ROOT_LF_RICH_SINGLE: &str = "173226ff98963fba71af8e5be5a65b8801b57802a8da0f3df194630a60e3c6b4";
const ROOT_ONE_LF_SINGLE: &str = "67ebbd370daa02ba9aadd05d8e091e862d0d8bcadafdf2a22360240a42fe922e";

// LF_BATCH: 9-record (non-power-of-two) sequence with REC_LF_RICH at
// position 4 and REC_ONE_LF at position 8 (lone right subtree).
const LF_BATCH: &[&[u8]] = &[
    b"alpha",     // 0
    b"beta",      // 1
    b"",          // 2 empty record
    b"gamma\r",   // 3 trailing CR is content
    REC_LF_RICH,  // 4 target: the LF-rich record
    b"\xff\x00z", // 5 non-UTF-8 and NUL bytes
    b"epsilon",   // 6
    b"zeta\x01tail", // 7
    REC_ONE_LF,   // 8 target: the record that is exactly one LF
];
const ROOT_LF_BATCH: &str = "0da784b08ff8dc5d6ce28573aef2f1870116467b242aea9bdddc09e7878ea281";
const PATH_LF_BATCH_M4: &[&str] = &["874bb321567c2878c37d117d7b4844d505bba48fb28ef79e9a384783cd83981c", "3fc0ce0f8d78eb619bf4d612fea9ce899778ce65c0f4057ccdff93d5e5a1cb11", "24ff5ce2ca4e64d47365292c6d5408d2118f70f3eb7d4baf88caf779e61cc1c5", "67ebbd370daa02ba9aadd05d8e091e862d0d8bcadafdf2a22360240a42fe922e"];
const PATH_LF_BATCH_M8: &[&str] = &["6815e839c7f397a279197c64b82fa20441773460c830112ced04f25607a30d8f"];

#[test]
fn lf_containing_records_match_independent_constants() {
    // Single-record trees: the LF-rich record and the one-LF record each hash
    // to their independently fixed roots, with an empty audit path.
    for (record, root) in [(REC_LF_RICH, ROOT_LF_RICH_SINGLE), (REC_ONE_LF, ROOT_ONE_LF_SINGLE)] {
        let proof = prove_membership(&[record], 0).unwrap();
        assert!(proof.audit_path().is_empty());
        assert_eq!(hex_of(proof.root()), root);
        assert_eq!(
            proof.to_json(),
            format!("{{\"tree_size\":1,\"leaf_index\":0,\"root\":\"{root}\",\"audit_path\":[]}}")
        );
    }

    // The 9-record non-power-of-two batch: root and both target positions'
    // audit paths match the fixed constants hash for hash.
    for (index, path) in [(4u64, PATH_LF_BATCH_M4), (8u64, PATH_LF_BATCH_M8)] {
        let proof = prove_membership(LF_BATCH, index).unwrap();
        assert_eq!(proof.tree_size(), 9);
        assert_eq!(proof.leaf_index(), index);
        assert_eq!(hex_of(proof.root()), ROOT_LF_BATCH);
        let got: Vec<String> = proof.audit_path().iter().map(hex_of).collect();
        assert_eq!(got, path, "audit path at position {index}");
    }
}

#[test]
fn generated_json_for_lf_records_verifies_against_trusted_constants() {
    // The generated JSON (record content never appears in it) goes straight
    // into verification with the independently fixed trusted values.
    let cases: &[(&[&[u8]], u64, u64, &str)] = &[
        (&[REC_LF_RICH], 0, 1, ROOT_LF_RICH_SINGLE),
        (&[REC_ONE_LF], 0, 1, ROOT_ONE_LF_SINGLE),
        (LF_BATCH, 4, 9, ROOT_LF_BATCH),
        (LF_BATCH, 8, 9, ROOT_LF_BATCH),
    ];
    for (records, index, size, root) in cases {
        let proof = prove_membership(records, *index).unwrap();
        let json = proof.to_json();
        assert!(!json.ends_with('\n'));
        let trusted_root = hash_of(root);
        let m = verify_membership(records[*index as usize], json.as_bytes(), *size, &trusted_root)
            .unwrap_or_else(|e| panic!("index {index} of tree {size} must verify: {e}"));
        assert_eq!(m.leaf_index(), *index);
        assert_eq!(m.tree_size(), *size);
        assert_eq!(m.root(), &trusted_root);
    }
}

// --- record boundaries --------------------------------------------------------

#[test]
fn record_bytes_are_verbatim_and_empty_record_occupies_a_position() {
    // LF (leading/interior/trailing), CR, space, NUL and non-UTF-8 bytes are
    // all content: each of these is ONE record, never split or trimmed.
    let records: &[&[u8]] = &[b"\nlead", b"mid\ndle", b"trail\n", b"\r \x00\xff", b""];
    let proof = prove_membership(records, 4).unwrap();
    assert_eq!(proof.tree_size(), 5, "the empty byte record is position 4");

    // The empty byte record is not the empty batch: one element b"" gives a
    // tree of size 1 whose root is SHA-256(0x00); zero elements is an error.
    let single_empty = prove_membership(&[b""], 0).unwrap();
    assert_eq!(single_empty.tree_size(), 1);
    assert_eq!(
        hex_of(single_empty.root()),
        "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"
    );
    assert!(matches!(
        prove_membership(&[], 0),
        Err(ProveError::IndexOutOfRange { tree_size: 0, .. })
    ));

    // A record that is exactly one LF differs from the empty record.
    let one_lf = prove_membership(&[b"\n"], 0).unwrap();
    assert_ne!(one_lf.root(), single_empty.root());
}

// --- out-of-range indices: typed error, no truncation --------------------------

#[test]
fn out_of_range_index_is_a_typed_error_carrying_index_and_count() {
    let records: &[&[u8]] = &[b"a", b"b", b"c"];
    // Index equal to the count, past the count, and huge u64 values: all the
    // same typed error, carrying the requested index untruncated and the
    // actual record count. u64::MAX must not wrap into a valid position.
    for index in [3u64, 4, 100, u64::from(u32::MAX) + 1, u64::MAX] {
        assert_eq!(
            prove_membership(records, index),
            Err(ProveError::IndexOutOfRange {
                requested_index: index,
                tree_size: 3,
            }),
            "index {index} must be IndexOutOfRange"
        );
    }
    // The empty batch has no position at all: every index errors the same
    // way — no panic, no empty-tree membership proof.
    let empty: &[&[u8]] = &[];
    for index in [0u64, 1, u64::MAX] {
        assert_eq!(
            prove_membership(empty, index),
            Err(ProveError::IndexOutOfRange {
                requested_index: index,
                tree_size: 0,
            }),
            "empty batch, index {index}"
        );
    }
    // The boundary itself: the last valid index of a one-record batch works,
    // the next one errors.
    assert!(prove_membership(&[b"a"], 0).is_ok());
    assert!(matches!(
        prove_membership(&[b"a"], 1),
        Err(ProveError::IndexOutOfRange { requested_index: 1, tree_size: 1 })
    ));
}
