//! Integration tests for the in-memory proof-GENERATION library entry point
//! (`roottrace::prove_membership`), called the way an external Rust program
//! would: an ordered, already-divided record batch held in memory and a
//! 0-based record index — no batch file and no command line.
//!
//! Coverage:
//!   * for batches a batch file CAN express, the generated one-line JSON is
//!     byte-for-byte identical to `roottrace prove` output at EVERY position
//!     (sizes 1, 7, 8, 9, i.e. across the power-of-two boundary), with and
//!     without the file's trailing LF; the root matches `roottrace root`
//!   * each element is one COMPLETE record: leading/internal/trailing LF, CR,
//!     NUL and non-UTF-8 bytes are never split out or trimmed — the
//!     batch-file-inexpressible cases reproduce the independently fixed
//!     constants from tests/reference/rfc6962_lf_record_vectors.py and then
//!     round-trip through `verify_membership` AND the `verify`/`inspect` CLI
//!     using the full record bytes and independently trusted values
//!   * an empty element is one empty record (one position), distinct from the
//!     empty batch; duplicate content keeps a position-specific proof for a
//!     later occurrence; order participates in the root
//!   * one record -> empty audit path; odd sizes keep RFC 6962 geometry with
//!     no duplicated/empty last record
//!   * out-of-range indices (empty batch for any index, index == count, huge
//!     u64 indices) return the typed PositionNotFound carrying the requested
//!     index and the actual count, never panicking or returning a proof
//!   * the JSON carries no trailing newline and accepts several collection
//!     shapes (`&[&[u8]]`, `&[Vec<u8>]`, owned `Vec<Vec<u8>>`, arrays)

mod common;

use std::process::Command;

use common::TempFile;
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

fn roottrace_hex(root: &[u8; 32]) -> String {
    root.iter().map(|b| format!("{b:02x}")).collect()
}

/// Run a CLI subcommand successfully and return its stdout with the single
/// trailing LF removed.
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

fn cli_root(file: &TempFile) -> [u8; 32] {
    let hex = cli_stdout(&["root", file.path.to_str().unwrap()]);
    hash_of(std::str::from_utf8(&hex).unwrap())
}

fn cli_prove(file: &TempFile, index: u64) -> Vec<u8> {
    let idx = index.to_string();
    cli_stdout(&["prove", file.path.to_str().unwrap(), &idx])
}

// --- Byte-for-byte agreement with the CLI on representable batches ----------

/// Seven records shared by the 7/8/9 batches: includes an empty record,
/// duplicate-free here except where noted, CR/NUL/non-UTF-8 bytes, but NO LF
/// byte inside any record so every sequence below is expressible as a batch
/// file.
const SEVEN: &[&[u8]] = &[
    b"alpha",
    b"beta",
    b"",
    b"gamma\r",
    b"\xff\x00z",
    b"epsilon",
    b"zeta\x01tail",
];

fn batch_records(size: usize) -> Vec<&'static [u8]> {
    assert!((7..=9).contains(&size));
    let mut recs = SEVEN.to_vec();
    if size >= 8 {
        recs.push(b"omega");
    }
    if size == 9 {
        recs.push(b"theta");
    }
    recs
}

#[test]
fn generated_json_matches_cli_prove_at_every_position() {
    for size in [1usize, 7, 8, 9] {
        let records: Vec<&[u8]> = if size == 1 {
            vec![b"only"]
        } else {
            batch_records(size)
        };
        assert_eq!(records.len(), size);

        // The same record sequence in both batch-file encodings.
        for trailing_lf in [true, false] {
            let file = TempFile::create(&common::join_lf(&records, trailing_lf));
            let cli_batch_root = cli_root(&file);

            for index in 0..size as u64 {
                let proof = prove_membership(&records, index)
                    .unwrap_or_else(|e| panic!("size {size} index {index} must exist: {e}"));

                // Typed getters.
                assert_eq!(proof.tree_size(), size as u64);
                assert_eq!(proof.leaf_index(), index);
                assert_eq!(proof.root(), &cli_batch_root, "size {size} index {index}");

                // The generated JSON is byte-for-byte the CLI `prove` line
                // (minus the CLI's trailing LF, which the library never adds).
                let cli_proof = cli_prove(&file, index);
                assert_eq!(
                    proof.to_json().as_bytes(),
                    cli_proof.as_slice(),
                    "size {size} index {index} trailing_lf {trailing_lf}"
                );
            }
        }
    }
}

// --- Geometry: empty path for one record, RFC shape for odd sizes -----------

#[test]
fn single_record_has_empty_path_and_odd_tree_uses_rfc_geometry() {
    let one: [&[u8]; 1] = [b"solo"];
    let proof = prove_membership(&one, 0).unwrap();
    assert!(proof.audit_path().is_empty());
    assert!(proof.to_json().contains("\"audit_path\":[]"));

    // n=9 (uneven, RFC k=8): the last leaf pairs directly with MTH of the
    // first eight, so its path is exactly one hash; middle leaves stay shorter
    // than the full depth. No leaf is duplicated and no empty record is added.
    let nine = batch_records(9);
    let last = prove_membership(&nine, 8).unwrap();
    assert_eq!(last.audit_path().len(), 1, "last leaf of 9 has one sibling");
    assert_eq!(
        last.audit_path()[0],
        roottrace::mth(&nine[..8]),
        "the one sibling is MTH of the first eight records"
    );
    // A power-of-two 8 batch gives a full depth-3 path at every position.
    let eight = batch_records(8);
    for i in 0..8u64 {
        assert_eq!(prove_membership(&eight, i).unwrap().audit_path().len(), 3);
    }
}

// --- Each element is one whole record, including LF-bearing records ---------
//
// Fixed vectors copied verbatim from the independent generator
// tests/reference/rfc6962_lf_record_vectors.py (two structurally different
// RFC 6962 implementations plus an independent inclusion verifier). They are
// not derived from roottrace, so agreement here is external confirmation.

const REC_LF_RICH: &[u8] = b"\n\x00\xff\xfe\rlf-rich-record:\n\n\nsegment-B\r\nabcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz012\n";
const REC_ONE_LF: &[u8] = b"\n";

const ROOT_LF_RICH_SINGLE: &str = "173226ff98963fba71af8e5be5a65b8801b57802a8da0f3df194630a60e3c6b4";
const ROOT_ONE_LF_SINGLE: &str = "67ebbd370daa02ba9aadd05d8e091e862d0d8bcadafdf2a22360240a42fe922e";
const ROOT_LF_BATCH: &str = "0da784b08ff8dc5d6ce28573aef2f1870116467b242aea9bdddc09e7878ea281";
const PATH_LF_BATCH_M4: &[&str] = &[
    "874bb321567c2878c37d117d7b4844d505bba48fb28ef79e9a384783cd83981c",
    "3fc0ce0f8d78eb619bf4d612fea9ce899778ce65c0f4057ccdff93d5e5a1cb11",
    "24ff5ce2ca4e64d47365292c6d5408d2118f70f3eb7d4baf88caf779e61cc1c5",
    "67ebbd370daa02ba9aadd05d8e091e862d0d8bcadafdf2a22360240a42fe922e",
];
const PATH_LF_BATCH_M8: &[&str] =
    &["6815e839c7f397a279197c64b82fa20441773460c830112ced04f25607a30d8f"];

/// The 9-record sequence that contains LF-bearing records (cannot be written
/// as a batch file).
fn lf_batch() -> Vec<&'static [u8]> {
    vec![
        b"alpha",
        b"beta",
        b"",
        b"gamma\r",
        REC_LF_RICH,
        b"\xff\x00z",
        b"epsilon",
        b"zeta\x01tail",
        REC_ONE_LF,
    ]
}

fn fixed_proof_json(size: u64, index: u64, root: &str, path: &[&str]) -> String {
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

#[test]
fn lf_containing_records_reproduce_independent_vectors() {
    // Single-record trees: the whole LF-bearing record is the only leaf.
    let rich_single = prove_membership(&[REC_LF_RICH], 0).unwrap();
    assert_eq!(roottrace_hex(rich_single.root()), ROOT_LF_RICH_SINGLE);
    assert!(rich_single.audit_path().is_empty());
    assert_eq!(
        rich_single.to_json(),
        fixed_proof_json(1, 0, ROOT_LF_RICH_SINGLE, &[])
    );

    let one_lf_single = prove_membership(&[REC_ONE_LF], 0).unwrap();
    assert_eq!(roottrace_hex(one_lf_single.root()), ROOT_ONE_LF_SINGLE);
    assert!(one_lf_single.audit_path().is_empty());
    assert_eq!(
        one_lf_single.to_json(),
        fixed_proof_json(1, 0, ROOT_ONE_LF_SINGLE, &[])
    );

    // The 9-record LF batch at the two target positions matches the fixed
    // root and leaf-to-root paths exactly.
    let batch = lf_batch();
    let batch_root = hash_of(ROOT_LF_BATCH);
    let p4 = prove_membership(&batch, 4).unwrap();
    assert_eq!(p4.tree_size(), 9);
    assert_eq!(p4.leaf_index(), 4);
    assert_eq!(p4.root(), &batch_root);
    assert_eq!(
        p4.audit_path().iter().map(roottrace_hex).collect::<Vec<_>>(),
        PATH_LF_BATCH_M4
    );
    assert_eq!(p4.to_json(), fixed_proof_json(9, 4, ROOT_LF_BATCH, PATH_LF_BATCH_M4));

    let p8 = prove_membership(&batch, 8).unwrap();
    assert_eq!(p8.leaf_index(), 8);
    assert_eq!(p8.root(), &batch_root);
    assert_eq!(
        p8.audit_path().iter().map(roottrace_hex).collect::<Vec<_>>(),
        PATH_LF_BATCH_M8
    );
    assert_eq!(p8.to_json(), fixed_proof_json(9, 8, ROOT_LF_BATCH, PATH_LF_BATCH_M8));
}

#[test]
fn generated_lf_proofs_round_trip_through_library_and_cli() {
    let batch = lf_batch();
    let batch_root = hash_of(ROOT_LF_BATCH);

    for (index, record) in [(4u64, REC_LF_RICH), (8, REC_ONE_LF)] {
        let proof = prove_membership(&batch, index).unwrap();

        // Library verification with the FULL record bytes and the
        // independently trusted size/root succeeds; the result carries the
        // claimed position plus the trusted values.
        let m = verify_membership(record, proof.to_json().as_bytes(), 9, &batch_root)
            .unwrap_or_else(|e| panic!("LF record at {index} must verify: {e}"));
        assert_eq!(m.leaf_index(), index);
        assert_eq!(m.tree_size(), 9);
        assert_eq!(m.root(), &batch_root);

        // CLI interop: feed the generated JSON (with no added newline) and the
        // exact record bytes to `verify` with independently trusted values.
        let rec_file = TempFile::create(record);
        let proof_file = TempFile::create(proof.to_json().as_bytes());
        let out = Command::new(common::bin())
            .arg("verify")
            .arg(&rec_file.path)
            .arg(&proof_file.path)
            .arg("9")
            .arg(ROOT_LF_BATCH)
            .output()
            .expect("failed to execute roottrace binary");
        assert_eq!(out.status.code(), Some(0), "stderr: {}", String::from_utf8_lossy(&out.stderr));
        assert_eq!(out.stdout, b"verified\n");
        assert!(out.stderr.is_empty());

        // `inspect` shows exactly the three claims from the generated proof.
        let claims = inspect_proof(proof.to_json().as_bytes()).unwrap();
        assert_eq!(claims.tree_size(), 9);
        assert_eq!(claims.leaf_index(), index);
        assert_eq!(claims.root(), &batch_root);
    }

    // Single-record LF proofs verify as one-record trees too.
    for (record, root) in [(REC_LF_RICH, ROOT_LF_RICH_SINGLE), (REC_ONE_LF, ROOT_ONE_LF_SINGLE)] {
        let proof = prove_membership(&[record], 0).unwrap();
        let trusted = hash_of(root);
        verify_membership(record, proof.to_json().as_bytes(), 1, &trusted).unwrap();
    }
}

#[test]
fn one_lf_record_is_distinct_from_empty_record_and_split_lines() {
    // ["\n"] (one element) is a single record whose content is LF; it is not
    // the zero-byte empty record, and not the two-record sequence ["a","b"]
    // that a batch file would derive from bytes "a\nb".
    let lf_root = *prove_membership(&[b"a\nb"], 0).unwrap().root();
    let split_root = *prove_membership(&[b"a", b"b"], 0).unwrap().root();
    assert_ne!(lf_root, split_root, "an embedded LF is content, not a separator");
    assert_eq!(prove_membership(&[b"a\nb"], 0).unwrap().tree_size(), 1);
    assert_eq!(prove_membership(&[b"a", b"b"], 0).unwrap().tree_size(), 2);

    // Full bytes verify against the LF record's proof; any trimming or line
    // splitting fails verification against the independently trusted root.
    let proof = prove_membership(&[b"a\nb"], 0).unwrap();
    let trusted = *proof.root();
    let json = proof.to_json();
    verify_membership(b"a\nb", json.as_bytes(), 1, &trusted).unwrap();
    for wrong in [b"a".as_slice(), b"b", b"", b"a\nb\n", b"a\n"] {
        assert!(matches!(
            verify_membership(wrong, json.as_bytes(), 1, &trusted),
            Err(roottrace::VerifyError::VerificationFailed(_))
        ));
    }
}

// --- Empty records, duplicates and order ------------------------------------

#[test]
fn empty_element_is_one_position_but_empty_batch_has_none() {
    // One empty element is a batch of size 1; two consecutive empties are two
    // positions, each with an empty (single-record) audit path.
    let one_empty = prove_membership(&[b""], 0).unwrap();
    assert_eq!(one_empty.tree_size(), 1);
    assert!(one_empty.audit_path().is_empty());
    assert_eq!(
        roottrace_hex(one_empty.root()),
        "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d" // SHA-256(0x00)
    );

    let three: [&[u8]; 3] = [b"a", b"", b"b"];
    let proof = prove_membership(&three, 2).unwrap();
    assert_eq!(proof.tree_size(), 3);
    verify_membership(b"b", proof.to_json().as_bytes(), 3, proof.root()).unwrap();
    // Dropping the empty record changes the root.
    let two: [&[u8]; 2] = [b"a", b"b"];
    assert_ne!(prove_membership(&three, 0).unwrap().root(), prove_membership(&two, 0).unwrap().root());
}

#[test]
fn duplicate_content_keeps_position_specific_proof_for_later_occurrence() {
    let records: [&[u8]; 5] = [b"x", b"a", b"b", b"c", b"x"];
    let p0 = prove_membership(&records, 0).unwrap();
    let p4 = prove_membership(&records, 4).unwrap();
    assert_ne!(p0.to_json(), p4.to_json());
    assert_eq!(p4.leaf_index(), 4, "a later index must not be remapped to 0");
    let root = *p4.root();
    // Each proof verifies only at its own position.
    verify_membership(b"x", p4.to_json().as_bytes(), 5, &root).unwrap();
    assert!(matches!(
        verify_membership(b"x", p0.to_json().as_bytes(), 5, &root),
        Ok(m) if m.leaf_index() == 0
    ));
    // The position-4 proof does not verify if the claim is force-moved to 0.
    let moved = p4.to_json().replace("\"leaf_index\":4", "\"leaf_index\":0");
    assert!(matches!(
        verify_membership(b"x", moved.as_bytes(), 5, &root),
        Err(roottrace::VerifyError::VerificationFailed(_))
    ));
}

#[test]
fn record_order_participates_in_the_root() {
    let ab: [&[u8]; 2] = [b"a", b"b"];
    let ba: [&[u8]; 2] = [b"b", b"a"];
    let root_ab = *prove_membership(&ab, 0).unwrap().root();
    let root_ba = *prove_membership(&ba, 0).unwrap().root();
    assert_ne!(root_ab, root_ba);
}

// --- Typed out-of-range error -----------------------------------------------

#[test]
fn out_of_range_and_empty_batch_return_typed_error_with_values() {
    struct Case {
        records: Vec<Vec<u8>>,
        index: u64,
    }

    let empty: Vec<Vec<u8>> = vec![];
    let one: Vec<Vec<u8>> = vec![b"only".to_vec()];
    let three: Vec<Vec<u8>> = vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()];

    let cases = [
        Case { records: empty.clone(), index: 0 },
        Case { records: empty.clone(), index: 1 },
        Case { records: empty, index: u64::MAX },
        Case { records: one.clone(), index: 1 },
        Case { records: one, index: u64::MAX },
        Case { records: three.clone(), index: 3 },
        Case { records: three.clone(), index: 4 },
        Case { records: three, index: u64::MAX },
    ];

    for case in cases {
        let count = case.records.len() as u64;
        let result = prove_membership(&case.records, case.index);
        match result {
            Err(ProveError::PositionNotFound {
                requested_index,
                record_count,
            }) => {
                assert_eq!(requested_index, case.index, "requested index is carried verbatim");
                assert_eq!(record_count, count, "actual count is carried");
            }
            other => panic!(
                "index {} of {} records must be PositionNotFound, got {other:?}",
                case.index, count
            ),
        }
    }

    // Boundaries that DO exist succeed, including the last position.
    assert!(prove_membership(&[b"only"], 0).is_ok());
    assert!(prove_membership(&[b"a", b"b", b"c"], 2).is_ok());
}

#[test]
fn huge_u64_index_is_not_truncated_into_a_legal_position() {
    // Six records; an index with a high bit set must stay out of range and be
    // reported with its full 64-bit value, not narrowed to an in-range usize.
    let records: [&[u8]; 6] = [b"a", b"b", b"c", b"d", b"e", b"f"];
    for huge in [1u64 << 63, (1u64 << 63) + 1, u64::MAX] {
        match prove_membership(&records, huge) {
            Err(ProveError::PositionNotFound {
                requested_index,
                record_count,
            }) => {
                assert_eq!(requested_index, huge);
                assert_eq!(record_count, 6);
            }
            other => panic!("huge index {huge} must be PositionNotFound, got {other:?}"),
        }
    }
}

// --- JSON shape and collection ergonomics -----------------------------------

#[test]
fn json_is_a_single_line_without_trailing_newline() {
    let proof = prove_membership(&[b"a", b"b", b"c"], 1).unwrap();
    let json = proof.to_json();
    assert!(!json.contains('\n'), "JSON must be one line: {json:?}");
    assert!(!json.ends_with('\n'), "library JSON carries no trailing LF");
    // It still parses as a proof (inspect) and verifies directly.
    let claims = inspect_proof(json.as_bytes()).unwrap();
    assert_eq!(claims.leaf_index(), 1);
    let root = *proof.root();
    verify_membership(b"b", json.as_bytes(), 3, &root).unwrap();
    // The CLI tolerates the line as-is when written to a file (already
    // covered with a trailing LF elsewhere); here confirm a trailing LF does
    // not change verification either.
    let mut with_lf = json.clone().into_bytes();
    with_lf.push(b'\n');
    verify_membership(b"b", &with_lf, 3, &root).unwrap();
}

#[test]
fn accepts_borrowed_owned_and_array_batches() {
    let expected = {
        let refs: [&[u8]; 3] = [b"a", b"b", b"c"];
        prove_membership(&refs, 2).unwrap().to_json()
    };

    // Slice of borrowed byte slices.
    let refs: Vec<&[u8]> = vec![b"a", b"b", b"c"];
    assert_eq!(prove_membership(&refs, 2).unwrap().to_json(), expected);

    // Slice of owned Vecs, borrowed.
    let owned: Vec<Vec<u8>> = vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()];
    assert_eq!(prove_membership(&owned, 2).unwrap().to_json(), expected);

    // Owned collection moved by value (the function keeps the items alive).
    assert_eq!(prove_membership(owned, 2).unwrap().to_json(), expected);

    // A fixed-size array of owned Vecs.
    let arr: [Vec<u8>; 3] = [b"a".to_vec(), b"b".to_vec(), b"c".to_vec()];
    assert_eq!(prove_membership(arr, 2).unwrap().to_json(), expected);
}
