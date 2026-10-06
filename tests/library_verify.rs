//! Integration tests for the roottrace LIBRARY entry point
//! (`roottrace::verify_membership`), called the way an external Rust program
//! would: one in-memory record, one in-memory JSON proof, and independently
//! trusted tree size and root — no batch file, no temporary files for the
//! verification itself.
//!
//! Proofs and trusted roots are produced by the actual `roottrace` CLI binary
//! (and, for unmaterialisably large trees, by the fixed constants shared with
//! `tests/verify_big_tree_regression.rs`), so the library is checked to
//! interoperate with the command line byte for byte.
//!
//! Coverage:
//!   * real CLI proofs verify through the library at every position of a
//!     batch, and the typed result carries the claimed position plus the
//!     caller's trusted size and root
//!   * failures are distinguishable BY TYPE: malformed proof vs.
//!     verification failure vs. a zero trusted tree size (invalid argument)
//!   * record bytes are verbatim: empty record, trailing LF/CR/space/NUL and
//!     non-UTF-8 bytes all take part; no batch-file LF splitting applies
//!   * field reordering, JSON whitespace and equivalent string escapes are
//!     accepted; duplicate fields and invalid integers/hashes stay rejected
//!   * duplicate content is verified only at the claimed position
//!   * tree sizes and indices past the platform index width keep their full
//!     64-bit meaning (2^63, 2^63+1, 2^64-1 trees)

mod common;

use std::process::Command;

use roottrace::{verify_membership, Membership, VerifyError};

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

/// A batch used across the tests: duplicate content ("x" at positions 0 and
/// 4), an empty record, and a record with NUL/CR/non-UTF-8 bytes.
const BATCH_RECORDS: &[&[u8]] = &[
    b"x",
    b"alpha",
    b"",
    b"bin\x00\xff\xfe\x01",
    b"x",
    b"omega",
];

fn batch_file() -> common::TempFile {
    common::TempFile::create(&common::join_lf(BATCH_RECORDS, true))
}

fn batch_root() -> [u8; 32] {
    let batch = batch_file();
    let hex = cli_stdout(&["root", batch.path.to_str().unwrap()]);
    hash_of(std::str::from_utf8(&hex).unwrap())
}

fn cli_proof(batch: &common::TempFile, index: usize) -> Vec<u8> {
    cli_stdout(&["prove", batch.path.to_str().unwrap(), &index.to_string()])
}

// --- success: typed result carries position and the trusted values ---------

#[test]
fn library_verifies_cli_proofs_at_every_position() {
    let batch = batch_file();
    let root = batch_root();
    let size = BATCH_RECORDS.len() as u64;
    for (i, record) in BATCH_RECORDS.iter().enumerate() {
        let proof = cli_proof(&batch, i);
        let m: Membership = verify_membership(record, &proof, size, &root)
            .unwrap_or_else(|e| panic!("position {i} must verify: {e}"));
        // The claimed position comes back exactly — including the duplicate
        // "x" at positions 0 and 4, which get distinct proofs.
        assert_eq!(m.leaf_index(), i as u64, "position {i}");
        // Size and root are the caller's trusted values, checked against the
        // proof — not fields read out of the proof.
        assert_eq!(m.tree_size(), size);
        assert_eq!(m.root(), &root);
    }
}

#[test]
fn library_single_record_tree_needs_empty_path() {
    let batch = common::TempFile::create(b"only");
    let root = batch_root_for(&batch);
    let proof = cli_proof(&batch, 0);
    assert!(
        String::from_utf8_lossy(&proof).contains("\"audit_path\":[]"),
        "single-record proof must have an empty path: {proof:?}"
    );
    let m = verify_membership(b"only", &proof, 1, &root).expect("single record must verify");
    assert_eq!(m.leaf_index(), 0);
    assert_eq!(m.tree_size(), 1);

    // A non-empty path on a single-record tree cannot verify.
    let doctored = std::str::from_utf8(&proof)
        .unwrap()
        .replace("\"audit_path\":[]", "\"audit_path\":[\"0000000000000000000000000000000000000000000000000000000000000000\"]");
    assert!(matches!(
        verify_membership(b"only", doctored.as_bytes(), 1, &root),
        Err(VerifyError::VerificationFailed(_))
    ));
}

fn batch_root_for(batch: &common::TempFile) -> [u8; 32] {
    let hex = cli_stdout(&["root", batch.path.to_str().unwrap()]);
    hash_of(std::str::from_utf8(&hex).unwrap())
}

// --- error typing: malformed vs. failed vs. invalid argument ---------------

#[test]
fn library_distinguishes_error_types() {
    let batch = batch_file();
    let root = batch_root();
    let size = BATCH_RECORDS.len() as u64;
    let proof = cli_proof(&batch, 1);

    // A zero trusted tree size is an INVALID ARGUMENT — not an empty-tree
    // membership proof, not a format error, not a cryptographic mismatch.
    assert_eq!(
        verify_membership(BATCH_RECORDS[1], &proof, 0, &root),
        Err(VerifyError::InvalidTrustedSize)
    );

    // Malformed proofs: not an object, truncated, duplicate field, bad
    // integer, bad hash, trailing bytes.
    let text = String::from_utf8(proof.clone()).unwrap();
    let dup = text.replace("\"tree_size\":", "\"tree_size\":6,\"tree_size\":");
    let bad_int = text.replace("\"leaf_index\":1", "\"leaf_index\":1.0");
    let bad_hash = text.replace(&roottrace_hex(&root), "abcd");
    let malformed: Vec<Vec<u8>> = vec![
        b"".to_vec(),
        b"null".to_vec(),
        b"{}".to_vec(),
        proof[..proof.len() - 3].to_vec(),
        dup.into_bytes(),
        bad_int.into_bytes(),
        bad_hash.into_bytes(),
        [proof.clone(), b" {}".to_vec()].concat(),
    ];
    for bad in &malformed {
        match verify_membership(BATCH_RECORDS[1], bad, size, &root) {
            Err(VerifyError::MalformedProof(_)) => {}
            other => panic!("{} must be MalformedProof, got {other:?}", String::from_utf8_lossy(bad)),
        }
    }

    // Well-formed proofs that do not establish inclusion: wrong record,
    // wrong trusted size, wrong trusted root, wrong position, short path.
    let mut wrong_root = root;
    wrong_root[0] ^= 0x01;
    let moved = text.replace("\"leaf_index\":1", "\"leaf_index\":2");
    // Drop the first audit-path hash entirely: one hash short.
    let short = rebuild_without_first_path_hash(&text);
    let failures: Vec<(&[u8], Vec<u8>, u64, [u8; 32])> = vec![
        (b"not-the-record", proof.clone(), size, root),
        (BATCH_RECORDS[1], proof.clone(), size + 1, root),
        (BATCH_RECORDS[1], proof.clone(), size, wrong_root),
        (BATCH_RECORDS[1], moved.into_bytes(), size, root),
        (BATCH_RECORDS[1], short.into_bytes(), size, root),
    ];
    for (record, proof, size, root) in failures {
        match verify_membership(record, &proof, size, &root) {
            Err(VerifyError::VerificationFailed(_)) => {}
            other => panic!("must be VerificationFailed, got {other:?}"),
        }
    }
}

fn roottrace_hex(root: &[u8; 32]) -> String {
    root.iter().map(|b| format!("{b:02x}")).collect()
}

fn first_path_hash(proof: &str) -> String {
    let start = proof.find("\"audit_path\":[\"").unwrap() + "\"audit_path\":[\"".len();
    proof[start..start + 64].to_string()
}

fn rebuild_without_first_path_hash(proof: &str) -> String {
    let first = first_path_hash(proof);
    proof.replacen(&format!("\"{first}\","), "", 1)
}

// --- record bytes are verbatim ----------------------------------------------

#[test]
fn library_record_bytes_are_verbatim() {
    let batch = batch_file();
    let root = batch_root();
    let size = BATCH_RECORDS.len() as u64;

    // The empty record at position 2 verifies from an EMPTY byte slice.
    let proof = cli_proof(&batch, 2);
    let m = verify_membership(b"", &proof, size, &root).expect("empty record");
    assert_eq!(m.leaf_index(), 2);

    // Appending LF, CR, space or NUL changes the record: verification fails.
    let proof = cli_proof(&batch, 1);
    for suffix in [b"\n".as_slice(), b"\r", b" ", b"\x00"] {
        let mut longer = BATCH_RECORDS[1].to_vec();
        longer.extend_from_slice(suffix);
        assert!(
            matches!(
                verify_membership(&longer, &proof, size, &root),
                Err(VerifyError::VerificationFailed(_))
            ),
            "record + trailing {suffix:?} must fail"
        );
    }

    // The binary record (NUL + non-UTF-8 bytes) verifies as-is; one flipped
    // byte fails.
    let bin = BATCH_RECORDS[3];
    let proof = cli_proof(&batch, 3);
    assert!(verify_membership(bin, &proof, size, &root).is_ok());
    let mut tampered = bin.to_vec();
    *tampered.last_mut().unwrap() ^= 0x01;
    assert!(matches!(
        verify_membership(&tampered, &proof, size, &root),
        Err(VerifyError::VerificationFailed(_))
    ));
}

// --- proof surface syntax: reorder, whitespace, escapes ---------------------

#[test]
fn library_accepts_reordered_whitespace_and_escaped_proofs() {
    let batch = batch_file();
    let root = batch_root();
    let size = BATCH_RECORDS.len() as u64;
    let proof = cli_proof(&batch, 1);
    let text = String::from_utf8(proof).unwrap();

    // Pretty-printed with reordered fields: parse the compact form apart and
    // re-emit it with different order and whitespace.
    let root_hex = roottrace_hex(&root);
    let path_hashes: Vec<String> = {
        let start = text.find("\"audit_path\":[").unwrap() + "\"audit_path\":[".len();
        let end = text[start..].find(']').unwrap() + start;
        text[start..end]
            .split(',')
            .map(|s| s.trim_matches('"').to_string())
            .collect()
    };
    let mut pretty = String::from("  {\n  \"audit_path\" : [ ");
    for (i, h) in path_hashes.iter().enumerate() {
        if i > 0 {
            pretty.push_str(" , ");
        }
        pretty.push('"');
        pretty.push_str(h);
        pretty.push('"');
    }
    pretty.push_str(&format!(
        " ] ,\n  \"root\" : \"{root_hex}\",\n  \"leaf_index\" : 1 ,\n  \"tree_size\" : {size}\n}}\n"
    ));
    let m = verify_membership(BATCH_RECORDS[1], pretty.as_bytes(), size, &root)
        .expect("reordered/pretty proof must verify");
    assert_eq!(m.leaf_index(), 1);

    // Equivalent \uXXXX escapes in keys and hash characters: spell the first
    // character of the root hash as its \uXXXX escape.
    let escaped_root = format!("\\u{:04x}{}", root_hex.as_bytes()[0], &root_hex[1..]);
    let escaped = text
        .replace("\"tree_size\"", "\"tree_siz\\u0065\"")
        .replacen(&root_hex, &escaped_root, 1);
    assert!(verify_membership(BATCH_RECORDS[1], escaped.as_bytes(), size, &root).is_ok());

    // Duplicate fields stay rejected, even when one copy is escaped.
    let dup = text.replace(
        "\"leaf_index\":1",
        "\"leaf_index\":1,\"leaf_inde\\u0078\":1",
    );
    assert!(matches!(
        verify_membership(BATCH_RECORDS[1], dup.as_bytes(), size, &root),
        Err(VerifyError::MalformedProof(_))
    ));
}

// --- duplicate content is position-specific ---------------------------------

#[test]
fn library_duplicate_content_is_verified_at_the_claimed_position_only() {
    let batch = batch_file();
    let root = batch_root();
    let size = BATCH_RECORDS.len() as u64;
    // "x" sits at positions 0 and 4. Each proof verifies only its own
    // position; the other position's proof must not substitute.
    let proof0 = cli_proof(&batch, 0);
    let proof4 = cli_proof(&batch, 4);
    assert_ne!(proof0, proof4, "same content, different positions, different proofs");
    assert_eq!(verify_membership(b"x", &proof0, size, &root).unwrap().leaf_index(), 0);
    assert_eq!(verify_membership(b"x", &proof4, size, &root).unwrap().leaf_index(), 4);
    // Reclaiming position 0 with the position-4 proof (edit leaf_index) fails.
    let moved = String::from_utf8(proof4).unwrap().replace("\"leaf_index\":4", "\"leaf_index\":0");
    assert!(matches!(
        verify_membership(b"x", moved.as_bytes(), size, &root),
        Err(VerifyError::VerificationFailed(_))
    ));
}

// --- 64-bit sizes and indices are never truncated ---------------------------
//
// The same synthetic big-tree proofs as tests/verify_big_tree_regression.rs:
// the trusted roots are fixed constants generated by
// tests/reference/rfc6962_vectors.py with two independent implementations.

const BIG_TREE_RECORD: &[u8] = b"big-tree-record\x00\xff\xfe";

struct BigCase {
    size: u64,
    index: u64,
    depth: usize,
    root: &'static str,
}

const BIG_TREE_CASES: &[BigCase] = &[
    // 2**63 (power-of-two tree), record 2**32 (first index past 32 bits).
    BigCase { size: 9223372036854775808, index: 4294967296, depth: 63, root: "afcfe7edcae41e08965824b245fd42bd162c459feecedd1bf581349b664d8ebe" },
    // 2**63+1 (uneven), last record = lone right subtree, one-hash path.
    BigCase { size: 9223372036854775809, index: 9223372036854775808, depth: 1, root: "e3004442ff263eaa1f454e07a87f17253cb9aadc06d4e2df78e23db1b3f82fd3" },
    // 2**64-1 (uneven), first record.
    BigCase { size: 18446744073709551615, index: 0, depth: 64, root: "00374def40979015a9865a6e90b2fbd6effc8e235befab92877dcdf5e63f0361" },
    // 2**64-1 (uneven), last record.
    BigCase { size: 18446744073709551615, index: 18446744073709551614, depth: 63, root: "c035bef423e3cc7dcaa0a23687221787e739ef1ad6717b6c9e562addde480fc6" },
];

fn big_proof(case: &BigCase) -> Vec<u8> {
    let mut out = format!(
        "{{\"tree_size\":{},\"leaf_index\":{},\"root\":\"{}\",\"audit_path\":[",
        case.size, case.index, case.root
    );
    for i in 0..case.depth {
        if i > 0 {
            out.push(',');
        }
        out.push_str(&format!("\"{i:064x}\""));
    }
    out.push_str("]}");
    out.into_bytes()
}

#[test]
fn library_big_tree_sizes_and_indices_keep_64bit_meaning() {
    for case in BIG_TREE_CASES {
        let proof = big_proof(case);
        let root = hash_of(case.root);
        let m = verify_membership(BIG_TREE_RECORD, &proof, case.size, &root).unwrap_or_else(|e| {
            panic!("tree_size={} leaf_index={} must verify: {e}", case.size, case.index)
        });
        // The full-width values come back untruncated.
        assert_eq!(m.leaf_index(), case.index);
        assert_eq!(m.tree_size(), case.size);
        assert_eq!(m.root(), &root);

        // Off-by-one trusted size fails rather than truncating.
        assert!(matches!(
            verify_membership(BIG_TREE_RECORD, &proof, case.size - 1, &root),
            Err(VerifyError::VerificationFailed(_))
        ));
        // Off-by-one claimed index fails rather than wrapping. (The last
        // record of the 2^64-1 tree cannot move up: index == tree_size is a
        // format error, so that case moves down instead.)
        let off_index = if case.index + 1 < case.size {
            case.index + 1
        } else {
            case.index - 1
        };
        let moved_proof = String::from_utf8(big_proof(case))
            .unwrap()
            .replace(
                &format!("\"leaf_index\":{}", case.index),
                &format!("\"leaf_index\":{off_index}"),
            );
        assert!(matches!(
            verify_membership(BIG_TREE_RECORD, moved_proof.as_bytes(), case.size, &root),
            Err(VerifyError::VerificationFailed(_))
        ));
    }
}
