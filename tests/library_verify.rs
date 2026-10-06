//! Library-API regression tests for
//! `roottrace::{verify_inclusion, VerifiedInclusion, VerifyInclusionError}`.
//!
//! These tests treat roottrace strictly as an external crate: only public
//! items are used, inputs and outputs live in memory (no record/proof
//! temporary files are handed to the API), and the trusted tree size and
//! root are passed as a `u64` and a `[u8; 32]`. Real proof JSON is produced
//! by the `roottrace prove` binary over a temporary BATCH file (the only
//! place files appear), and trusted roots by `roottrace root`; the big-tree
//! constants are copied from the independent reference vectors also used by
//! `verify_big_tree_regression.rs`.
//!
//! Coverage:
//!   * success returns a TYPED result: leaf_index (0-based, the claimed
//!     position only), tree_size and root, the latter two already checked
//!     against the caller's trusted values
//!   * the whole record slice is content: empty slice is an empty record;
//!     trailing LF/CR/space/NUL and non-UTF-8 bytes all take part, with no
//!     batch-style LF splitting
//!   * errors are typed: invalid proof format vs verification failure vs
//!     invalid calling argument (zero trusted tree size), and zero is
//!     rejected even when the proof bytes themselves are garbage
//!   * field reordering, whitespace and equivalent string escapes are
//!     accepted; duplicate fields (also when the duplicate name is escape
//!     spelled), illegal integers and illegal hashes are InvalidProof
//!   * a one-record tree verifies only with an empty path
//!   * identical content elsewhere never substitutes for the claimed
//!     position
//!   * tree sizes/indices at the unsigned 64-bit boundary keep their exact
//!     meaning

mod common;

use std::process::Command;

use common::{join_lf, TempFile};

use roottrace::{verify_inclusion, VerifiedInclusion, VerifyInclusionError};

// --- small helpers ----------------------------------------------------------

fn prove_cmd(batch: &std::path::Path, index: u64) -> Vec<u8> {
    let out = Command::new(common::bin())
        .arg("prove")
        .arg(batch)
        .arg(index.to_string())
        .output()
        .expect("failed to run roottrace prove");
    assert!(out.status.success(), "prove failed: {}", String::from_utf8_lossy(&out.stderr));
    // `prove` prints one JSON line terminated by LF. The API accepts
    // trailing whitespace, but strip the LF here so callers see the exact
    // object the way an in-memory producer would hand it over.
    let mut bytes = out.stdout;
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
    }
    bytes
}

fn root_cmd(batch: &std::path::Path) -> [u8; 32] {
    let out = Command::new(common::bin())
        .arg("root")
        .arg(batch)
        .output()
        .expect("failed to run roottrace root");
    assert!(out.status.success(), "root failed: {}", String::from_utf8_lossy(&out.stderr));
    let hex = std::str::from_utf8(out.stdout.trim_ascii()).expect("root is ASCII hex");
    decode_hex_32(hex)
}

fn decode_hex_32(hex: &str) -> [u8; 32] {
    assert_eq!(hex.len(), 64, "root must be 64 hex chars: {hex}");
    let mut out = [0u8; 32];
    for (i, pair) in hex.as_bytes().chunks_exact(2).enumerate() {
        let nib = |b: u8| -> u8 {
            match b {
                b'0'..=b'9' => b - b'0',
                b'a'..=b'f' => b - b'a' + 10,
                other => panic!("not lowercase hex: {other}"),
            }
        };
        out[i] = (nib(pair[0]) << 4) | nib(pair[1]);
    }
    out
}

/// Build a batch file from exact record bytes, generate the proof at `m`,
/// and return proof bytes plus the trusted root. Record bytes are known
/// verbatim here (the API never sees batch files).
struct Batch {
    _file: TempFile,
    path: std::path::PathBuf,
}

impl Batch {
    fn of(records: &[&[u8]], trailing_lf: bool) -> Self {
        let file = TempFile::create(&join_lf(records, trailing_lf));
        let path = file.path.clone();
        Batch { _file: file, path }
    }

    fn proof(&self, m: u64) -> Vec<u8> {
        prove_cmd(&self.path, m)
    }

    fn root(&self) -> [u8; 32] {
        root_cmd(&self.path)
    }
}

fn check(record: &[u8], proof: &[u8], size: u64, root: &[u8; 32]) -> VerifiedInclusion {
    verify_inclusion(record, proof, size, root)
        .unwrap_or_else(|e| panic!("verification must succeed, got {e:?}: {e}"))
}

// --- success result ---------------------------------------------------------

#[test]
fn success_result_carries_position_size_and_checked_root() {
    let sizes: Vec<usize> = (1..=18).chain([31, 32, 33, 63, 64, 65, 100, 127, 128, 257]).collect();
    for n in sizes {
        let records: Vec<Vec<u8>> = (0..n).map(|i| format!("record-{i:04}").into_bytes()).collect();
        let refs: Vec<&[u8]> = records.iter().map(|r| r.as_slice()).collect();
        let batch = Batch::of(&refs, false);
        let trusted_root = batch.root();
        let size = n as u64;
        for m in 0..n as u64 {
            let proof = batch.proof(m);
            let got = check(refs[m as usize], &proof, size, &trusted_root);
            // The position is exactly the one the proof claims.
            assert_eq!(got.leaf_index(), m, "n={n} m={m}");
            // Size and root come back as the independently trusted values,
            // having been compared with the proof's own fields.
            assert_eq!(got.tree_size(), size, "n={n} m={m}");
            assert_eq!(got.root(), trusted_root, "n={n} m={m}");
            assert_eq!(got.root_bytes(), &trusted_root, "n={n} m={m}");
        }
    }
}

#[test]
fn empty_slice_is_one_empty_record() {
    // Batch "\n" holds exactly one empty record (the trailing-LF file form
    // is required: join_lf without it would write a zero-byte file, which is
    // zero records); the root is the RFC leaf hash of the empty input.
    let batch = Batch::of(&[b""], true);
    let root = batch.root();
    let proof = batch.proof(0);
    // One-record tree: empty audit path.
    assert!(proof.windows(b"\"audit_path\":[]".len()).any(|w| w == b"\"audit_path\":[]"));
    let got = check(b"", &proof, 1, &root);
    assert_eq!(got.leaf_index(), 0);
    assert_eq!(got.tree_size(), 1);
    assert_eq!(got.root(), root);

    // Empty records inside a multi-record tree as well; the file must end on
    // LF so the final empty record is not swallowed by record splitting.
    let records: Vec<&[u8]> = vec![b"", b"x", b""];
    let batch = Batch::of(&records, true);
    let root = batch.root();
    for m in 0u64..3 {
        let proof = batch.proof(m);
        let got = check(records[m as usize], &proof, 3, &root);
        assert_eq!(got.leaf_index(), m);
    }
}

#[test]
fn every_record_byte_is_content_including_trailing_and_binary_bytes() {
    let bin: &[u8] = b"\xff\xfe\x00binary-tail\xff";
    let records: Vec<&[u8]> = vec![b"alpha", bin, b"beta"];
    let batch = Batch::of(&records, true); // trailing LF file form
    let root = batch.root();
    let proof = batch.proof(1);

    let got = check(bin, &proof, 3, &root);
    assert_eq!(got.leaf_index(), 1);

    // Appending or changing any byte changes the record: no LF splitting and
    // no trimming happens inside the library.
    for suffix in [b"\n".as_slice(), b" ", b"\r", b"\x00", b"\xff"] {
        let mut longer = bin.to_vec();
        longer.extend_from_slice(suffix);
        assert_eq!(
            verify_inclusion(&longer, &proof, 3, &root),
            Err(VerifyInclusionError::VerificationFailed),
            "appended suffix {suffix:?} must change the record"
        );
    }
    let mut flipped = bin.to_vec();
    *flipped.last_mut().unwrap() ^= 0x01;
    assert_eq!(
        verify_inclusion(&flipped, &proof, 3, &root),
        Err(VerifyInclusionError::VerificationFailed)
    );
}

// --- typed failures ---------------------------------------------------------

#[test]
fn zero_trusted_tree_size_is_an_invalid_argument_even_with_garbage_proof() {
    // Zero names a tree containing no record; it must never verify a
    // membership, and must be distinguishable from both other failures. It
    // is rejected before the proof is inspected.
    let root = [0u8; 32];
    for proof in [b"{\"tree_size\":0,\"leaf_index\":0,\"root\":\"0000000000000000000000000000000000000000000000000000000000000000\",\"audit_path\":[]}".as_slice(), b"", b"not json at all"] {
        assert_eq!(
            verify_inclusion(b"x", proof, 0, &root),
            Err(VerifyInclusionError::InvalidArgument),
            "proof {proof:?}"
        );
    }
}

#[test]
fn malformed_proof_bytes_are_invalid_proof_not_verification_failures() {
    let records: Vec<&[u8]> = vec![b"a", b"b"];
    let batch = Batch::of(&records, false);
    let root = batch.root();
    let good = String::from_utf8(batch.proof(0)).unwrap();

    let plain: &[&[u8]] = &[
        b"",
        b"   ",
        b"null",
        b"[]",
        b"123",
        b"{}",
        b"{",
        b"{\"tree_size\":2}",
        b"[{\"tree_size\":2,\"leaf_index\":0,\"root\":\"0000000000000000000000000000000000000000000000000000000000000000\",\"audit_path\":[]}]",
    ];
    for case in plain {
        assert_eq!(
            verify_inclusion(b"a", case, 2, &root),
            Err(VerifyInclusionError::InvalidProof),
            "must be an invalid proof: {case:?}"
        );
    }

    let mutated: Vec<String> = vec![
        good.replace("\"tree_size\":2", "\"tree_size\":\"2\""),
        good.replace("\"tree_size\":2", "\"tree_size\":02"),
        good.replace("\"tree_size\":2", "\"tree_size\":2e0"),
        good.replace("\"tree_size\":2", "\"tree_size\":18446744073709551616"),
        good.replace("\"tree_size\":2", "\"tree_size\":1e400"),
        good.replace("\"tree_size\":2", "\"tree_size\":-2"),
        good.replace("\"audit_path\"", "\"auditpath\""),
        // leaf_index == tree_size: the claimed position does not exist.
        good.replace("\"leaf_index\":0", "\"leaf_index\":2"),
        // Trailing non-whitespace bytes after the object.
        format!("{good} extra"),
    ];
    for case in &mutated {
        assert_eq!(
            verify_inclusion(b"a", case.as_bytes(), 2, &root),
            Err(VerifyInclusionError::InvalidProof),
            "must be an invalid proof: {case:?}"
        );
    }

    // Truncated at several cut points.
    for cut in [0usize, 1, good.len() / 2, good.len() - 1] {
        assert_eq!(
            verify_inclusion(b"a", good.as_bytes()[..cut].as_ref(), 2, &root),
            Err(VerifyInclusionError::InvalidProof),
            "truncation at {cut} must be invalid"
        );
    }
}

#[test]
fn duplicate_fields_are_invalid_even_when_one_name_is_escape_spelled() {
    let records: Vec<&[u8]> = vec![b"a", b"b"];
    let batch = Batch::of(&records, false);
    let root = batch.root();
    let good = String::from_utf8(batch.proof(0)).unwrap();
    let h = &good[good.find("\"root\":\"").unwrap() + 8..good.find("\"root\":\"").unwrap() + 72];

    // Plain duplicate.
    let dup = |member: &str| {
        let close = good.rfind('}').unwrap();
        format!("{},{}}}", &good[..close], member)
    };
    for bad in [
        dup("\"tree_size\":2"),
        dup("\"leaf_index\":0"),
        dup(&format!("\"root\":\"{h}\"")),
        // The duplicate key decodes to the SAME name via a \uXXXX escape.
        dup("\"r\\u006fot\":\"0000000000000000000000000000000000000000000000000000000000000000\""),
        dup("\"\\u0074ree_size\":2"),
    ] {
        assert_eq!(
            verify_inclusion(b"a", bad.as_bytes(), 2, &root),
            Err(VerifyInclusionError::InvalidProof),
            "duplicate field must be invalid: {bad}"
        );
    }
}

#[test]
fn content_size_root_and_path_mismatches_are_verification_failures() {
    let records: Vec<&[u8]> = vec![b"a", b"b", b"c"];
    let batch = Batch::of(&records, false);
    let root = batch.root();
    let proof = batch.proof(1);
    let proof = String::from_utf8(proof).unwrap();

    // Wrong record bytes.
    for record in [b"a".as_slice(), b"b ", b"c", b"", b"B"] {
        assert_eq!(
            verify_inclusion(record, proof.as_bytes(), 3, &root),
            Err(VerifyInclusionError::VerificationFailed),
            "record {record:?}"
        );
    }
    // Trusted size differs while proof and record are untouched: the proof's
    // own tree_size must never substitute for the trusted one.
    for other in [1u64, 2, 4, 9, u64::MAX] {
        assert_eq!(
            verify_inclusion(b"b", proof.as_bytes(), other, &root),
            Err(VerifyInclusionError::VerificationFailed),
            "trusted size {other}"
        );
    }
    // Trusted root differs.
    let mut other_root = root;
    other_root[31] ^= 0x01;
    assert_eq!(
        verify_inclusion(b"b", proof.as_bytes(), 3, &other_root),
        Err(VerifyInclusionError::VerificationFailed)
    );

    // One path hash altered in content (same JSON shape, same hash count).
    let start = proof.find('[').unwrap() + 2;
    let mut swapped = proof.clone().into_bytes();
    swapped[start] = if swapped[start] == b'0' { b'1' } else { b'0' };
    assert_ne!(&swapped[start..start + 1], &proof.as_bytes()[start..start + 1]);
    assert_eq!(
        verify_inclusion(b"b", &swapped, 3, &root),
        Err(VerifyInclusionError::VerificationFailed)
    );

    // A well-formed proof whose root is uppercase never reaches this branch:
    // it is a format error instead.
    let upper = proof.replace(&h_of(&proof), &h_of(&proof).to_uppercase());
    assert_eq!(
        verify_inclusion(b"b", upper.as_bytes(), 3, &root),
        Err(VerifyInclusionError::InvalidProof)
    );
}

fn h_of(proof: &str) -> String {
    let start = proof.find("\"root\":\"").unwrap() + 8;
    proof[start..start + 64].to_string()
}

#[test]
fn one_record_tree_verifies_only_with_the_empty_path() {
    let records: Vec<&[u8]> = vec![b"only"];
    let batch = Batch::of(&records, false);
    let root = batch.root();
    let proof = batch.proof(0);
    check(b"only", &proof, 1, &root);

    // The array with one extra hash is well formed JSON but the geometry
    // check must reject the unconsumed hash.
    let with_extra = String::from_utf8(proof).unwrap().replace("\"audit_path\":[]", "\"audit_path\":[\"0000000000000000000000000000000000000000000000000000000000000000\"]");
    assert_eq!(
        verify_inclusion(b"only", with_extra.as_bytes(), 1, &root),
        Err(VerifyInclusionError::VerificationFailed)
    );
}

#[test]
fn identical_content_elsewhere_never_substitutes_for_the_claimed_position() {
    // b"x" at positions 0 and 2.
    let records: Vec<&[u8]> = vec![b"x", b"a", b"x"];
    let batch = Batch::of(&records, false);
    let root = batch.root();
    let proof2 = String::from_utf8(batch.proof(2)).unwrap();

    // The position-2 proof verifies b"x" at position 2.
    let got = check(b"x", proof2.as_bytes(), 3, &root);
    assert_eq!(got.leaf_index(), 2);

    // The SAME record and path with only the claimed index moved to 0 must
    // not be searched or repaired: verification fails, and no success value
    // exists for it.
    let moved = proof2.replace("\"leaf_index\":2", "\"leaf_index\":0");
    assert_eq!(
        verify_inclusion(b"x", moved.as_bytes(), 3, &root),
        Err(VerifyInclusionError::VerificationFailed)
    );
}

// --- format tolerance kept, strictness kept ---------------------------------

#[test]
fn reordered_pretty_and_equivalently_escaped_proofs_verify() {
    let records: Vec<&[u8]> = vec![b"a", b"b", b"c"];
    let batch = Batch::of(&records, false);
    let root = batch.root();
    let compact = batch.proof(1);
    check(b"b", &compact, 3, &root);

    let compact = String::from_utf8(compact).unwrap();
    // Extract the three values and rebuild in a different order with
    // arbitrary whitespace.
    let size = json_u64(&compact, "tree_size");
    let index = json_u64(&compact, "leaf_index");
    let h = json_string(&compact, "root");
    let path_hashes = json_array_strings(&compact, "audit_path");
    let pretty = format!(
        "  {{\n  \"audit_path\" : [ {} ] ,\n  \"root\": \"{}\",\r\n\t\"leaf_index\": {} , \"tree_size\": {}\n}}\n",
        path_hashes
            .iter()
            .map(|s| format!("\"{s}\""))
            .collect::<Vec<_>>()
            .join(", "),
        h,
        index,
        size,
    );
    check(b"b", pretty.as_bytes(), 3, &root);

    // Equivalent \uXXXX spellings of the field names and of hash characters
    // decode to the same proof.
    let escaped_key = compact.replace("\"tree_size\"", "\"\\u0074ree_size\"");
    check(b"b", escaped_key.as_bytes(), 3, &root);
    let escaped_key2 = compact.replace("\"audit_path\"", "\"audit\\u005fp\\u0061th\"");
    check(b"b", escaped_key2.as_bytes(), 3, &root);
    // Escape the first character of the root string (all these roots start
    // with a lowercase hex digit); the decoded hash must still match.
    let first = h.chars().next().unwrap();
    let escaped_root = compact.replacen(
        &format!("\"root\":\"{first}"),
        &format!("\"root\":\"\\u{:04x}", first as u32),
        1,
    );
    assert_ne!(escaped_root, compact, "the proof text must actually change");
    check(b"b", escaped_root.as_bytes(), 3, &root);
}

fn json_u64(json: &str, key: &str) -> u64 {
    let needle = format!("\"{key}\":");
    let start = json.find(&needle).unwrap() + needle.len();
    let rest = &json[start..];
    let end = rest
        .bytes()
        .position(|b| !b.is_ascii_digit())
        .unwrap_or(rest.len());
    rest[..end].parse().unwrap()
}

fn json_string(json: &str, key: &str) -> String {
    let needle = format!("\"{key}\":\"");
    let start = json.find(&needle).unwrap() + needle.len();
    let end = json[start..].find('"').unwrap() + start;
    json[start..end].to_string()
}

fn json_array_strings(json: &str, key: &str) -> Vec<String> {
    let needle = format!("\"{key}\":[");
    let start = json.find(&needle).unwrap() + needle.len();
    let end = json[start..].find(']').unwrap() + start;
    json[start..end]
        .split(',')
        .map(|piece| {
            let s = piece.trim();
            assert!(s.starts_with('"') && s.ends_with('"'));
            s[1..s.len() - 1].to_string()
        })
        .collect()
}

// --- unsigned 64-bit boundary ------------------------------------------------

const BIG_TREE_RECORD: &[u8] = b"big-tree-record\x00\xff\xfe";

struct BigCase {
    size: u64,
    index: u64,
    depth: usize,
    root: &'static str,
}

// Copied from tests/reference/rfc6962_vectors.py via
// verify_big_tree_regression.rs: two structurally different independent
// reference computations agree on every constant.
const BIG_CASES: &[BigCase] = &[
    BigCase { size: 9223372036854775808, index: 0, depth: 63, root: "ee3d1ca8d1cb646feeaa90be0fb22c6d8674b545ab84e113a3fe41af630838dc" },
    BigCase { size: 9223372036854775808, index: 4294967296, depth: 63, root: "afcfe7edcae41e08965824b245fd42bd162c459feecedd1bf581349b664d8ebe" },
    // 2^63+1, last record = lone right subtree leaf: exactly one path hash.
    BigCase { size: 9223372036854775809, index: 9223372036854775808, depth: 1, root: "e3004442ff263eaa1f454e07a87f17253cb9aadc06d4e2df78e23db1b3f82fd3" },
    BigCase { size: 18446744073709551615, index: 0, depth: 64, root: "00374def40979015a9865a6e90b2fbd6effc8e235befab92877dcdf5e63f0361" },
    BigCase { size: 18446744073709551615, index: 18446744073709551614, depth: 63, root: "c035bef423e3cc7dcaa0a23687221787e739ef1ad6717b6c9e562addde480fc6" },
];

fn big_proof(size: u64, index: u64, root: &str, depth: usize) -> Vec<u8> {
    let path: Vec<String> = (0..depth).map(|i| format!("{i:064x}")).collect();
    format!(
        "{{\"tree_size\":{size},\"leaf_index\":{index},\"root\":\"{root}\",\"audit_path\":[{}]}}",
        path.iter()
            .map(|h| format!("\"{h}\""))
            .collect::<Vec<_>>()
            .join(",")
    )
    .into_bytes()
}

#[test]
fn big_tree_proofs_verify_with_exact_64_bit_values() {
    for case in BIG_CASES {
        let proof = big_proof(case.size, case.index, case.root, case.depth);
        let root = decode_hex_32(case.root);
        let got = check(BIG_TREE_RECORD, &proof, case.size, &root);
        assert_eq!(got.leaf_index(), case.index);
        assert_eq!(got.tree_size(), case.size);
        assert_eq!(got.root(), root);
    }
}

#[test]
fn big_tree_values_are_not_truncated_or_taken_from_the_proof() {
    let case = &BIG_CASES[0]; // 2^63, first record
    let proof = big_proof(case.size, case.index, case.root, case.depth);
    let root = decode_hex_32(case.root);

    // Adjacent trusted sizes: off by one, or a different legal size, must
    // fail even though record and path are untouched.
    for other in [case.size - 1, case.size + 1, 4294967296, 0x7fff_ffff_ffff_ffff] {
        assert_eq!(
            verify_inclusion(BIG_TREE_RECORD, &proof, other, &root),
            Err(VerifyInclusionError::VerificationFailed),
            "trusted size {other}"
        );
    }
    // Zero at this boundary is an invalid argument, not a failure.
    assert_eq!(
        verify_inclusion(BIG_TREE_RECORD, &proof, 0, &root),
        Err(VerifyInclusionError::InvalidArgument)
    );

    // Reusing the proof with the claimed index moved by one changes the
    // geometry: an implementation that truncates to 32 bits would conflate
    // positions (the 2^32 case from the fixed vector is used for this).
    let cross = &BIG_CASES[1];
    for shifted in [cross.index - 1, cross.index + 1] {
        let proof = big_proof(cross.size, shifted, cross.root, cross.depth);
        let root = decode_hex_32(cross.root);
        assert_eq!(
            verify_inclusion(BIG_TREE_RECORD, &proof, cross.size, &root),
            Err(VerifyInclusionError::VerificationFailed),
            "index {shifted} must not verify with the {} proof",
            cross.index
        );
    }
}

#[test]
fn max_tree_index_equal_to_size_is_invalid_proof() {
    // The valid last-record case of a 2^64-1 tree, with only the position
    // bumped to leaf_index == tree_size: format error, kept distinct from a
    // cryptographic failure.
    let size = 18446744073709551615u64;
    let root = decode_hex_32("c035bef423e3cc7dcaa0a23687221787e739ef1ad6717b6c9e562addde480fc6");
    let proof = big_proof(size, size, "c035bef423e3cc7dcaa0a23687221787e739ef1ad6717b6c9e562addde480fc6", 63);
    assert_eq!(
        verify_inclusion(BIG_TREE_RECORD, &proof, size, &root),
        Err(VerifyInclusionError::InvalidProof)
    );
}

// --- error type ergonomics --------------------------------------------------

#[test]
fn error_type_is_copy_send_sync_and_displays_distinctly() {
    fn assert_bounds<T: Copy + Send + Sync + Unpin>() {}
    assert_bounds::<VerifyInclusionError>();
    assert_bounds::<VerifiedInclusion>();

    assert_eq!(VerifyInclusionError::InvalidProof.to_string(), "invalid proof");
    assert_eq!(
        VerifyInclusionError::VerificationFailed.to_string(),
        "verification failed"
    );
    assert_eq!(
        VerifyInclusionError::InvalidArgument.to_string(),
        "invalid argument"
    );

    // Usable through the standard Error trait.
    fn as_error(e: &VerifyInclusionError) -> &dyn std::error::Error {
        e
    }
    assert_eq!(as_error(&VerifyInclusionError::InvalidProof).to_string(), "invalid proof");

    // A failure never carries a success value: the Err variant exhausts the
    // failure cases by construction.
    let res: Result<VerifiedInclusion, VerifyInclusionError> =
        Err(VerifyInclusionError::VerificationFailed);
    assert!(matches!(res, Err(VerifyInclusionError::VerificationFailed)));
}
