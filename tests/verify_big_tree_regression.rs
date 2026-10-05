//! End-to-end regression tests for `roottrace verify` on HUGE trees: tree
//! sizes 2^63 (9223372036854775808, a power of two), 2^63 + 1
//! (9223372036854775809) and 2^64 - 1 (18446744073709551615), the uneven
//! extremes of the unsigned 64-bit range.
//!
//! Batches this large cannot be materialised, and they do not need to be:
//! `verify` exists precisely so that a receiver holding one record, its
//! proof, and an independently confirmed tree size and root can check
//! membership without ever seeing the batch. The fixed vectors below are
//! generated independently of roottrace by
//! `tests/reference/rfc6962_vectors.py`: the sibling hashes are openly
//! derived stand-ins for the subtree hashes (SHA-256 of
//! "big-tree-sibling-<i>"), each case consumes the pool in rotation from
//! its own offset, and every root is folded from the record bytes and the
//! siblings by TWO structurally different verifiers (the recursive RFC
//! 6962 geometry and the bit-driven fold used by CT implementations),
//! which must agree. Nothing here is derived from roottrace output.
//!
//! Coverage:
//!   * first, last and left/right-subtree-boundary positions of all three
//!     tree sizes verify, with leaf indices far beyond 32 bits: stdout is
//!     exactly "verified\n", exit 0, stderr empty
//!   * the trusted tree size on the command line keeps its exact 64-bit
//!     integer meaning — not truncated to 32 bits, not sign-flipped, never
//!     mistaken for a smaller batch — and the proof's own tree_size can
//!     never substitute for it (same record and path, another legal
//!     trusted size: cryptographic failure, not success)
//!   * uneven trees keep the RFC 6962 shape (no padding, no duplicated
//!     tail record): the lone right-subtree leaf of 2^63+1 has a
//!     one-hash path, the last leaf of 2^64-1 a 63-hash one
//!   * a path one hash short, one hash long, or with one hash altered
//!     fails as a cryptographic mismatch: exit 1, empty stdout, stderr
//!     says "verification failed" — not a usage error, not "invalid
//!     proof", no abnormal termination
//!   * leaf_index == tree_size (including the maximum tree size, where
//!     the index is u64::MAX) is an INVALID PROOF, kept distinct from a
//!     cryptographic verification failure
//!   * the record file is still taken verbatim at huge tree sizes

mod common;

use std::process::Command;

use common::TempFile;

// --- Fixed big-tree vectors (copied from the reference generator) ----------

const REC_BIG_TREE: &[u8] = b"big-tree-record:\x00\xff\xfetail\r";
const BIG_TREE_SIBLINGS: &[&str] = &["1a872bf70e2697195d1017b2f01934b9ca139c3f4f8c230df962907f15ba001b", "9693e28491f8c5c4f573bdf992edbc6381446381673053c5c968db2db125d0bc", "5eb2da4052c7413fa663e3649efe3e020baa6a033d3f7c8915b94feef956a4b4", "956443d56f9b9808f2811482b3f7868d1f7efe141390f3eeefffe6dc452b573a", "e86e1e92d21c605fd611b0463f1c0e7be10b92d0d4ec05ce524faf9458290e24", "ebae0ea7fdbe417b8090d317d03e398b996b191411d45921910cbb7d2b296dc6", "02be23c51e91f35b1e02c304ce0865fe15540349073f3ae9c4ed741beefbb009", "b8ac701edb2bfa887a3855abfa0c88299eecc9db52eed26f225aad7c45929a5f", "df63572ebcc082fa71f6547889a830642f45457511cdbce1dca9b30748b9f272", "23fc3bcff4759a291e5729d80c17099248fa206cc6402c0e9a5d690b7ea39b76", "45ab41aef661dcc2e9aaec9c6206bea238ef6e0743678e3d5c01e24b3144bb16", "ba72542753aa1ac8d89797eae6bf73e58a11a3ff30c585f11730e9b9fc1b28f7", "d1d345adec5105db578d324bd0528f39103d6eeab0f0a36bafaf9686446aef99", "a3cee27a2b1ccbcbc1c2a1e3999ed3eb3aee821eea90963aac2c2865571d40c9", "cae4b014548d07acd636035ea0d75be3e195f107ccff3c21c63492d84f2779f7", "59aa39dea5c86371bab4936939ca4322bf448ac207941496ff770838176122f2", "092ba7b83ff85443063d83ab56291d971014ebc34e51510ea33e3734343f296a", "50f85c77bf1d31baaec01104f73cdfefe39bd9ef9885d048063bec10080735c7", "44f8475b18d75091428713f03be2747dcdff3741d0fec0daf54b6159e1c4912b", "fbb18b9ba2ebd87a7eb04e1209748b20d6de331e58cb4fc803991a26ce22b2a1", "61defd8a0d3f0c701288e3b14220669ab64b0417dcc6d75e0fe420566f45cda1", "1dbd554fd9f43796351bcc833de696336cb513aaf84ae94d7eb736e3cdf36223", "301071c7a67aa485b69d1918b275cf195f09574066d14f435c0433859ae5b0c1", "fa0c5b8e8bc3b6281ab6235c83b25a275abb0526666216cb93450598de8fd4b9", "9855e68b12e761774d2d0db0003d3805140ac4b512580aa8d4cf45a709351a86", "3d6f09f1b472bc62a1851f09a446946bff32ed5ef3a91239d5e0cf4f30b4850d", "31c47d868348f53c25711e775b4ec7159f288bf44f6a8f46e77b3efdb4fb7e19", "9060bf3470007594f895b638bf5b57b01a1b125fa4c2b95f13224f206a037b24", "e818d09cfb25783197f2855810f92d2c1849671f027f42e108e249b83c325b5e", "339c98cd51a6554f324807aaf62691e0d9eec69b1d7dc68ea3dc452afba9a801", "c02ddbfa7b167c08bbcf593a8e8f48fa18efa5238d03e20324fc137567a6fff1", "eb7b29bb932363b1f09d50c6395c3d6b71ceb39966bfb516d7db9e7db30a4b68", "525ba6bd0a21367cfd938c73eeea81eb46560912ec6c031c93287ebf45f0ad86", "181e0b7281a6dd08a3963eb991bc05974886c8a1f7681cd35a0585db795c7767", "fdb992d32a6d237a8483421903c3304ce39ba33dd8da664bcd2e256f8bb7f12d", "ea874db0249737ba2c7b7b8d51fb1c56a282771c86be7f96d86b688212677b15", "7428500f26f490a15a3efa6c424969fa0c1dbe1449b36b7ac767c2e2890831d6", "407c1af8e7774b0e6150cfa2ca94e14014f7536fd147582abe5d466bd0a20492", "66ddc432a249d4eab3a98318398e033dbd356397334c3fc13b265dcf76a76586", "042541e28b8c8743a22cb722665f62718e4aff2ab34974b3d05949d871c3be2e", "923a4825703162e596422644a0bfbf2b7dce1640a3ca845bcc0428769899f2d2", "6efa054380ed25b1c7a396190a94f84d2e718a900bba7153be08f08befc50bb0", "0d7e3e5d32c326339e36daff9d41fa46d0a88294c28a77514454e07c7bb7a229", "83ac434038ad15b334fe5cca98188bd79e44174a59d6a95373c6804dbaf268f1", "f7e81f1990b6825083c512b85b50ed401241ede4f31aa42b0dd849521ca687cb", "e92654ea54a54a37388af59a3ce10ded88184ce6d997da1e2f217ba40c94c048", "91e92828eb7dd9b0cc51c68c35cf32cf7b02035707687d9f373c28ea7e177e6f", "21b212de8dcdbefb2426d84c0c05bd1d38d8a7dd522a3d2000c9873c0c41560f", "ff340c7d0e55e007b3218f943f6ab2f11704d394c35bb525b5369d0cb095493d", "692fcfec742ea5c2a72a74b5b4d4a2402c5d4d552ccb94399b878b7bd9053809", "5c9cd16f37fff1c2a273499b3d7feea98d5b74b4cd10f474e3c44b1a8f0ffeff", "41e9486efb0f6e0ec7c35c57a9a91da19a627d89c39cc54e948d0e9ab92b56c2", "4f89eb52aa76936a518fb7c404409b40d1e39aaedd30855a50d72a413a0b6b31", "8b22b5dad0138cd5cd2a79a197d31e305f3603be63d040d2fffb89491b9725f0", "07dd0b3b70f1c4745b5e4bb6065026b2dc6e04d0c517a23c592e2a227ec06998", "bd5cd9561b1144e82cf731672eea807c5e70b4fb01e8ef75198d740458d7a1a7", "60ce56b772c073731defe42cafbd96d66409234630cf6d388895433f04c7c46c", "ef367bc0af8be95ef6b7accb5ebee017d9039e929707462c322ea37157cea0f8", "882f3f363eb5fbf109b16eb9bf769d040ffe8736397aed21258cced98edc06ce", "6e016fc6bd8b06890cdc7a76277f579049031e4dd696d38105c09dcb723aa74d", "21ecefa115478c736d37981577508cd51b273d0d0c73613f18b8593f36cfb468", "cd59831c2c512a5ee69588df818f446f13627dc67651bf999eddf9f0f381d0da", "5892739cd79e0c4c1920c121e6f9fe2018d295320d53074241be63a3d59cd7c2", "d3a5f31c4cb0b5ef3d2b4ce05d29d42d172701860c912f7485530c73b3c811b3"];
// (tree_size, leaf_index, sibling offset, audit_path length, root);
// the audit path is BIG_TREE_SIBLINGS cycled from the offset.
const BIG_TREE_CASES: &[(u64, u64, usize, usize, &str)] = &[
    // P63_FIRST: first record of the balanced 2**63 tree
    (9223372036854775808, 0, 0, 63, "9178c3c3d428ed9719272a86f0032b6d3b8bdabb2c55735574dd358d52237292"),
    // P63_LEFT_OF_SPLIT: last record left of the top-level split of 2**63
    (9223372036854775808, 4611686018427387903, 6, 63, "18331122a88ec69c6c0efe36a2a73f32c7eb1662bc8558ee19668fc075e3a137"),
    // P63_RIGHT_OF_SPLIT: first record right of the top-level split of 2**63
    (9223372036854775808, 4611686018427387904, 12, 63, "28b6bc62cbb95e55a4d52f2f1677ff5136794b679b252e0cbf083ba45aac5d0d"),
    // P63_LAST: last record of the balanced 2**63 tree
    (9223372036854775808, 9223372036854775807, 18, 63, "be3449333cf2ca0d1fd52a24730fce997caee30d048c5c4eefa5ecac02d7f25c"),
    // P63P1_FIRST: first record of the uneven 2**63+1 tree
    (9223372036854775809, 0, 24, 64, "54cd98e2a284fb87340cc24840d8dd4078762d44e6239413cfd6b6bae317b3b5"),
    // P63P1_LEFT_OF_SPLIT: last record of the size-2**63 left subtree of 2**63+1
    (9223372036854775809, 9223372036854775807, 30, 64, "9a0d56f02001358eb64367bdf3882bd6d108009381af21fc4e2d818de6dba354"),
    // P63P1_LAST: lone right-subtree record of 2**63+1: path is a single hash (no padding, no duplicated tail)
    (9223372036854775809, 9223372036854775808, 36, 1, "38c47b1a538b9702198b3b613d68b40156ca5059ab318a023af350ee410487bc"),
    // MAX_FIRST: first record of the 2**64-1 tree
    (18446744073709551615, 0, 42, 64, "eed61125067bfd6910c6b8bf72557ab54f41cba4f10febb2c49584de54052d2b"),
    // MAX_LEFT_OF_SPLIT: last record of the size-2**63 left subtree of 2**64-1
    (18446744073709551615, 9223372036854775807, 48, 64, "0a8cd9dd58db5803efec17016be05418b41bfc69881c49ba68511a4488f1d5d2"),
    // MAX_RIGHT_OF_SPLIT: first record of the size-(2**63-1) right subtree of 2**64-1
    (18446744073709551615, 9223372036854775808, 54, 64, "67bc48b964537adf52d8dcb818e5040ac4cb352fc03b50fd967f8f4869e15843"),
    // MAX_LAST: last record of the 2**64-1 tree (uneven right spine)
    (18446744073709551615, 18446744073709551614, 60, 63, "982338f6342ec299974e43f17d9a2745c42310348fdb914c1d4041f95bcd22dc"),
];

const SIZE_P63: u64 = 9223372036854775808; // 2^63
const SIZE_P63P1: u64 = 9223372036854775809; // 2^63 + 1
const SIZE_MAX: u64 = 18446744073709551615; // 2^64 - 1

/// The audit path of a fixed case: the shared sibling pool cycled from the
/// case's offset, so cases whose RFC geometry coincides still anchor to
/// distinct roots.
fn big_path(offset: usize, len: usize) -> Vec<&'static str> {
    (0..len)
        .map(|i| BIG_TREE_SIBLINGS[(offset + i) % BIG_TREE_SIBLINGS.len()])
        .collect()
}

fn proof_json<S: AsRef<str>>(size: u64, index: u64, root: &str, path: &[S]) -> String {
    let mut out =
        format!("{{\"tree_size\":{size},\"leaf_index\":{index},\"root\":\"{root}\",\"audit_path\":[");
    for (i, h) in path.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push('"');
        out.push_str(h.as_ref());
        out.push('"');
    }
    out.push_str("]}");
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

/// A cryptographic mismatch: exit 1, empty stdout, stderr reports the
/// verification failure — never a usage error (exit 2), never "invalid
/// proof", never an abnormal termination (no exit code).
fn assert_verification_failed(desc: &str, record: &[u8], proof: &[u8], size: &str, root: &str) {
    let rec = TempFile::create(record);
    let prf = TempFile::create(proof);
    let out = run(&rec.path, &prf.path, size, root);
    assert_eq!(out.status.code(), Some(1), "[{desc}] must exit 1");
    assert!(out.stdout.is_empty(), "[{desc}] stdout must be empty, got {:?}", out.stdout);
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("verification failed"), "[{desc}] stderr: {err}");
    assert!(!err.contains("invalid proof"), "[{desc}] stderr: {err}");
    assert!(!err.contains("Usage"), "[{desc}] stderr: {err}");
}

/// A malformed proof: exit 1, empty stdout, stderr reports the format
/// problem — kept distinct from a cryptographic verification failure.
fn assert_invalid_proof(desc: &str, record: &[u8], proof: &[u8], size: &str, root: &str) {
    let rec = TempFile::create(record);
    let prf = TempFile::create(proof);
    let out = run(&rec.path, &prf.path, size, root);
    assert_eq!(out.status.code(), Some(1), "[{desc}] must exit 1");
    assert!(out.stdout.is_empty(), "[{desc}] stdout must be empty, got {:?}", out.stdout);
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("invalid proof"), "[{desc}] stderr: {err}");
    assert!(!err.contains("verification failed"), "[{desc}] stderr: {err}");
    assert!(!err.contains("Usage"), "[{desc}] stderr: {err}");
}

// --- Success: every fixed big-tree vector verifies --------------------------

#[test]
fn big_tree_proofs_verify_at_first_last_and_split_boundary_positions() {
    for &(size, index, offset, depth, root) in BIG_TREE_CASES {
        let path = big_path(offset, depth);
        let proof = proof_json(size, index, root, &path);
        assert_verified(
            &format!("tree_size={size} leaf_index={index}"),
            REC_BIG_TREE,
            proof.as_bytes(),
            &size.to_string(),
            root,
        );
    }
}

#[test]
fn fixed_vectors_cover_positions_beyond_32_bits_for_every_big_size() {
    // First/last/boundary positions: for each of the three tree sizes at
    // least one fixed position lies past the 32-bit range (in fact all
    // non-zero positions here do, up to 2^64 - 2).
    for size in [SIZE_P63, SIZE_P63P1, SIZE_MAX] {
        assert!(
            BIG_TREE_CASES
                .iter()
                .any(|&(s, m, ..)| s == size && m > u64::from(u32::MAX)),
            "no >32-bit position fixed for tree size {size}"
        );
    }
}

// --- Trusted tree size: exact 64-bit meaning, proof cannot self-anchor ------

#[test]
fn trusted_tree_size_keeps_exact_u64_meaning_and_proof_cannot_self_anchor() {
    // The proof for the last record of the 2^63 tree, presented with the
    // SAME record and path but a different (legal) trusted size: the
    // proof's own tree_size must not let it through. The rejected sizes
    // include the other two big sizes, 2^63-1, 2^32 (a truncation
    // artifact) and small batches — a size that lost its high bits would
    // land among these and must not succeed either.
    let &(size, index, offset, depth, root) = &BIG_TREE_CASES[3]; // P63_LAST
    assert_eq!(size, SIZE_P63);
    let proof = proof_json(size, index, root, &big_path(offset, depth));
    for other in [
        "1",
        "63",
        "4294967296",
        "9223372036854775807",
        "9223372036854775809",
        "18446744073709551615",
    ] {
        assert_verification_failed(
            &format!("2^63 proof against trusted size {other}"),
            REC_BIG_TREE,
            proof.as_bytes(),
            other,
            root,
        );
    }

    // Same for the maximum-size tree against 2^63 and 2^63+1.
    let &(size, index, offset, depth, root) = &BIG_TREE_CASES[10]; // MAX_LAST
    assert_eq!(size, SIZE_MAX);
    let proof = proof_json(size, index, root, &big_path(offset, depth));
    for other in ["9223372036854775808", "9223372036854775809", "18446744073709551614"] {
        assert_verification_failed(
            &format!("2^64-1 proof against trusted size {other}"),
            REC_BIG_TREE,
            proof.as_bytes(),
            other,
            root,
        );
    }
}

#[test]
fn big_tree_proof_cannot_anchor_to_another_root() {
    // Same tree size, same record and path, but the trusted root of a
    // DIFFERENT position's proof: cryptographic failure.
    for group in [&BIG_TREE_CASES[0..4], &BIG_TREE_CASES[4..7], &BIG_TREE_CASES[7..11]] {
        for (i, &(size, index, offset, depth, root)) in group.iter().enumerate() {
            let other_root = group[(i + 1) % group.len()].4;
            assert_ne!(root, other_root);
            let proof = proof_json(size, index, root, &big_path(offset, depth));
            assert_verification_failed(
                &format!("tree_size={size} leaf_index={index} with another position's root"),
                REC_BIG_TREE,
                proof.as_bytes(),
                &size.to_string(),
                other_root,
            );
        }
    }
}

// --- Path length and content are enforced at huge sizes ---------------------

#[test]
fn big_tree_path_must_have_exact_length_and_content() {
    // A balanced-tree position (63 hashes), the lone right-subtree leaf of
    // 2^63+1 (a single hash — the uneven RFC shape, no padding), and the
    // last leaf of 2^64-1 (63 hashes down the uneven right spine).
    for &(size, index, offset, depth, root) in
        &[BIG_TREE_CASES[2], BIG_TREE_CASES[6], BIG_TREE_CASES[10]]
    {
        let path = big_path(offset, depth);
        let desc = format!("tree_size={size} leaf_index={index}");
        // Sanity: the unmodified vector verifies.
        assert_verified(
            &desc,
            REC_BIG_TREE,
            proof_json(size, index, root, &path).as_bytes(),
            &size.to_string(),
            root,
        );

        // One hash missing.
        assert_verification_failed(
            &format!("{desc}: path one hash short"),
            REC_BIG_TREE,
            proof_json(size, index, root, &path[..depth - 1]).as_bytes(),
            &size.to_string(),
            root,
        );

        // One hash too many (the next pool sibling is well-formed but must
        // remain unconsumed).
        let mut long = path.clone();
        long.push(BIG_TREE_SIBLINGS[(offset + depth) % BIG_TREE_SIBLINGS.len()]);
        assert_verification_failed(
            &format!("{desc}: path one hash too long"),
            REC_BIG_TREE,
            proof_json(size, index, root, &long).as_bytes(),
            &size.to_string(),
            root,
        );

        // One hash altered in content (same length, still lowercase hex).
        let mut altered: Vec<String> = path.iter().map(|h| h.to_string()).collect();
        let mid = &mut altered[depth / 2];
        let replacement = if mid.starts_with('0') { '1' } else { '0' };
        mid.replace_range(..1, &replacement.to_string());
        assert_verification_failed(
            &format!("{desc}: one path hash altered"),
            REC_BIG_TREE,
            proof_json(size, index, root, &altered).as_bytes(),
            &size.to_string(),
            root,
        );
    }
}

// --- leaf_index == tree_size is a format error, not a crypto failure --------

#[test]
fn big_tree_index_equal_to_tree_size_is_an_invalid_proof() {
    let root = BIG_TREE_CASES[0].4;
    // At the maximum tree size the out-of-range index is u64::MAX itself:
    // it parses as an integer but names no position, so the proof is
    // FORMAT-invalid — distinct from a cryptographic failure at a legal
    // position. The same boundary holds for the other big sizes, and an
    // index beyond the tree size is invalid as well.
    for (size, index) in [
        (SIZE_MAX, SIZE_MAX),
        (SIZE_P63, SIZE_P63),
        (SIZE_P63P1, SIZE_P63P1),
        (SIZE_P63, SIZE_MAX),
    ] {
        let proof = proof_json(size, index, root, &big_path(0, 1));
        assert_invalid_proof(
            &format!("leaf_index {index} in a tree of {size}"),
            REC_BIG_TREE,
            proof.as_bytes(),
            &size.to_string(),
            root,
        );
    }
}

// --- Record bytes are still verbatim at huge tree sizes ---------------------

#[test]
fn big_tree_record_file_bytes_are_verbatim() {
    let &(size, index, offset, depth, root) = &BIG_TREE_CASES[0]; // P63_FIRST
    let proof = proof_json(size, index, root, &big_path(offset, depth));
    let size_arg = size.to_string();

    // The fixed record (which itself carries NUL, non-UTF-8 and a trailing
    // CR) verifies; any added or flipped byte changes the record.
    assert_verified("exact record bytes", REC_BIG_TREE, proof.as_bytes(), &size_arg, root);

    let mut with_lf = REC_BIG_TREE.to_vec();
    with_lf.push(b'\n');
    assert_verification_failed("record + trailing LF", &with_lf, proof.as_bytes(), &size_arg, root);

    let mut with_nul = REC_BIG_TREE.to_vec();
    with_nul.push(b'\x00');
    assert_verification_failed("record + trailing NUL", &with_nul, proof.as_bytes(), &size_arg, root);

    let mut flipped = REC_BIG_TREE.to_vec();
    flipped[0] ^= 0x01;
    assert_verification_failed("first byte flipped", &flipped, proof.as_bytes(), &size_arg, root);

    assert_verification_failed("empty record file", b"", proof.as_bytes(), &size_arg, root);
}
