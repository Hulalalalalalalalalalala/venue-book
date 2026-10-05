use std::env;
use std::fs;
use std::process::ExitCode;

const VERSION: &str = "0.1.0";

const USAGE: &str = "\
Usage:
    roottrace root <file>
    roottrace prove <file> <record-index>
    roottrace --version

Commands:
    root <file>
        Print the SHA-256 RFC 6962 Merkle Tree Hash of all records in <file>
        as one line of 64 lowercase hexadecimal characters.

    prove <file> <record-index>
        Print the RFC 6962 section 2.1.1 inclusion (membership) proof for the
        record at <record-index> within the whole batch. The index is
        0-based and counts records in file order: 0 is the first record,
        1 the second, and so on; the same content at multiple positions gets
        the proof for the exact position given, with no deduplication. Output
        is one JSON object with the fields tree_size, leaf_index, root and
        audit_path (leaf-to-root hashes, lowercase hex; empty for a batch of
        exactly one record).

        Example:
            roottrace prove batch.txt 0

Exit status:
    0  success
    1  the file cannot be read, or the record index does not exist
    2  usage error (unknown command, missing or extra arguments, bad index)";

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    match args.as_slice() {
        [flag] if flag == "--version" => {
            println!("roottrace {VERSION}");
            ExitCode::SUCCESS
        }
        [cmd, path] if cmd == "root" => match merkle_root_of_file(path) {
            Ok(root) => {
                println!("{}", hex(&root));
                ExitCode::SUCCESS
            }
            Err(reason) => {
                eprintln!("roottrace: {reason}");
                ExitCode::FAILURE
            }
        },
        [cmd, path, index] if cmd == "prove" => match parse_index(index) {
            Some(index) => match proof_for_file(path, index) {
                Ok(proof) => {
                    println!("{}", proof);
                    ExitCode::SUCCESS
                }
                Err(ProveError::Read(reason)) => {
                    eprintln!("roottrace: {reason}");
                    ExitCode::FAILURE
                }
                Err(ProveError::Missing(index, size)) => {
                    if size == 0 {
                        eprintln!(
                            "roottrace: record index {index} does not exist: the file holds zero records"
                        );
                    } else {
                        eprintln!(
                            "roottrace: record index {index} does not exist: file holds {size} record(s), valid indices are 0 through {}",
                            size - 1
                        );
                    }
                    ExitCode::FAILURE
                }
            },
            None => {
                eprintln!("roottrace: invalid record index '{index}': expected a decimal non-negative integer of ASCII digits");
                eprintln!("{USAGE}");
                ExitCode::from(2)
            }
        },
        _ => {
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
    }
}

enum ProveError {
    Read(String),
    Missing(u64, u64),
}

fn merkle_root_of_file(path: &str) -> Result<[u8; 32], String> {
    let data = fs::read(path).map_err(|e| format!("cannot read '{path}': {e}"))?;
    Ok(mth(&split_records(&data)))
}

fn proof_for_file(path: &str, index: u64) -> Result<String, ProveError> {
    let data = fs::read(path).map_err(|e| ProveError::Read(format!("cannot read '{path}': {e}")))?;
    let records = split_records(&data);
    let size = records.len() as u64;
    if index >= size {
        return Err(ProveError::Missing(index, size));
    }
    let idx = index as usize;
    let (root, audit_path) = root_and_path(&records, idx);
    Ok(proof_json(size, index, &root, &audit_path))
}

/// Parse a record index: one or more ASCII decimal digits, non-negative, no
/// sign or whitespace, fitting in an unsigned 64-bit integer. Anything else
/// (including "+1", " 1", "1.0", "", "-1") is rejected.
fn parse_index(text: &str) -> Option<u64> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let mut value: u64 = 0;
    for b in text.bytes() {
        value = value.checked_mul(10)?.checked_add(u64::from(b - b'0'))?;
    }
    Some(value)
}

/// Build the one-line JSON object printed by `prove`: integer tree_size and
/// leaf_index, the lowercase-hex root, and the audit path as a JSON array of
/// lowercase-hex hashes ordered leaf to root.
fn proof_json(tree_size: u64, leaf_index: u64, root: &[u8; 32], audit_path: &[[u8; 32]]) -> String {
    let mut out = String::new();
    out.push_str("{\"tree_size\":");
    out.push_str(&tree_size.to_string());
    out.push_str(",\"leaf_index\":");
    out.push_str(&leaf_index.to_string());
    out.push_str(",\"root\":\"");
    out.push_str(&hex(root));
    out.push_str("\",\"audit_path\":[");
    for (i, node) in audit_path.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push('"');
        out.push_str(&hex(node));
        out.push('"');
    }
    out.push_str("]}");
    out
}

/// Split raw bytes into records on LF (0x0a). The separator is not part of
/// any record. A trailing LF terminates the last record without adding an
/// empty one; an empty file yields zero records.
fn split_records(data: &[u8]) -> Vec<&[u8]> {
    if data.is_empty() {
        return Vec::new();
    }
    let mut records: Vec<&[u8]> = data.split(|&b| b == b'\n').collect();
    if data.last() == Some(&b'\n') {
        records.pop();
    }
    records
}

/// RFC 6962 section 2.1 leaf hash: SHA-256(0x00 || data).
fn leaf_hash(data: &[u8]) -> [u8; 32] {
    let mut input = Vec::with_capacity(1 + data.len());
    input.push(0x00);
    input.extend_from_slice(data);
    sha256(&input)
}

/// RFC 6962 section 2.1 interior node hash: SHA-256(0x01 || left || right).
fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut input = Vec::with_capacity(65);
    input.push(0x01);
    input.extend_from_slice(left);
    input.extend_from_slice(right);
    sha256(&input)
}

/// RFC 6962 section 2.1 Merkle Tree Hash over SHA-256.
fn mth(leaves: &[&[u8]]) -> [u8; 32] {
    match leaves.len() {
        0 => sha256(&[]),
        1 => leaf_hash(leaves[0]),
        n => {
            // Largest power of two strictly smaller than n.
            let k = 1usize << (usize::BITS - 1 - (n - 1).leading_zeros());
            node_hash(&mth(&leaves[..k]), &mth(&leaves[k..]))
        }
    }
}

/// RFC 6962 section 2.1.1: the Merkle Tree Hash of the whole batch together
/// with the Merkle Audit Path for the record at `m`, computed in a single
/// traversal. Every leaf hash and every subtree hash is computed exactly
/// once: each interior hash on the path from the leaf to the root feeds both
/// the root computation and (for the sibling subtree) the audit path, so
/// producing a proof never rehashes a record byte or a subtree that already
/// contributed to the root.
///
/// ```text
/// PATH(m, [d0]) = []
/// PATH(m, [d0..d(n-1)]) = PATH(m, [d0..d(k-1)]) + MTH([dk..d(n-1)])   if m < k
///                       = PATH(m, [dk..d(n-1)]) + MTH([d0..d(k-1)])   if m >= k
/// ```
///
/// with k the largest power of two strictly smaller than n. Uneven batches
/// are handled by the recursion itself: no leaf is duplicated and no empty
/// record is appended to round the size up to a power of two. The returned
/// path is ordered from the leaf level up to the root.
fn root_and_path(leaves: &[&[u8]], m: usize) -> ([u8; 32], Vec<[u8; 32]>) {
    let n = leaves.len();
    assert!(m < n, "leaf index {m} out of range for {n} record(s)");
    let mut path = Vec::new();
    let root = root_and_path_rec(leaves, m, &mut path);
    (root, path)
}

fn root_and_path_rec(leaves: &[&[u8]], m: usize, path: &mut Vec<[u8; 32]>) -> [u8; 32] {
    let n = leaves.len();
    if n == 1 {
        return leaf_hash(leaves[0]);
    }
    // Largest power of two strictly smaller than n.
    let k = 1usize << (usize::BITS - 1 - (n - 1).leading_zeros());
    if m < k {
        let left = root_and_path_rec(&leaves[..k], m, path);
        let right = mth(&leaves[k..]);
        path.push(right);
        node_hash(&left, &right)
    } else {
        let left = mth(&leaves[..k]);
        let right = root_and_path_rec(&leaves[k..], m - k, path);
        path.push(left);
        node_hash(&left, &right)
    }
}

fn hex(digest: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in digest {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((b & 0x0f) as u32, 16).unwrap());
    }
    s
}

// --- SHA-256 (FIPS 180-4) ---

// Test-only instrumentation: counts sha256 invocations on the current thread
// (each test runs on its own thread) so a test can pin down exactly how many
// hashes a proof generation performs.
#[cfg(test)]
thread_local! {
    static SHA256_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

fn sha256(data: &[u8]) -> [u8; 32] {
    #[cfg(test)]
    SHA256_CALLS.with(|c| c.set(c.get() + 1));
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for block in msg.chunks_exact(64) {
        let mut w = [0u32; 64];
        for (i, word) in block.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    let mut out = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_of(d: &[u8; 32]) -> String {
        hex(d)
    }

    /// Verify an RFC 6962 inclusion proof with the RFC's recursive verifier:
    /// it re-derives the combination order from the tree geometry (k =
    /// largest power of two below the current subtree size) while consuming
    /// exactly the supplied sibling hashes. A wrong length, order or hash
    /// fails; the root computed here must equal the tree root.
    fn verify_proof(leaf: &[u8], m: usize, n: usize, path: &[[u8; 32]]) -> [u8; 32] {
        assert!(m < n);
        fn sub(leaf: &[u8], m: usize, n: usize, path: &[[u8; 32]], pos: &mut usize) -> [u8; 32] {
            if n == 1 {
                return leaf_hash(leaf);
            }
            let k = 1usize << (usize::BITS - 1 - (n - 1).leading_zeros());
            if m < k {
                let left = sub(leaf, m, k, path, pos);
                assert!(*pos < path.len(), "proof too short");
                let right = path[*pos];
                *pos += 1;
                node_hash(&left, &right)
            } else {
                let right = sub(leaf, m - k, n - k, path, pos);
                assert!(*pos < path.len(), "proof too short");
                let left = path[*pos];
                *pos += 1;
                node_hash(&left, &right)
            }
        }
        let mut pos = 0;
        let root = sub(leaf, m, n, path, &mut pos);
        assert_eq!(pos, path.len(), "proof too long: {pos} consumed of {}", path.len());
        root
    }

    #[test]
    fn sha256_known_vectors() {
        assert_eq!(
            hex_of(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex_of(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        // Longer than one block.
        assert_eq!(
            hex_of(&sha256(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    #[test]
    fn record_splitting() {
        assert_eq!(split_records(b""), Vec::<&[u8]>::new());
        assert_eq!(split_records(b"\n"), vec![b"".as_slice()]);
        assert_eq!(split_records(b"a\nb"), vec![b"a".as_slice(), b"b".as_slice()]);
        assert_eq!(split_records(b"a\nb\n"), vec![b"a".as_slice(), b"b".as_slice()]);
        assert_eq!(split_records(b"a\n\n"), vec![b"a".as_slice(), b"".as_slice()]);
        assert_eq!(split_records(b"a\n\n\n"), vec![b"a".as_slice(), b"".as_slice(), b"".as_slice()]);
        // CR is content, not a separator.
        assert_eq!(split_records(b"a\r\nb\r\n"), vec![b"a\r".as_slice(), b"b\r".as_slice()]);
        // Non-UTF-8 bytes are fine.
        assert_eq!(split_records(b"\xff\xfe\n\x00"), vec![b"\xff\xfe".as_slice(), b"\x00".as_slice()]);
    }

    #[test]
    fn mth_rfc6962() {
        // Empty tree: SHA-256 of empty input.
        assert_eq!(hex_of(&mth(&[])), hex_of(&sha256(b"")));
        // Single leaf: SHA-256(0x00 || leaf).
        let leaf = b"hello";
        let mut expect = vec![0x00];
        expect.extend_from_slice(leaf);
        assert_eq!(hex_of(&mth(&[leaf])), hex_of(&sha256(&expect)));
        // Two leaves: SHA-256(0x01 || L || R).
        let l = mth(&[b"a"]);
        let r = mth(&[b"b"]);
        let mut expect = vec![0x01];
        expect.extend_from_slice(&l);
        expect.extend_from_slice(&r);
        assert_eq!(hex_of(&mth(&[b"a", b"b"])), hex_of(&sha256(&expect)));
        // Three leaves: split k=2, right subtree is a single leaf.
        let left = mth(&[b"a", b"b"]);
        let right = mth(&[b"c"]);
        let mut expect = vec![0x01];
        expect.extend_from_slice(&left);
        expect.extend_from_slice(&right);
        assert_eq!(hex_of(&mth(&[b"a", b"b", b"c"])), hex_of(&sha256(&expect)));
    }

    #[test]
    fn audit_paths_verify_at_every_position_for_many_sizes() {
        // Sizes both sides of several power-of-two boundaries (uneven sizes
        // must not pad with empty or duplicated trailing records).
        let sizes: Vec<usize> = (1..=18).chain([31, 32, 33, 63, 64, 65, 100, 127, 128, 129, 257]).collect();
        for n in sizes {
            let records: Vec<Vec<u8>> = (0..n).map(|i| format!("record-{i:04}").into_bytes()).collect();
            let refs: Vec<&[u8]> = records.iter().map(|r| r.as_slice()).collect();
            let root = mth(&refs);
            for m in 0..n {
                let (fused_root, path) = root_and_path(&refs, m);
                assert_eq!(
                    hex_of(&fused_root),
                    hex_of(&root),
                    "single-pass root must equal mth at n={n}, m={m}"
                );
                if n == 1 {
                    assert!(path.is_empty(), "single record must have an empty path");
                } else {
                    // Path length is bounded by the tree depth; for an even
                    // power-of-two batch every position sits at full depth.
                    let depth = usize::BITS - (n - 1).leading_zeros();
                    if n.is_power_of_two() {
                        assert_eq!(path.len(), depth as usize, "n={n}, m={m}");
                    } else {
                        assert!(path.len() <= depth as usize, "n={n}, m={m}");
                    }
                }
                let computed = verify_proof(refs[m], m, n, &path);
                assert_eq!(hex_of(&computed), hex_of(&root), "proof mismatch at n={n}, m={m}");
            }
        }
    }

    #[test]
    fn proof_generation_hashes_every_leaf_and_subtree_exactly_once() {
        // A batch of n records has n leaf hashes and n - 1 interior node
        // hashes. Computing the root and one audit path in a single pass must
        // cost exactly 2n - 1 SHA-256 invocations: the old two-phase
        // implementation (mth for the root, then inclusion_path recomputing
        // the sibling subtrees) needed strictly more for any n >= 2.
        for n in [1usize, 2, 3, 4, 5, 8, 9, 10, 16, 33] {
            let records: Vec<Vec<u8>> = (0..n).map(|i| format!("record-{i:04}").into_bytes()).collect();
            let refs: Vec<&[u8]> = records.iter().map(|r| r.as_slice()).collect();
            for m in 0..n {
                SHA256_CALLS.with(|c| c.set(0));
                let _ = root_and_path(&refs, m);
                let calls = SHA256_CALLS.with(|c| c.get());
                assert_eq!(
                    calls,
                    2 * n - 1,
                    "n={n}, m={m}: expected {n} leaf + {} interior hashes, each computed once",
                    n - 1
                );
            }
        }
    }

    #[test]
    fn single_record_audit_path_is_empty_but_fields_still_present() {
        let records = [b"only".as_slice()];
        let (root, path) = root_and_path(&records, 0);
        assert!(path.is_empty());
        assert_eq!(hex_of(&root), hex_of(&mth(&records)));
        let json = proof_json(1, 0, &root, &path);
        assert_eq!(
            json,
            format!(
                "{{\"tree_size\":1,\"leaf_index\":0,\"root\":\"{}\",\"audit_path\":[]}}",
                hex_of(&mth(&records))
            )
        );
    }

    #[test]
    fn duplicate_content_gets_distinct_position_specific_proofs() {
        // Same bytes at positions 0 and 4 (like the regression batch): the
        // proofs must anchor the exact requested position.
        let refs: Vec<&[u8]> = vec![b"x", b"a", b"b", b"c", b"x", b"d", b"e"];
        let n = refs.len();
        let root = mth(&refs);
        let (root0, p0) = root_and_path(&refs, 0);
        let (root4, p4) = root_and_path(&refs, 4);
        assert_eq!(hex_of(&root0), hex_of(&root));
        assert_eq!(hex_of(&root4), hex_of(&root));
        assert_ne!(p0, p4, "equal content at different positions needs different proofs");
        assert_eq!(hex_of(&verify_proof(b"x", 0, n, &p0)), hex_of(&root));
        assert_eq!(hex_of(&verify_proof(b"x", 4, n, &p4)), hex_of(&root));
        // The proof for position 4 must not verify at position 0.
        let wrong = verify_proof(b"x", 0, n, &p4);
        assert_ne!(hex_of(&wrong), hex_of(&root));
    }

    #[test]
    fn proof_for_uneven_batch_does_not_use_padded_tree() {
        // n=5: RFC split k=4, so leaf 4 pairs directly with MTH of the whole
        // size-4 subtree — a single sibling. A power-of-two padding scheme
        // would pad to 8 and emit a three-element path instead.
        let owned: Vec<Vec<u8>> = (0..5).map(|i| vec![b'a' + i as u8]).collect();
        let refs: Vec<&[u8]> = owned.iter().map(|v| v.as_slice()).collect();
        let root = mth(&refs);
        let (fused_root, path) = root_and_path(&refs, 4);
        assert_eq!(hex_of(&fused_root), hex_of(&root));
        assert_eq!(path.len(), 1);
        assert_eq!(path[0], mth(&refs[..4]), "the one sibling is MTH(d0..d3)");
        assert_eq!(hex_of(&verify_proof(refs[4], 4, 5, &path)), hex_of(&root));
    }

    #[test]
    fn index_parsing_accepts_only_ascii_unsigned_decimal() {
        assert_eq!(parse_index("0"), Some(0));
        assert_eq!(parse_index("00"), Some(0));
        assert_eq!(parse_index("123"), Some(123));
        assert_eq!(parse_index("18446744073709551615"), Some(u64::MAX));
        assert_eq!(parse_index("18446744073709551616"), None);
        assert_eq!(parse_index(""), None);
        assert_eq!(parse_index("-1"), None);
        assert_eq!(parse_index("+1"), None);
        assert_eq!(parse_index("1.0"), None);
        assert_eq!(parse_index(" 1"), None);
        assert_eq!(parse_index("1 "), None);
        assert_eq!(parse_index("0x1"), None);
        assert_eq!(parse_index("①"), None);
        // Leading-zero overflow is still overflow.
        assert_eq!(parse_index("0018446744073709551616"), None);
    }
}
