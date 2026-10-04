use std::env;
use std::fs;
use std::process::ExitCode;

const VERSION: &str = "0.1.0";

const USAGE: &str = "Usage: roottrace --version | roottrace root <file> | roottrace prove <file> <record-index>";

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
        [cmd, path, index] if cmd == "prove" => {
            // A malformed index is a usage error even if the file cannot be
            // read, so parse it before touching the file.
            let Some(leaf_index) = parse_record_index(index) else {
                eprintln!("{USAGE}");
                eprintln!("error: record index must be a decimal non-negative integer of ASCII digits, at most 2^64 - 1");
                return ExitCode::from(2);
            };
            match membership_proof_of_file(path, leaf_index) {
                Ok(proof) => {
                    print!("{}", render_proof(&proof));
                    ExitCode::SUCCESS
                }
                Err(ProveError::Read(reason)) => {
                    eprintln!("roottrace: {reason}");
                    ExitCode::FAILURE
                }
                Err(ProveError::NoPosition(reason)) => {
                    eprintln!("roottrace: {reason}");
                    ExitCode::FAILURE
                }
            }
        }
        _ => {
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
    }
}

/// A membership proof for one record position in one batch.
struct Proof {
    tree_size: u64,
    leaf_index: u64,
    root: [u8; 32],
    /// Sibling hashes ordered from the leaf level up to the root (RFC 6962
    /// section 2.1.1).
    audit_path: Vec<[u8; 32]>,
}

enum ProveError {
    Read(String),
    NoPosition(String),
}

fn merkle_root_of_file(path: &str) -> Result<[u8; 32], String> {
    let data = fs::read(path).map_err(|e| format!("cannot read '{path}': {e}"))?;
    Ok(mth(&split_records(&data)))
}

fn membership_proof_of_file(path: &str, leaf_index: u64) -> Result<Proof, ProveError> {
    let data = fs::read(path).map_err(|e| ProveError::Read(format!("cannot read '{path}': {e}")))?;
    let records = split_records(&data);
    let tree_size = records.len() as u64;
    if leaf_index >= tree_size {
        return Err(ProveError::NoPosition(format!(
            "record index {leaf_index} does not exist: the batch holds {tree_size} record(s), valid indices are 0..{}",
            tree_size.saturating_sub(1)
        )));
    }
    // Positioned purely by index: identical bytes at other positions are
    // separate records and each position gets its own proof.
    Ok(Proof {
        tree_size,
        leaf_index,
        root: mth(&records),
        audit_path: audit_path(&records, leaf_index as usize),
    })
}

/// Parse `<record-index>`: a non-empty string of ASCII decimal digits that
/// fits in an unsigned 64-bit integer. Signs, spaces, leading `+` and other
/// non-digit characters are rejected.
fn parse_record_index(s: &str) -> Option<u64> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse::<u64>().ok()
}

/// RFC 6962 section 2.1.1 audit path for record `m` of `leaves`, ordered
/// from the leaf toward the root. A one-record tree has an empty path; no
/// leaf is copied or padded for non-power-of-two sizes.
fn audit_path(leaves: &[&[u8]], m: usize) -> Vec<[u8; 32]> {
    let n = leaves.len();
    if n <= 1 {
        return Vec::new();
    }
    // Largest power of two strictly smaller than n.
    let k = 1usize << (usize::BITS - 1 - (n - 1).leading_zeros());
    if m < k {
        let mut path = audit_path(&leaves[..k], m);
        path.push(mth(&leaves[k..]));
        path
    } else {
        let mut path = audit_path(&leaves[k..], m - k);
        path.push(mth(&leaves[..k]));
        path
    }
}

/// Render the proof as a single JSON object line (with trailing LF), keyed
/// tree_size, leaf_index, root, audit_path.
fn render_proof(proof: &Proof) -> String {
    let mut out = String::new();
    out.push_str("{\"tree_size\":");
    out.push_str(&proof.tree_size.to_string());
    out.push_str(",\"leaf_index\":");
    out.push_str(&proof.leaf_index.to_string());
    out.push_str(",\"root\":\"");
    out.push_str(&hex(&proof.root));
    out.push_str("\",\"audit_path\":[");
    for (i, node) in proof.audit_path.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push('"');
        out.push_str(&hex(node));
        out.push('"');
    }
    out.push_str("]}\n");
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

/// RFC 6962 section 2.1 Merkle Tree Hash over SHA-256.
fn mth(leaves: &[&[u8]]) -> [u8; 32] {
    match leaves.len() {
        0 => sha256(&[]),
        1 => {
            let mut input = Vec::with_capacity(1 + leaves[0].len());
            input.push(0x00);
            input.extend_from_slice(leaves[0]);
            sha256(&input)
        }
        n => {
            // Largest power of two strictly smaller than n.
            let k = 1usize << (usize::BITS - 1 - (n - 1).leading_zeros());
            let left = mth(&leaves[..k]);
            let right = mth(&leaves[k..]);
            let mut input = Vec::with_capacity(65);
            input.push(0x01);
            input.extend_from_slice(&left);
            input.extend_from_slice(&right);
            sha256(&input)
        }
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
    fn record_index_parsing() {
        assert_eq!(parse_record_index("0"), Some(0));
        assert_eq!(parse_record_index("1"), Some(1));
        assert_eq!(parse_record_index("18446744073709551615"), Some(u64::MAX));
        // No signs, no leading plus, no spaces, no empties, no non-ASCII digits.
        for bad in [
            "", "-1", "+1", "1.0", " 1", "1 ", "0x1", "a", "①", "18446744073709551616",
        ] {
            assert_eq!(parse_record_index(bad), None, "must reject {bad:?}");
        }
    }

    /// Sibling side for one proof level, ordered leaf -> root.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    enum Side {
        Left,
        Right,
    }

    /// Independently derive the leaf ranges and sides of the audit-path
    /// siblings straight from the RFC 6962 section 2.1.1 recursive split,
    /// without computing any hashes the way `audit_path` does. Each entry
    /// is `(side, sibling_lo, sibling_hi)`.
    fn sibling_ranges(lo: usize, hi: usize, m: usize, out: &mut Vec<(Side, usize, usize)>) {
        let n = hi - lo;
        if n == 1 {
            return;
        }
        let k = 1usize << (usize::BITS - 1 - (n - 1).leading_zeros());
        if m < lo + k {
            sibling_ranges(lo, lo + k, m, out);
            out.push((Side::Right, lo + k, hi));
        } else {
            sibling_ranges(lo + k, hi, m, out);
            out.push((Side::Left, lo, lo + k));
        }
    }

    /// Verify a proof using only the independently derived sibling ranges:
    /// every path hash must equal MTH of that sibling's records (looked up
    /// in the shared memoized table), and folding leaf-to-root must rebuild
    /// the batch root.
    fn verify_with_ranges(
        batch: &[&[u8]],
        m: usize,
        path: &[[u8; 32]],
        mth_at: &impl Fn(usize, usize) -> [u8; 32],
    ) -> [u8; 32] {
        let mut ranges = Vec::new();
        sibling_ranges(0, batch.len(), m, &mut ranges);
        assert_eq!(ranges.len(), path.len(), "path length mismatch for n={}, m={m}", batch.len());

        let mut leaf_input = vec![0x00];
        leaf_input.extend_from_slice(batch[m]);
        let mut node = sha256(&leaf_input);
        for ((side, lo, hi), sibling) in ranges.iter().zip(path) {
            let expected = mth_at(*lo, *hi);
            assert_eq!(sibling, &expected, "wrong sibling hash at level for m={m}, range {lo}..{hi}");
            node = match side {
                Side::Right => {
                    let mut input = Vec::with_capacity(65);
                    input.push(0x01);
                    input.extend_from_slice(&node);
                    input.extend_from_slice(sibling);
                    sha256(&input)
                }
                Side::Left => {
                    let mut input = Vec::with_capacity(65);
                    input.push(0x01);
                    input.extend_from_slice(sibling);
                    input.extend_from_slice(&node);
                    sha256(&input)
                }
            };
        }
        node
    }

    /// Memoized MTH over index ranges, so exhaustively verifying every
    /// position does not recompute the same subtree hashes over and over.
    fn make_mth_memo<'a>(batch: &'a [&'a [u8]]) -> impl Fn(usize, usize) -> [u8; 32] + use<'a> {
        use std::cell::RefCell;
        use std::collections::HashMap;
        let table: RefCell<HashMap<(usize, usize), [u8; 32]>> = RefCell::new(HashMap::new());
        // Seed recursively once so the whole subtree table is populated.
        fn fill(batch: &[&[u8]], lo: usize, hi: usize, table: &mut HashMap<(usize, usize), [u8; 32]>) -> [u8; 32] {
            if let Some(h) = table.get(&(lo, hi)) {
                return *h;
            }
            let h = if hi - lo == 1 {
                let mut input = vec![0x00];
                input.extend_from_slice(batch[lo]);
                sha256(&input)
            } else {
                let n = hi - lo;
                let k = 1usize << (usize::BITS - 1 - (n - 1).leading_zeros());
                let l = fill(batch, lo, lo + k, table);
                let r = fill(batch, lo + k, hi, table);
                let mut input = Vec::with_capacity(65);
                input.push(0x01);
                input.extend_from_slice(&l);
                input.extend_from_slice(&r);
                sha256(&input)
            };
            table.insert((lo, hi), h);
            h
        }
        fill(batch, 0, batch.len(), &mut table.borrow_mut());
        move |lo, hi| *table.borrow().get(&(lo, hi)).unwrap()
    }

    #[test]
    fn audit_paths_verify_for_every_position_and_size() {
        // Include duplicate content on purpose: proofs must be per position.
        let leaves: Vec<&[u8]> = vec![
            b"same", b"b", b"", b"d", b"same", b"f\r", b"\xff\x00", b"h", b"i", b"same",
        ];
        // Exhaustive in-process check across the power-of-two boundaries
        // 2, 4, 8, 16, 32, 64 and 128, every position of every size.
        const MAX_N: usize = 130;
        let batch_pool: Vec<&[u8]> = (0..MAX_N)
            .map(|i| leaves[i % leaves.len()])
            .collect();
        for n in 1..=MAX_N {
            let batch = &batch_pool[..n];
            let root = mth(batch);
            let mth_at = make_mth_memo(batch);
            for m in 0..n {
                let path = audit_path(batch, m);
                // A one-record tree has an empty path; every position in a
                // larger tree has at least one sibling.
                assert_eq!(path.is_empty(), n == 1, "n={n}, m={m}");
                assert_eq!(
                    hex_of(&verify_with_ranges(batch, m, &path, &mth_at)),
                    hex_of(&root),
                    "proof must reconstruct root for n={n}, m={m}"
                );
            }
        }
        // Explicit non-power-of-two short-path cases: a leaf that is itself
        // the complete right-hand subtree has fewer siblings and no padding.
        assert_eq!(audit_path(&batch_pool[..3], 2).len(), 1);
        assert_eq!(audit_path(&batch_pool[..5], 4).len(), 1);
        assert_eq!(audit_path(&batch_pool[..7], 6).len(), 2);
        assert_eq!(audit_path(&batch_pool[..33], 32).len(), 1);
        assert_eq!(audit_path(&batch_pool[..129], 128).len(), 1);
    }

    #[test]
    fn duplicate_records_get_position_bound_proofs() {
        let leaves: Vec<&[u8]> = vec![b"x", b"x", b"x"];
        let root = mth(&leaves);
        let p0 = audit_path(&leaves, 0);
        let p1 = audit_path(&leaves, 1);
        let p2 = audit_path(&leaves, 2);
        let mth_at = make_mth_memo(&leaves);
        // Every position's proof verifies at its own index.
        for (m, path) in [(0, &p0), (1, &p1), (2, &p2)] {
            assert_eq!(hex_of(&verify_with_ranges(&leaves, m, path, &mth_at)), hex_of(&root));
        }
        // The third leaf is the complete right subtree: short path.
        assert_eq!(p0.len(), 2);
        assert_eq!(p1.len(), 2);
        assert_eq!(p2.len(), 1);
        // Position binding is in the side sequence: with identical leaves the
        // hash bytes at one level may coincide, but a verifier uses index and
        // tree_size to choose the combine side, and the directions differ.
        let side_seq = |m: usize| {
            let mut ranges = Vec::new();
            sibling_ranges(0, 3, m, &mut ranges);
            ranges.into_iter().map(|(side, _, _)| side).collect::<Vec<_>>()
        };
        assert_eq!(side_seq(0), vec![Side::Right, Side::Right]);
        assert_eq!(side_seq(1), vec![Side::Left, Side::Right]);
        assert_eq!(side_seq(2), vec![Side::Left]);
    }
}
