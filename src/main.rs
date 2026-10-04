use std::env;
use std::fs;
use std::process::ExitCode;

const VERSION: &str = "0.1.0";

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
        _ => {
            eprintln!("Usage: roottrace --version | roottrace root <file>");
            ExitCode::from(2)
        }
    }
}

fn merkle_root_of_file(path: &str) -> Result<[u8; 32], String> {
    let data = fs::read(path).map_err(|e| format!("cannot read '{path}': {e}"))?;
    Ok(mth(&split_records(&data)))
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
}
