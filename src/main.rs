use std::env;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::Path;
use std::process::ExitCode;

const VERSION: &str = "0.1.0";

const USAGE: &str = "\
Usage:
    roottrace root <file>
    roottrace prove <file> <record-index>
    roottrace verify <record-file> <proof-file> <trusted-tree-size> <trusted-root>
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

    verify <record-file> <proof-file> <trusted-tree-size> <trusted-root>
        Verify an inclusion proof produced by `prove` without needing the
        whole batch. The record file holds the raw bytes of exactly one
        target record (no LF splitting, byte for byte including any trailing
        LF/space/CR, NUL and non-UTF-8 bytes; an empty file is one empty
        record). The proof is read as one complete JSON object. The trusted
        tree size (an ASCII decimal positive integer) and the trusted root
        (64 lowercase hexadecimal characters) must be confirmed
        independently; they are never taken from fields inside the proof.
        On success stdout is exactly \"verified\\n\", stderr is empty and the
        exit status is 0.

        Example:
            roottrace verify record.bin proof.json 9 a8a3e76e...723adc3

Exit status:
    0  success
    1  an input file cannot be read, the proof is malformed, or verification fails
    2  usage error (unknown command, missing or extra arguments, bad arguments)";

fn main() -> ExitCode {
    // Raw OS arguments: file paths are handed to the filesystem exactly as
    // received, byte for byte. On Unix a path may contain bytes that are not
    // valid UTF-8 (e.g. 0xff); such a path is not invalid and must reach the
    // file rather than aborting argument collection. The command name, the
    // record index and the trusted tree size/root arguments are required to
    // be UTF-8 text.
    let args: Vec<OsString> = env::args_os().skip(1).collect();
    match args.as_slice() {
        [flag] if flag == OsStr::new("--version") => {
            println!("roottrace {VERSION}");
            ExitCode::SUCCESS
        }
        [cmd, path] if cmd == OsStr::new("root") => match merkle_root_of_file(Path::new(path)) {
            Ok(root) => {
                println!("{}", hex(&root));
                ExitCode::SUCCESS
            }
            Err(reason) => {
                eprintln!("roottrace: {reason}");
                ExitCode::FAILURE
            }
        },
        [cmd, path, index] if cmd == OsStr::new("prove") => match parse_index(index) {
            Some(index) => match proof_for_file(Path::new(path), index) {
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
                let shown = index.to_string_lossy();
                eprintln!("roottrace: invalid record index '{shown}': expected a decimal non-negative integer of ASCII digits");
                eprintln!("{USAGE}");
                ExitCode::from(2)
            }
        },
        [cmd, path, proof_path, size_arg, root_arg] if cmd == OsStr::new("verify") => {
            match (parse_trusted_size(size_arg), parse_trusted_root(root_arg)) {
                (Some(trusted_size), Some(trusted_root)) => {
                    match verify_files(Path::new(path), Path::new(proof_path), trusted_size, &trusted_root) {
                        Ok(()) => {
                            println!("verified");
                            ExitCode::SUCCESS
                        }
                        Err(VerifyError::Read { path, source }) => {
                            eprintln!(
                                "roottrace: cannot read '{}': {source}",
                                display_path(&path)
                            );
                            ExitCode::FAILURE
                        }
                        Err(VerifyError::MalformedProof(reason)) => {
                            eprintln!("roottrace: invalid proof: {reason}");
                            ExitCode::FAILURE
                        }
                        Err(VerifyError::Failed(reason)) => {
                            eprintln!("roottrace: verification failed: {reason}");
                            ExitCode::FAILURE
                        }
                    }
                }
                (bad_size, bad_root) => {
                    if bad_size.is_none() {
                        let shown = size_arg.to_string_lossy();
                        eprintln!(
                            "roottrace: invalid trusted tree size '{shown}': expected an ASCII decimal positive integer within unsigned 64-bit range"
                        );
                    }
                    if bad_root.is_none() {
                        let shown = root_arg.to_string_lossy();
                        eprintln!(
                            "roottrace: invalid trusted root '{shown}': expected exactly 64 lowercase hexadecimal characters"
                        );
                    }
                    eprintln!("{USAGE}");
                    ExitCode::from(2)
                }
            }
        }
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

/// Failures reported by `verify`, kept separate so that malformed proofs and
/// cryptographic mismatches both exit 1 but say different things on stderr.
enum VerifyError {
    /// One of the two input paths cannot be read (missing, a directory, ...).
    Read { path: std::path::PathBuf, source: std::io::Error },
    /// The proof bytes are not a well-formed proof object.
    MalformedProof(String),
    /// The proof is well-formed but does not establish the claimed inclusion
    /// against the independently trusted tree size and root.
    Failed(String),
}

/// Read the two input files and run an RFC 6962 inclusion check. The record
/// file's ENTIRE byte content is the target record: no LF splitting and no
/// trimming of trailing LF, space or CR; NUL and non-UTF-8 bytes take part as
/// they are. A zero-byte file is one empty record.
fn verify_files(
    record_path: &Path,
    proof_path: &Path,
    trusted_size: u64,
    trusted_root: &[u8; 32],
) -> Result<(), VerifyError> {
    let record = fs::read(record_path).map_err(|source| VerifyError::Read {
        path: record_path.to_path_buf(),
        source,
    })?;
    let proof_bytes = fs::read(proof_path).map_err(|source| VerifyError::Read {
        path: proof_path.to_path_buf(),
        source,
    })?;
    let proof = parse_proof(&proof_bytes).map_err(VerifyError::MalformedProof)?;
    verify_proof(&proof, &record, trusted_size, trusted_root).map_err(VerifyError::Failed)
}

/// Parse the trusted tree size given on the command line: one or more ASCII
/// decimal digits naming a POSITIVE 64-bit unsigned integer. Unlike a record
/// index, zero is not accepted (it cannot be a tree that contains a record).
/// Anything else (sign, whitespace, non-UTF-8 bytes, a value above u64::MAX)
/// is a usage error.
fn parse_trusted_size(arg: &OsStr) -> Option<u64> {
    let text = arg.to_str()?;
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let mut value: u64 = 0;
    for b in text.bytes() {
        value = value.checked_mul(10)?.checked_add(u64::from(b - b'0'))?;
    }
    if value == 0 {
        return None;
    }
    Some(value)
}

/// Parse the trusted root given on the command line: exactly 64 lowercase
/// ASCII hexadecimal characters (32 bytes). Uppercase, wrong length, non-hex
/// or non-UTF-8 bytes are usage errors.
fn parse_trusted_root(arg: &OsStr) -> Option<[u8; 32]> {
    let text = arg.to_str()?;
    if text.len() != 64 || !text.bytes().all(is_lower_hex) {
        return None;
    }
    let bytes = text.as_bytes();
    let mut out = [0u8; 32];
    for (i, pair) in bytes.chunks_exact(2).enumerate() {
        out[i] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    Some(out)
}

fn is_lower_hex(b: u8) -> bool {
    b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    }
}

// --- Proof parsing -----------------------------------------------------------
//
// The proof must be ONE complete JSON object. `prove` output is plain JSON,
// but the file may also arrive over a channel that reorders fields or changes
// whitespace, so both are accepted. Nothing else is: a truncated value, a
// duplicate key, a value of the wrong JSON type, a number that is not an
// exact unsigned 64-bit integer, a non-lowercase/non-64-char hash, trailing
// bytes after the object, or an empty file all make the proof invalid.
// Parsing is structural: no text decoding of the proof is required for the
// hashes, and integer fields are accumulated digit by digit so a value above
// u64::MAX (including 1e400) is rejected rather than wrapped or approximated.

/// The fields of a well-formed inclusion proof.
struct Proof {
    tree_size: u64,
    leaf_index: u64,
    root: [u8; 32],
    audit_path: Vec<[u8; 32]>,
}

struct ProofParser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

fn parse_proof(input: &[u8]) -> Result<Proof, String> {
    let mut p = ProofParser { bytes: input, pos: 0 };
    p.ws();
    let proof = p.parse_object().map_err(|e| e.to_string())?;
    p.ws();
    if p.pos != p.bytes.len() {
        return Err("trailing data after the JSON object".to_string());
    }
    let tree_size = proof.tree_size.ok_or_else(|| "missing field 'tree_size'".to_string())?;
    let leaf_index = proof.leaf_index.ok_or_else(|| "missing field 'leaf_index'".to_string())?;
    let root = proof.root.ok_or_else(|| "missing field 'root'".to_string())?;
    let audit_path =
        proof.audit_path.ok_or_else(|| "missing field 'audit_path'".to_string())?;
    if tree_size == 0 {
        return Err("tree_size must be positive".to_string());
    }
    if leaf_index >= tree_size {
        return Err(format!(
            "leaf_index {leaf_index} is out of range for tree_size {tree_size}"
        ));
    }
    Ok(Proof { tree_size, leaf_index, root, audit_path })
}

/// Accumulator for the four recognised object members; a `Some` already
/// present when the same key is seen again makes the proof invalid.
struct ProofFields {
    tree_size: Option<u64>,
    leaf_index: Option<u64>,
    root: Option<[u8; 32]>,
    audit_path: Option<Vec<[u8; 32]>>,
}

impl<'a> ProofParser<'a> {
    fn ws(&mut self) {
        while self.pos < self.bytes.len() && matches!(self.bytes[self.pos], b' ' | b'\t' | b'\n' | b'\r') {
            self.pos += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn eat(&mut self, b: u8) -> Result<(), String> {
        if self.peek() == Some(b) {
            self.pos += 1;
            Ok(())
        } else {
            Err(format!("expected '{}' at byte {}", b as char, self.pos))
        }
    }

    fn parse_object(&mut self) -> Result<ProofFields, String> {
        self.eat(b'{')?;
        let mut fields = ProofFields {
            tree_size: None,
            leaf_index: None,
            root: None,
            audit_path: None,
        };
        self.ws();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Err("empty object: none of the required fields are present".to_string());
        }
        loop {
            self.ws();
            let key = self.parse_string()?;
            self.ws();
            self.eat(b':')?;
            self.ws();
            match key.as_str() {
                "tree_size" => {
                    if fields.tree_size.is_some() {
                        return Err("duplicate field 'tree_size'".to_string());
                    }
                    fields.tree_size = Some(self.parse_u64()?);
                }
                "leaf_index" => {
                    if fields.leaf_index.is_some() {
                        return Err("duplicate field 'leaf_index'".to_string());
                    }
                    fields.leaf_index = Some(self.parse_u64()?);
                }
                "root" => {
                    if fields.root.is_some() {
                        return Err("duplicate field 'root'".to_string());
                    }
                    fields.root = Some(self.parse_hash()?);
                }
                "audit_path" => {
                    if fields.audit_path.is_some() {
                        return Err("duplicate field 'audit_path'".to_string());
                    }
                    fields.audit_path = Some(self.parse_hash_array()?);
                }
                other => return Err(format!("unexpected field '{other}'")),
            }
            self.ws();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                }
                Some(b'}') => {
                    self.pos += 1;
                    break;
                }
                _ => return Err(format!("expected ',' or '}}' at byte {}", self.pos)),
            }
        }
        Ok(fields)
    }

    /// A JSON string returned as UTF-8 text. Proof keys are ASCII; escapes
    /// (including `\uXXXX`) are decoded so a spelled-out key cannot bypass the
    /// recognized-name matching. Any string value anywhere is gated through
    /// here, so invalid escapes or an unclosed string reject the proof.
    fn parse_string(&mut self) -> Result<String, String> {
        self.eat(b'"')?;
        let mut out = String::new();
        loop {
            match self.peek() {
                None => return Err("unterminated string".to_string()),
                Some(b'"') => {
                    self.pos += 1;
                    break;
                }
                Some(b'\\') => {
                    self.pos += 1;
                    match self.peek() {
                        Some(b'"') => out.push('"'),
                        Some(b'\\') => out.push('\\'),
                        Some(b'/') => out.push('/'),
                        Some(b'b') => out.push('\u{0008}'),
                        Some(b'f') => out.push('\u{000C}'),
                        Some(b'n') => out.push('\n'),
                        Some(b'r') => out.push('\r'),
                        Some(b't') => out.push('\t'),
                        Some(b'u') => {
                            self.pos += 1;
                            let cp = self.parse_hex4()?;
                            // High surrogate demands a matching low surrogate.
                            let cp = if (0xD800..=0xDBFF).contains(&cp) {
                                if self.peek() != Some(b'\\') {
                                    return Err("lone high surrogate".to_string());
                                }
                                self.pos += 1;
                                if self.peek() != Some(b'u') {
                                    return Err("lone high surrogate".to_string());
                                }
                                self.pos += 1;
                                let lo = self.parse_hex4()?;
                                if !(0xDC00..=0xDFFF).contains(&lo) {
                                    return Err("high surrogate not followed by a low surrogate".to_string());
                                }
                                0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00)
                            } else if (0xDC00..=0xDFFF).contains(&cp) {
                                return Err("lone low surrogate".to_string());
                            } else {
                                cp
                            };
                            match char::from_u32(cp) {
                                Some(c) => out.push(c),
                                None => return Err("invalid unicode escape".to_string()),
                            }
                            continue;
                        }
                        _ => return Err("invalid escape sequence".to_string()),
                    }
                    self.pos += 1;
                }
                Some(_) => {
                    // Copy a run of ordinary bytes, reinterpreting the slice as
                    // UTF-8 for appending; control characters and invalid UTF-8
                    // inside a string are rejected. The run stops at ASCII
                    // delimiters only, so a multibyte sequence is never split.
                    let start = self.pos;
                    while self.pos < self.bytes.len() {
                        let b = self.bytes[self.pos];
                        if b == b'"' || b == b'\\' {
                            break;
                        }
                        if b < 0x20 {
                            return Err("unescaped control character in string".to_string());
                        }
                        self.pos += 1;
                    }
                    match std::str::from_utf8(&self.bytes[start..self.pos]) {
                        Ok(s) => out.push_str(s),
                        Err(_) => return Err("string is not valid UTF-8".to_string()),
                    }
                }
            }
        }
        Ok(out)
    }

    fn parse_hex4(&mut self) -> Result<u32, String> {
        if self.pos + 4 > self.bytes.len() {
            return Err("truncated unicode escape".to_string());
        }
        let mut v = 0u32;
        for _ in 0..4 {
            let b = self.bytes[self.pos];
            self.pos += 1;
            let n = match b {
                b'0'..=b'9' => u32::from(b - b'0'),
                b'a'..=b'f' => u32::from(b - b'a' + 10),
                b'A'..=b'F' => u32::from(b - b'A' + 10),
                _ => return Err("invalid hex digit in unicode escape".to_string()),
            };
            v = (v << 4) | n;
        }
        Ok(v)
    }

    /// A JSON number accepted only when it is an exact unsigned 64-bit
    /// integer token: digits only, no sign, fraction or exponent.
    fn parse_u64(&mut self) -> Result<u64, String> {
        let start = self.pos;
        while self.peek().is_some_and(|b| b.is_ascii_digit()) {
            self.pos += 1;
        }
        if start == self.pos {
            return Err("expected an unsigned integer".to_string());
        }
        // Canonical JSON integer token: "0" alone is allowed, but no leading
        // zeros (so "01" is rejected, not read as 1).
        if self.pos - start > 1 && self.bytes[start] == b'0' {
            return Err("integer must not have leading zeros".to_string());
        }
        if self.peek().is_some_and(|b| matches!(b, b'.' | b'e' | b'E' | b'+' | b'-')) {
            return Err("number must be an unsigned 64-bit integer".to_string());
        }
        let text = std::str::from_utf8(&self.bytes[start..self.pos])
            .map_err(|_| "integer is not ASCII".to_string())?;
        let mut value: u64 = 0;
        for b in text.bytes() {
            value = value
                .checked_mul(10)
                .and_then(|v| v.checked_add(u64::from(b - b'0')))
                .ok_or_else(|| "integer exceeds unsigned 64-bit range".to_string())?;
        }
        Ok(value)
    }

    /// A JSON string that must contain exactly 64 lowercase hexadecimal
    /// characters, decoded to 32 bytes.
    fn parse_hash(&mut self) -> Result<[u8; 32], String> {
        let s = self.parse_string()?;
        if s.len() != 64 || !s.bytes().all(is_lower_hex) {
            return Err("hash must be a string of 64 lowercase hexadecimal characters".to_string());
        }
        let bytes = s.as_bytes();
        let mut out = [0u8; 32];
        for (i, pair) in bytes.chunks_exact(2).enumerate() {
            out[i] = (hex_nibble(pair[0]).unwrap() << 4) | hex_nibble(pair[1]).unwrap();
        }
        Ok(out)
    }

    fn parse_hash_array(&mut self) -> Result<Vec<[u8; 32]>, String> {
        self.eat(b'[')?;
        let mut hashes = Vec::new();
        self.ws();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(hashes);
        }
        loop {
            self.ws();
            hashes.push(self.parse_hash()?);
            self.ws();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                }
                Some(b']') => {
                    self.pos += 1;
                    break;
                }
                _ => return Err(format!("expected ',' or ']' at byte {}", self.pos)),
            }
        }
        Ok(hashes)
    }
}

/// Check a well-formed proof against the independently trusted tree size and
/// root, exactly per RFC 6962 section 2.1.1:
///
/// 1. the proof's `tree_size` must equal the trusted size (the proof must not
///    name its own trust anchor);
/// 2. the proof's `root` must equal the trusted root;
/// 3. `leaf_index` must exist in a tree of that size (already enforced while
///    parsing);
/// 4. starting from SHA-256(0x00 || record), the audit path hashes must
///    recombine in the order dictated by the (possibly uneven) tree geometry
///    into that root, consuming every supplied hash exactly once.
///
/// Duplicate content is never searched for: the check is against the exact
/// `leaf_index` the proof claims. A single-record tree needs an empty path;
/// a path that is too short or too long for the geometry cannot succeed.
fn verify_proof(proof: &Proof, record: &[u8], trusted_size: u64, trusted_root: &[u8; 32]) -> Result<(), String> {
    if proof.tree_size != trusted_size {
        return Err(format!(
            "proof tree_size {} does not match the trusted tree size {trusted_size}",
            proof.tree_size
        ));
    }
    if proof.root != *trusted_root {
        return Err("proof root does not match the trusted root".to_string());
    }
    let computed = include_record(
        leaf_hash(record),
        proof.leaf_index,
        proof.tree_size,
        &proof.audit_path,
    )
    .map_err(|e| e.to_string())?;
    if computed != *trusted_root {
        return Err("record bytes or audit_path do not match the root at the claimed position".to_string());
    }
    Ok(())
}

/// RFC 6962-bis recursive inclusion recomputation: the combination order is
/// derived from the subtree sizes, and the path is consumed in its given
/// leaf-to-root order. A missing sibling or an unconsumed leftover hash is an
/// error, so an over- or under-long path never verifies. Arithmetic stays in
/// u64 so sizes above `usize::MAX` cannot truncate on a 32-bit platform; the
/// recursion depth is bounded by the hashes actually present in the path.
fn include_record(
    leaf: [u8; 32],
    m: u64,
    n: u64,
    path: &[[u8; 32]],
) -> Result<[u8; 32], String> {
    fn sub(
        leaf: [u8; 32],
        m: u64,
        n: u64,
        path: &[[u8; 32]],
        pos: &mut usize,
    ) -> Result<[u8; 32], String> {
        if n == 1 {
            return Ok(leaf);
        }
        // Largest power of two strictly smaller than n.
        let k = 1u64 << (u64::BITS - 1 - (n - 1).leading_zeros());
        if m < k {
            let left = sub(leaf, m, k, path, pos)?;
            let right = take(path, pos)?;
            Ok(node_hash(&left, &right))
        } else {
            let right = sub(leaf, m - k, n - k, path, pos)?;
            let left = take(path, pos)?;
            Ok(node_hash(&left, &right))
        }
    }
    fn take(path: &[[u8; 32]], pos: &mut usize) -> Result<[u8; 32], String> {
        let h = *path
            .get(*pos)
            .ok_or_else(|| "audit_path is shorter than the tree requires".to_string())?;
        *pos += 1;
        Ok(h)
    }
    let mut pos = 0;
    let root = sub(leaf, m, n, path, &mut pos)?;
    if pos != path.len() {
        return Err("audit_path is longer than the tree requires".to_string());
    }
    Ok(root)
}

/// Render a path for a human-readable error message. This is used ONLY in
/// diagnostics: the filesystem is always given the raw `Path`, never this
/// lossy rendering, so a file whose name contains 0xff is not confused with a
/// differently named file that merely displays the same way.
fn display_path(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn merkle_root_of_file(path: &Path) -> Result<[u8; 32], String> {
    let data = fs::read(path).map_err(|e| format!("cannot read '{}': {e}", display_path(path)))?;
    Ok(mth(&split_records(&data)))
}

fn proof_for_file(path: &Path, index: u64) -> Result<String, ProveError> {
    let data = fs::read(path)
        .map_err(|e| ProveError::Read(format!("cannot read '{}': {e}", display_path(path))))?;
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
/// (including "+1", " 1", "1.0", "", "-1", or an argument that is not valid
/// UTF-8) is rejected as a usage error.
fn parse_index(arg: &OsStr) -> Option<u64> {
    let text = arg.to_str()?;
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
    use std::os::unix::ffi::OsStrExt;

    fn hex_of(d: &[u8; 32]) -> String {
        hex(d)
    }

    /// Verify an RFC 6962 inclusion proof with the RFC's recursive verifier:
    /// it re-derives the combination order from the tree geometry (k =
    /// largest power of two below the current subtree size) while consuming
    /// exactly the supplied sibling hashes. A wrong length, order or hash
    /// fails; the root computed here must equal the tree root.
    fn rfc_recompute_root(leaf: &[u8], m: usize, n: usize, path: &[[u8; 32]]) -> [u8; 32] {
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
                let computed = rfc_recompute_root(refs[m], m, n, &path);
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
        assert_eq!(hex_of(&rfc_recompute_root(b"x", 0, n, &p0)), hex_of(&root));
        assert_eq!(hex_of(&rfc_recompute_root(b"x", 4, n, &p4)), hex_of(&root));
        // The proof for position 4 must not verify at position 0.
        let wrong = rfc_recompute_root(b"x", 0, n, &p4);
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
        assert_eq!(hex_of(&rfc_recompute_root(refs[4], 4, 5, &path)), hex_of(&root));
    }

    #[test]
    fn index_parsing_accepts_only_ascii_unsigned_decimal() {
        assert_eq!(parse_index(OsStr::new("0")), Some(0));
        assert_eq!(parse_index(OsStr::new("00")), Some(0));
        assert_eq!(parse_index(OsStr::new("123")), Some(123));
        assert_eq!(parse_index(OsStr::new("18446744073709551615")), Some(u64::MAX));
        assert_eq!(parse_index(OsStr::new("18446744073709551616")), None);
        assert_eq!(parse_index(OsStr::new("")), None);
        assert_eq!(parse_index(OsStr::new("-1")), None);
        assert_eq!(parse_index(OsStr::new("+1")), None);
        assert_eq!(parse_index(OsStr::new("1.0")), None);
        assert_eq!(parse_index(OsStr::new(" 1")), None);
        assert_eq!(parse_index(OsStr::new("1 ")), None);
        assert_eq!(parse_index(OsStr::new("0x1")), None);
        assert_eq!(parse_index(OsStr::new("①")), None);
        // Leading-zero overflow is still overflow.
        assert_eq!(parse_index(OsStr::new("0018446744073709551616")), None);
        // An argument that is not valid UTF-8 is a usage error, never a panic.
        assert_eq!(parse_index(OsStr::from_bytes(b"1\xff")), None);
        assert_eq!(parse_index(OsStr::from_bytes(b"\xff")), None);
    }

    // --- trusted command-line arguments -------------------------------------

    #[test]
    fn trusted_size_accepts_only_positive_ascii_decimal_u64() {
        assert_eq!(parse_trusted_size(OsStr::new("1")), Some(1));
        assert_eq!(parse_trusted_size(OsStr::new("09")), Some(9));
        assert_eq!(parse_trusted_size(OsStr::new("18446744073709551615")), Some(u64::MAX));
        // Zero is not a tree that can contain a record.
        assert_eq!(parse_trusted_size(OsStr::new("0")), None);
        assert_eq!(parse_trusted_size(OsStr::new("00")), None);
        for bad in ["", "-1", "+1", "1.0", " 1", "1 ", "0x1", "18446744073709551616", "①"] {
            assert_eq!(parse_trusted_size(OsStr::new(bad)), None, "size {bad:?}");
        }
        assert_eq!(parse_trusted_size(OsStr::from_bytes(b"9\xff")), None);
    }

    #[test]
    fn trusted_root_accepts_exactly_64_lowercase_hex() {
        let h = hex_of(&mth(&[b"a"]));
        let parsed = parse_trusted_root(OsStr::new(&h)).expect("valid root");
        assert_eq!(parsed, mth(&[b"a"]));
        for bad in [
            "",
            &"a".repeat(63),
            &"a".repeat(65),
            // One uppercase digit.
            &{
                let mut s = h.clone();
                s.replace_range(0..1, "A");
                s
            },
            &format!("{h} "),
            &format!(" {h}"),
            &"z".repeat(64),
        ] {
            assert!(parse_trusted_root(OsStr::new(bad)).is_none(), "root {bad:?}");
        }
        assert!(parse_trusted_root(OsStr::from_bytes(&[b'a'; 65])).is_none());
    }

    // --- proof parsing ------------------------------------------------------

    fn valid_proof_bytes(size: u64, index: u64, root: &[u8; 32], path: &[[u8; 32]]) -> Vec<u8> {
        proof_json(size, index, root, path).into_bytes()
    }

    #[test]
    fn parse_proof_accepts_compact_reordered_and_pretty_forms() {
        let refs: Vec<&[u8]> = vec![b"a", b"b", b"c"];
        let (root, path) = root_and_path(&refs, 1);
        let compact = valid_proof_bytes(3, 1, &root, &path);
        assert!(parse_proof(&compact).is_ok());

        // Field order changed and arbitrary whitespace added (incl. inside
        // the array and around punctuation).
        let pretty = format!(
            "  {{\n  \"audit_path\" : [ \"{}\", \"{}\" ] ,\n  \"root\": \"{}\",\n  \"leaf_index\": 1 , \"tree_size\": 3\n}}\n",
            hex(&path[0]),
            hex(&path[1]),
            hex(&root),
        );
        let p = parse_proof(pretty.as_bytes()).expect("pretty/reordered proof must parse");
        assert_eq!(p.tree_size, 3);
        assert_eq!(p.leaf_index, 1);
        assert_eq!(p.root, root);
        assert_eq!(p.audit_path, path);

        // Tabs and CRs are JSON whitespace too. Parsing does not check the
        // path-vs-geometry relationship (verification does), so a short path
        // parses here as long as the shape is right.
        let tabbed = format!(
            "{{\t\"tree_size\":3,\r\n\"leaf_index\":1,\"root\":\"{}\",\"audit_path\":[]}}",
            hex(&root)
        );
        assert!(parse_proof(tabbed.as_bytes()).is_ok());
    }

    #[test]
    fn parse_proof_rejects_missing_fields_and_empty_or_wrong_container() {
        let refs: Vec<&[u8]> = vec![b"a", b"b"];
        let (root, path) = root_and_path(&refs, 0);
        let full = valid_proof_bytes(2, 0, &root, &path);
        assert!(parse_proof(&full).is_ok());

        let drop_field = |bytes: &[u8], needle: &str| -> Vec<u8> {
            let text = String::from_utf8(bytes.to_vec()).unwrap();
            // Rebuild without the named member by string surgery on the
            // canonical compact form emitted by proof_json.
            let idx = text.find(needle).unwrap();
            let mut end = idx + needle.len();
            // Consume through the member's value terminator.
            match needle {
                "\"tree_size\":" | "\"leaf_index\":" => {
                    while end < text.len()
                        && text.as_bytes()[end] != b','
                        && text.as_bytes()[end] != b'}'
                    {
                        end += 1;
                    }
                }
                "\"root\":" => {
                    while end < text.len() && text.as_bytes()[end] != b'"' {
                        end += 1;
                    }
                    end += 1;
                }
                _ => {
                    end = text.rfind(']').unwrap() + 1;
                }
            }
            let mut s = String::new();
            s.push_str(&text[..idx]);
            let rest = &text[end..];
            // Tidy the separator left by the removed member.
            if rest.starts_with(',') {
                s.push_str(&rest[1..]);
            } else if text[..idx].ends_with(',') {
                s.pop();
                s.push_str(rest);
            } else {
                s.push_str(rest);
            }
            s.into_bytes()
        };

        for key in ["\"tree_size\":", "\"leaf_index\":", "\"root\":", "\"audit_path\":"] {
            let cut = drop_field(&full, key);
            assert!(parse_proof(&cut).is_err(), "proof missing {key} must be invalid: {cut:?}");
        }

        for bad in [
            b"".as_slice(),
            b"   ",
            b"null",
            b"[]",
            b"\"x\"",
            b"123",
            b"{}",
            b"[{\"tree_size\":1}]",
        ] {
            assert!(parse_proof(bad).is_err(), "{bad:?} must not parse as a proof");
        }
    }

    #[test]
    fn parse_proof_rejects_trailing_bytes_truncation_and_duplicates() {
        let refs: Vec<&[u8]> = vec![b"a", b"b"];
        let (root, path) = root_and_path(&refs, 0);
        let full = valid_proof_bytes(2, 0, &root, &path);

        let mut trailing = full.clone();
        trailing.extend_from_slice(b" ");
        assert!(parse_proof(&trailing).is_ok(), "trailing whitespace is allowed");
        let mut trailing = full.clone();
        trailing.extend_from_slice(b"x");
        assert!(parse_proof(&trailing).is_err());
        let mut trailing = full.clone();
        trailing.extend_from_slice(b"{}");
        assert!(parse_proof(&trailing).is_err());
        // Truncated at every cut point.
        for cut in 0..full.len() {
            assert!(
                parse_proof(&full[..cut]).is_err(),
                "truncation at {cut} must fail: {:?}",
                &full[..cut]
            );
        }

        // Each duplicated member invalidates the proof.
        let dup = |member: &str| {
            let text = String::from_utf8(full.clone()).unwrap();
            let close = text.rfind('}').unwrap();
            let mut s = text[..close].to_string();
            s.push(',');
            s.push_str(member);
            s.push('}');
            s
        };
        assert!(parse_proof(dup("\"tree_size\":2").as_bytes()).is_err());
        assert!(parse_proof(dup("\"leaf_index\":0").as_bytes()).is_err());
        assert!(parse_proof(dup(&format!("\"root\":\"{}\"", hex(&root))).as_bytes()).is_err());
        assert!(parse_proof(
            dup(&format!("\"audit_path\":[\"{}\"]", hex(&path[0]))).as_bytes()
        )
        .is_err());
    }

    #[test]
    fn parse_proof_rejects_wrong_types_and_non_integer_numbers() {
        let refs: Vec<&[u8]> = vec![b"a", b"b"];
        let (root, path) = root_and_path(&refs, 0);
        let h = hex(&root);
        let p0 = hex(&path[0]);
        let good = format!("{{\"tree_size\":2,\"leaf_index\":0,\"root\":\"{h}\",\"audit_path\":[\"{p0}\"]}}");
        assert!(parse_proof(good.as_bytes()).is_ok());

        let cases = [
            format!("{{\"tree_size\":\"2\",\"leaf_index\":0,\"root\":\"{h}\",\"audit_path\":[\"{p0}\"]}}"),
            format!("{{\"tree_size\":2.0,\"leaf_index\":0,\"root\":\"{h}\",\"audit_path\":[\"{p0}\"]}}"),
            format!("{{\"tree_size\":2,\"leaf_index\":true,\"root\":\"{h}\",\"audit_path\":[\"{p0}\"]}}"),
            format!("{{\"tree_size\":2,\"leaf_index\":null,\"root\":\"{h}\",\"audit_path\":[\"{p0}\"]}}"),
            format!("{{\"tree_size\":-2,\"leaf_index\":0,\"root\":\"{h}\",\"audit_path\":[\"{p0}\"]}}"),
            format!("{{\"tree_size\":+2,\"leaf_index\":0,\"root\":\"{h}\",\"audit_path\":[\"{p0}\"]}}"),
            format!("{{\"tree_size\":2e0,\"leaf_index\":0,\"root\":\"{h}\",\"audit_path\":[\"{p0}\"]}}"),
            format!("{{\"tree_size\":02,\"leaf_index\":0,\"root\":\"{h}\",\"audit_path\":[\"{p0}\"]}}"),
            format!("{{\"tree_size\":18446744073709551616,\"leaf_index\":0,\"root\":\"{h}\",\"audit_path\":[\"{p0}\"]}}"),
            format!("{{\"tree_size\":99999999999999999999999999999,\"leaf_index\":0,\"root\":\"{h}\",\"audit_path\":[\"{p0}\"]}}"),
            format!("{{\"tree_size\":1e400,\"leaf_index\":0,\"root\":\"{h}\",\"audit_path\":[\"{p0}\"]}}"),
            format!("{{\"tree_size\":2,\"leaf_index\":0,\"root\":{h},\"audit_path\":[\"{p0}\"]}}"),
            format!("{{\"tree_size\":2,\"leaf_index\":0,\"root\":\"{H}\",\"audit_path\":[\"{p0}\"]}}", H = h.to_uppercase()),
            format!("{{\"tree_size\":2,\"leaf_index\":0,\"root\":\"{h}0\",\"audit_path\":[\"{p0}\"]}}"),
            format!("{{\"tree_size\":2,\"leaf_index\":0,\"root\":\"short\",\"audit_path\":[\"{p0}\"]}}"),
            format!("{{\"tree_size\":2,\"leaf_index\":0,\"root\":\"{h}\",\"audit_path\":\"{p0}\"}}"),
            format!("{{\"tree_size\":2,\"leaf_index\":0,\"root\":\"{h}\",\"audit_path\":[{p0}]}}"),
            format!("{{\"tree_size\":2,\"leaf_index\":0,\"root\":\"{h}\",\"audit_path\":[null]}}"),
            format!("{{\"tree_size\":2,\"leaf_index\":0,\"root\":\"{h}\",\"audit_path\":[\"{P}\"]}}", P = p0.to_uppercase()),
            // Unknown member.
            format!("{{\"tree_size\":2,\"leaf_index\":0,\"root\":\"{h}\",\"audit_path\":[\"{p0}\"],\"extra\":1}}"),
        ];
        for case in cases {
            assert!(
                parse_proof(case.as_bytes()).is_err(),
                "must be invalid: {case}"
            );
        }
    }

    #[test]
    fn parse_proof_rejects_zero_size_and_out_of_range_index() {
        let h = hex(&sha256(b""));
        let cases = [
            format!("{{\"tree_size\":0,\"leaf_index\":0,\"root\":\"{h}\",\"audit_path\":[]}}"),
            format!("{{\"tree_size\":1,\"leaf_index\":1,\"root\":\"{h}\",\"audit_path\":[]}}"),
            format!("{{\"tree_size\":3,\"leaf_index\":3,\"root\":\"{h}\",\"audit_path\":[]}}"),
            format!("{{\"tree_size\":18446744073709551615,\"leaf_index\":18446744073709551615,\"root\":\"{h}\",\"audit_path\":[]}}"),
        ];
        for case in cases {
            assert!(parse_proof(case.as_bytes()).is_err(), "{case}");
        }
        // Boundary that IS valid: index size-1.
        let ok = format!("{{\"tree_size\":1,\"leaf_index\":0,\"root\":\"{h}\",\"audit_path\":[]}}");
        assert!(parse_proof(ok.as_bytes()).is_ok());
    }

    // --- end-to-end verification logic --------------------------------------

    /// Build a real proof object (as produced by `prove`) for one record of a
    /// batch, then verify it exactly the way the command does.
    fn verify_record(records: &[&[u8]], m: usize, record: &[u8], trusted_size: u64) -> Result<(), String> {
        let (root, path) = root_and_path(records, m);
        let size = records.len() as u64;
        let bytes = proof_json(size, m as u64, &root, &path).into_bytes();
        let proof = parse_proof(&bytes).unwrap();
        verify_proof(&proof, record, trusted_size, &root)
    }

    #[test]
    fn verify_accepts_real_proofs_at_every_position_of_many_sizes() {
        let sizes: Vec<usize> = (1..=18).chain([31, 32, 33, 63, 64, 65, 100, 127, 128, 257]).collect();
        for n in sizes {
            let records: Vec<Vec<u8>> = (0..n).map(|i| format!("record-{i:04}").into_bytes()).collect();
            let refs: Vec<&[u8]> = records.iter().map(|r| r.as_slice()).collect();
            let root = mth(&refs);
            for m in 0..n {
                verify_record(&refs, m, refs[m], n as u64).unwrap_or_else(|e| {
                    panic!("n={n} m={m} must verify: {e}")
                });
                // The proof must not be trusted by itself: a different
                // trusted size or root always fails.
                assert!(verify_record(&refs, m, refs[m], n as u64 + 1).is_err());
                let mut other_root = root;
                other_root[0] ^= 0x01;
                let (_, path) = root_and_path(&refs, m);
                let bytes = proof_json(n as u64, m as u64, &root, &path).into_bytes();
                let proof = parse_proof(&bytes).unwrap();
                assert!(verify_proof(&proof, refs[m], n as u64, &other_root).is_err());
            }
        }
    }

    #[test]
    fn verify_is_strict_about_record_bytes() {
        // Empty record verifies when the record file is empty; adding even a
        // single terminating LF changes the content and must fail.
        let refs: Vec<&[u8]> = vec![b"", b"x"];
        assert!(verify_record(&refs, 0, b"", 2).is_ok());
        assert!(verify_record(&refs, 0, b"\n", 2).is_err());
        assert!(verify_record(&refs, 0, b" ", 2).is_err());
        assert!(verify_record(&refs, 0, b"\r", 2).is_err());
        // NUL and non-UTF-8 bytes are part of the target record.
        let bin: &[u8] = b"\xff\xfe\x00binary";
        let refs: Vec<&[u8]> = vec![b"alpha", bin, b"beta"];
        assert!(verify_record(&refs, 1, bin, 3).is_ok());
        let mut almost = bin.to_vec();
        *almost.last_mut().unwrap() ^= 0x01;
        assert!(verify_record(&refs, 1, &almost, 3).is_err());
        // Trailing LF/space/CR appended to an otherwise right record fails.
        for suffix in [b"\n".as_slice(), b" ", b"\r", b"\x00"] {
            let mut s = bin.to_vec();
            s.extend_from_slice(suffix);
            assert!(verify_record(&refs, 1, &s, 3).is_err(), "suffix {suffix:?}");
        }
    }

    #[test]
    fn verify_single_record_needs_empty_path() {
        let refs: Vec<&[u8]> = vec![b"only"];
        let (root, path) = root_and_path(&refs, 0);
        assert!(path.is_empty());
        let bytes = proof_json(1, 0, &root, &path).into_bytes();
        let proof = parse_proof(&bytes).unwrap();
        assert!(verify_proof(&proof, b"only", 1, &root).is_ok());

        // One extra hash cannot succeed: the parser accepts the array but the
        // geometry check must reject the unconsumed hash.
        let extra = leaf_hash(b"sibling");
        let bytes = proof_json(1, 0, &root, &[extra]).into_bytes();
        let proof = parse_proof(&bytes).unwrap();
        assert!(verify_proof(&proof, b"only", 1, &root).is_err());
    }

    #[test]
    fn verify_uneven_tree_uses_rfc_geometry_and_declared_position_only() {
        // n=5: the last leaf pairs directly with MTH of the first four.
        let owned: Vec<Vec<u8>> = (0..5).map(|i| vec![b'a' + i as u8]).collect();
        let refs: Vec<&[u8]> = owned.iter().map(|v| v.as_slice()).collect();
        let (root, path4) = root_and_path(&refs, 4);
        assert_eq!(path4.len(), 1);
        let bytes = proof_json(5, 4, &root, &path4).into_bytes();
        let proof = parse_proof(&bytes).unwrap();
        assert!(verify_proof(&proof, refs[4], 5, &root).is_ok());

        // A missing hash fails.
        let bytes = proof_json(5, 4, &root, &[]).into_bytes();
        let proof = parse_proof(&bytes).unwrap();
        assert!(verify_proof(&proof, refs[4], 5, &root).is_err());

        // Duplicate content is verified at the claimed position only: the
        // same bytes at a different position do not verify with this proof.
        let dup: Vec<&[u8]> = vec![b"x", b"a", b"x"];
        let (_, p2) = root_and_path(&dup, 2);
        let (droot, _) = root_and_path(&dup, 0);
        let bytes = proof_json(3, 2, &droot, &p2).into_bytes();
        let proof = parse_proof(&bytes).unwrap();
        assert!(verify_proof(&proof, b"x", 3, &droot).is_ok());
        // Position 0 with the position-2 proof must not be searched/fixed up.
        let bytes = proof_json(3, 0, &droot, &p2).into_bytes();
        let proof = parse_proof(&bytes).unwrap();
        assert!(verify_proof(&proof, b"x", 3, &droot).is_err());
    }

    #[test]
    fn include_record_matches_recursive_verifier_and_checks_length() {
        // Cross-check the command's verifier against the test-module RFC
        // verifier across geometries, and pin short/long path rejection.
        for n in 1..=20usize {
            let records: Vec<Vec<u8>> = (0..n).map(|i| format!("r{i}").into_bytes()).collect();
            let refs: Vec<&[u8]> = records.iter().map(|r| r.as_slice()).collect();
            let root = mth(&refs);
            for m in 0..n {
                let (_, path) = root_and_path(&refs, m);
                let got = include_record(leaf_hash(refs[m]), m as u64, n as u64, &path).unwrap();
                assert_eq!(got, root, "n={n} m={m}");
                assert_eq!(hex_of(&got), hex_of(&verify_proof_old(refs[m], m, n, &path)));
                if !path.is_empty() {
                    assert!(
                        include_record(leaf_hash(refs[m]), m as u64, n as u64, &path[..path.len() - 1])
                            .is_err()
                    );
                }
                let mut longer = path.clone();
                longer.push(leaf_hash(b"extra"));
                assert!(include_record(leaf_hash(refs[m]), m as u64, n as u64, &longer).is_err());
            }
        }
    }

    /// The pre-existing test verifier (asserting form), reused above to cross
    /// check the production verifier on common inputs.
    fn verify_proof_old(leaf: &[u8], m: usize, n: usize, path: &[[u8; 32]]) -> [u8; 32] {
        rfc_recompute_root(leaf, m, n, path)
    }
}
