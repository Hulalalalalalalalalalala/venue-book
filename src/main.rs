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
        Verify that the complete contents of <record-file> (every byte of the
        file, exactly as stored) form the record at the position named by the
        inclusion proof in <proof-file> (a JSON object as printed by `prove`).
        <trusted-tree-size> is the batch's record count as a decimal positive
        integer and <trusted-root> its Merkle root as 64 lowercase hexadecimal
        characters; both must be confirmed independently by the user and are
        never taken from the proof itself. On success prints \"verified\".

        Example:
            roottrace verify record.bin proof.json 9 a8a3e76e...723adc3

Exit status:
    0  success
    1  a file cannot be read, the record index does not exist, the proof is
       invalid, or verification fails
    2  usage error (unknown command, missing or extra arguments, bad index,
       bad trusted tree size or root)";

fn main() -> ExitCode {
    // Raw OS arguments: file paths are handed to the filesystem exactly as
    // received, byte for byte. On Unix a path may contain bytes that are not
    // valid UTF-8 (e.g. 0xff); such a path is not invalid and must reach the
    // file rather than aborting argument collection. Only the command name
    // and the record index are required to be UTF-8 text.
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
        [cmd, record, proof, size, root] if cmd == OsStr::new("verify") => {
            // The trusted tree size and root come from the user, never from
            // the proof: both are validated as command line syntax first.
            let trusted_size = match parse_index(size).filter(|&v| v >= 1) {
                Some(v) => v,
                None => {
                    let shown = size.to_string_lossy();
                    eprintln!("roottrace: invalid trusted tree size '{shown}': expected a decimal positive integer of ASCII digits");
                    eprintln!("{USAGE}");
                    return ExitCode::from(2);
                }
            };
            let trusted_root = match root.to_str().and_then(|s| parse_hex_hash(s.as_bytes())) {
                Some(r) => r,
                None => {
                    let shown = root.to_string_lossy();
                    eprintln!("roottrace: invalid trusted root '{shown}': expected 64 lowercase hexadecimal characters");
                    eprintln!("{USAGE}");
                    return ExitCode::from(2);
                }
            };
            match verify_record(Path::new(record), Path::new(proof), trusted_size, &trusted_root) {
                Ok(()) => {
                    println!("verified");
                    ExitCode::SUCCESS
                }
                Err(reason) => {
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

enum ProveError {
    Read(String),
    Missing(u64, u64),
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

/// A parsed inclusion proof: the four required fields of the JSON object
/// printed by `prove`, already type- and range-checked.
struct Proof {
    tree_size: u64,
    leaf_index: u64,
    root: [u8; 32],
    audit_path: Vec<[u8; 32]>,
}

/// Verify that `record_path`'s complete byte content is the record at the
/// position named by the proof in `proof_path`, under a tree of
/// `trusted_size` records whose root is `trusted_root`. The trusted values
/// come from the user (confirmed independently); the proof's own tree_size
/// and root fields must agree with them, never replace them.
fn verify_record(
    record_path: &Path,
    proof_path: &Path,
    trusted_size: u64,
    trusted_root: &[u8; 32],
) -> Result<(), String> {
    // The record file is NOT split on LF and nothing is trimmed: every byte
    // (trailing newlines, spaces, CR, NUL, non-UTF-8 bytes) is part of the
    // record. A zero-byte file is one empty record.
    let record = fs::read(record_path)
        .map_err(|e| format!("cannot read '{}': {e}", display_path(record_path)))?;
    let proof_bytes = fs::read(proof_path)
        .map_err(|e| format!("cannot read '{}': {e}", display_path(proof_path)))?;
    let proof = parse_proof(&proof_bytes).map_err(|e| format!("invalid proof: {e}"))?;

    if proof.tree_size != trusted_size {
        return Err(format!(
            "verification failed: proof tree_size {} does not match the trusted tree size {trusted_size}",
            proof.tree_size
        ));
    }
    if proof.root != *trusted_root {
        return Err(
            "verification failed: proof root does not match the trusted root".to_string()
        );
    }
    let computed = verify_inclusion(&record, proof.leaf_index, proof.tree_size, &proof.audit_path)
        .ok_or_else(|| {
            format!(
                "verification failed: audit path does not fit a tree of size {} at leaf index {}",
                proof.tree_size, proof.leaf_index
            )
        })?;
    if computed != *trusted_root {
        return Err(
            "verification failed: record and audit path do not hash to the trusted root"
                .to_string(),
        );
    }
    Ok(())
}

/// RFC 6962 section 2.1.1 inclusion verification: recompute the tree root
/// from the leaf hash of `record`, the position `leaf_index` within a tree
/// of `tree_size` records, and the sibling hashes in `audit_path` (ordered
/// leaf to root, used exactly in that order). Returns the computed root, or
/// `None` when the path has too few or too many hashes for the tree shape.
/// Uneven (non power-of-two) sizes follow the same k-split tree shape as
/// proof generation: no record is duplicated or padded in.
fn verify_inclusion(
    record: &[u8],
    leaf_index: u64,
    tree_size: u64,
    audit_path: &[[u8; 32]],
) -> Option<[u8; 32]> {
    fn sub(
        record: &[u8],
        m: u64,
        n: u64,
        path: &[[u8; 32]],
        pos: &mut usize,
    ) -> Option<[u8; 32]> {
        if n == 1 {
            return Some(leaf_hash(record));
        }
        // Largest power of two strictly smaller than n.
        let k = 1u64 << (u64::BITS - 1 - (n - 1).leading_zeros());
        if m < k {
            let left = sub(record, m, k, path, pos)?;
            let right = *path.get(*pos)?;
            *pos += 1;
            Some(node_hash(&left, &right))
        } else {
            let right = sub(record, m - k, n - k, path, pos)?;
            let left = *path.get(*pos)?;
            *pos += 1;
            Some(node_hash(&left, &right))
        }
    }
    let mut pos = 0;
    let root = sub(record, leaf_index, tree_size, audit_path, &mut pos)?;
    if pos != audit_path.len() {
        return None; // leftover hashes: the path is too long
    }
    Some(root)
}

/// Decode a 64-character lowercase hexadecimal string into 32 bytes.
fn parse_hex_hash(text: &[u8]) -> Option<[u8; 32]> {
    if text.len() != 64 {
        return None;
    }
    let nibble = |b: u8| -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            _ => None,
        }
    };
    let mut out = [0u8; 32];
    for (i, pair) in text.chunks_exact(2).enumerate() {
        out[i] = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Some(out)
}

// --- Proof JSON parsing ---

/// A parsed JSON value. Numbers keep their raw token so integer-only fields
/// can reject fractions and exponents; strings are stored unescaped.
enum JsonValue {
    Null,
    Bool,
    Number(Vec<u8>),
    String(Vec<u8>),
    Array(Vec<JsonValue>),
    Object(Vec<(Vec<u8>, JsonValue)>),
}

/// Parse the proof file: one complete JSON object (any field order, any
/// whitespace) with exactly the required fields tree_size, leaf_index, root
/// and audit_path, each of the right type and range. Unknown extra fields
/// are ignored; missing, duplicated or mistyped required fields are not.
fn parse_proof(data: &[u8]) -> Result<Proof, String> {
    let mut parser = JsonParser { data, pos: 0 };
    parser.skip_ws();
    let value = parser.parse_value()?;
    parser.skip_ws();
    if parser.pos != data.len() {
        return Err("trailing data after the JSON object".to_string());
    }
    let entries = match value {
        JsonValue::Object(entries) => entries,
        _ => return Err("proof must be a JSON object".to_string()),
    };

    let mut tree_size = None;
    let mut leaf_index = None;
    let mut root = None;
    let mut audit_path = None;
    for (key, value) in entries {
        let slot = match key.as_slice() {
            b"tree_size" => &mut tree_size,
            b"leaf_index" => &mut leaf_index,
            b"root" => &mut root,
            b"audit_path" => &mut audit_path,
            _ => continue, // unknown fields are ignored
        };
        if slot.is_some() {
            return Err(format!("duplicate field '{}'", String::from_utf8_lossy(&key)));
        }
        *slot = Some(value);
    }

    let tree_size = match tree_size {
        Some(v) => json_u64(&v, "tree_size")?,
        None => return Err("missing field 'tree_size'".to_string()),
    };
    let leaf_index = match leaf_index {
        Some(v) => json_u64(&v, "leaf_index")?,
        None => return Err("missing field 'leaf_index'".to_string()),
    };
    let root = match root {
        Some(JsonValue::String(s)) => parse_hex_hash(&s)
            .ok_or_else(|| "field 'root' must be 64 lowercase hexadecimal characters".to_string())?,
        Some(_) => return Err("field 'root' must be a string".to_string()),
        None => return Err("missing field 'root'".to_string()),
    };
    let audit_path = match audit_path {
        Some(JsonValue::Array(items)) => {
            let mut path = Vec::with_capacity(items.len());
            for item in &items {
                match item {
                    JsonValue::String(s) => path.push(parse_hex_hash(s).ok_or_else(|| {
                        "audit_path elements must be 64 lowercase hexadecimal characters"
                            .to_string()
                    })?),
                    _ => return Err("audit_path elements must be strings".to_string()),
                }
            }
            path
        }
        Some(_) => return Err("field 'audit_path' must be an array".to_string()),
        None => return Err("missing field 'audit_path'".to_string()),
    };

    if tree_size == 0 {
        return Err("tree_size must be at least 1".to_string());
    }
    if leaf_index >= tree_size {
        return Err(format!(
            "leaf_index {leaf_index} does not exist in a tree of size {tree_size}"
        ));
    }
    Ok(Proof { tree_size, leaf_index, root, audit_path })
}

/// A required integer field: a JSON number that is a 64-bit unsigned integer
/// (bare ASCII digits only — no sign, fraction or exponent).
fn json_u64(value: &JsonValue, field: &str) -> Result<u64, String> {
    let bad = || format!("field '{field}' must be a 64-bit unsigned JSON integer");
    let token = match value {
        JsonValue::Number(token) => token,
        _ => return Err(bad()),
    };
    if token.is_empty() || !token.iter().all(|b| b.is_ascii_digit()) {
        return Err(bad());
    }
    let mut value: u64 = 0;
    for &b in token {
        value = value
            .checked_mul(10)
            .and_then(|v| v.checked_add(u64::from(b - b'0')))
            .ok_or_else(bad)?;
    }
    Ok(value)
}

struct JsonParser<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> JsonParser<'a> {
    fn err(&self, reason: &str) -> String {
        format!("invalid JSON: {reason}")
    }

    fn skip_ws(&mut self) {
        while let Some(&b) = self.data.get(self.pos) {
            if matches!(b, b' ' | b'\t' | b'\n' | b'\r') {
                self.pos += 1;
            } else {
                break;
            }
        }
    }

    fn peek(&self) -> Option<u8> {
        self.data.get(self.pos).copied()
    }

    fn parse_value(&mut self) -> Result<JsonValue, String> {
        match self.peek() {
            Some(b'{') => self.parse_object(),
            Some(b'[') => self.parse_array(),
            Some(b'"') => Ok(JsonValue::String(self.parse_string()?)),
            Some(b't') => self.parse_literal(b"true").map(|()| JsonValue::Bool),
            Some(b'f') => self.parse_literal(b"false").map(|()| JsonValue::Bool),
            Some(b'n') => self.parse_literal(b"null").map(|()| JsonValue::Null),
            Some(b'-') | Some(b'0'..=b'9') => self.parse_number(),
            _ => Err(self.err("expected a value")),
        }
    }

    fn parse_literal(&mut self, literal: &[u8]) -> Result<(), String> {
        if self.data.len() >= self.pos + literal.len()
            && &self.data[self.pos..self.pos + literal.len()] == literal
        {
            self.pos += literal.len();
            Ok(())
        } else {
            Err(self.err("expected a value"))
        }
    }

    fn parse_number(&mut self) -> Result<JsonValue, String> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        match self.peek() {
            Some(b'0') => self.pos += 1,
            Some(b'1'..=b'9') => {
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.pos += 1;
                }
            }
            _ => return Err(self.err("malformed number")),
        }
        if self.peek() == Some(b'.') {
            self.pos += 1;
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(self.err("malformed number"));
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
        }
        if matches!(self.peek(), Some(b'e') | Some(b'E')) {
            self.pos += 1;
            if matches!(self.peek(), Some(b'+') | Some(b'-')) {
                self.pos += 1;
            }
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(self.err("malformed number"));
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
        }
        Ok(JsonValue::Number(self.data[start..self.pos].to_vec()))
    }

    fn parse_string(&mut self) -> Result<Vec<u8>, String> {
        self.pos += 1; // opening quote
        let mut out = Vec::new();
        loop {
            let b = match self.peek() {
                Some(b) => b,
                None => return Err(self.err("unterminated string")),
            };
            self.pos += 1;
            match b {
                b'"' => return Ok(out),
                b'\\' => {
                    let esc = match self.peek() {
                        Some(e) => e,
                        None => return Err(self.err("unterminated string")),
                    };
                    self.pos += 1;
                    match esc {
                        b'"' => out.push(b'"'),
                        b'\\' => out.push(b'\\'),
                        b'/' => out.push(b'/'),
                        b'b' => out.push(0x08),
                        b'f' => out.push(0x0c),
                        b'n' => out.push(b'\n'),
                        b'r' => out.push(b'\r'),
                        b't' => out.push(b'\t'),
                        b'u' => {
                            let hi = self.parse_hex4()?;
                            let code = if (0xd800..0xdc00).contains(&hi) {
                                // High surrogate: a low surrogate must follow.
                                if self.peek() == Some(b'\\') {
                                    self.pos += 1;
                                }
                                if self.peek() != Some(b'u') {
                                    return Err(self.err("lone surrogate in string escape"));
                                }
                                self.pos += 1;
                                let lo = self.parse_hex4()?;
                                if !(0xdc00..0xe000).contains(&lo) {
                                    return Err(self.err("lone surrogate in string escape"));
                                }
                                0x10000 + ((hi - 0xd800) << 10) + (lo - 0xdc00)
                            } else {
                                hi
                            };
                            match char::from_u32(code) {
                                Some(c) => {
                                    let mut buf = [0u8; 4];
                                    out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
                                }
                                None => return Err(self.err("lone surrogate in string escape")),
                            }
                        }
                        _ => return Err(self.err("invalid escape in string")),
                    }
                }
                0x00..=0x1f => return Err(self.err("control character in string")),
                _ => out.push(b),
            }
        }
    }

    fn parse_hex4(&mut self) -> Result<u32, String> {
        let mut value: u32 = 0;
        for _ in 0..4 {
            let b = match self.peek() {
                Some(b) => b,
                None => return Err(self.err("truncated \\u escape")),
            };
            self.pos += 1;
            let digit = match b {
                b'0'..=b'9' => u32::from(b - b'0'),
                b'a'..=b'f' => u32::from(b - b'a' + 10),
                b'A'..=b'F' => u32::from(b - b'A' + 10),
                _ => return Err(self.err("invalid \\u escape")),
            };
            value = (value << 4) | digit;
        }
        Ok(value)
    }

    fn parse_object(&mut self) -> Result<JsonValue, String> {
        self.pos += 1; // '{'
        let mut entries = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(JsonValue::Object(entries));
        }
        loop {
            self.skip_ws();
            if self.peek() != Some(b'"') {
                return Err(self.err("expected an object key"));
            }
            let key = self.parse_string()?;
            self.skip_ws();
            if self.peek() != Some(b':') {
                return Err(self.err("expected ':' after object key"));
            }
            self.pos += 1;
            self.skip_ws();
            let value = self.parse_value()?;
            entries.push((key, value));
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(JsonValue::Object(entries));
                }
                _ => return Err(self.err("expected ',' or '}' in object")),
            }
        }
    }

    fn parse_array(&mut self) -> Result<JsonValue, String> {
        self.pos += 1; // '['
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(JsonValue::Array(items));
        }
        loop {
            self.skip_ws();
            items.push(self.parse_value()?);
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b']') => {
                    self.pos += 1;
                    return Ok(JsonValue::Array(items));
                }
                _ => return Err(self.err("expected ',' or ']' in array")),
            }
        }
    }
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

    #[test]
    fn hex_hash_parsing_accepts_only_64_lowercase_hex() {
        let good = "a8a3e76ecf28b850e84cb5465729921212ffd07de3c0e6e170cd233bf723adc3";
        assert!(parse_hex_hash(good.as_bytes()).is_some());
        assert_eq!(parse_hex_hash(b""), None);
        assert_eq!(parse_hex_hash(&good.as_bytes()[..63]), None); // too short
        assert_eq!(parse_hex_hash(format!("{good}0").as_bytes()), None); // too long
        assert_eq!(parse_hex_hash(good.to_uppercase().as_bytes()), None); // uppercase
        assert_eq!(parse_hex_hash(good.replacen('a', "g", 1).as_bytes()), None); // non-hex
    }

    #[test]
    fn verify_inclusion_roundtrips_generated_proofs_for_many_sizes() {
        let sizes: Vec<usize> = (1..=18).chain([31, 32, 33, 100, 257]).collect();
        for n in sizes {
            let records: Vec<Vec<u8>> =
                (0..n).map(|i| format!("record-{i:04}").into_bytes()).collect();
            let refs: Vec<&[u8]> = records.iter().map(|r| r.as_slice()).collect();
            let root = mth(&refs);
            for m in 0..n {
                let (_, path) = root_and_path(&refs, m);
                let computed = verify_inclusion(refs[m], m as u64, n as u64, &path);
                assert_eq!(computed, Some(root), "n={n}, m={m}");
                // A different record at the same position must not verify
                // (unless it is byte-identical).
                let alien = b"alien-record".as_slice();
                if alien != refs[m] {
                    assert_ne!(
                        verify_inclusion(alien, m as u64, n as u64, &path),
                        Some(root),
                        "n={n}, m={m}: wrong record must fail"
                    );
                }
                // Too few hashes: drop the last one.
                if !path.is_empty() {
                    assert_eq!(
                        verify_inclusion(refs[m], m as u64, n as u64, &path[..path.len() - 1]),
                        None,
                        "n={n}, m={m}: truncated path must fail"
                    );
                }
                // Too many hashes: append a copy of the last one (or any hash).
                let extra = if path.is_empty() { mth(&refs) } else { path[path.len() - 1] };
                let mut longer = path.clone();
                longer.push(extra);
                assert!(
                    verify_inclusion(refs[m], m as u64, n as u64, &longer) != Some(root),
                    "n={n}, m={m}: extended path must fail"
                );
                // Reordered hashes must not verify either.
                if path.len() >= 2 {
                    let mut swapped = path.clone();
                    swapped.swap(0, 1);
                    assert_ne!(
                        verify_inclusion(refs[m], m as u64, n as u64, &swapped),
                        Some(root),
                        "n={n}, m={m}: reordered path must fail"
                    );
                }
            }
        }
    }

    #[test]
    fn verify_inclusion_single_record_needs_empty_path() {
        let record = b"only".as_slice();
        let root = mth(&[record]);
        assert_eq!(verify_inclusion(record, 0, 1, &[]), Some(root));
        // Even one stray hash makes the proof fail.
        assert_eq!(verify_inclusion(record, 0, 1, &[root]), None);
    }

    fn proof_bytes(json: &str) -> Result<Proof, String> {
        parse_proof(json.as_bytes())
    }

    const ROOT_HEX: &str =
        "a8a3e76ecf28b850e84cb5465729921212ffd07de3c0e6e170cd233bf723adc3";
    const HASH_HEX: &str =
        "80f3f98ae8d7d9d1d2139a6a2dc94628e02fba22e125f922ea8a4c10799cb912";

    fn valid_proof_json() -> String {
        format!(
            "{{\"tree_size\":9,\"leaf_index\":8,\"root\":\"{ROOT_HEX}\",\"audit_path\":[\"{HASH_HEX}\"]}}"
        )
    }

    #[test]
    fn proof_parsing_accepts_field_order_whitespace_and_extra_fields() {
        let proof = proof_bytes(&valid_proof_json()).unwrap();
        assert_eq!(proof.tree_size, 9);
        assert_eq!(proof.leaf_index, 8);
        assert_eq!(proof.audit_path.len(), 1);

        // Shuffled field order, generous whitespace, a trailing newline and
        // unknown extra fields are all fine.
        let fancy = format!(
            "{{\n  \"audit_path\": [ \"{HASH_HEX}\" ],\n  \"note\": {{\"nested\": [1, \"two\", null]}},\n  \"root\": \"{ROOT_HEX}\",\n  \"leaf_index\": 8,\n  \"tree_size\": 9\n}}\n"
        );
        let proof = proof_bytes(&fancy).unwrap();
        assert_eq!(proof.tree_size, 9);
        assert_eq!(proof.leaf_index, 8);
        assert_eq!(proof.audit_path.len(), 1);

        // u64::MAX is a legitimate field value.
        let max = format!(
            "{{\"tree_size\":18446744073709551615,\"leaf_index\":18446744073709551614,\"root\":\"{ROOT_HEX}\",\"audit_path\":[]}}"
        );
        let proof = proof_bytes(&max).unwrap();
        assert_eq!(proof.tree_size, u64::MAX);
        assert_eq!(proof.leaf_index, u64::MAX - 1);
    }

    #[test]
    fn proof_parsing_rejects_malformed_or_mistyped_proofs() {
        let cases: Vec<String> = vec![
            String::new(),                  // empty file
            "[]".into(),                    // not an object
            "null".into(),                  // not an object
            "{}".into(),                    // all fields missing
            valid_proof_json().replace("\"tree_size\":9,", ""), // missing tree_size
            valid_proof_json().replace("\"leaf_index\":8,", ""), // missing leaf_index
            valid_proof_json().replace(&format!("\"root\":\"{ROOT_HEX}\","), ""), // missing root
            valid_proof_json().replace("\"audit_path\":", "\"audit_path_2\":"), // missing audit_path
            valid_proof_json().replace("{\"tree_size\":9", "{\"tree_size\":9,\"tree_size\":9"), // duplicate
            valid_proof_json().replace("\"leaf_index\":8", "\"leaf_index\":8,\"leaf_index\":8"), // duplicate
            valid_proof_json().replace("\"tree_size\":9", "\"tree_size\":0"), // zero size
            valid_proof_json().replace("\"tree_size\":9", "\"tree_size\":-9"), // negative
            valid_proof_json().replace("\"tree_size\":9", "\"tree_size\":9.0"), // fraction
            valid_proof_json().replace("\"tree_size\":9", "\"tree_size\":9e0"), // exponent
            valid_proof_json().replace("\"tree_size\":9", "\"tree_size\":\"9\""), // string
            valid_proof_json().replace("\"tree_size\":9", "\"tree_size\":18446744073709551616"), // overflow
            valid_proof_json().replace("\"leaf_index\":8", "\"leaf_index\":9"), // index == size
            valid_proof_json().replace("\"leaf_index\":8", "\"leaf_index\":100"), // index > size
            valid_proof_json().replace(ROOT_HEX, &ROOT_HEX.to_uppercase()), // uppercase root
            valid_proof_json().replace(ROOT_HEX, &ROOT_HEX[..63]), // short root
            valid_proof_json().replace(HASH_HEX, &HASH_HEX.replacen('8', "g", 1)), // non-hex path
            valid_proof_json().replace(&format!("\"{HASH_HEX}\""), HASH_HEX), // unquoted path element
            valid_proof_json().replace("\"audit_path\":[", "\"audit_path\":").replace("]}", "}"), // path not an array
            format!("{} trailing", valid_proof_json()), // trailing garbage
            format!("{} {{}}", valid_proof_json()),     // second object
            valid_proof_json().replacen('{', "{ ", 1) + " ", // fine actually; replaced below
        ];
        for (i, case) in cases.iter().enumerate() {
            if i == cases.len() - 1 {
                continue; // the last case is valid JSON, checked separately
            }
            assert!(proof_bytes(case).is_err(), "case {i} must be rejected: {case:?}");
        }
        // Leading whitespace and a trailing space are accepted.
        assert!(proof_bytes(&cases[cases.len() - 1]).is_ok());
    }

    #[test]
    fn proof_parsing_handles_json_string_escapes() {
        // An escaped hex digit still decodes to the same hash string.
        let escaped = valid_proof_json().replacen("\"root\":\"a", "\"root\":\"\\u0061", 1);
        let proof = proof_bytes(&escaped).unwrap();
        assert_eq!(proof.root, parse_hex_hash(ROOT_HEX.as_bytes()).unwrap());
        // Unterminated strings, bad escapes and raw control bytes are invalid.
        assert!(proof_bytes("{\"tree_size\":\"abc}").is_err());
        assert!(proof_bytes("{\"tree_size\":\"a\\xb\"}").is_err());
        assert!(proof_bytes("{\"tree_size\":\"a\nb\"}").is_err());
    }
}
