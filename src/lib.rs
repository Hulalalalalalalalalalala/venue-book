//! roottrace 库入口：为其他 Rust 程序提供 RFC 6962 成员证明（包含证明）核验。
//!
//! 命令行程序 `roottrace` 的 `root`/`prove`/`verify` 子命令同样建立在本文件的
//! 实现之上，因此库与命令行对同一批数据的核验结果完全一致。
//!
//! # 用法概览
//!
//! 调用方需要准备三样东西，全部在内存中，无需完整批次或临时文件：
//!
//! 1. **记录**：目标记录的全部原始字节（`&[u8]`）。每个字节都属于内容——
//!    空切片表示一条空记录；末尾的 LF、CR、空格、NUL 与非 UTF-8 字节都参与
//!    核验，不沿用批次文件的 LF 分行规则。
//! 2. **证明**：`roottrace prove` 输出的 JSON 证明的原始字节。字段重排、
//!    合法 JSON 空白与等价字符串转义按既有规则接受；重复字段、不合法的整数
//!    或哈希仍被拒绝。
//! 3. **独立确认的可信值**：树大小（`u64`，必须为正）与根值（`[u8; 32]`），
//!    必须来自可信渠道（签名公告、带外账本、对完整批次自行运行
//!    `roottrace root` 等），绝不能取自证明内部。
//!
//! 核验成功返回 [`Membership`]，可直接读取记录序号、所绑定的树大小和根值；
//! 返回的大小和根值就是调用方提供的可信值（已与证明核对一致），不是从证明
//! 里读出的字段。失败按类型区分为 [`VerifyError`] 的三个变体，库本身不向
//! 标准输出或标准错误打印任何内容，展示方式由调用方决定。
//!
//! # 示例
//!
//! ```
//! use roottrace::{verify_membership, VerifyError};
//!
//! // 只含一条空记录的批次：根值为 SHA-256(0x00)，审计路径为空。
//! let record: &[u8] = b"";
//! let proof = br#"{"tree_size":1,"leaf_index":0,"root":"6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d","audit_path":[]}"#;
//! let trusted_root: [u8; 32] = [
//!     0x6e, 0x34, 0x0b, 0x9c, 0xff, 0xb3, 0x7a, 0x98,
//!     0x9c, 0xa5, 0x44, 0xe6, 0xbb, 0x78, 0x0a, 0x2c,
//!     0x78, 0x90, 0x1d, 0x3f, 0xb3, 0x37, 0x38, 0x76,
//!     0x85, 0x11, 0xa3, 0x06, 0x17, 0xaf, 0xa0, 0x1d,
//! ];
//!
//! match verify_membership(record, proof, 1, &trusted_root) {
//!     Ok(m) => {
//!         assert_eq!(m.leaf_index(), 0);
//!         assert_eq!(m.tree_size(), 1);
//!         assert_eq!(m.root(), &trusted_root);
//!     }
//!     Err(VerifyError::MalformedProof(reason)) => {
//!         panic!("证明格式无效: {reason}");
//!     }
//!     Err(VerifyError::VerificationFailed(reason)) => {
//!         panic!("核验失败: {reason}");
//!     }
//!     Err(VerifyError::InvalidTrustedSize) => {
//!         panic!("可信树大小必须为正整数");
//!     }
//! }
//! ```

use std::fmt;

/// 核验成功后的类型化结果：记录在某个 Merkle 树中的成员身份已被确认。
///
/// 序号从 0 开始，指向证明声明的位置；相同内容出现在其他位置不能替代这个
/// 位置。树大小和根值已经与调用方的可信值核对一致——它们就是核验所锚定的
/// 值，而不是从证明中读出的字段。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Membership {
    leaf_index: u64,
    tree_size: u64,
    root: [u8; 32],
}

impl Membership {
    /// 被核验记录在树中的序号（从 0 开始），即证明声明的 `leaf_index`。
    /// 即使树大小超过平台的索引宽度，也保留完整的 64 位含义。
    pub fn leaf_index(&self) -> u64 {
        self.leaf_index
    }

    /// 核验所绑定的树大小，等于调用方提供的可信树大小。
    pub fn tree_size(&self) -> u64 {
        self.tree_size
    }

    /// 核验所绑定的树根值，等于调用方提供的可信根值。
    pub fn root(&self) -> &[u8; 32] {
        &self.root
    }
}

/// 核验失败的分类，调用方可按变体区分处理方式。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    /// 调用参数无效：可信树大小为 0。不存在包含记录的零节点树，因此这不
    /// 能被当作"空树中的成员证明"接受。该判断在解读证明之前完成。
    InvalidTrustedSize,
    /// 证明格式无效：证明字节不能按现有格式解读（不是完整 JSON 对象、字段
    /// 缺失/重复/类型错误、整数或哈希不合法、`tree_size` 为 0、序号越界、
    /// 对象后有多余字节等）。附带人类可读的原因说明。
    MalformedProof(String),
    /// 核验失败：证明格式合法，但记录内容、可信树大小、可信根值或审计路径
    /// 不匹配。附带人类可读的原因说明。
    VerificationFailed(String),
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerifyError::InvalidTrustedSize => {
                write!(f, "trusted tree size must be positive: zero cannot name a tree that holds a record")
            }
            VerifyError::MalformedProof(reason) => write!(f, "invalid proof: {reason}"),
            VerifyError::VerificationFailed(reason) => write!(f, "verification failed: {reason}"),
        }
    }
}

impl std::error::Error for VerifyError {}

/// 核验一条记录的 RFC 6962 成员证明，无需完整批次或临时文件。
///
/// - `record`：目标记录的全部原始字节。空切片表示一条空记录；末尾 LF、CR、
///   空格、NUL 与非 UTF-8 字节都属于内容，不做任何切分或修剪。
/// - `proof`：证明 JSON 的原始字节（如 `roottrace prove` 的输出）。字段
///   重排、合法空白与等价字符串转义被接受；重复字段、不合法的整数或哈希
///   被拒绝。
/// - `trusted_tree_size`：调用方**独立确认**的树大小，必须为正；为 0 时
///   返回 [`VerifyError::InvalidTrustedSize`]，而不是按空树核验。
/// - `trusted_root`：调用方**独立确认**的 32 字节根值。
///
/// 证明自带的 `tree_size` 与 `root` 只用于和可信值比对，绝不作为信任依据。
/// 成功时返回 [`Membership`]；失败时按 [`VerifyError`] 变体区分格式错误与
/// 核验失败，且不会返回任何表示已核验成功的结果。
pub fn verify_membership(
    record: &[u8],
    proof: &[u8],
    trusted_tree_size: u64,
    trusted_root: &[u8; 32],
) -> Result<Membership, VerifyError> {
    // 可信树大小为零是调用参数无效：必须先于证明解读拒绝，否则一份
    // tree_size 为 0 的"证明"会被当成空树成员证明的格式问题来报告。
    if trusted_tree_size == 0 {
        return Err(VerifyError::InvalidTrustedSize);
    }
    let proof = parse_proof(proof).map_err(VerifyError::MalformedProof)?;
    verify_proof(&proof, record, trusted_tree_size, trusted_root)
        .map_err(VerifyError::VerificationFailed)?;
    Ok(Membership {
        leaf_index: proof.leaf_index,
        tree_size: trusted_tree_size,
        root: *trusted_root,
    })
}

// --- 供命令行程序复用的内部实现 ------------------------------------------------
//
// 以下项是 `roottrace` 命令行程序（src/main.rs）与库共享的实现细节，不属于
// 稳定的库 API，故对文档隐藏。命令行的 root/prove/verify 子命令与库函数走
// 完全相同的代码路径，保证两边结果一致。

#[doc(hidden)]
pub fn is_lower_hex(b: u8) -> bool {
    b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
}

#[doc(hidden)]
pub fn hex_nibble(b: u8) -> Option<u8> {
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

/// Split raw bytes into records on LF (0x0a). The separator is not part of
/// any record. A trailing LF terminates the last record without adding an
/// empty one; an empty file yields zero records.
///
/// This materializes one slice per record and is kept for callers that
/// already hold a whole batch in memory (e.g. the in-memory test helpers and
/// `prove`); the `root` command builds the same tree without it via the
/// fixed-buffer [`StreamRoot`].
#[doc(hidden)]
pub fn split_records(data: &[u8]) -> Vec<&[u8]> {
    if data.is_empty() {
        return Vec::new();
    }
    let mut records: Vec<&[u8]> = data.split(|&b| b == b'\n').collect();
    if data.last() == Some(&b'\n') {
        records.pop();
    }
    records
}

// --- Streaming root ----------------------------------------------------------
//
// The `root` command must hash batches too large (or made of records too
// long, or too numerous) to fit in memory. The construction below keeps:
//
//   * ONE fixed-size read buffer ([`READ_CAPACITY`] bytes), independently of
//     the file's total length — the file is never read whole;
//   * ONE leaf hash in progress, fed record bytes straight from that buffer,
//     independently of the longest record — a record is never stored;
//   * a stack of O(log n) finalized subtree hashes, independently of the
//     record count — leaf hashes are not retained.
//
// Nothing here bounds the input: memory does not shrink by refusing large
// files, long records or many records, only by never holding them.
//
// Result equivalence with the in-memory [`build_tree`] comes from the same
// RFC 6962 fold order: pushing leaf hashes left to right and merging equal
// levels builds complete subtrees in postfix order, and the final
// right-to-left fold joins exactly the sibling pairs the recursive
// definition's "largest power of two below n" split chooses. Uneven batches
// therefore need no duplicate of the last leaf and no padded empty leaf.

/// Fixed capacity of the single read buffer used while streaming a batch.
/// Reads may return fewer bytes at any time (including one); the result is
/// independent of where read boundaries fall because records are recognized by
/// their LF bytes, not by chunk boundaries.
#[doc(hidden)]
pub const READ_CAPACITY: usize = 64 * 1024;

/// Streaming RFC 6962 Merkle Tree Hash builder.
///
/// Feed the raw file bytes in arbitrary chunking with [`StreamRoot::extend`]
/// and finish with [`StreamRoot::finish`]. Bytes are split into records on LF
/// exactly like [`split_records`]: the LF is a separator and never content, a
/// trailing LF only terminates the last record, and an empty input is zero
/// records. All other bytes — spaces, tabs, CR, NUL, non-UTF-8 sequences —
/// are record content.
///
/// The builder stores a leaf hash in progress (a [`Sha256`] state) and a
/// log-depth stack of finalized subtree hashes; record bytes are fed straight
/// from the caller's read buffer, so no file-sized, record-sized or
/// record-count-sized storage is ever held. Its working memory is bounded
/// independently of the file's total size, of its longest record and of its
/// record count.
struct StreamRoot {
    /// Hash of the record currently being read: SHA-256(0x00 || record...).
    /// `None` between records; becoming `Some` writes the 0x00 leaf prefix
    /// exactly once, including for an empty record.
    leaf: Option<Sha256>,
    /// Level stack, bottom level first. An entry is the root hash of a
    /// complete finalized subtree together with its power-of-two leaf count
    /// (encoded as the level, 0 = a single leaf). Counts stay implicit in the
    /// level numbers, so nothing per record is retained.
    stack: Vec<StackNode>,
    /// Number of records finalized onto the stack so far. Kept only for the
    /// invariant check in `finish` (stack size equals its popcount); the fold
    /// geometry itself is encoded entirely by the stack levels.
    count: u64,
}

/// One finalized subtree on [`StreamRoot`]'s stack.
#[derive(Clone, Copy)]
struct StackNode {
    level: u32,
    hash: [u8; 32],
}

impl StreamRoot {
    fn new() -> Self {
        StreamRoot {
            leaf: None,
            stack: Vec::new(),
            count: 0,
        }
    }

    /// Absorb one chunk of raw file bytes. Every LF in `chunk` terminates the
    /// record currently in progress; bytes between LFs are appended to it.
    /// The chunk may begin, end or be split in the middle of a record — the
    /// streaming leaf hasher absorbs the bytes regardless, so read boundaries
    /// never become record boundaries.
    fn extend(&mut self, chunk: &[u8]) {
        let mut rest = chunk;
        while let Some(rel) = rest.iter().position(|&b| b == b'\n') {
            // Bytes up to the LF complete the current record's content.
            self.begin_leaf();
            self.leaf.as_mut().unwrap().update(&rest[..rel]);
            self.close_leaf();
            rest = &rest[rel + 1..];
        }
        // A trailing run without an LF is more content of the same record; it
        // stays in the hasher across calls rather than being copied out.
        if !rest.is_empty() {
            self.begin_leaf();
            self.leaf.as_mut().unwrap().update(rest);
        }
    }

    /// Lazily begin a record's leaf hash: create the hasher and write the RFC
    /// 6962 0x00 leaf prefix exactly once, including for an empty record.
    fn begin_leaf(&mut self) {
        if self.leaf.is_none() {
            let mut h = Sha256::new();
            h.update(&[0x00]);
            self.leaf = Some(h);
        }
    }

    /// Finalize the record in progress onto the stack, then collapse equal
    /// levels so each level is held at most once (binary carry).
    fn close_leaf(&mut self) {
        let hash = self.leaf.take().unwrap().finalize();
        self.push_node(StackNode { level: 0, hash });
        self.count += 1;
    }

    fn push_node(&mut self, mut node: StackNode) {
        while self.stack.last().is_some_and(|top| top.level == node.level) {
            let left = self.stack.pop().unwrap();
            node = StackNode {
                level: node.level + 1,
                hash: node_hash(&left.hash, &node.hash),
            };
        }
        self.stack.push(node);
    }

    /// Produce the batch root. A record still open at end of input (the file
    /// did not end with LF) is a complete record; an input of zero records is
    /// the empty-tree root SHA-256("").
    fn finish(mut self) -> [u8; 32] {
        if let Some(leaf) = self.leaf.take() {
            let hash = leaf.finalize();
            self.push_node(StackNode { level: 0, hash });
            self.count += 1;
        }
        debug_assert_eq!(
            self.stack.len() as u32,
            self.count.count_ones(),
            "one stack entry per set bit of the record count"
        );
        // Postfix fold, right to left: merge the smallest rightmost subtree
        // into the subtree on its left, which is precisely the RFC's uneven
        // split at every step. With one or zero entries there is nothing to
        // merge (a single record is its own leaf hash; zero records below).
        let mut iter = self.stack.into_iter().rev();
        let mut acc = match iter.next() {
            Some(node) => node.hash,
            None => return sha256(&[]),
        };
        for left in iter {
            acc = node_hash(&left.hash, &acc);
        }
        acc
    }
}

/// RFC 6962 Merkle Tree Hash of the LF-separated records read from `reader`,
/// computed with a fixed-size read buffer and O(log n) additional working
/// memory. The produced root is byte-for-byte the one [`mth`] computes over
/// the same records (same uneven tree, same order, duplicates preserved).
///
/// A read error mid-batch is returned to the caller; nothing is treated as a
/// complete batch until the reader reports end of input.
#[doc(hidden)]
pub fn root_from_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<[u8; 32]> {
    let mut builder = StreamRoot::new();
    let mut buf = [0u8; READ_CAPACITY];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        builder.extend(&buf[..n]);
    }
    Ok(builder.finish())
}

/// RFC 6962 section 2.1 leaf hash: SHA-256(0x00 || data). The prefix byte and
/// the record are fed to the hasher as two consecutive slices, so hashing a
/// record of any length needs no copy of the record and no allocation beyond
/// the hasher's fixed-size state.
fn leaf_hash(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(&[0x00]);
    h.update(data);
    h.finalize()
}

/// RFC 6962 section 2.1 interior node hash: SHA-256(0x01 || left || right).
fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(&[0x01]);
    h.update(left);
    h.update(right);
    h.finalize()
}

/// Construct the RFC 6962 Merkle tree over a batch. This is the SINGLE place
/// that maintains the tree-construction rules: both `root` (via `mth`) and
/// `prove` (via `root_and_path`) build their leaves and subtrees here, so the
/// two commands can never disagree on how a batch is shaped or hashed.
///
/// ```text
/// MTH([])      = SHA-256("")
/// MTH([d])     = SHA-256(0x00 || d)
/// MTH(d0..dn)  = SHA-256(0x01 || MTH(d0..dk) || MTH(dk..dn))
/// ```
///
/// with k the largest power of two strictly smaller than n. Uneven batches
/// are handled by the recursion itself: no leaf is duplicated and no empty
/// record is appended to round the size up to a power of two.
///
/// `target` selects the one leaf a membership proof is built for:
///
/// ```text
/// PATH(m, [d0]) = []
/// PATH(m, [d0..d(n-1)]) = PATH(m, [d0..d(k-1)]) + MTH([dk..d(n-1)])   if m < k
///                       = PATH(m, [dk..d(n-1)]) + MTH([d0..d(k-1)])   if m >= k
/// ```
///
/// When `target` is `Some(m)`, the sibling subtree hashes on the route from
/// leaf `m` to the root are appended to `path` in leaf-to-root order
/// (RFC 6962 section 2.1.1); the reindexed `Some(m - k)` follows the audited
/// leaf into whichever subtree contains it, while the sibling subtree is
/// built with `None`. With `None` only the root is built. Every leaf hash and
/// every interior hash is computed exactly once in either mode, so producing
/// a proof costs the same 2n - 1 SHA-256 invocations as the root alone.
fn build_tree(
    leaves: &[&[u8]],
    target: Option<usize>,
    path: &mut Vec<[u8; 32]>,
) -> [u8; 32] {
    match leaves.len() {
        0 => sha256(&[]),
        1 => leaf_hash(leaves[0]),
        n => {
            // Largest power of two strictly smaller than n.
            let k = 1usize << (usize::BITS - 1 - (n - 1).leading_zeros());
            let (left_leaves, right_leaves) = leaves.split_at(k);
            match target {
                // The audited leaf is in the left subtree; the right subtree
                // hash is this level's sibling on the leaf-to-root path.
                Some(m) if m < k => {
                    let left = build_tree(left_leaves, Some(m), path);
                    let right = build_tree(right_leaves, None, path);
                    path.push(right);
                    node_hash(&left, &right)
                }
                // The audited leaf is in the right subtree; reindex it
                // relative to that subtree and take the left subtree as the
                // sibling.
                Some(m) => {
                    let left = build_tree(left_leaves, None, path);
                    let right = build_tree(right_leaves, Some(m - k), path);
                    path.push(left);
                    node_hash(&left, &right)
                }
                // No audited leaf: both subtrees are plain root constructions.
                None => {
                    let left = build_tree(left_leaves, None, path);
                    let right = build_tree(right_leaves, None, path);
                    node_hash(&left, &right)
                }
            }
        }
    }
}

/// RFC 6962 section 2.1 Merkle Tree Hash over SHA-256: the batch root, built
/// by the shared `build_tree` constructor so it follows exactly the same
/// rules as proof generation.
#[doc(hidden)]
pub fn mth(leaves: &[&[u8]]) -> [u8; 32] {
    build_tree(leaves, None, &mut Vec::new())
}

/// RFC 6962 section 2.1.1: the Merkle Tree Hash of the whole batch together
/// with the Merkle Audit Path for the record at `m`, both produced by the
/// shared `build_tree` constructor. The returned path is ordered from the
/// leaf level up to the root and is empty for a batch of exactly one record.
#[doc(hidden)]
pub fn root_and_path(leaves: &[&[u8]], m: usize) -> ([u8; 32], Vec<[u8; 32]>) {
    let n = leaves.len();
    assert!(m < n, "leaf index {m} out of range for {n} record(s)");
    let mut path = Vec::new();
    let root = build_tree(leaves, Some(m), &mut path);
    (root, path)
}

#[doc(hidden)]
pub fn hex(digest: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in digest {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((b & 0x0f) as u32, 16).unwrap());
    }
    s
}

/// Build the one-line JSON object printed by `prove`: integer tree_size and
/// leaf_index, the lowercase-hex root, and the audit path as a JSON array of
/// lowercase-hex hashes ordered leaf to root.
#[doc(hidden)]
pub fn proof_json(tree_size: u64, leaf_index: u64, root: &[u8; 32], audit_path: &[[u8; 32]]) -> String {
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

// --- SHA-256 (FIPS 180-4) ---

// Test-only instrumentation: counts hash computations on the current thread
// (each test runs on its own thread, and every leaf/node hash creates exactly
// one `Sha256`) so a test can pin down exactly how many hashes a proof
// generation performs.
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

/// One-shot SHA-256 over a byte slice, kept for the empty-tree root and for
/// callers that already hold the whole input. Streams through `Sha256`, so it
/// performs no copy of `data` itself.
fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize()
}

/// Streaming SHA-256 (FIPS 180-4). The working state is the eight hash words
/// plus one 64-byte block buffer, so the temporary memory a hash needs is a
/// small constant no matter how long the hashed input is: a record is fed in
/// place from the batch buffer and is never copied for hashing.
struct Sha256 {
    h: [u32; 8],
    buf: [u8; 64],
    buf_len: usize,
    total_len: u64,
}

impl Sha256 {
    fn new() -> Self {
        #[cfg(test)]
        SHA256_CALLS.with(|c| c.set(c.get() + 1));
        Sha256 {
            h: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c,
                0x1f83d9ab, 0x5be0cd19,
            ],
            buf: [0u8; 64],
            buf_len: 0,
            total_len: 0,
        }
    }

    /// Feed the next chunk of input. Bytes are consumed straight from `data`;
    /// only a partial trailing block is ever staged in `buf`.
    fn update(&mut self, mut data: &[u8]) {
        self.total_len = self.total_len.wrapping_add(data.len() as u64);
        if self.buf_len > 0 {
            let take = (64 - self.buf_len).min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len == 64 {
                let block = self.buf;
                self.compress(&block);
                self.buf_len = 0;
            }
        }
        while data.len() >= 64 {
            let (block, rest) = data.split_at(64);
            let mut staged = [0u8; 64];
            staged.copy_from_slice(block);
            self.compress(&staged);
            data = rest;
        }
        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.buf_len = data.len();
        }
    }

    /// Append the FIPS 180-4 padding (0x80, zeros, 64-bit big-endian bit
    /// length) inside the block buffer and produce the digest. At most one
    /// extra block is needed when the length field does not fit after the
    /// final data byte.
    fn finalize(mut self) -> [u8; 32] {
        let bit_len = self.total_len.wrapping_mul(8);
        self.update(&[0x80]);
        while self.buf_len != 56 {
            self.update(&[0]);
        }
        self.update(&bit_len.to_be_bytes());
        debug_assert_eq!(self.buf_len, 0, "padding must end on a block boundary");

        let mut out = [0u8; 32];
        for (i, word) in self.h.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        out
    }

    /// The SHA-256 compression function over one 64-byte block.
    fn compress(&mut self, block: &[u8; 64]) {
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

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = self.h;
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

        self.h[0] = self.h[0].wrapping_add(a);
        self.h[1] = self.h[1].wrapping_add(b);
        self.h[2] = self.h[2].wrapping_add(c);
        self.h[3] = self.h[3].wrapping_add(d);
        self.h[4] = self.h[4].wrapping_add(e);
        self.h[5] = self.h[5].wrapping_add(f);
        self.h[6] = self.h[6].wrapping_add(g);
        self.h[7] = self.h[7].wrapping_add(hh);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{self, Read};

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
    fn streaming_hash_matches_one_shot_for_every_chunking() {
        // Input long enough to span several blocks, including NUL, CR and
        // non-UTF-8 bytes; every split into chunks must give the one-shot
        // digest, so no chunk boundary can drop, duplicate or reorder a byte.
        let mut input = Vec::new();
        for i in 0..300u32 {
            input.extend_from_slice(&i.to_be_bytes());
            input.extend_from_slice(b"\x00\xff\rrec\n");
        }
        let want = sha256(&input);
        for chunk in [1usize, 2, 3, 55, 56, 63, 64, 65, 127, 128, 1000] {
            let mut h = Sha256::new();
            for piece in input.chunks(chunk) {
                h.update(piece);
            }
            assert_eq!(hex_of(&h.finalize()), hex_of(&want), "chunk size {chunk}");
        }
        // Byte-at-a-time feeding of the padding-boundary lengths 54..=66.
        for len in 54..=66usize {
            let data: Vec<u8> = (0..len as u8).map(|b| b.wrapping_mul(37).wrapping_add(1)).collect();
            let mut h = Sha256::new();
            for b in &data {
                h.update(&[*b]);
            }
            assert_eq!(hex_of(&h.finalize()), hex_of(&sha256(&data)), "len {len}");
        }
    }

    #[test]
    fn leaf_and_node_hash_match_manual_rfc6962_construction() {
        // Leaf: SHA-256(0x00 || record) for a record crossing block and
        // padding boundaries, computed here by concatenation as the RFC
        // writes it; the streaming leaf_hash must agree byte for byte.
        for len in [0usize, 1, 54, 55, 56, 63, 64, 65, 128, 135, 1000] {
            let record: Vec<u8> = (0..len as u32).map(|i| (i.wrapping_mul(131) ^ 0x5a) as u8).collect();
            let mut expect = vec![0x00];
            expect.extend_from_slice(&record);
            assert_eq!(hex_of(&leaf_hash(&record)), hex_of(&sha256(&expect)), "len {len}");
        }
        // Node: SHA-256(0x01 || left || right).
        let l = leaf_hash(b"left");
        let r = leaf_hash(b"right");
        let mut expect = vec![0x01];
        expect.extend_from_slice(&l);
        expect.extend_from_slice(&r);
        assert_eq!(hex_of(&node_hash(&l, &r)), hex_of(&sha256(&expect)));
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

    // --- streaming root -----------------------------------------------------

    /// Feed all of `data` to a fresh [`StreamRoot`] in chunks of exactly
    /// `chunk` bytes (the final chunk may be shorter) and finish the root.
    fn stream_in_chunks(data: &[u8], chunk: usize) -> [u8; 32] {
        let mut builder = StreamRoot::new();
        for part in data.chunks(chunk.max(1)) {
            builder.extend(part);
        }
        builder.finish()
    }

    /// Join exact record bytes with LF, optionally adding a trailing LF.
    fn join_records(records: &[Vec<u8>], trailing_lf: bool) -> Vec<u8> {
        let mut data = Vec::new();
        for (i, rec) in records.iter().enumerate() {
            if i > 0 {
                data.push(b'\n');
            }
            data.extend_from_slice(rec);
        }
        if trailing_lf && !records.is_empty() {
            data.push(b'\n');
        }
        data
    }

    #[test]
    fn stream_root_matches_mth_for_empty_and_special_byte_files() {
        // Exactly the record semantics of split_records, streamed.
        let cases: &[(&[u8], &[&[u8]])] = &[
            (b"", &[]),
            (b"\n", &[b""]),
            (b"\n\n", &[b"", b""]),
            (b"\n\n\n", &[b"", b"", b""]),
            (b"a\n\nb", &[b"a", b"", b"b"]),
            (b"a\nb", &[b"a", b"b"]),
            (b"a\nb\n", &[b"a", b"b"]),
            (b"a\r\nb\r\n", &[b"a\r", b"b\r"]),
            (b" \t\x00\n\xff\xfe\r", &[b" \t\x00", b"\xff\xfe\r"]),
        ];
        for (data, records) in cases {
            let want = mth(records);
            for chunk in [1usize, 2, 3, 5, 64, 1000] {
                assert_eq!(
                    hex_of(&stream_in_chunks(data, chunk)),
                    hex_of(&want),
                    "{data:?} chunked by {chunk} must hash as {records:?}"
                );
            }
        }
    }

    #[test]
    fn stream_root_matches_mth_at_every_size_and_is_chunk_independent() {
        // Sizes on both sides of many power-of-two boundaries so the uneven
        // geometry is exercised thoroughly.
        let sizes: Vec<usize> = (1..=18)
            .chain([31, 32, 33, 63, 64, 65, 100, 127, 128, 129, 257, 500])
            .collect();
        for n in sizes {
            let records: Vec<Vec<u8>> = (0..n)
                .map(|i| match i % 8 {
                    0 => Vec::new(),
                    1 => format!("record-{i:05}").into_bytes(),
                    2 => format!("{i}-ends-with-cr\r").into_bytes(),
                    3 => vec![0xff, 0xfe, 0x00, b'b', 0x80 | (i as u8 & 0x7f)],
                    4 => b"x".to_vec(),
                    5 => format!("{i}").into_bytes(),
                    6 => b"\t spaced \t".to_vec(),
                    // A long record, occasionally longer than one read buffer.
                    _ => vec![b'q'; (i * 137) % (2 * READ_CAPACITY + 50) + 1],
                })
                .collect();
            for trailing_lf in [false, true] {
                let data = join_records(&records, trailing_lf);
                // The bytes encode exactly what split_records yields: a file
                // cannot distinguish "zero records" from "one empty record
                // with no terminating LF" (both are zero bytes), so the
                // streamed root must match the root of the records the bytes
                // actually delimit, trailing LF included.
                let encoded: Vec<&[u8]> = split_records(&data);
                let want = mth(&encoded);
                // Chunk sizes at and around the fixed read capacity must not
                // matter, and neither must byte-at-a-time feeding.
                for chunk in [
                    1usize, 2, 3, 7, 55, 63, 64, 65, 4096, 65535, 65536, 65537, 200_000,
                ] {
                    assert_eq!(
                        stream_in_chunks(&data, chunk),
                        want,
                        "n={n}, trailing_lf={trailing_lf}, chunk={chunk}"
                    );
                }
            }
        }
    }

    #[test]
    fn stream_root_handles_records_much_longer_than_the_read_buffer() {
        // One record several read-buffers long, with and without a trailing
        // LF; every byte must reach the leaf hash across many reads.
        for len in [READ_CAPACITY - 1, READ_CAPACITY, READ_CAPACITY + 1, 3 * READ_CAPACITY + 17] {
            let mut record = vec![0u8; len];
            for (i, b) in record.iter_mut().enumerate() {
                *b = (i as u8).wrapping_mul(31).wrapping_add(7);
            }
            // Make sure binary content is present and no byte looks like LF:
            // remap every 0x0a byte away while keeping the content arbitrary.
            for b in &mut record {
                if *b == 0x0a {
                    *b = 0x0b;
                }
            }
            record[0] = 0xff;
            *record.last_mut().unwrap() = 0x00;
            let want = leaf_hash(&record);
            let mut with_lf = record.clone();
            with_lf.push(b'\n');
            for chunk in [1usize, 7, 4096, READ_CAPACITY, READ_CAPACITY + 1] {
                assert_eq!(stream_in_chunks(&record, chunk), want, "len={len}, chunk={chunk}");
                assert_eq!(stream_in_chunks(&with_lf, chunk), want, "len={len}+LF, chunk={chunk}");
            }
        }
    }

    #[test]
    fn stream_root_stack_depth_is_logarithmic_in_record_count() {
        // After every finalized record the stack holds exactly popcount(n)
        // subtree roots and the in-progress leaf hasher is gone: no per-record
        // state survives.
        let n = 200_000usize;
        let mut builder = StreamRoot::new();
        for i in 1..=n {
            builder.extend(b".\n");
            assert_eq!(builder.stack.len() as u32, (i as u64).count_ones(), "after {i} records");
            assert!(builder.leaf.is_none(), "no leaf hash lingers between records");
            assert!(builder.stack.len() <= 64, "O(log n), never O(n)");
        }
        // Cross-check against the in-memory tree over the same sequence.
        let refs: Vec<&[u8]> = vec![b"."; n];
        assert_eq!(builder.finish(), mth(&refs));
    }

    #[test]
    fn stream_root_hashes_each_leaf_and_node_exactly_once() {
        // n records cost n leaf hashes plus n - 1 interior hashes, no matter
        // how the bytes are chunked: nothing is re-hashed across reads. The
        // empty tree's root is SHA-256(""), itself one hash computation.
        for n in [0usize, 1, 2, 3, 4, 5, 8, 9, 16, 33] {
            let data = join_records(
                &(0..n).map(|i| format!("record-{i:04}").into_bytes()).collect::<Vec<_>>(),
                true,
            );
            SHA256_CALLS.with(|c| c.set(0));
            let _ = stream_in_chunks(&data, 3);
            let calls = SHA256_CALLS.with(|c| c.get());
            assert_eq!(calls, if n == 0 { 1 } else { 2 * n - 1 }, "n={n}");
        }
    }

    /// Reader that hands out at most `max` bytes per `read` call, so the fixed
    /// 64 KiB buffer can be driven through arbitrary (including
    /// byte-at-a-time) read boundaries.
    struct LimitedReader<'a> {
        data: &'a [u8],
        max: usize,
    }

    impl Read for LimitedReader<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let m = self.max.min(self.data.len()).min(buf.len());
            buf[..m].copy_from_slice(&self.data[..m]);
            self.data = &self.data[m..];
            Ok(m)
        }
    }

    /// Reader that serves `ok` bytes (repeating "a\n") and then fails.
    struct FailReader {
        served: usize,
        ok: usize,
    }

    impl Read for FailReader {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.served >= self.ok {
                return Err(io::Error::new(io::ErrorKind::Other, "simulated read failure"));
            }
            let m = buf.len().min(self.ok - self.served);
            for b in &mut buf[..m] {
                *b = if self.served % 2 == 0 { b'a' } else { b'\n' };
                self.served += 1;
            }
            Ok(m)
        }
    }

    #[test]
    fn root_from_reader_matches_mth_whatever_each_read_returns() {
        let records: Vec<Vec<u8>> = (0..1000u32)
            .map(|i| {
                let mut r = format!("line-{i:05}").into_bytes();
                if i % 3 == 0 {
                    r.extend_from_slice(b"\r\xff\x00");
                }
                r
            })
            .collect();
        let refs: Vec<&[u8]> = records.iter().map(|r| r.as_slice()).collect();
        let want = mth(&refs);
        let data = join_records(&records, true);
        for max in [1usize, 2, 3, 17, 4096, READ_CAPACITY - 1, READ_CAPACITY, READ_CAPACITY + 1] {
            let mut reader = LimitedReader { data: &data, max };
            let got = root_from_reader(&mut reader).expect("reader must not fail");
            assert_eq!(got, want, "read returns at most {max} bytes");
        }
    }

    #[test]
    fn root_from_reader_empty_input_is_the_empty_tree_root() {
        let mut reader = LimitedReader { data: b"", max: 16 };
        assert_eq!(root_from_reader(&mut reader).unwrap(), sha256(&[]));
    }

    #[test]
    fn root_from_reader_propagates_a_mid_batch_read_error_and_emits_no_root() {
        let mut reader = FailReader { served: 0, ok: 7 };
        let err = root_from_reader(&mut reader).expect_err("a mid-batch read error must surface");
        assert_eq!(err.kind(), io::ErrorKind::Other);
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

    // --- public library entry point ------------------------------------------

    /// A real proof for `records[m]`, verified through the public API with
    /// the batch root as the trusted root.
    fn membership_of(records: &[&[u8]], m: usize, record: &[u8], trusted_size: u64, trusted_root: &[u8; 32]) -> Result<Membership, VerifyError> {
        let (root, path) = root_and_path(records, m);
        let size = records.len() as u64;
        let bytes = proof_json(size, m as u64, &root, &path).into_bytes();
        verify_membership(record, &bytes, trusted_size, trusted_root)
    }

    #[test]
    fn api_success_returns_position_and_trusted_values() {
        let records: Vec<&[u8]> = vec![b"alpha", b"beta", b"gamma", b"beta", b"delta"];
        let root = mth(&records);
        for (m, record) in records.iter().enumerate() {
            let membership = membership_of(&records, m, record, 5, &root)
                .unwrap_or_else(|e| panic!("position {m} must verify: {e}"));
            // The claimed position is returned exactly, even for the duplicate
            // "beta" at positions 1 and 3.
            assert_eq!(membership.leaf_index(), m as u64);
            // Size and root are the caller's trusted values, already checked
            // against the proof — not fields read out of the proof.
            assert_eq!(membership.tree_size(), 5);
            assert_eq!(membership.root(), &root);
        }
    }

    #[test]
    fn api_zero_trusted_size_is_invalid_argument_not_empty_tree_membership() {
        let records: Vec<&[u8]> = vec![b"only"];
        let root = mth(&records);
        let (_, path) = root_and_path(&records, 0);
        let proof = proof_json(1, 0, &root, &path).into_bytes();
        // A zero trusted size must be rejected as an invalid argument, never
        // verified as "membership in the empty tree" and never reported as a
        // cryptographic mismatch.
        assert_eq!(
            verify_membership(b"only", &proof, 0, &root),
            Err(VerifyError::InvalidTrustedSize)
        );
        // Even a proof that itself claims tree_size 0 (malformed on its own)
        // still hits the argument check first.
        let zero_proof = format!(
            "{{\"tree_size\":0,\"leaf_index\":0,\"root\":\"{}\",\"audit_path\":[]}}",
            hex(&sha256(b""))
        );
        assert_eq!(
            verify_membership(b"", zero_proof.as_bytes(), 0, &sha256(b"")),
            Err(VerifyError::InvalidTrustedSize)
        );
    }

    #[test]
    fn api_distinguishes_malformed_proof_from_verification_failure() {
        let records: Vec<&[u8]> = vec![b"a", b"b", b"c"];
        let root = mth(&records);
        let (_, path) = root_and_path(&records, 1);
        let good = proof_json(3, 1, &root, &path).into_bytes();
        assert!(verify_membership(b"b", &good, 3, &root).is_ok());

        // Format problems → MalformedProof.
        for bad in [
            b"".as_slice(),
            b"null",
            b"{}",
            &good[..good.len() - 2], // truncated
            b"{\"tree_size\":3,\"leaf_index\":1,\"root\":\"00\",\"audit_path\":[]}",
        ] {
            assert!(
                matches!(verify_membership(b"b", bad, 3, &root), Err(VerifyError::MalformedProof(_))),
                "{bad:?} must be a malformed proof"
            );
        }

        // Well-formed but not establishing inclusion → VerificationFailed.
        let mut wrong_root = root;
        wrong_root[0] ^= 0x01;
        let short_path = proof_json(3, 1, &root, &path[..path.len() - 1]).into_bytes();
        assert!(matches!(
            verify_membership(b"b", &good, 4, &root),
            Err(VerifyError::VerificationFailed(_))
        ));
        assert!(matches!(
            verify_membership(b"b", &good, 3, &wrong_root),
            Err(VerifyError::VerificationFailed(_))
        ));
        assert!(matches!(
            verify_membership(b"x", &good, 3, &root),
            Err(VerifyError::VerificationFailed(_))
        ));
        assert!(matches!(
            verify_membership(b"b", &short_path, 3, &root),
            Err(VerifyError::VerificationFailed(_))
        ));
    }

    #[test]
    fn api_failure_never_yields_a_membership() {
        // No failing call may return anything shaped like a success: every
        // error path above is an Err, and Membership can only be constructed
        // by a successful verification (its fields are private).
        let records: Vec<&[u8]> = vec![b"a", b"b"];
        let root = mth(&records);
        let (_, path) = root_and_path(&records, 0);
        let proof = proof_json(2, 0, &root, &path).into_bytes();
        assert!(verify_membership(b"a", &proof, 2, &root).is_ok());
        assert!(verify_membership(b"a", &proof, 0, &root).is_err());
        assert!(verify_membership(b"a", b"garbage", 2, &root).is_err());
        assert!(verify_membership(b"b", &proof, 2, &root).is_err());
    }

    #[test]
    fn api_record_bytes_are_verbatim_including_empty_and_non_utf8() {
        // An empty byte slice is one empty record.
        let records: Vec<&[u8]> = vec![b"", b"x"];
        let root = mth(&records);
        assert!(membership_of(&records, 0, b"", 2, &root).is_ok());
        // Trailing LF / CR / space / NUL all belong to the record.
        for suffix in [b"\n".as_slice(), b"\r", b" ", b"\x00"] {
            assert!(
                membership_of(&records, 0, suffix, 2, &root).is_err(),
                "suffix {suffix:?} must change the record"
            );
        }
        // Non-UTF-8 bytes take part as they are.
        let bin: &[u8] = b"\xff\xfe\x00bin";
        let records: Vec<&[u8]> = vec![b"a", bin];
        let root = mth(&records);
        assert!(membership_of(&records, 1, bin, 2, &root).is_ok());
    }

    #[test]
    fn api_accepts_reordered_whitespace_and_escaped_proofs() {
        let records: Vec<&[u8]> = vec![b"a", b"b"];
        let root = mth(&records);
        let (_, path) = root_and_path(&records, 1);
        let h = hex(&root);
        let p0 = hex(&path[0]);
        // Reordered fields, arbitrary whitespace, and \uXXXX-escaped key and
        // hash characters all keep the existing acceptance rules.
        let pretty = format!(
            " {{\n \"audit_path\" : [ \"{p0}\" ] ,\n \"root\" : \"{h}\" ,\n \"leaf_index\" : 1 ,\n \"tree_size\" : 2 }} \n"
        );
        let m = verify_membership(b"b", pretty.as_bytes(), 2, &root).expect("pretty proof");
        assert_eq!(m.leaf_index(), 1);
        let escaped = format!(
            "{{\"tree_siz\\u0065\":2,\"leaf_index\":1,\"root\":\"{h}\",\"audit_path\":[\"{p0}\"]}}"
        );
        assert!(verify_membership(b"b", escaped.as_bytes(), 2, &root).is_ok());
        // Duplicate fields (even via escapes) stay rejected as malformed.
        let dup = format!(
            "{{\"tree_size\":2,\"tree_siz\\u0065\":2,\"leaf_index\":1,\"root\":\"{h}\",\"audit_path\":[\"{p0}\"]}}"
        );
        assert!(matches!(
            verify_membership(b"b", dup.as_bytes(), 2, &root),
            Err(VerifyError::MalformedProof(_))
        ));
    }

    #[test]
    fn api_keeps_full_64bit_meaning_of_size_and_index() {
        // A synthetic proof for a tree of 2^63 records at index 2^32: the
        // audit path element i is the 64-char lowercase hex of i, and the
        // trusted root is recomputed here with the internal verifier. The
        // point is that u64 sizes/indices flow through verify_membership
        // untruncated and come back in the Membership result unchanged.
        let record = b"big-tree-record\x00\xff\xfe";
        let size: u64 = 1 << 63;
        let index: u64 = 1 << 32;
        let path: Vec<[u8; 32]> = (0..63u64)
            .map(|i| {
                let s = format!("{i:064x}");
                let mut h = [0u8; 32];
                for (j, pair) in s.as_bytes().chunks_exact(2).enumerate() {
                    h[j] = (hex_nibble(pair[0]).unwrap() << 4) | hex_nibble(pair[1]).unwrap();
                }
                h
            })
            .collect();
        let root = include_record(leaf_hash(record), index, size, &path).unwrap();
        let proof = proof_json(size, index, &root, &path).into_bytes();
        let m = verify_membership(record, &proof, size, &root).expect("2^63 tree must verify");
        assert_eq!(m.leaf_index(), 1u64 << 32);
        assert_eq!(m.tree_size(), 1u64 << 63);
        assert_eq!(m.root(), &root);
        // Off by one in the trusted size or the claimed index must fail, not
        // truncate to a smaller tree.
        assert!(matches!(
            verify_membership(record, &proof, size - 1, &root),
            Err(VerifyError::VerificationFailed(_))
        ));
        let off = proof_json(size, index + 1, &root, &path).into_bytes();
        assert!(matches!(
            verify_membership(record, &off, size, &root),
            Err(VerifyError::VerificationFailed(_))
        ));
    }
}
