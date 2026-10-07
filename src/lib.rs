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
//! 如果只想查看证明自身声明的大小、序号和根值，而没有目标记录与独立可信
//! 值，请改用 [`inspect_proof`]：它做同样的完整格式解读，但不做成员核验，
//! 其结果 [`ProofClaims`] 中的大小与根值直接来自证明、不可当作可信输入。
//!
//! # 直接在内存中生成证明
//!
//! [`verify_membership`] 消费一份已有证明；要在没有批次文件、不调用命令行
//! 的情况下**生成**证明，请用 [`prove_membership`]：传入内存中已经划分好
//! 的有序记录批次（每个元素就是一条完整记录）和一个从 0 开始的序号，
//! 成功即得到 [`InclusionProof`]，可读取树大小、序号、32 字节根值与从叶子
//! 到根排列的兄弟哈希，并用 [`InclusionProof::to_json`] 取得与
//! `roottrace prove` 逐字节一致的一行 JSON（不含行末换行）。
//!
//! 批次中的每个元素就是一条完整记录，本函数**不**按记录内容里的 LF
//! 拆分：开头、内部或末尾的 LF、CR、空格、NUL 与非 UTF-8 字节都属于该
//! 记录。因此“记录本身含有 LF”的批次——无法用 LF 分隔的批次文件表达——
//! 也能直接生成证明。空切片元素占一个位置（一条空记录），与零个元素的
//! 空批次不同；序号达到或超过记录数（含空批次）时返回按类型识别的
//! [`ProveError::PositionNotFound`]，并携带请求序号与实际记录数。
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

/// 解读一份成员证明后、**未经任何核验**的声明值：`inspect` 操作的结果。
///
/// 与 [`Membership`] 不同，这里的树大小和根值直接来自证明自身的字段，没有
/// 与任何独立可信值比对，也没有目标记录可供重算路径。它们只表示“证明声称
/// 如此”，绝不表示记录已被证明属于该批次——即使审计路径的哈希数量、顺序或
/// 内容根本无法把任何记录结合到该根值，只要证明格式合法，这些字段仍会被
/// 原样读出。调用方不得把这里的 `tree_size()`/`root()` 当作
/// [`verify_membership`] 的可信输入。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofClaims {
    tree_size: u64,
    leaf_index: u64,
    root: [u8; 32],
}

impl ProofClaims {
    /// 证明声明的树大小（证明中的 `tree_size` 字段），保持完整 64 位无符号
    /// 整数含义。该值未经验证，不是独立确认的可信树大小。
    pub fn tree_size(&self) -> u64 {
        self.tree_size
    }

    /// 证明声明的记录序号（证明中的 `leaf_index` 字段），从 0 开始。格式
    /// 合法时必有 `0 <= leaf_index < tree_size`，但该位置上是否确有该记录
    /// 并未核验。
    pub fn leaf_index(&self) -> u64 {
        self.leaf_index
    }

    /// 证明声明的根值（证明中的 `root` 字段）。该值直接取自证明，未经
    /// 独立确认，不是可信根值。
    pub fn root(&self) -> &[u8; 32] {
        &self.root
    }
}

/// 解读证明失败：证明字节不符合当前的完整证明格式。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InspectError {
    /// 证明格式无效，判定标准与核验路径完全相同——不是完整 JSON 对象、
    /// 必需字段（含不展示的 `audit_path`）缺失/重复/类型错误、整数或哈希
    /// 不合法、`tree_size` 为 0、序号越界、对象后有多余字节等。附带人类
    /// 可读的原因说明。
    MalformedProof(String),
}

impl fmt::Display for InspectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InspectError::MalformedProof(reason) => write!(f, "invalid proof: {reason}"),
        }
    }
}

impl std::error::Error for InspectError {}

/// 解读一份成员证明，取出它声明的树大小、记录序号与根值，**不做成员核验**。
///
/// 解读使用与 [`verify_membership`] 完全相同的完整格式判定：证明必须是一个
/// 完整的 JSON 对象，四个必需字段齐全且无重复，类型、整数与哈希合法，
/// `tree_size` 为正且 `leaf_index` 在声明范围内——即使损坏发生在不展示的
/// `audit_path` 中（哈希长度不对、数组未结束等）也按格式无效拒绝。字段重排、
/// 合法 JSON 空白与等价 Unicode 转义不影响解读结果。
///
/// 成功只代表证明符合当前格式：没有目标记录、没有独立可信值，因此既不检查
/// 审计路径能否证明声明的位置，也不返回任何表示核验成功的结论。需要确认
/// 成员身份时请改用 [`verify_membership`]。
pub fn inspect_proof(proof: &[u8]) -> Result<ProofClaims, InspectError> {
    let proof = parse_proof(proof).map_err(InspectError::MalformedProof)?;
    Ok(ProofClaims {
        tree_size: proof.tree_size,
        leaf_index: proof.leaf_index,
        root: proof.root,
    })
}

// --- 直接在内存中生成成员证明 --------------------------------------------------

/// 在内存中生成的成员证明：批次根值、记录位置与从叶子到根排列的兄弟哈希。
///
/// 由 [`prove_membership`] 直接在内存中产生，无需批次文件或临时文件，也不
/// 经过命令行。字段与 `roottrace prove` 输出的 JSON 完全一致，可经
/// [`InclusionProof::to_json`] 取得逐字节相同的一行 JSON（无行末换行），并
/// 直接交给 [`inspect_proof`]、[`verify_membership`] 或命令行的
/// `inspect`/`verify`。
///
/// 与 [`ProofClaims`] 一样，这里的 `tree_size()` 与 `root()` **只描述调用方
/// 自己提交的批次**，不代表它们已经获得任何外部信任：把证明发给别人时，
/// 对方仍须用独立渠道确认树大小和根值后再用 [`verify_membership`] 核验。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InclusionProof {
    tree_size: u64,
    leaf_index: u64,
    root: [u8; 32],
    audit_path: Vec<[u8; 32]>,
}

impl InclusionProof {
    /// 完整批次的记录数（证明 JSON 中的 `tree_size`），保持完整 64 位
    /// 无符号整数含义。
    pub fn tree_size(&self) -> u64 {
        self.tree_size
    }

    /// 被证明记录从 0 开始的序号（证明 JSON 中的 `leaf_index`），即调用
    /// [`prove_membership`] 时给出的位置。
    pub fn leaf_index(&self) -> u64 {
        self.leaf_index
    }

    /// 整个批次的 32 字节 RFC 6962 Merkle Tree Hash（证明 JSON 中的
    /// `root`），与 `roottrace root` 对同一记录序列给出的根值完全相同。
    pub fn root(&self) -> &[u8; 32] {
        &self.root
    }

    /// 从叶子向根排列的兄弟哈希（证明 JSON 中的 `audit_path`）。批次只有
    /// 一条记录时为空；非二次幂批次按 RFC 6962 的不均匀子树排列，既不
    /// 复制末尾记录也不补空记录。
    pub fn audit_path(&self) -> &[[u8; 32]] {
        &self.audit_path
    }

    /// 与 `roottrace prove` 逐字节一致的单行 JSON 证明（紧凑形式、字段顺序
    /// 固定、小写十六进制哈希），**不含**行末换行，也不包含原始记录。需要
    /// 写入文件或交给命令行时由调用方自行添加换行。
    ///
    /// 当记录序列可以用 LF 分隔的批次文件表示时，这里的输出与
    /// `roottrace prove <批次文件> <序号>` 去掉行末换行后的输出逐字节相同；
    /// 记录本身含 LF（批次文件无法表达）时，输出仍是同一格式的合法证明。
    pub fn to_json(&self) -> String {
        proof_json(self.tree_size, self.leaf_index, &self.root, &self.audit_path)
    }
}

/// 直接在内存中生成成员证明失败的分类。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProveError {
    /// 请求的位置在批次中不存在：序号达到或超过记录数。空批次（零条记录）
    /// 对任何序号都报这一类错误，而不是产生一份“空树成员证明”。附带
    /// `requested_index`（调用方请求的序号，完整保留 64 位含义）与
    /// `record_count`（批次实际记录数）。
    PositionNotFound {
        /// 调用方请求的从 0 开始的记录序号。
        requested_index: u64,
        /// 批次实际包含的记录数。
        record_count: u64,
    },
}

impl fmt::Display for ProveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProveError::PositionNotFound {
                requested_index,
                record_count,
            } => {
                if *record_count == 0 {
                    write!(
                        f,
                        "record index {requested_index} does not exist: the batch holds zero records"
                    )
                } else {
                    write!(
                        f,
                        "record index {requested_index} does not exist: batch holds {record_count} record(s), valid indices are 0 through {}",
                        record_count - 1
                    )
                }
            }
        }
    }
}

impl std::error::Error for ProveError {}

/// 直接为内存中的有序记录批次生成 RFC 6962 第 2.1.1 节成员证明。
///
/// - `records`：已经划分好的有序记录批次。**批次中的每个元素就是一条完整
///   记录**，本函数不按记录内容里的 LF 再做任何拆分、修剪或替换：开头、
///   内部或末尾的 LF、CR、空格、NUL 与非 UTF-8 字节都属于该记录内容。
///   这让“记录本身含有 LF”的批次也能直接生成证明——这种序列无法用
///   `root`/`prove` 的 LF 分隔批次文件表达。空切片元素（`b""`）占一个
///   位置（一条空记录），与零个元素的空批次不同；重复内容按实际位置
///   保留，记录顺序参与根值计算。
///
///   参数接受任何可按引用迭代出字节串的集合：`&[&[u8]]`、`&[Vec<u8>]`、
///   `Vec<Vec<u8>>`（按值移入）、数组等均可。
/// - `leaf_index`：从 0 开始的记录序号，按 `records` 的顺序定位。相同内容
///   出现在多个位置时，生成的是该序号指定位置的证明，不会改成前一次出现
///   的位置。序号达到或超过记录数（含空批次）时返回
///   [`ProveError::PositionNotFound`]，其中携带请求序号与实际记录数；
///   序号按完整的 `u64` 处理，较大值不会被截断后误选一个合法位置。
///
/// 成功返回 [`InclusionProof`]：可读取树大小、记录序号、32 字节根值与从
/// 叶子到根排列的兄弟哈希，并经 [`InclusionProof::to_json`] 取得与
/// `roottrace prove` 逐字节一致的单行 JSON（无行末换行）。该函数不向标准
/// 输出或标准错误打印任何内容；返回的根值只是对调用方所提交批次的描述，
/// 不代表它已获得外部信任。
///
/// # 示例
///
/// ```
/// use roottrace::prove_membership;
///
/// // 三条记录的批次；每条元素就是一条完整记录。
/// let records: [&[u8]; 3] = [b"a", b"b", b"c"];
/// let proof = prove_membership(&records, 1).expect("position 1 exists");
/// assert_eq!(proof.tree_size(), 3);
/// assert_eq!(proof.leaf_index(), 1);
/// assert_eq!(proof.audit_path().len(), 2);
/// // JSON 与 `roottrace prove` 的输出逐字节一致（这里不含行末换行）。
/// assert_eq!(
///     proof.to_json(),
///     "{\"tree_size\":3,\"leaf_index\":1,\"root\":\"36642e73c2540ab121e3a6bf9545b0a24982cd830eb13d3cd19de3ce6c021ec1\",\"audit_path\":[\"022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c\",\"597fcb31282d34654c200d3418fca5705c648ebf326ec73d8ddef11841f876d8\"]}"
/// );
///
/// // 记录本身含 LF：批次文件无法表达，这里每个元素仍只算一条记录。
/// let lf_records: [&[u8]; 1] = [b"line-1\nline-2\n"];
/// let single = prove_membership(&lf_records, 0).expect("position 0 exists");
/// assert_eq!(single.tree_size(), 1);
/// assert!(single.audit_path().is_empty()); // 只有一条记录，路径为空
///
/// // 空批次对任何序号都返回可按类型识别的“位置不存在”。
/// let empty: [&[u8]; 0] = [];
/// assert!(matches!(
///     prove_membership(&empty, 0),
///     Err(roottrace::ProveError::PositionNotFound { requested_index: 0, record_count: 0 })
/// ));
/// ```
pub fn prove_membership<I, R>(records: I, leaf_index: u64) -> Result<InclusionProof, ProveError>
where
    I: IntoIterator<Item = R>,
    R: AsRef<[u8]>,
{
    // Hold every element for the whole call. Each element is ALREADY one
    // complete record: no LF splitting, trimming or replacement happens here,
    // so a record whose own bytes contain LF is a single leaf. A zero-length
    // collection is the empty batch, distinct from one element that is empty.
    let owned: Vec<R> = records.into_iter().collect();
    let slices: Vec<&[u8]> = owned.iter().map(AsRef::as_ref).collect();
    prove_membership_from_slices(&slices, leaf_index)
}

/// Slice-based core shared by [`prove_membership`] and the `prove` command:
/// range-check the position, then build the root and one leaf-to-root audit
/// path with the single shared [`build_tree`] constructor, so the library and
/// the command line can never disagree on the tree or the path.
fn prove_membership_from_slices(
    records: &[&[u8]],
    leaf_index: u64,
) -> Result<InclusionProof, ProveError> {
    // `records.len()` is at most usize::MAX and hence always fits in u64, so
    // the full-width comparison happens BEFORE any narrowing to usize: a large
    // `leaf_index` is reported as a missing position, never truncated into a
    // legal one.
    let count = records.len() as u64;
    if leaf_index >= count {
        // Empty batch and out-of-range index are the same typed condition; the
        // two carried values let the caller tell them apart and log precisely.
        return Err(ProveError::PositionNotFound {
            requested_index: leaf_index,
            record_count: count,
        });
    }
    // In range, so this narrowing is always in bounds.
    let idx = leaf_index as usize;
    let mut audit_path = Vec::new();
    let root = build_tree(records, Some(idx), &mut audit_path);
    Ok(InclusionProof {
        tree_size: count,
        leaf_index,
        root,
        audit_path,
    })
}

// --- 供命令行程序复用的内部实现 ------------------------------------------------
//
// 以下项是 `roottrace` 命令行程序（src/main.rs）与库共享的实现细节，不属于
// 稳定的库 API，故对文档隐藏。命令行的 root/prove/verify/inspect 子命令与库
// 函数走完全相同的代码路径，保证两边结果一致。

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

// --- Record division --------------------------------------------------------
//
// This is the SINGLE place that maintains how a raw byte batch is divided into
// records. Both commands drive the same rule:
//
// - `prove` scans an already-read batch with [`RecordScanner::scan`], collecting
//   one slice per record ([`split_records`]);
// - `root` feeds its fixed-size read buffer chunk by chunk to the same
//   [`RecordScanner`] inside [`RootStream`], so a read boundary is never a
//   record boundary.
//
// The rule, byte for byte:
//
// - LF (0x0a) separates records and is never itself content. Every other byte
//   — CR, space, tab, NUL, a non-UTF-8 byte — is content delivered verbatim;
//   there is no text decoding, trimming or newline normalization.
// - A record comes into existence either by receiving content or by being
//   terminated with an LF. Leading and consecutive LFs therefore keep their
//   empty records; an empty input is zero records, while a single LF is one
//   empty record.
// - A trailing LF only terminates the record in progress and adds no empty
//   record; a final record without a trailing LF is the same record sequence.
//
// The division is expressed as an event sink ([`RecordSink`]) rather than as a
// returned list, so the streaming caller never has to accumulate a complete
// record or batch: `record_bytes` hands out sub-slices straight from the chunk
// being scanned.

/// Receives the division of a byte stream into records from
/// [`RecordScanner`]. Every method sees raw bytes only; the scanner alone
/// decides *when* each event fires, so a sink never re-interprets LF or the
/// end of stream.
trait RecordSink {
    /// A non-empty run of content bytes belonging to the record currently in
    /// progress; the slice is borrowed from the chunk being scanned and must
    /// not be relied on after the call returns. One record arrives as any
    /// number of these runs (a long record spanning many chunks gets many),
    /// but an empty record gets none.
    fn record_bytes(&mut self, bytes: &[u8]);

    /// One record was terminated by an LF (which is never delivered as
    /// content). Fires for every LF in the stream, including a leading LF and
    /// the second of two consecutive LFs — those close empty records.
    fn record_end(&mut self);

    /// The stream ended right after content bytes with no terminating LF, so
    /// that content is itself the final record. Fires at most once, only when
    /// such content exists; after a bare trailing LF it does not fire.
    fn tail_end(&mut self);
}

/// The shared record-boundary state machine. Independent of how the bytes are
/// obtained: one whole batch ([`RecordScanner::scan`]) or arbitrarily sized
/// chunks fed across reads ([`RecordScanner::feed`]) divide into exactly the
/// same record sequence. The only state it keeps is whether a content-only
/// record is open at the end of the last chunk, so nothing grows with the
/// number of records or their length.
struct RecordScanner<S: RecordSink> {
    sink: S,
    /// Content has arrived for the record currently in progress and no LF has
    /// closed it yet. Decides whether [`RecordSink::tail_end`] fires at end of
    /// stream — the one place the "trailing LF adds no record" rule lives.
    open: bool,
}

impl<S: RecordSink> RecordScanner<S> {
    fn new(sink: S) -> Self {
        RecordScanner { sink, open: false }
    }

    /// Feed the next chunk. Read boundaries fall inside content or on LF
    /// bytes; either way the division sees no boundary of its own — an LF split
    /// across two chunks still ends the record, and two LFs in adjacent chunks
    /// keep the empty record between them.
    fn feed(&mut self, chunk: &[u8]) {
        let mut rest = chunk;
        while let Some(pos) = rest.iter().position(|&b| b == b'\n') {
            // Content before this LF (nothing for a leading/consecutive LF);
            // the empty-run case must not look like content.
            if pos > 0 {
                self.sink.record_bytes(&rest[..pos]);
            }
            self.sink.record_end();
            rest = &rest[pos + 1..];
            self.open = false;
        }
        // Bytes after the last LF (or all of an LF-free chunk) open the
        // record the next chunk or end of stream will close.
        if !rest.is_empty() {
            self.sink.record_bytes(rest);
            self.open = true;
        }
    }

    /// Finish the stream and give back the sink.
    fn finish(mut self) -> S {
        if self.open {
            self.sink.tail_end();
        }
        self.sink
    }

    /// Convenience for callers that already hold the whole input: divide it in
    /// one pass.
    fn scan(self, data: &[u8]) -> S {
        let mut scanner = self;
        scanner.feed(data);
        scanner.finish()
    }
}

/// Divide a complete batch into records on LF (0x0a), per the shared rule
/// documented on [`RecordScanner`]. The separator is not part of any record; a
/// trailing LF terminates the last record without adding an empty one; an empty
/// file yields zero records and a file containing one LF yields one empty
/// record.
#[doc(hidden)]
pub fn split_records(data: &[u8]) -> Vec<&[u8]> {
    /// Sink for the whole-batch case: content runs of one record are stitched
    /// back into slice positions. A run never crosses a chunk boundary here
    /// (the whole batch is one feed), but every record goes through the same
    /// content/end events as the streaming path.
    struct CollectRecords<'a> {
        data: &'a [u8],
        records: Vec<&'a [u8]>,
        /// Start offset of the record currently in progress. `None` until the
        /// record actually receives content: a record exists only once it has
        /// content or is terminated by an LF, so an empty input stays empty.
        start: Option<usize>,
        pos: usize,
    }

    impl<'a> RecordSink for CollectRecords<'a> {
        fn record_bytes(&mut self, bytes: &[u8]) {
            // The scanner only calls this with non-empty content; the first run
            // of a record opens it at the byte it starts at.
            if self.start.is_none() {
                self.start = Some(self.pos);
            }
            self.pos += bytes.len();
        }

        fn record_end(&mut self) {
            // Termination by LF always closes a record, even an empty one.
            let start = self.start.take().unwrap_or(self.pos);
            self.records.push(&self.data[start..self.pos]);
            self.pos += 1; // the terminating LF
        }

        fn tail_end(&mut self) {
            // Only reached when content without a trailing LF is open.
            let start = self.start.take().expect("tail_end implies open content");
            self.records.push(&self.data[start..self.pos]);
        }
    }

    let collector = RecordScanner::new(CollectRecords {
        data,
        records: Vec::new(),
        start: None,
        pos: 0,
    })
    .scan(data);
    collector.records
}

/// A fresh leaf hasher primed with the RFC 6962 section 2.1 leaf prefix 0x00.
fn new_leaf_hasher() -> Sha256 {
    let mut h = Sha256::new();
    h.update(&[0x00]);
    h
}

/// RFC 6962 section 2.1 leaf hash: SHA-256(0x00 || data). The prefix byte and
/// the record are fed to the hasher as two consecutive slices, so hashing a
/// record of any length needs no copy of the record and no allocation beyond
/// the hasher's fixed-size state.
fn leaf_hash(data: &[u8]) -> [u8; 32] {
    let mut h = new_leaf_hasher();
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

// --- Streaming root computation ---------------------------------------------
//
// `roottrace root` must not hold the batch in memory: the file is read through
// a fixed-size buffer and pushed through the shared [`RecordScanner`]. Every
// record is hashed as its bytes stream past (a record is never stored, however
// long it is), and the only per-record state the sink keeps is the stack of
// completed subtree hashes below — at most one entry per bit of the record
// count, so O(log n) hashes independent of the file's byte length and of the
// longest record. Record division itself lives entirely in `RecordScanner`,
// which is the exact code `prove`'s `split_records` drives.

/// Incremental RFC 6962 Merkle Tree Hash over an LF-separated byte stream.
///
/// Bytes are fed through [`RootStream::feed`] in chunks of any size; how many
/// bytes one read returns is meaningless to the result, and a record that
/// spans any number of chunks is hashed in full. The LF/empty-record/trailing
/// rule is applied by the shared [`RecordScanner`], exactly as
/// [`split_records`] applies it to a whole batch, and the tree is folded with
/// the same largest-power-of-two split as `build_tree`, so
/// [`RootStream::finish`] returns exactly `mth(&split_records(whole))` for the
/// concatenation `whole` of everything fed.
///
/// Memory use is the read buffer plus a small fixed amount and at most 64
/// subtree hashes (one per bit of the record count): nothing grows with the
/// number of bytes fed or with the length of any single record.
#[doc(hidden)]
pub struct RootStream {
    /// The shared divider, feeding this stream's hashing sink.
    scanner: RecordScanner<StreamSink>,
}

/// [`RecordSink`] for the streaming root: hash content into the open leaf and
/// fold one leaf per finished record into the subtree stack.
struct StreamSink {
    /// Hasher for the record currently being accumulated, primed with 0x00.
    /// It stays primed even before any content arrives, so an LF-terminated
    /// empty record hashes to SHA-256(0x00).
    leaf: Sha256,
    /// Completed subtree hashes, bottom to top in strictly decreasing height;
    /// entry i covers 2^height consecutive leaves. Together the entries are
    /// the binary decomposition of the record count so far, which is exactly
    /// the shape the recursive largest-power-of-two split produces.
    subtrees: Vec<([u8; 32], u32)>,
}

impl RecordSink for StreamSink {
    fn record_bytes(&mut self, bytes: &[u8]) {
        self.leaf.update(bytes);
    }

    fn record_end(&mut self) {
        // Fires once per LF, so a leading or consecutive LF folds the empty
        // record between them.
        self.finish_record();
    }

    fn tail_end(&mut self) {
        // Content after the last LF: the same fold as an LF termination.
        self.finish_record();
    }
}

impl StreamSink {
    fn new() -> Self {
        StreamSink {
            leaf: new_leaf_hasher(),
            subtrees: Vec::new(),
        }
    }

    /// Close the current record: finalize its leaf hash and fold it into the
    /// subtree stack, merging completed subtrees of equal height so the stack
    /// always holds the largest complete subtrees on the left.
    fn finish_record(&mut self) {
        let leaf = std::mem::replace(&mut self.leaf, new_leaf_hasher()).finalize();
        let mut acc = leaf;
        let mut height = 0u32;
        while self.subtrees.last().is_some_and(|&(_, h)| h == height) {
            let (left, _) = self.subtrees.pop().unwrap();
            acc = node_hash(&left, &acc);
            height += 1;
        }
        self.subtrees.push((acc, height));
    }

    /// Fold the completed subtrees into the batch root. No record means the
    /// RFC 6962 empty-tree hash SHA-256("").
    fn root(mut self) -> [u8; 32] {
        match self.subtrees.pop() {
            None => sha256(&[]),
            Some((mut acc, _)) => {
                // Fold the remaining complete subtrees right to left: reading
                // the binary decomposition of the record count this way is
                // the recursive k-split of build_tree.
                while let Some((left, _)) = self.subtrees.pop() {
                    acc = node_hash(&left, &acc);
                }
                acc
            }
        }
    }
}

impl RootStream {
    #[doc(hidden)]
    pub fn new() -> Self {
        RootStream {
            scanner: RecordScanner::new(StreamSink::new()),
        }
    }

    /// Feed the next chunk of input. Division is the scanner's job: LF bytes
    /// split records and are not content, while every other byte — space, tab,
    /// CR, NUL, non-UTF-8 — is hashed into the current record as-is. A read
    /// boundary never becomes a record boundary.
    #[doc(hidden)]
    pub fn feed(&mut self, chunk: &[u8]) {
        self.scanner.feed(chunk);
    }

    /// Produce the batch root. A final record without a terminating LF counts
    /// in full; a trailing LF adds no record; no input at all is the RFC 6962
    /// empty-tree hash SHA-256("").
    #[doc(hidden)]
    pub fn finish(self) -> [u8; 32] {
        self.scanner.finish().root()
    }

    /// Number of completed subtrees currently held, for the test that pins
    /// state growth to O(log n) in the record count.
    #[cfg(test)]
    fn subtree_len(&self) -> usize {
        self.scanner.sink.subtrees.len()
    }
}

impl Default for RootStream {
    fn default() -> Self {
        Self::new()
    }
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

/// Build the one-line JSON object printed by `inspect`: only the integer
/// tree_size and leaf_index plus the lowercase-hex root the proof itself
/// claims. The audit path is intentionally absent — inspect performs no
/// membership check and must never emit "verified" or similar wording.
#[doc(hidden)]
pub fn claims_json(claims: &ProofClaims) -> String {
    format!(
        "{{\"tree_size\":{},\"leaf_index\":{},\"root\":\"{}\"}}",
        claims.tree_size,
        claims.leaf_index,
        hex(&claims.root),
    )
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

    // --- streaming root computation ------------------------------------------

    /// Root of a batch computed by streaming it through `chunk`-byte feeds.
    fn streaming_root(data: &[u8], chunk: usize) -> [u8; 32] {
        let mut s = RootStream::new();
        for piece in data.chunks(chunk) {
            s.feed(piece);
        }
        s.finish()
    }

    #[test]
    fn streaming_root_matches_whole_file_root_for_every_chunking() {
        let mut batches: Vec<Vec<u8>> = vec![
            b"".to_vec(),
            b"\n".to_vec(),
            b"\n\n\n".to_vec(),
            b"a".to_vec(),
            b"a\n".to_vec(),
            b"\na".to_vec(),
            b"a\nb".to_vec(),
            b"a\nb\n".to_vec(),
            b"a\n\n\nb\n\n".to_vec(),
            b"\r\n \t\r\n".to_vec(),
            b"\xff\xfe\x00bin\n\x00\r \xff".to_vec(),
            b"alpha\nbeta\n\ngamma\nalpha\ndelta\r\n\xff\xfe\x00binary\nepsilon\nzeta\x01tail\n".to_vec(),
        ];
        // A record far longer than any read buffer (200 KB, no LF inside,
        // NUL/CR/non-UTF-8 bytes throughout) between two short records.
        let mut long = b"head\n".to_vec();
        long.extend((0..200_000u32).map(|i| {
            let b = (i.wrapping_mul(2_654_435_761) >> 13) as u8;
            if b == b'\n' { 0x0b } else { b }
        }));
        long.extend_from_slice(b"\ntail\n");
        batches.push(long);
        // Many short and empty records, duplicates included.
        let mut many = Vec::new();
        for i in 0..5_000u32 {
            many.extend_from_slice(format!("rec{}\n", i % 7).as_bytes());
            many.push(b'\n'); // an empty record after each
        }
        batches.push(many);

        for data in &batches {
            let expected = mth(&split_records(data));
            for chunk in [1usize, 2, 3, 5, 7, 31, 63, 64, 65, 100, 4096, 64 * 1024] {
                assert_eq!(
                    hex_of(&streaming_root(data, chunk)),
                    hex_of(&expected),
                    "chunk size {chunk} changed the root for a {}-byte batch",
                    data.len()
                );
            }
            // One single feed of the whole batch must agree as well.
            assert_eq!(hex_of(&streaming_root(data, data.len().max(1))), hex_of(&expected));
        }
    }

    #[test]
    fn streaming_root_agrees_with_proof_root_for_the_same_batch() {
        // `prove` commits to the root from root_and_path; the streamed root
        // of the same batch must be identical at every position.
        let owned: Vec<Vec<u8>> = (0..100u32).map(|i| format!("record-{i:04}").into_bytes()).collect();
        let refs: Vec<&[u8]> = owned.iter().map(|r| r.as_slice()).collect();
        let mut file = Vec::new();
        for r in &refs {
            file.extend_from_slice(r);
            file.push(b'\n');
        }
        let streamed = streaming_root(&file, 13);
        assert_eq!(hex_of(&streamed), hex_of(&mth(&refs)));
        for m in [0usize, 1, 50, 99] {
            let (proof_root, _) = root_and_path(&refs, m);
            assert_eq!(hex_of(&streamed), hex_of(&proof_root), "prove/root disagree at m={m}");
        }
    }

    #[test]
    fn streaming_root_keeps_only_a_logarithmic_subtree_stack() {
        let mut s = RootStream::new();
        // 102_400 empty records fed as fixed-size chunks of pure LF.
        let chunk = [b'\n'; 4096];
        for _ in 0..25 {
            s.feed(&chunk);
        }
        // One stack entry per set bit of the record count: 102_400 < 2^17.
        let stack = s.subtree_len();
        assert!(
            stack <= 17,
            "subtree stack must stay logarithmic, got {stack} entries"
        );
        let expected = mth(&vec![b"".as_slice(); 102_400]);
        assert_eq!(hex_of(&s.finish()), hex_of(&expected));
    }

    #[test]
    fn streaming_root_edge_cases_match_fixed_definitions() {
        // Empty input: SHA-256(""). Single LF: one empty record, SHA-256(0x00).
        assert_eq!(hex_of(&streaming_root(b"", 1)), hex_of(&sha256(b"")));
        assert_eq!(hex_of(&streaming_root(b"\n", 1)), hex_of(&leaf_hash(b"")));
        // A trailing LF adds no record; a missing one still completes it.
        assert_eq!(streaming_root(b"a\n", 1), streaming_root(b"a", 1));
        // Consecutive LFs keep the empty record between them.
        assert_eq!(streaming_root(b"a\n\n", 1), mth(&[b"a", b""]));
        assert_ne!(streaming_root(b"a\n\n", 1), streaming_root(b"a\n", 1));
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

    // --- inspect_proof --------------------------------------------------------

    #[test]
    fn inspect_reads_claims_without_checking_the_audit_path() {
        // A well-formed proof whose audit path could never establish the
        // claimed position (too short) is still inspectable: inspect has no
        // target record and performs no membership check.
        let records: Vec<&[u8]> = vec![b"a", b"b", b"c"];
        let root = mth(&records);
        let (_, full_path) = root_and_path(&records, 1);
        let bogus = proof_json(3, 1, &root, &full_path[..full_path.len() - 1]).into_bytes();
        let claims = inspect_proof(&bogus).expect("format-valid proof is inspectable");
        assert_eq!(claims.tree_size(), 3);
        assert_eq!(claims.leaf_index(), 1);
        assert_eq!(claims.root(), &root);

        // Even an empty path for a multi-record tree and an arbitrary root are
        // displayed: the claims come straight from the proof.
        let arbitrary = [0xa5u8; 32];
        let proof = proof_json(7, 6, &arbitrary, &[]).into_bytes();
        let claims = inspect_proof(&proof).expect("empty path is still well formed");
        assert_eq!(claims.tree_size(), 7);
        assert_eq!(claims.leaf_index(), 6);
        assert_eq!(claims.root(), &arbitrary);
    }

    #[test]
    fn inspect_success_json_has_exactly_three_fields() {
        let root = [0xabu8; 32];
        let proof = proof_json(1, 0, &root, &[]).into_bytes();
        let claims = inspect_proof(&proof).unwrap();
        assert_eq!(
            claims_json(&claims),
            format!(
                "{{\"tree_size\":1,\"leaf_index\":0,\"root\":\"{}\"}}",
                hex(&root)
            )
        );
        // The line must never mention verification or the audit path.
        let line = claims_json(&claims);
        assert!(!line.contains("verified"));
        assert!(!line.contains("audit_path"));
    }

    #[test]
    fn inspect_accepts_reordered_whitespace_and_unicode_escapes() {
        let root_hex = "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d";
        // Field reordering, legal whitespace and equivalent \uXXXX escapes in
        // field names and hash characters display exactly the same claims.
        let pretty = format!(
            " {{\n  \"audit_path\" : [] ,\n  \"root\" : \"{}\",\n  \"leaf_index\" : 0 ,\n  \"tree_size\" : 1\n}}\t",
            root_hex.replace('e', "\\u0065").replace('a', "\\u0061")
        );
        let with_escaped_key = br#"{"tree_size":1,"leaf_index":0,"root":"6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d","audit_path":[]}"#;
        for bytes in [pretty.into_bytes(), with_escaped_key.to_vec()] {
            let claims = inspect_proof(&bytes).expect("escaped/reordered proof parses");
            assert_eq!(claims.tree_size(), 1);
            assert_eq!(claims.leaf_index(), 0);
            assert_eq!(hex(claims.root()), root_hex);
        }
    }

    #[test]
    fn inspect_enforces_the_full_proof_format_including_audit_path() {
        let h = "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d";
        let z = "0".repeat(64);
        // Every one of these already contains the three displayed fields;
        // inspect must still reject them for the reason verify would.
        let malformed: Vec<Vec<u8>> = vec![
            // audit_path missing entirely
            br#"{"tree_size":1,"leaf_index":0,"root":"6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"}"#.to_vec(),
            // hash of the wrong length inside the non-displayed audit_path
            format!(r#"{{"tree_size":2,"leaf_index":0,"root":"{z}","audit_path":["00"]}}"#)
                .into_bytes(),
            // array never closed
            format!(r#"{{"tree_size":2,"leaf_index":0,"root":"{z}","audit_path":["{z}""#)
                .into_bytes(),
            // duplicate field
            format!(r#"{{"tree_size":1,"tree_size":1,"leaf_index":0,"root":"{h}","audit_path":[]}}"#)
                .into_bytes(),
            b"".to_vec(),
            b"{}".to_vec(),
            b"null".to_vec(),
            b"[]".to_vec(),
            // trailing data after the object
            format!(r#"{{"tree_size":1,"leaf_index":0,"root":"{h}","audit_path":[]}}garbage"#)
                .into_bytes(),
        ];
        for bad in &malformed {
            assert!(
                matches!(inspect_proof(bad), Err(InspectError::MalformedProof(_))),
                "{bad:?} must be malformed for inspect"
            );
        }
        // tree_size zero and an out-of-range index are rejected even though
        // the bytes otherwise form a complete JSON object.
        let zero = format!(
            r#"{{"tree_size":0,"leaf_index":0,"root":"{h}","audit_path":[]}}"#
        );
        let oob = format!(
            r#"{{"tree_size":1,"leaf_index":1,"root":"{h}","audit_path":[]}}"#
        );
        for bad in [zero.as_bytes(), oob.as_bytes()] {
            assert!(matches!(
                inspect_proof(bad),
                Err(InspectError::MalformedProof(_))
            ));
        }
    }

    #[test]
    fn inspect_keeps_full_64bit_meaning() {
        // No materializable tree is needed: only the claimed integers and root
        // are read, so u64::MAX with the largest valid index inspects fine even
        // with an empty audit path.
        let root = [0x01u8; 32];
        let proof = proof_json(u64::MAX, u64::MAX - 1, &root, &[]).into_bytes();
        let claims = inspect_proof(&proof).expect("u64::MAX claims are in range");
        assert_eq!(claims.tree_size(), u64::MAX);
        assert_eq!(claims.leaf_index(), u64::MAX - 1);
        assert_eq!(claims.root(), &root);
        // An integer token above u64::MAX stays a format error.
        let overflowed = format!(
            r#"{{"tree_size":18446744073709551616,"leaf_index":0,"root":"{}","audit_path":[]}}"#,
            hex(&root)
        );
        assert!(matches!(
            inspect_proof(overflowed.as_bytes()),
            Err(InspectError::MalformedProof(_))
        ));
    }
}
