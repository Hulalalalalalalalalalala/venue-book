//! 批次根值回归保障：记录数量跨过二次幂边界（7、8、9 条）时，`roottrace root`
//! 输出的根值必须符合 README 公开的 RFC 6962 第 2.1 节 SHA-256 Merkle Tree Hash。
//!
//! 所有预期根值都是事先确定的常量，可追溯到下列明确的记录序列；它们由独立于
//! 本crate的参考实现（Python hashlib 按 RFC 6962 §2.1 计算）得出，不是任何一次
//! 被测程序运行的输出。

use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

// --- 固定记录序列 -----------------------------------------------------------
//
// 三个批次共享前七条记录，第八条、第九条内容各自明确且不同。
// 序列中刻意包含重复内容（"alpha" 位于索引 0 和 2）和空记录（索引 3 和 5），
// 它们占据不同位置，位置与顺序都参与计算。
const R1: &[u8] = b"alpha";
const R2: &[u8] = b"beta";
const R3: &[u8] = b"alpha"; // 与 R1 内容相同，位置不同
const R4: &[u8] = b""; // 空记录
const R5: &[u8] = b"gamma";
const R6: &[u8] = b""; // 第二条空记录，位置不同
const R7: &[u8] = b"delta";
const R8: &[u8] = b"epsilon";
const R9: &[u8] = b"zeta";

const BATCH7: [&[u8]; 7] = [R1, R2, R3, R4, R5, R6, R7];
const BATCH8: [&[u8]; 8] = [R1, R2, R3, R4, R5, R6, R7, R8];
const BATCH9: [&[u8]; 9] = [R1, R2, R3, R4, R5, R6, R7, R8, R9];

// 变体一：重复内容 "alpha" 的第二个位置（索引 2）改为其他字节 "omega"，
// 索引 0 的 "alpha" 保持不变。
const BATCH9_DUP_CHANGED: [&[u8]; 9] = [R1, R2, b"omega", R4, R5, R6, R7, R8, R9];

// 变体二：交换两条不同内容的记录（索引 1 的 "beta" 与索引 4 的 "gamma"）。
const BATCH9_SWAPPED: [&[u8]; 9] = [R1, R5, R3, R4, R2, R6, R7, R8, R9];

// --- 事先确定的预期根值（独立参考实现计算） ---------------------------------
const ROOT_BATCH7: &str = "e51429f2de82dfe39a35c5e47b364d76f46133d8d066b4308c27697144c851b7";
const ROOT_BATCH8: &str = "40e329e4e079ae5fbdfada2a7e4816b28b2d663937a84989e482f1afe7870c7c";
const ROOT_BATCH9: &str = "9dada71a422144155034168db02385d7d302e74c3f8ff44abaf5c4dd1cb95c1c";
const ROOT_BATCH9_DUP_CHANGED: &str =
    "a16bf853b48e7f7632087d1888066191f3aae9c2319b7ff2b66071cf42fea36a";
const ROOT_BATCH9_SWAPPED: &str =
    "33a133f8d7b69cb9d82788cba7832cadef02cac226b88e9b0bcc2bc2d566ea84";
// 空文件（零条记录）：空输入的 SHA-256。
const ROOT_EMPTY_FILE: &str =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
// 只含一个 LF（一条空记录）：SHA-256(0x00)。
const ROOT_SINGLE_LF: &str =
    "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d";

// --- 测试辅助 ---------------------------------------------------------------

/// 写入临时文件，离开作用域时自动删除。
struct TempFile(PathBuf);

impl TempFile {
    fn write(bytes: &[u8]) -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let name = format!(
            "roottrace-test-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        let path = std::env::temp_dir().join(name);
        std::fs::write(&path, bytes).expect("write temp input file");
        TempFile(path)
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_roottrace"))
        .args(args)
        .output()
        .expect("spawn roottrace")
}

/// 把记录序列按线格式序列化：LF 分隔，末尾 LF 结束最后一条记录。
fn serialize(records: &[&[u8]]) -> Vec<u8> {
    let mut data = Vec::new();
    for rec in records {
        data.extend_from_slice(rec);
        data.push(b'\n');
    }
    data
}

/// 断言给定记录序列的根值等于事先确定的预期值。
///
/// 区分两类失败：命令执行失败（非零退出、stderr 有内容）与根值不符。
/// 失败信息中包含对应的记录序列与预期根值。
fn assert_root(records: &[&[u8]], expected_root: &str, label: &str) {
    let file = TempFile::write(&serialize(records));
    let output = run(&["root", file.0.to_str().unwrap()]);

    assert!(
        output.status.success(),
        "{label}: 命令执行失败（退出状态 {:?}），stderr: {}\n记录序列: {records:?}\n预期根值: {expected_root}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(
        output.stderr.is_empty(),
        "{label}: 成功运行时 stderr 应为空，实际: {}\n记录序列: {records:?}",
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8(output.stdout).expect("stdout 应为 UTF-8");
    let expected_stdout = format!("{expected_root}\n");
    assert_eq!(
        stdout, expected_stdout,
        "{label}: 根值不符（应为一行 64 位小写十六进制加换行）\n记录序列: {records:?}\n预期根值: {expected_root}"
    );
}

// --- 跨过二次幂边界的批次 ---------------------------------------------------

#[test]
fn root_of_seven_records() {
    assert_root(&BATCH7, ROOT_BATCH7, "七条记录");
}

#[test]
fn root_of_eight_records() {
    assert_root(&BATCH8, ROOT_BATCH8, "八条记录");
}

#[test]
fn root_of_nine_records() {
    assert_root(&BATCH9, ROOT_BATCH9, "九条记录");
}

// --- 位置与顺序敏感性 -------------------------------------------------------

#[test]
fn changing_one_position_of_duplicated_content() {
    // 重复内容 "alpha" 出现在索引 0 和 2；只改索引 2 必须得到该新序列
    // 各自的确定根值，而不是仅仅“与原来不同”。
    assert_root(
        &BATCH9_DUP_CHANGED,
        ROOT_BATCH9_DUP_CHANGED,
        "九条记录（索引 2 的重复内容改为 omega）",
    );
}

#[test]
fn swapping_two_distinct_records() {
    // 交换索引 1 的 "beta" 与索引 4 的 "gamma"：内容集合不变，顺序改变，
    // 必须得到交换后序列各自的确定根值。
    assert_root(
        &BATCH9_SWAPPED,
        ROOT_BATCH9_SWAPPED,
        "九条记录（交换 beta 与 gamma）",
    );
}

// --- 记录划分规则 -----------------------------------------------------------

#[test]
fn trailing_lf_does_not_change_root() {
    // 末尾 LF 只结束最后一条记录：同一序列带或不带末尾 LF 根值相同，
    // 且都等于事先确定的值。
    let with_lf = TempFile::write(&serialize(&BATCH9));
    let mut without_lf_bytes = serialize(&BATCH9);
    without_lf_bytes.pop();
    let without_lf = TempFile::write(&without_lf_bytes);

    for (label, file) in [("带末尾 LF", &with_lf), ("不带末尾 LF", &without_lf)] {
        let output = run(&["root", file.0.to_str().unwrap()]);
        assert!(
            output.status.success(),
            "九条记录（{label}）: 命令执行失败，stderr: {}",
            String::from_utf8_lossy(&output.stderr),
        );
        let stdout = String::from_utf8(output.stdout).expect("stdout 应为 UTF-8");
        assert_eq!(
            stdout,
            format!("{ROOT_BATCH9}\n"),
            "九条记录（{label}）: 根值不符\n记录序列: {BATCH9:?}\n预期根值: {ROOT_BATCH9}"
        );
    }
}

#[test]
fn empty_file_is_zero_records() {
    let file = TempFile::write(b"");
    let output = run(&["root", file.0.to_str().unwrap()]);
    assert!(
        output.status.success(),
        "空文件: 命令执行失败，stderr: {}",
        String::from_utf8_lossy(&output.stderr),
    );
    assert_eq!(
        String::from_utf8(output.stdout).expect("stdout 应为 UTF-8"),
        format!("{ROOT_EMPTY_FILE}\n"),
        "空文件（零条记录）: 根值不符，预期空输入的 SHA-256"
    );
}

#[test]
fn single_lf_is_one_empty_record() {
    // 一个 LF 是一条空记录，与空文件（零条记录）的根值不同。
    let file = TempFile::write(b"\n");
    let output = run(&["root", file.0.to_str().unwrap()]);
    assert!(
        output.status.success(),
        "单个 LF: 命令执行失败，stderr: {}",
        String::from_utf8_lossy(&output.stderr),
    );
    assert_eq!(
        String::from_utf8(output.stdout).expect("stdout 应为 UTF-8"),
        format!("{ROOT_SINGLE_LF}\n"),
        "一条空记录: 根值不符，预期 SHA-256(0x00)"
    );
}

// --- 既有公开行为 -----------------------------------------------------------

#[test]
fn version_output() {
    let output = run(&["--version"]);
    assert!(output.status.success());
    assert_eq!(output.stdout, b"roottrace 0.1.0\n");
    assert!(output.stderr.is_empty());
}

#[test]
fn usage_errors_exit_with_status_2() {
    for args in [
        &[][..],                       // 缺少参数
        &["root"][..],                 // 缺少文件路径
        &["root", "a", "b"][..],       // 参数多余
        &["unknown", "a"][..],         // 未知命令
    ] {
        let output = run(args);
        assert_eq!(
            output.status.code(),
            Some(2),
            "参数 {args:?} 应以状态 2 退出"
        );
        assert!(
            output.stdout.is_empty(),
            "参数 {args:?} 不应向 stdout 写根值"
        );
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("Usage:"),
            "参数 {args:?} 的 stderr 应包含用法说明"
        );
    }
}

#[test]
fn unreadable_file_exits_with_status_1() {
    let missing = std::env::temp_dir().join(format!(
        "roottrace-test-nonexistent-{}",
        std::process::id()
    ));
    let output = run(&["root", missing.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty(), "读取失败不应向 stdout 写根值");
    assert!(
        !output.stderr.is_empty(),
        "读取失败应向 stderr 输出失败原因"
    );
}
