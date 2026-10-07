//! Deterministic mid-file read-fault injection for the `roottrace root`
//! end-to-end regressions.
//!
//! Ordinary regular files cannot produce the conditions this guard needs:
//! `read(2)` returning `EINTR` after earlier reads delivered bytes, or a
//! fatal error after a partial read - on a regular file every read succeeds
//! up to EOF. Signals and pseudo-terminal master closure can produce these
//! only non-deterministically and not at an exact file offset. The shared C
//! shim [`read_fault_shim.c`] is therefore interposed with `LD_PRELOAD`: it
//! rewrites only the result of the batch file's 64 KiB reads (the fixed
//! buffer `merkle_root_of_file` uses, matching [`READ_BUF`]) according to a
//! per-process `RT_SCRIPT`, and leaves every other read untouched. The
//! injected faults are still genuine errors on the real `read` syscall path
//! (the shim only fabricates their `errno`/result), so the built command's
//! actual `std::io::Read` handling - retry on `ErrorKind::Interrupted`, fatal
//! abort on anything else, and the bytes already buffered in between - runs
//! end to end; nothing inside roottrace is stubbed or altered.
//!
//! Script actions are consumed in call order, one per 64 KiB read:
//!   * [`ReadAction::Pass`]      - leave this read unchanged;
//!   * [`ReadAction::Interrupt`] - this read fails with EINTR;
//!   * [`ReadAction::ReadError`] - this read fails with EIO;
//!   * [`ReadAction::Short(n)`]  - this read is clamped to exactly n bytes,
//!     placing the next action at an exact file offset.
//!
//! Availability: the shim only works on a dynamically linked Linux binary
//! with a C compiler present, so [`available`] is checked by the tests,
//! which soft-skip (print a note and return) when it is not. Nothing here is
//! used by the other regression targets.

#![allow(dead_code)]

use std::env;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::OnceLock;

use super::bin;

/// The fixed batch buffer `roottrace root` reads through (src/main.rs); the
/// shim only interposes reads requesting exactly this many bytes.
pub const READ_BUF: usize = 64 * 1024;

/// One scripted behavior for a single 64 KiB batch-file read call, in order.
#[derive(Clone, Copy, Debug)]
pub enum ReadAction {
    /// Leave the read unchanged (used to walk past earlier calls).
    Pass,
    /// Fail the read with EINTR (`ErrorKind::Interrupted`): the command must
    /// retry the same read and keep every byte already obtained.
    Interrupt,
    /// Fail the read with EIO: a persistent, non-retryable read failure.
    ReadError,
    /// Clamp the read to exactly `n` bytes (`1..READ_BUF`), so the call is a
    /// deliberately short read returning the first `n` remaining bytes and
    /// the next action lands at that exact file offset.
    Short(usize),
}

impl ReadAction {
    fn encode(self) -> String {
        match self {
            ReadAction::Pass => ".".to_string(),
            ReadAction::Interrupt => "i".to_string(),
            ReadAction::ReadError => "e".to_string(),
            ReadAction::Short(n) => {
                assert!(
                    (1..READ_BUF).contains(&n),
                    "a short-read limit must be between 1 and {} bytes",
                    READ_BUF - 1
                );
                format!("r{n}")
            }
        }
    }
}

/// Whether the fault-injection harness can run here (Linux, a C compiler and
/// the shim source). Tests soft-skip when this is false rather than failing.
pub fn available() -> bool {
    shim_path().is_some()
}

fn shim_path() -> Option<PathBuf> {
    static SHIM: OnceLock<Option<PathBuf>> = OnceLock::new();
    SHIM.get_or_init(build_shim).clone()
}

/// Compile the interposer once per test process. Each integration test is
/// its own process, so the PID-keyed name is unique even when several test
/// binaries run in parallel; the small artifact is left in the system temp
/// directory (it is a build product, like any compiler output there).
fn build_shim() -> Option<PathBuf> {
    if cfg!(not(target_os = "linux")) {
        return None;
    }
    let compiler = env::var_os("CC")
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("cc"));
    let source = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/common/read_fault_shim.c");
    if !source.is_file() {
        return None;
    }
    let object = env::temp_dir().join(format!(
        "roottrace-readfault-shim-{}.so",
        std::process::id()
    ));
    let ok = Command::new(&compiler)
        .arg("-shared")
        .arg("-fPIC")
        .arg("-O0")
        .arg("-o")
        .arg(&object)
        .arg(&source)
        .arg("-ldl")
        .status()
        .map(|status| status.success())
        .unwrap_or(false);
    ok.then_some(object)
}

/// Run `roottrace root <file>` with the given per-read fault script. Returns
/// `None` only when the harness itself is unavailable (the caller should
/// soft-skip); a failure to execute the binary panics like the other
/// regression helpers.
pub fn root_under_faults(file: &Path, script: &[ReadAction]) -> Option<Output> {
    let shim = shim_path()?;
    let encoded: Vec<String> = script.iter().copied().map(ReadAction::encode).collect();
    let output = Command::new(bin())
        .arg("root")
        .arg(file)
        .env("LD_PRELOAD", &shim)
        // An empty script would also be inert in the shim, but there is no
        // reason to inject anything without at least one action.
        .env("RT_SCRIPT", encoded.join(";"))
        .output()
        .expect("failed to execute roottrace binary");
    Some(output)
}

/// Assert the fully documented success path after one or more read faults:
/// exit 0, empty stderr, and stdout exactly the 64 lowercase hex digits of
/// `expected_hex` plus one LF.
pub fn assert_root_success(output: &Output, expected_hex: &str, desc: &str) {
    assert_eq!(
        output.status.code(),
        Some(0),
        "[{desc}] expected exit status 0 after recovered reads\n\
         stderr: {}\nstdout: {}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout),
    );
    assert!(
        output.stderr.is_empty(),
        "[{desc}] a recoverable interruption must not be reported: {}",
        String::from_utf8_lossy(&output.stderr),
    );
    assert_eq!(
        output.stdout.len(),
        65,
        "[{desc}] stdout must be exactly 64 hex digits plus LF, got {:?}",
        String::from_utf8_lossy(&output.stdout),
    );
    assert_eq!(output.stdout[64], b'\n', "[{desc}] stdout must end with one LF");
    let hex = std::str::from_utf8(&output.stdout[..64]).unwrap();
    assert!(
        hex.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
        "[{desc}] root must be 64 lowercase hex digits, got {hex}"
    );
    assert_eq!(
        hex, expected_hex,
        "[{desc}] root after the read faults does not match the fixed root \
         of the uninterrupted record sequence"
    );
}

/// Assert the documented failure path after a fatal post-partial read error:
/// exit 1, nothing on stdout, and stderr naming both the input path and the
/// read reason - a file-read failure (exit 1), never a usage error (exit 2),
/// never the empty-tree root or any other partial result.
pub fn assert_read_failure(output: &Output, path: &Path, desc: &str) {
    assert_eq!(
        output.status.code(),
        Some(1),
        "[{desc}] a fatal read error must exit 1\n\
         stderr: {}\nstdout: {}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout),
    );
    assert!(
        output.stdout.is_empty(),
        "[{desc}] no partial root may be written, got stdout: {:?}",
        String::from_utf8_lossy(&output.stdout),
    );
    let err = String::from_utf8_lossy(&output.stderr);
    assert!(!err.is_empty(), "[{desc}] stderr must explain the failure");
    assert!(
        err.contains("cannot read"),
        "[{desc}] stderr must classify this as a read failure: {err}"
    );
    let shown = path.to_string_lossy();
    assert!(
        err.contains(&*shown),
        "[{desc}] stderr must name the input path {shown}: {err}"
    );
    assert!(
        err.contains("Input/output error"),
        "[{desc}] stderr must state the read reason: {err}"
    );
    assert!(
        !err.contains("Usage"),
        "[{desc}] a file-read failure must not be reported as a usage error: {err}"
    );
}
