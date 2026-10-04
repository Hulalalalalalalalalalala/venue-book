//! Shared helpers for the end-to-end regression tests: temporary files and
//! directories, LF joining of exact record sequences, and the strict
//! success-path assertion for `roottrace root`.

// Not every helper is used by every integration-test target that includes
// this module (e.g. TempDir is only needed by root_regression).
#![allow(dead_code)]

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static COUNTER: AtomicU64 = AtomicU64::new(0);

pub fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_roottrace")
}

/// File that is deleted when the guard drops, even if the test panics.
pub struct TempFile {
    pub path: PathBuf,
}

impl TempFile {
    pub fn create(data: &[u8]) -> Self {
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "roottrace-regtest-{}-{}",
            std::process::id(),
            id,
        ));
        fs::write(&path, data).unwrap_or_else(|e| panic!("cannot create {}: {e}", path.display()));
        TempFile { path }
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

/// Temporary directory (used to trigger "path is a directory" failures).
pub struct TempDir {
    pub path: PathBuf,
}

impl TempDir {
    pub fn create() -> Self {
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir()
            .join(format!("roottrace-regtest-dir-{}-{}", std::process::id(), id));
        fs::create_dir(&path).unwrap();
        TempDir { path }
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir(&self.path);
    }
}

pub fn join_lf(records: &[&[u8]], trailing_lf: bool) -> Vec<u8> {
    let mut data: Vec<u8> = Vec::new();
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

/// Run `roottrace root <file>` and fully verify the documented success path:
/// exit status 0, empty stderr, stdout is exactly one line of 64 lowercase
/// hex digits terminated by a single LF, equal to `expected`.
pub fn assert_root(desc: &str, records: &[&[u8]], file_bytes: &[u8], expected: &str) {
    let tmp = TempFile::create(file_bytes);
    let output = Command::new(bin())
        .arg("root")
        .arg(&tmp.path)
        .output()
        .expect("failed to execute roottrace binary");

    let sequence = records;
    if !output.status.success() || output.status.code() != Some(0) {
        panic!(
            "[{desc}] command execution failed for record sequence {sequence:?}\n\
             file bytes: {file_bytes:?}\n\
             expected root: {expected}\n\
             exit status: {:?}\n\
             stderr: {}\n\
             stdout: {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr),
            String::from_utf8_lossy(&output.stdout),
        );
    }
    if !output.stderr.is_empty() {
        panic!(
            "[{desc}] successful run wrote to stderr for sequence {sequence:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let stdout = &output.stdout;
    if stdout.len() != 65 || stdout[64] != b'\n' {
        panic!(
            "[{desc}] stdout is not exactly 64 hex digits + LF for sequence {sequence:?}: {stdout:?}"
        );
    }
    let hex = &stdout[..64];
    if !hex.iter().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()) {
        panic!("[{desc}] root must be lowercase hex, got: {:?}", std::str::from_utf8(hex));
    }
    let actual = std::str::from_utf8(hex).unwrap();
    if actual != expected {
        panic!(
            "[{desc}] ROOT MISMATCH\n\
             record sequence: {sequence:?}\n\
             file bytes: {file_bytes:?}\n\
             expected root: {expected}\n\
             actual root:   {actual}"
        );
    }
}
