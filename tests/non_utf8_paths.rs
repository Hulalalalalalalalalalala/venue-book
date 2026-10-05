//! End-to-end regression coverage for file paths that are not valid UTF-8.
//!
//! On Unix a file name (or any parent component) may contain bytes such as
//! 0xff that do not form valid UTF-8. Such a path is not invalid: the file
//! system accepts it and the program must open exactly the path bytes the
//! user passed, instead of aborting while collecting command line arguments
//! or opening a differently named file whose rendered name looks the same.
//!
//! These tests exercise the built binary directly with raw `OsStr`
//! arguments. They are Unix-only because non-Unicode file names are a
//! Unix-only concept.

#![cfg(unix)]

use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_roottrace")
}

/// Scratch directory deleted on drop, even if the test panics.
struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn create() -> Self {
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "roottrace-nonutf8-{}-{}",
            std::process::id(),
            id
        ));
        fs::create_dir(&path).unwrap();
        TempDir { path }
    }

    fn child(&self, name: &[u8]) -> PathBuf {
        self.path.join(std::ffi::OsStr::from_bytes(name))
    }

    fn write(&self, name: &[u8], data: &[u8]) -> PathBuf {
        let path = self.child(name);
        fs::write(&path, data).unwrap();
        path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn run(args: &[&[u8]], current_dir: Option<&Path>) -> std::process::Output {
    let mut cmd = Command::new(bin());
    for arg in args {
        cmd.arg(std::ffi::OsStr::from_bytes(arg));
    }
    if let Some(dir) = current_dir {
        cmd.current_dir(dir);
    }
    cmd.output().unwrap()
}

// Batch content exercising every content-preservation rule: a trailing CR,
// a NUL byte, non-UTF-8 record bytes and a terminating LF.
const CONTENT: &[u8] = b"alpha\r\n\x00nul-record\n\xff\xfebinary\n";

/// `root` over a 0xff-named file must match the ASCII-named twin byte for
/// byte and must not touch stderr.
#[test]
fn root_accepts_non_utf8_file_name_and_parent_directory() {
    let dir = TempDir::create();
    let ascii_path = dir.write(b"ascii.txt", CONTENT);
    let weird_path = dir.write(b"weird-\xff-name.txt", CONTENT);
    let ascii_out = run(&[b"root", ascii_path.as_os_str().as_bytes()], None);
    assert_eq!(ascii_out.status.code(), Some(0));
    assert!(ascii_out.stderr.is_empty());

    let weird_out = run(&[b"root", weird_path.as_os_str().as_bytes()], None);
    assert_eq!(weird_out.status.code(), Some(0), "{:?}", weird_out.stderr);
    assert!(weird_out.stderr.is_empty());
    assert_eq!(weird_out.stdout, ascii_out.stdout);
    assert_eq!(weird_out.stdout.len(), 65);

    // A parent component carrying 0xff must work for both relative and
    // absolute spellings.
    let sub = dir.child(b"sub-\xff");
    fs::create_dir(&sub).unwrap();
    let nested = sub.join(std::ffi::OsStr::from_bytes(b"batch-\xfe.txt"));
    fs::write(&nested, CONTENT).unwrap();

    let abs_out = run(&[b"root", nested.as_os_str().as_bytes()], None);
    assert_eq!(abs_out.status.code(), Some(0), "{:?}", abs_out.stderr);
    assert!(abs_out.stderr.is_empty());
    assert_eq!(abs_out.stdout, ascii_out.stdout);

    let rel_out = run(&[b"root", b"./batch-\xfe.txt"], Some(&sub));
    assert_eq!(rel_out.status.code(), Some(0), "{:?}", rel_out.stderr);
    assert!(rel_out.stderr.is_empty());
    assert_eq!(rel_out.stdout, ascii_out.stdout);
}

/// The raw 0xff bytes must reach the filesystem untouched. A sibling whose
/// name contains the replacement character U+FFFD displays the same under
/// lossy conversion but is a different file with different content; it must
/// never be read by mistake.
#[test]
fn raw_path_bytes_are_not_confused_with_a_replacement_character_file() {
    let dir = TempDir::create();
    let real = dir.write(b"real-\xff.bin", b"correct-a\ncorrect-b\ncorrect-c\n");
    // U+FFFD encoded as UTF-8 is ef bf bd: a distinct file name that merely
    // renders the same as the 0xff name under lossy conversion.
    let mut decoy_bytes: Vec<u8> = b"real-".to_vec();
    decoy_bytes.extend_from_slice("\u{FFFD}".as_bytes());
    decoy_bytes.extend_from_slice(b".bin");
    let decoy = dir.write(&decoy_bytes, b"decoy-a\ndecoy-b\ndecoy-c\n");
    assert_ne!(real, decoy);

    let real_out = run(&[b"root", real.as_os_str().as_bytes()], None);
    assert_eq!(real_out.status.code(), Some(0));
    let decoy_out = run(&[b"root", decoy.as_os_str().as_bytes()], None);
    assert_eq!(decoy_out.status.code(), Some(0));
    assert_ne!(
        real_out.stdout, decoy_out.stdout,
        "the U+FFFD-named file has different content and must hash differently"
    );

    for index in [b"0".as_slice(), b"1".as_slice(), b"2".as_slice()] {
        let real_proof = run(
            &[b"prove", real.as_os_str().as_bytes(), index],
            None,
        );
        assert_eq!(real_proof.status.code(), Some(0), "{:?}", real_proof.stderr);
        let decoy_proof = run(
            &[b"prove", decoy.as_os_str().as_bytes(), index],
            None,
        );
        assert_eq!(decoy_proof.status.code(), Some(0), "{:?}", decoy_proof.stderr);
        assert_ne!(real_proof.stdout, decoy_proof.stdout);
    }
}

/// `prove` results for identical content must be identical regardless of the
/// path bytes used to name the file, at every record position.
#[test]
fn prove_results_are_identical_across_path_byte_variants() {
    let dir = TempDir::create();
    let ascii_path = dir.write(b"ascii.txt", CONTENT);
    let weird_path = dir.write(b"weird-\xff.txt", CONTENT);
    for index in [b"0".as_slice(), b"1".as_slice(), b"2".as_slice()] {
        let a = run(&[b"prove", ascii_path.as_os_str().as_bytes(), index], None);
        let w = run(&[b"prove", weird_path.as_os_str().as_bytes(), index], None);
        assert_eq!(a.status.code(), Some(0), "{:?}", a.stderr);
        assert_eq!(w.status.code(), Some(0), "{:?}", w.stderr);
        assert!(a.stderr.is_empty() && w.stderr.is_empty());
        assert_eq!(w.stdout, a.stdout, "index {:?}", index);
    }
    // A valid index past the end of a non-UTF-8-named file is still a
    // position error (exit 1), not a usage error.
    let missing_pos = run(
        &[b"prove", weird_path.as_os_str().as_bytes(), b"3"],
        None,
    );
    assert_eq!(missing_pos.status.code(), Some(1));
    assert!(missing_pos.stdout.is_empty());
    let err = String::from_utf8_lossy(&missing_pos.stderr);
    assert!(err.contains("does not exist"), "{err}");
}

/// A missing or directory path that itself contains 0xff must produce the
/// stable read-failure contract: exit 1, empty stdout, a message on stderr,
/// and no panic.
#[test]
fn non_utf8_read_failures_exit_1_without_panicking() {
    let dir = TempDir::create();
    let missing = dir.child(b"no-such-\xff-file");
    let missing_bytes = missing.as_os_str().as_bytes();
    for args in [
        vec![b"root".as_slice(), missing_bytes],
        vec![b"prove".as_slice(), missing_bytes, b"0"],
    ] {
        let out = run(&args, None);
        assert_eq!(out.status.code(), Some(1), "args {args:?}");
        assert!(out.stdout.is_empty(), "args {args:?}");
        assert!(!out.stderr.is_empty(), "args {args:?}");
    }

    let sub = dir.child(b"dir-\xff");
    fs::create_dir(&sub).unwrap();
    let sub_bytes = sub.as_os_str().as_bytes();
    for args in [
        vec![b"root".as_slice(), sub_bytes],
        vec![b"prove".as_slice(), sub_bytes, b"0"],
    ] {
        let out = run(&args, None);
        assert_eq!(out.status.code(), Some(1), "args {args:?}");
        assert!(out.stdout.is_empty(), "args {args:?}");
        assert!(!out.stderr.is_empty(), "args {args:?}");
    }
}

/// `verify` must open record and proof files named with non-UTF-8 bytes, and
/// must report read failures for such paths with the usual exit-1 contract.
#[test]
fn verify_accepts_non_utf8_record_and_proof_paths() {
    let dir = TempDir::create();
    let batch = dir.write(b"batch.bin", CONTENT);
    let root_out = run(&[b"root", batch.as_os_str().as_bytes()], None);
    assert_eq!(root_out.status.code(), Some(0));
    let root = String::from_utf8(root_out.stdout[..64].to_vec()).unwrap();
    let proof_out = run(&[b"prove", batch.as_os_str().as_bytes(), b"1"], None);
    assert_eq!(proof_out.status.code(), Some(0));

    // Record 1 of CONTENT is b"\x00nul-record"; proof file carries 0xff too.
    let record = dir.write(b"record-\xff.bin", b"\x00nul-record");
    let proof = dir.write(b"proof-\xff.json", &proof_out.stdout);
    let out = run(
        &[
            b"verify".as_slice(),
            record.as_os_str().as_bytes(),
            proof.as_os_str().as_bytes(),
            b"3",
            root.as_bytes(),
        ],
        None,
    );
    assert_eq!(out.status.code(), Some(0), "{:?}", out.stderr);
    assert_eq!(out.stdout, b"verified\n");
    assert!(out.stderr.is_empty());

    // A missing non-UTF-8 record path is a read failure (exit 1), not a
    // usage error and not a panic.
    let missing = dir.child(b"no-such-\xff-record");
    let out = run(
        &[
            b"verify".as_slice(),
            missing.as_os_str().as_bytes(),
            proof.as_os_str().as_bytes(),
            b"3",
            root.as_bytes(),
        ],
        None,
    );
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty());
    assert!(!out.stderr.is_empty());
}

/// Non-UTF-8 bytes in the command name or record index are syntax errors:
/// exit 2 with the usage text and nothing on stdout.
#[test]
fn non_utf8_command_and_index_are_usage_errors() {
    let dir = TempDir::create();
    let file = dir.write(b"weird-\xff.txt", CONTENT);
    let file_bytes = file.as_os_str().as_bytes();

    let bad_cmd = run(&[b"r\xffot", file_bytes], None);
    assert_eq!(bad_cmd.status.code(), Some(2));
    assert!(bad_cmd.stdout.is_empty());
    assert!(String::from_utf8_lossy(&bad_cmd.stderr).contains("Usage"));

    for bad_index in [b"1\xff".as_slice(), b"\xff".as_slice()] {
        let out = run(&[b"prove", file_bytes, bad_index], None);
        assert_eq!(out.status.code(), Some(2), "index {bad_index:?}");
        assert!(out.stdout.is_empty(), "index {bad_index:?}");
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("Usage"),
            "index {bad_index:?}"
        );
    }
}
