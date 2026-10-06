use std::env;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::Path;
use std::process::ExitCode;

use roottrace::cli::{hex, mth, proof_json, root_and_path, split_records};
use roottrace::cli::CliVerifyError;

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

/// Read the two input files and run an RFC 6962 inclusion check through the
/// library. The record file's ENTIRE byte content is the target record: no LF
/// splitting and no trimming of trailing LF, space or CR; NUL and non-UTF-8
/// bytes take part as they are. A zero-byte file is one empty record.
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
    // The detailed variant is CLI-only so stderr can keep its historical
    // reason text; the classification (malformed vs failed) is identical to
    // the typed library entry point.
    match roottrace::cli::verify_inclusion_detailed(&record, &proof_bytes, trusted_size, trusted_root) {
        Ok(_) => Ok(()),
        Err(CliVerifyError::InvalidProof(reason)) => Err(VerifyError::MalformedProof(reason)),
        Err(CliVerifyError::VerificationFailed(reason)) => Err(VerifyError::Failed(reason)),
        // Defensive: a zero trusted size is rejected as a usage error at
        // argument parsing, before any file is read.
        Err(CliVerifyError::InvalidArgument) => {
            Err(VerifyError::Failed("trusted tree size must be positive".to_string()))
        }
    }
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
