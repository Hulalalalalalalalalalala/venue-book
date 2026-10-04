//! End-to-end regression tests for `roottrace root`, focused on the power-of
//! two boundary in the RFC 6962 SHA-256 Merkle Tree Hash (7, 8 and 9
//! records) and on long records straddling the SHA-256 padding and block
//! boundaries (54/55/56, 63/64/65 and 146 raw bytes).
//!
//! Expected roots are FIXED constants produced independently of roottrace by
//! `tests/reference/rfc6962_vectors.py`, which computes them with Python's
//! `hashlib.sha256` in two structurally different ways (the RFC's recursive
//! definition and an order-sensitive stack fold); the two implementations
//! agree for every vector, and the one-leaf/empty cases were additionally
//! cross-checked against the system `sha256sum`. The constants below are
//! copied from that generator and never derived from roottrace output.
//!
//! Each batch is spelled out as its exact record sequence so an expected root
//! can be traced back to the records it belongs to. Failures distinguish a
//! command execution failure from a root mismatch and report both the record
//! sequence and the expected root.

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_roottrace")
}

/// File that is deleted when the guard drops, even if the test panics.
struct TempFile {
    path: PathBuf,
}

impl TempFile {
    fn create(data: &[u8]) -> Self {
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
struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn create() -> Self {
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

fn join_lf(records: &[&[u8]], trailing_lf: bool) -> Vec<u8> {
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
fn assert_root(desc: &str, records: &[&[u8]], file_bytes: &[u8], expected: &str) {
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

// ---------------------------------------------------------------------------
// Fixed record sequences.
//
// The 7/8/9 batches share their first seven records. Those seven include:
//   * duplicated content at two different positions (r0 == r4 == b"alpha")
//   * an empty record (r2)
//   * a trailing CR kept as content (r5)
//   * non-UTF-8 / NUL bytes (r6)
// The eighth and ninth records are explicitly defined and distinct.
// ---------------------------------------------------------------------------

const B7: &[&[u8]] = &[
    b"alpha",
    b"beta",
    b"",
    b"gamma",
    b"alpha",
    b"delta\r",
    b"\xff\xfe\x00binary",
];

const B8: &[&[u8]] = &[
    b"alpha",
    b"beta",
    b"",
    b"gamma",
    b"alpha",
    b"delta\r",
    b"\xff\xfe\x00binary",
    b"epsilon",
];

const B9: &[&[u8]] = &[
    b"alpha",
    b"beta",
    b"",
    b"gamma",
    b"alpha",
    b"delta\r",
    b"\xff\xfe\x00binary",
    b"epsilon",
    b"zeta\x01tail",
];

// Independently fixed RFC 6962 roots (tests/reference/rfc6962_vectors.py).
const ROOT_B7: &str = "90caa8bddc2a50cf863a969533ad1700a80aeed313dcd1c7a4b46b0c93991b6e";
const ROOT_B8: &str = "80f3f98ae8d7d9d1d2139a6a2dc94628e02fba22e125f922ea8a4c10799cb912";
const ROOT_B9: &str = "a8a3e76ecf28b850e84cb5465729921212ffd07de3c0e6e170cd233bf723adc3";

// B9 with the duplicate-content position r4 changed to other bytes.
const V_DUP: &[&[u8]] = &[
    b"alpha",
    b"beta",
    b"",
    b"gamma",
    b"alpha-changed",
    b"delta\r",
    b"\xff\xfe\x00binary",
    b"epsilon",
    b"zeta\x01tail",
];
const ROOT_V_DUP: &str = "015cce68e9e800f3ff480da17c8f43f30eed95e0705b5500043c3bf74662dde0";

// B9 with two records of different content (r1 and r5) swapped. The byte
// multiset of records is unchanged, only their positions differ.
const V_SWAP: &[&[u8]] = &[
    b"alpha",
    b"delta\r",
    b"",
    b"gamma",
    b"alpha",
    b"beta",
    b"\xff\xfe\x00binary",
    b"epsilon",
    b"zeta\x01tail",
];
const ROOT_V_SWAP: &str = "3a6482dbcf43884e11018c885ff68e63717a13154217c591c8a01f6dafdb9dd9";

// B9 with the empty record r2 omitted: 8 records, but a DIFFERENT sequence
// from B8. Dropping an empty record must not be silently ignored.
const V_DROP_EMPTY: &[&[u8]] = &[
    b"alpha",
    b"beta",
    b"gamma",
    b"alpha",
    b"delta\r",
    b"\xff\xfe\x00binary",
    b"epsilon",
    b"zeta\x01tail",
];
const ROOT_V_DROP_EMPTY: &str = "918ae84b0d065be5148d048875c9f8cafb5e0ee14417cefbbbb4575631a5257a";

// B9 with one extra duplicate of r0 appended: the same record content
// included twice occupies two positions (10 records total).
const V_DUP_INSERT: &[&[u8]] = &[
    b"alpha",
    b"beta",
    b"",
    b"gamma",
    b"alpha",
    b"delta\r",
    b"\xff\xfe\x00binary",
    b"epsilon",
    b"zeta\x01tail",
    b"alpha",
];
const ROOT_V_DUP_INSERT: &str = "ae0586f6c285c304a53273198d19f5f137d1d9f546e9a74a6fd87547c09bd4e8";

// Empty file: zero records -> SHA-256(""). Single LF: one empty record ->
// SHA-256(0x00). Independently fixed (and cross-checked with sha256sum).
const ROOT_EMPTY_FILE: &str =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const ROOT_ONE_EMPTY_RECORD: &str =
    "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d";

// ---------------------------------------------------------------------------
// Long records straddling SHA-256 padding and block boundaries.
//
// The leaf input is 0x00 || record, so record lengths 54/55/56 put the leaf
// input at 55/56/57 bytes (the padding boundary: the 0x80 marker plus the
// 8-byte length field stop fitting in the first block) and 63/64/65 put it
// at 64/65/66 bytes (the block boundary). REC_L146's 147-byte leaf input
// spans three blocks and still has real content at its very end. Every
// record embeds NUL, non-UTF-8 and CR bytes, inside and at the very end;
// none contains LF (the separator). Records and expected roots are fixed
// independently of roottrace by tests/reference/rfc6962_vectors.py.
// ---------------------------------------------------------------------------

const REC_L54: &[u8] = b"boundary-54:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\x00\xff\xfe\r";
const REC_L55: &[u8] = b"boundary-55:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\x00\xff\xfe\r";
const REC_L56: &[u8] = b"boundary-56:cccccccccccccccccccccccccccccccccccccccc\xff\xfe\r\x00";
const REC_L63: &[u8] = b"boundary-63:ddddddddddddddddddddddddddddddddddddddddddddddd\x00\xff\xfe\r";
const REC_L64: &[u8] = b"boundary-64:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee\x00\xff\xfe\r";
const REC_L65: &[u8] = b"boundary-65:fffffffffffffffffffffffffffffffffffffffffffffffff\xff\xfe\r\x00";
const REC_L146: &[u8] = b"long-record-146:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\x00\xff\xfe\rTAIL-MARKER-\x00\xff";

// REC_L146 with ONE byte near the end changed (second-to-last). The root
// must reflect the full record including its tail.
const REC_V_TAIL: &[u8] = b"long-record-146:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\x00\xff\xfe\rTAIL-MARKER-\x01\xff";

// Fixed batch mixing long and short records (8 records): long records in a
// batch must be hashed by the same standard as when each is the only record.
const MIXED: &[&[u8]] = &[
    b"alpha",
    REC_L54,
    b"",
    REC_L65,
    b"delta\r",
    REC_L146,
    b"\xff\xfe\x00binary",
    REC_L56,
];

// Independently fixed RFC 6962 roots (tests/reference/rfc6962_vectors.py).
const ROOT_L54: &str = "44d6803161e92744f1d9a06d28a6571f43dc5cbcd4af9a20d045da94c8ef7187";
const ROOT_L55: &str = "47559229e7d06fde6b97580ddbff3ec47ae12eeda56496302cfc7888256529b3";
const ROOT_L56: &str = "f76075fc1a175a6ce37896ee738288c2cbaa7ad19b2336f4756106896e605fb8";
const ROOT_L63: &str = "cb49a74a87ec01e003c18302a0905a84a65371dc72a7b5542a5414f060ef4d0b";
const ROOT_L64: &str = "2f796ed6645515b2d7e4fe5d0971a907ac54f84d299001193db76b5159213e61";
const ROOT_L65: &str = "8f7eaf79f09d79a4b29e96d949cd57bd604546ed5f82a11311b38862f79d167f";
const ROOT_L146: &str = "2dd1eed6819e5ecee40397ce512908fddc19be932faa080ce7c9ac166291d584";
const ROOT_V_TAIL: &str = "4f2cd36e8a157e169057fd342756966cf8742711aada133d2edae6ded37aec0f";
const ROOT_MIXED: &str = "a62b61a3241e27a168df2125d40814733c5f5cc2e0e9da5d778c64b0104c5ee6";

/// The long records with their independently fixed single-record roots.
const LONG_SINGLES: &[(&str, &[u8], &str)] = &[
    ("L54: 54-byte record, leaf input 55 bytes (padding boundary)", REC_L54, ROOT_L54),
    ("L55: 55-byte record, leaf input 56 bytes (padding boundary)", REC_L55, ROOT_L55),
    ("L56: 56-byte record, leaf input 57 bytes (padding boundary)", REC_L56, ROOT_L56),
    ("L63: 63-byte record, leaf input 64 bytes (block boundary)", REC_L63, ROOT_L63),
    ("L64: 64-byte record, leaf input 65 bytes (block boundary)", REC_L64, ROOT_L64),
    ("L65: 65-byte record, leaf input 66 bytes (block boundary)", REC_L65, ROOT_L65),
    ("L146: 146-byte record, leaf input spans three blocks", REC_L146, ROOT_L146),
];

#[test]
fn roots_for_7_8_and_9_records_match_fixed_vectors() {
    assert_root(
        "B7: seven records (largest subtree split k=4, uneven right side)",
        B7,
        &join_lf(B7, true),
        ROOT_B7,
    );
    assert_root(
        "B8: eight records exactly fills a depth-3 tree (power-of-two boundary)",
        B8,
        &join_lf(B8, true),
        ROOT_B8,
    );
    assert_root(
        "B9: nine records crosses the 8-record power-of-two boundary (k=8)",
        B9,
        &join_lf(B9, true),
        ROOT_B9,
    );
}

#[test]
fn changing_one_duplicate_position_gives_its_own_fixed_root() {
    assert_root(
        "V_DUP: r4 (byte-equal to r0) changed, exact new root",
        V_DUP,
        &join_lf(V_DUP, true),
        ROOT_V_DUP,
    );
    assert_ne!(ROOT_V_DUP, ROOT_B9, "changed record must change the root");
}

#[test]
fn swapping_two_different_records_gives_its_own_fixed_root() {
    assert_root(
        "V_SWAP: r1 and r5 swapped; same record contents, different positions",
        V_SWAP,
        &join_lf(V_SWAP, true),
        ROOT_V_SWAP,
    );
    assert_ne!(ROOT_V_SWAP, ROOT_B9, "record order participates in the hash");
    // Equal contents at different positions are not interchangeable: while the
    // swap moved r1/r5, untouched duplicate positions r0 and r4 still prove
    // per-position participation via V_DUP's fixed root above.
}

#[test]
fn omitting_the_empty_record_gives_its_own_fixed_root() {
    assert_eq!(V_DROP_EMPTY.len(), 8);
    assert_ne!(V_DROP_EMPTY, B8, "8 records here is not the B8 sequence");
    assert_root(
        "V_DROP_EMPTY: empty r2 removed; empty records occupy a real position",
        V_DROP_EMPTY,
        &join_lf(V_DROP_EMPTY, true),
        ROOT_V_DROP_EMPTY,
    );
    assert_ne!(ROOT_V_DROP_EMPTY, ROOT_B9);
    assert_ne!(ROOT_V_DROP_EMPTY, ROOT_B8, "must not collide with B8's 8-record root");
}

#[test]
fn including_a_duplicate_record_twice_gives_its_own_fixed_root() {
    assert_eq!(V_DUP_INSERT.len(), 10);
    assert_root(
        "V_DUP_INSERT: duplicate of r0 appended; duplicates are not merged",
        V_DUP_INSERT,
        &join_lf(V_DUP_INSERT, true),
        ROOT_V_DUP_INSERT,
    );
    assert_ne!(ROOT_V_DUP_INSERT, ROOT_B9);
}

#[test]
fn trailing_lf_only_terminates_the_last_record() {
    // The same fixed sequence with and without a final LF has the same fixed
    // root, on both sides of the power-of-two boundary.
    for (desc, records, expected) in [
        ("B7 trailing/no-trailing LF", B7, ROOT_B7),
        ("B8 trailing/no-trailing LF", B8, ROOT_B8),
        ("B9 trailing/no-trailing LF", B9, ROOT_B9),
    ] {
        assert_root(desc, records, &join_lf(records, true), expected);
        assert_root(desc, records, &join_lf(records, false), expected);
    }
}

#[test]
fn empty_file_is_zero_records_single_lf_is_one_empty_record() {
    assert_root("EMPTY: 0-byte file, zero records", &[], b"", ROOT_EMPTY_FILE);
    assert_root(
        "ONE_LF: one LF, a single empty record",
        &[b""],
        b"\n",
        ROOT_ONE_EMPTY_RECORD,
    );
    assert_ne!(ROOT_EMPTY_FILE, ROOT_ONE_EMPTY_RECORD);
}

#[test]
fn long_single_records_at_sha256_boundaries_match_fixed_roots() {
    // The records really have the boundary lengths their names claim, and
    // really carry NUL, non-UTF-8 and CR bytes as content (none holds LF).
    let lengths: Vec<usize> = LONG_SINGLES.iter().map(|(_, rec, _)| rec.len()).collect();
    assert_eq!(lengths, [54, 55, 56, 63, 64, 65, 146]);
    for (_, rec, _) in LONG_SINGLES {
        assert!(!rec.contains(&b'\n'), "record must not contain the LF separator");
        assert!(rec.contains(&0x00) && rec.contains(&0xff) && rec.contains(&b'\r'));
    }
    assert!(REC_L54.ends_with(b"\r") && REC_L56.ends_with(b"\x00"));
    // Each long record as a single-record batch has its own fixed root.
    for (desc, rec, expected) in LONG_SINGLES {
        assert_root(desc, &[rec], &join_lf(&[rec], true), expected);
    }
    // Distinct full contents give distinct fixed roots.
    let roots: std::collections::BTreeSet<&&str> =
        LONG_SINGLES.iter().map(|(_, _, root)| root).collect();
    assert_eq!(roots.len(), LONG_SINGLES.len());
}

#[test]
fn changing_one_byte_near_the_end_of_a_long_record_gives_its_own_fixed_root() {
    // REC_V_TAIL differs from REC_L146 only in the second-to-last byte; the
    // fixed root belongs to the modified FULL record, so an implementation
    // that drops, truncates or decodes the tail cannot produce it.
    assert_eq!(REC_V_TAIL.len(), REC_L146.len());
    assert_eq!(REC_V_TAIL[..REC_V_TAIL.len() - 2], REC_L146[..REC_L146.len() - 2]);
    assert_ne!(REC_V_TAIL[REC_V_TAIL.len() - 2], REC_L146[REC_L146.len() - 2]);
    assert_eq!(REC_V_TAIL[REC_V_TAIL.len() - 1], REC_L146[REC_L146.len() - 1]);
    assert_root(
        "V_TAIL: L146 with one byte near the end changed, exact new root",
        &[REC_V_TAIL],
        &join_lf(&[REC_V_TAIL], true),
        ROOT_V_TAIL,
    );
    assert_ne!(ROOT_V_TAIL, ROOT_L146, "a near-end byte must reach the root");
}

#[test]
fn mixed_long_and_short_records_match_fixed_root() {
    assert_eq!(MIXED.len(), 8);
    assert_root(
        "MIXED: long and short records in one batch, same standard as singles",
        MIXED,
        &join_lf(MIXED, true),
        ROOT_MIXED,
    );
    for (_, _, single_root) in LONG_SINGLES {
        assert_ne!(&ROOT_MIXED, single_root);
    }
}

#[test]
fn long_records_trailing_lf_only_terminates_the_last_record() {
    // With and without a final LF, the same long record (or mixed batch) is
    // the same record sequence and has the same fixed root.
    for (desc, rec, expected) in LONG_SINGLES {
        assert_root(desc, &[rec], &join_lf(&[rec], true), expected);
        assert_root(desc, &[rec], &join_lf(&[rec], false), expected);
    }
    assert_root("MIXED trailing LF", MIXED, &join_lf(MIXED, true), ROOT_MIXED);
    assert_root("MIXED no trailing LF", MIXED, &join_lf(MIXED, false), ROOT_MIXED);
}

#[test]
fn version_output_is_unchanged() {
    let out = Command::new(bin()).arg("--version").output().unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert!(out.stderr.is_empty());
    assert_eq!(out.stdout, b"roottrace 0.1.0\n");
}

#[test]
fn usage_errors_exit_2_and_write_usage_to_stderr() {
    let no_args = Command::new(bin()).output().unwrap();
    assert_eq!(no_args.status.code(), Some(2));
    assert!(no_args.stdout.is_empty());
    let err = String::from_utf8_lossy(&no_args.stderr);
    assert!(err.contains("Usage"), "expected usage on stderr, got: {err}");

    for args in [
        vec!["bogus"],
        vec!["root"],
        vec!["root", "a", "b"],
        vec!["--version", "extra"],
    ] {
        let out = Command::new(bin()).args(&args).output().unwrap();
        assert_eq!(out.status.code(), Some(2), "args {args:?} should exit 2");
        assert!(out.stdout.is_empty(), "args {args:?} must not write stdout");
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("Usage"),
            "args {args:?} should print usage to stderr"
        );
    }
}

#[test]
fn read_failures_exit_1_and_write_nothing_to_stdout() {
    let missing = TempFile::create(b"x");
    let missing_path = missing.path.clone();
    drop(missing); // delete it so the path does not exist
    let out = Command::new(bin())
        .arg("root")
        .arg(&missing_path)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1), "missing file should exit 1");
    assert!(out.stdout.is_empty());
    assert!(!out.stderr.is_empty());

    let dir = TempDir::create();
    let out = Command::new(bin()).arg("root").arg(&dir.path).output().unwrap();
    assert_eq!(out.status.code(), Some(1), "directory path should exit 1");
    assert!(out.stdout.is_empty());
    assert!(!out.stderr.is_empty());
}
