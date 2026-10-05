//! End-to-end regression tests for JSON string escapes in proof files
//! accepted by `roottrace verify <record-file> <proof-file> ...`.
//!
//! A proof that was re-saved by another JSON tool may spell characters as
//! `\uXXXX` escapes instead of writing them directly. That is a different
//! *representation* of the same proof, not corrupted proof content, so it
//! must verify exactly like the plainly written form. Corrupt escapes, on
//! the other hand, are malformed proofs and must not be confused with a
//! mere verification failure.
//!
//! Coverage (all against the real binary, with the trusted tree size and
//! root supplied independently on the command line):
//!   * required field names and the hash characters in `root`/`audit_path`
//!     written directly, as `\uXXXX` escapes (uppercase hex letters in the
//!     escape allowed), or mixed inside one string, verify identically:
//!     exit 0, stdout exactly "verified\n", stderr empty
//!   * duplicate fields are judged by their DECODED names: a plain `root`
//!     next to an escape-spelled `root` is a duplicate even when both
//!     values are identical; same for tree_size, leaf_index, audit_path
//!   * invalid escapes, truncated `\uXXXX`, lone or mis-paired surrogates,
//!     unescaped control bytes and invalid UTF-8 bytes inside strings are
//!     all "invalid proof" (exit 1, empty stdout, format error on stderr)
//!   * legal escapes do not relax the hash content rules: a hash decoding
//!     to uppercase/non-hex/wrong length is a format error, while one
//!     decoding to a valid hash that mismatches the trusted root keeps the
//!     ordinary verification-failure result
//!   * the record file is still taken as raw bytes, and unmodified `prove`
//!     output remains directly acceptable

mod common;

use std::process::Command;

use common::TempFile;

// --- Fixed payloads, roots and paths (copied from the reference generator,
// --- the same constants verify_regression.rs uses) -------------------------

const PAYLOAD_B9: &[u8] =
    b"alpha\nbeta\n\ngamma\nalpha\ndelta\r\n\xff\xfe\x00binary\nepsilon\nzeta\x01tail\n";

const ROOT_B8: &str = "80f3f98ae8d7d9d1d2139a6a2dc94628e02fba22e125f922ea8a4c10799cb912";
const ROOT_B9: &str = "a8a3e76ecf28b850e84cb5465729921212ffd07de3c0e6e170cd233bf723adc3";
const ROOT_MIXED: &str = "3a460e4bda163253da14917c2f9c63208d1b24e3d285c763d2f6c6dedec6694b";

const PATH_B9_M4: &[&str] = &[
    "4957faa551907820ed93a476704ffd826ea5502881876c87f3acefc0a8d29bce",
    "b739bc437ae5d551d144d1478ee16d1119ba15b2198a3a8b7c47976c36cb6639",
    "6f2bd73a7406c5089558c115aaae63a717e4c6947c44898e7d9600023ff15d10",
    "5cc496b84d9250622d5de1219d1f156e7973503fbd80f7f3364800bbfa2947d2",
];
const PATH_MIXED_M8: &[&str] = &[
    "8a3600db5c87060b03bdb7b4c7b70056808cb54e5ab927b95731d6936bff303d",
    "4290a44282949b6321f1219162bb52eceb3358250c553ee76e820bea56378f49",
];

// The exact 65-byte L65 record that sits at MIXED position 8: NUL, CR and
// non-UTF-8 bytes inside, ending on a non-text byte.
const REC_L65: &[u8] =
    b"L65:\x00\xff\xfe\rabcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrst\xfe";

// --- Helpers -----------------------------------------------------------------

fn run(
    record: &std::path::Path,
    proof: &std::path::Path,
    size: &str,
    root: &str,
) -> std::process::Output {
    Command::new(common::bin())
        .arg("verify")
        .arg(record)
        .arg(proof)
        .arg(size)
        .arg(root)
        .output()
        .expect("failed to execute roottrace binary")
}

fn assert_verified(desc: &str, record: &[u8], proof: &[u8], size: &str, root: &str) {
    let rec = TempFile::create(record);
    let prf = TempFile::create(proof);
    let out = run(&rec.path, &prf.path, size, root);
    if out.status.code() != Some(0) || out.stdout != b"verified\n" || !out.stderr.is_empty() {
        panic!(
            "[{desc}] expected verified/exit0/empty-stderr\n\
             status: {:?}\nstdout: {:?}\nstderr: {}",
            out.status.code(),
            out.stdout,
            String::from_utf8_lossy(&out.stderr),
        );
    }
}

fn assert_verification_failed(desc: &str, record: &[u8], proof: &[u8], size: &str, root: &str) {
    let rec = TempFile::create(record);
    let prf = TempFile::create(proof);
    let out = run(&rec.path, &prf.path, size, root);
    assert_eq!(out.status.code(), Some(1), "[{desc}] must exit 1");
    assert!(out.stdout.is_empty(), "[{desc}] stdout must be empty, got {:?}", out.stdout);
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("verification failed"), "[{desc}] stderr: {err}");
}

fn assert_invalid_proof(desc: &str, proof: &[u8]) {
    let rec = TempFile::create(b"alpha");
    let prf = TempFile::create(proof);
    let out = run(&rec.path, &prf.path, "9", ROOT_B9);
    assert_eq!(out.status.code(), Some(1), "[{desc}] malformed proof must exit 1");
    assert!(out.stdout.is_empty(), "[{desc}] malformed proof must not touch stdout");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("invalid proof"), "[{desc}] stderr: {err}");
}

/// Rewrite every occurrence of `c` in `s` as a `\uXXXX` escape with UPPERCASE
/// hex digits (also legal JSON), leaving all other characters as plain text —
/// the result mixes direct and escaped characters inside a single string.
fn escape_every(s: &str, c: char) -> String {
    let mut out = String::new();
    for ch in s.chars() {
        if ch == c {
            out.push_str(&format!("\\u{:04X}", ch as u32));
        } else {
            out.push(ch);
        }
    }
    out
}

/// Rewrite EVERY character of `s` as a `\uXXXX` escape (lowercase hex).
fn escape_every_char(s: &str) -> String {
    let mut out = String::new();
    for ch in s.chars() {
        out.push_str(&format!("\\u{:04x}", ch as u32));
    }
    out
}

/// The canonical B9 m=4 proof with the given extra member appended before the
/// closing brace (used to inject escape-spelled duplicate fields).
fn proof_with_extra_member(extra: &str) -> String {
    format!(
        "{{\"tree_size\":9,\"leaf_index\":4,\"root\":\"{h}\",\"audit_path\":[\"{p0}\",\"{p1}\",\"{p2}\",\"{p3}\"],{extra}}}",
        h = ROOT_B9,
        p0 = PATH_B9_M4[0],
        p1 = PATH_B9_M4[1],
        p2 = PATH_B9_M4[2],
        p3 = PATH_B9_M4[3],
        extra = extra,
    )
}

/// The canonical B9 m=4 proof except that the CONTENT of the root string is
/// supplied as raw bytes, so tests can place arbitrary escape sequences,
/// control bytes or invalid UTF-8 inside the string.
fn proof_with_root_content(root_content: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(b"{\"tree_size\":9,\"leaf_index\":4,\"root\":\"");
    v.extend_from_slice(root_content);
    v.extend_from_slice(b"\",\"audit_path\":[\"");
    v.extend_from_slice(PATH_B9_M4[0].as_bytes());
    v.extend_from_slice(b"\",\"");
    v.extend_from_slice(PATH_B9_M4[1].as_bytes());
    v.extend_from_slice(b"\",\"");
    v.extend_from_slice(PATH_B9_M4[2].as_bytes());
    v.extend_from_slice(b"\",\"");
    v.extend_from_slice(PATH_B9_M4[3].as_bytes());
    v.extend_from_slice(b"\"]}");
    v
}

// --- Escaped representations verify like the plain form ----------------------

#[test]
fn escaped_field_names_verify_like_plain_names() {
    // Every required field name with some letters as \uXXXX escapes; the
    // escapes themselves use both lowercase and UPPERCASE hex letters
    // (\u006F and \u007A), which are equally legal JSON.
    let proof = format!(
        "{{\"tr\\u0065e_si\\u007Ae\":9,\"l\\u0065af_ind\\u0065x\":4,\"r\\u006Fot\":\"{h}\",\"\\u0061udit_p\\u0061th\":[\"{p0}\",\"{p1}\",\"{p2}\",\"{p3}\"]}}",
        h = ROOT_B9,
        p0 = PATH_B9_M4[0],
        p1 = PATH_B9_M4[1],
        p2 = PATH_B9_M4[2],
        p3 = PATH_B9_M4[3],
    );
    assert_verified("all field names partly escaped", b"alpha", proof.as_bytes(), "9", ROOT_B9);

    // Field names written ENTIRELY as escapes.
    let proof = format!(
        "{{\"{ts}\":9,\"{li}\":4,\"{rt}\":\"{h}\",\"{ap}\":[\"{p0}\",\"{p1}\",\"{p2}\",\"{p3}\"]}}",
        ts = escape_every_char("tree_size"),
        li = escape_every_char("leaf_index"),
        rt = escape_every_char("root"),
        ap = escape_every_char("audit_path"),
        h = ROOT_B9,
        p0 = PATH_B9_M4[0],
        p1 = PATH_B9_M4[1],
        p2 = PATH_B9_M4[2],
        p3 = PATH_B9_M4[3],
    );
    assert_verified("field names fully escaped", b"alpha", proof.as_bytes(), "9", ROOT_B9);
}

#[test]
fn escaped_hash_characters_verify_like_plain_hashes() {
    // Direct and escaped characters mixed inside each hash string.
    let root = escape_every(&escape_every(ROOT_B9, 'e'), '8');
    let p0 = escape_every(PATH_B9_M4[0], 'a');
    let p1 = escape_every(PATH_B9_M4[1], 'b');
    let p2 = escape_every(PATH_B9_M4[2], 'f');
    let p3 = escape_every(PATH_B9_M4[3], '0');
    let proof = format!(
        "{{\"tree_size\":9,\"leaf_index\":4,\"root\":\"{root}\",\"audit_path\":[\"{p0}\",\"{p1}\",\"{p2}\",\"{p3}\"]}}",
    );
    assert_verified("hashes with mixed direct/escaped chars", b"alpha", proof.as_bytes(), "9", ROOT_B9);

    // Every hash character escaped.
    let proof = format!(
        "{{\"tree_size\":9,\"leaf_index\":4,\"root\":\"{root}\",\"audit_path\":[\"{p0}\",\"{p1}\",\"{p2}\",\"{p3}\"]}}",
        root = escape_every_char(ROOT_B9),
        p0 = escape_every_char(PATH_B9_M4[0]),
        p1 = escape_every_char(PATH_B9_M4[1]),
        p2 = escape_every_char(PATH_B9_M4[2]),
        p3 = escape_every_char(PATH_B9_M4[3]),
    );
    assert_verified("hashes fully escaped", b"alpha", proof.as_bytes(), "9", ROOT_B9);

    // Field names AND hashes escaped in the same document, with JSON
    // whitespace and reordered fields on top (as a re-saving tool emits).
    let proof = format!(
        "{{\n  \"{ap}\": [ \"{p0}\", \"{p1}\", \"{p2}\", \"{p3}\" ],\n  \"{rt}\": \"{root}\",\n  \
         \"{li}\": 4,\n  \"{ts}\": 9\n}}\n",
        ap = escape_every("audit_path", 'a'),
        rt = escape_every("root", 'o'),
        li = escape_every("leaf_index", 'e'),
        ts = escape_every("tree_size", 'e'),
        root = escape_every(ROOT_B9, 'a'),
        p0 = escape_every(PATH_B9_M4[0], '4'),
        p1 = escape_every(PATH_B9_M4[1], '7'),
        p2 = escape_every(PATH_B9_M4[2], 'c'),
        p3 = escape_every(PATH_B9_M4[3], 'd'),
    );
    assert_verified("names+hashes escaped, reordered, pretty", b"alpha", proof.as_bytes(), "9", ROOT_B9);
}

// --- Duplicates are judged by the decoded field name -------------------------

#[test]
fn escape_spelled_duplicate_fields_are_invalid() {
    // Plain name plus an escape-spelled spelling of the SAME name, with
    // identical values: still a duplicate, for each of the four fields.
    let cases = [
        ("tree_size", proof_with_extra_member("\"tr\\u0065e_size\":9")),
        ("leaf_index", proof_with_extra_member("\"l\\u0065af_index\":4")),
        (
            "root",
            proof_with_extra_member(&format!("\"r\\u006Fot\":\"{h}\"", h = ROOT_B9)),
        ),
        (
            "audit_path",
            proof_with_extra_member(&format!(
                "\"audit\\u005Fpath\":[\"{p0}\",\"{p1}\",\"{p2}\",\"{p3}\"]",
                p0 = PATH_B9_M4[0],
                p1 = PATH_B9_M4[1],
                p2 = PATH_B9_M4[2],
                p3 = PATH_B9_M4[3],
            )),
        ),
    ];
    for (field, proof) in &cases {
        assert_invalid_proof(&format!("escape-spelled duplicate {field}"), proof.as_bytes());
    }

    // Both occurrences escaped differently, values identical.
    let proof = format!(
        "{{\"tree_size\":9,\"leaf_index\":4,\"r\\u006Fot\":\"{h}\",\"ro\\u006Ft\":\"{h}\",\"audit_path\":[]}}",
        h = ROOT_B9,
    );
    assert_invalid_proof("two escape spellings of root", proof.as_bytes());

    // Sanity: a single escape-spelled name with no plain twin is NOT a
    // duplicate and verifies.
    let proof = format!(
        "{{\"tree_size\":9,\"leaf_index\":4,\"r\\u006Fot\":\"{h}\",\"audit_path\":[\"{p0}\",\"{p1}\",\"{p2}\",\"{p3}\"]}}",
        h = ROOT_B9,
        p0 = PATH_B9_M4[0],
        p1 = PATH_B9_M4[1],
        p2 = PATH_B9_M4[2],
        p3 = PATH_B9_M4[3],
    );
    assert_verified("single escape-spelled root is fine", b"alpha", proof.as_bytes(), "9", ROOT_B9);
}

// --- Corrupt escapes and raw string bytes are format errors ------------------

#[test]
fn invalid_escapes_in_strings_are_format_errors() {
    let h = ROOT_B9;
    let cases: Vec<(&str, Vec<u8>)> = vec![
        // An escape character JSON does not define, inside the root hash.
        ("unknown escape \\x in hash", proof_with_root_content(b"a8a3\\x76ecf28b850e84cb5465729921212ffd07de3c0e6e170cd233bf723adc3")),
        // Truncated \uXXXX: too few hex digits before the closing quote.
        ("truncated unicode escape", proof_with_root_content(b"a8a3e76ecf28b850e84cb5465729921212ffd07de3c0e6e170cd233bf723ad\\u12")),
        // Lone / mis-paired surrogates.
        ("lone high surrogate", proof_with_root_content(b"\\uD800aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")),
        ("lone low surrogate", proof_with_root_content(b"\\uDC00aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")),
        ("high surrogate then non-low escape", proof_with_root_content(b"\\uD800\\u0041aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")),
        ("high surrogate then plain char", proof_with_root_content(b"\\uD800zzaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")),
        // Unescaped control byte and invalid UTF-8 byte inside the string.
        ("raw control byte in hash", proof_with_root_content(b"a8a3\x01e76ecf28b850e84cb5465729921212ffd07de3c0e6e170cd233bf723adc3")),
        ("raw 0xff byte in hash", proof_with_root_content(b"a8a3\xffe76ecf28b850e84cb5465729921212ffd07de3c0e6e170cd233bf723adc3")),
    ];
    for (desc, proof) in &cases {
        assert_invalid_proof(desc, proof);
    }

    // \u cut off by the end of the file itself.
    let truncated = b"{\"tree_size\":9,\"leaf_index\":4,\"root\":\"a8a3\\u".to_vec();
    assert_invalid_proof("unicode escape cut off at EOF", &truncated);

    // The same corruptions inside a FIELD NAME string.
    let bad_key_escape = format!("{{\"tr\\u0065e_siz\\x65\":9,\"leaf_index\":4,\"root\":\"{h}\",\"audit_path\":[]}}");
    assert_invalid_proof("unknown escape in field name", bad_key_escape.as_bytes());
    let bad_key_surrogate = format!("{{\"ro\\uD800ot\":9,\"leaf_index\":4,\"root\":\"{h}\",\"audit_path\":[]}}");
    assert_invalid_proof("lone surrogate in field name", bad_key_surrogate.as_bytes());
    let mut raw_ctrl_key = b"{\"ro".to_vec();
    raw_ctrl_key.push(0x01);
    raw_ctrl_key.extend_from_slice(format!("ot\":9,\"leaf_index\":4,\"root\":\"{h}\",\"audit_path\":[]}}").as_bytes());
    assert_invalid_proof("raw control byte in field name", &raw_ctrl_key);
}

#[test]
fn legal_escapes_do_not_relax_hash_content_rules() {
    // \u0041 decodes to 'A': an UPPERCASE hash character after decoding is
    // still a format error, not a verification failure.
    let upper = proof_with_root_content(b"\\u00418a3e76ecf28b850e84cb5465729921212ffd07de3c0e6e170cd233bf723adc3");
    assert_invalid_proof("escape decoding to uppercase hash char", &upper);

    // \u0067 decodes to 'g': not a hex character.
    let non_hex = proof_with_root_content(b"\\u00678a3e76ecf28b850e84cb5465729921212ffd07de3c0e6e170cd233bf723adc3");
    assert_invalid_proof("escape decoding to non-hex char", &non_hex);

    // A valid surrogate PAIR decodes fine but is not a hex character either.
    let emoji = proof_with_root_content(b"\\uD83D\\uDE008a3e76ecf28b850e84cb5465729921212ffd07de3c0e6e170cd233bf723adc3");
    assert_invalid_proof("surrogate pair decoding to non-hex char", &emoji);

    // 63 characters after decoding (one dropped), escapes and all.
    let short = proof_with_root_content(escape_every(&ROOT_B9[..63], 'e').as_bytes());
    assert_invalid_proof("decoded hash too short", &short);
    let long = proof_with_root_content(format!("{}0", escape_every(ROOT_B9, 'e')).as_bytes());
    assert_invalid_proof("decoded hash too long", &long);

    // The same rules inside audit_path elements.
    let upper_path = format!(
        "{{\"tree_size\":9,\"leaf_index\":4,\"root\":\"{h}\",\"audit_path\":[\"\\u0041957faa551907820ed93a476704ffd826ea5502881876c87f3acefc0a8d29bce\"]}}",
        h = ROOT_B9,
    );
    assert_invalid_proof("escape decoding to uppercase in audit_path", upper_path.as_bytes());
}

#[test]
fn escaped_valid_hashes_keep_verification_failure_results() {
    // The escaped root decodes to a VALID 64-char lowercase hex string that
    // simply is not the trusted root: this stays an ordinary verification
    // failure (exit 1, "verification failed"), not a format error.
    let proof = format!(
        "{{\"tree_size\":9,\"leaf_index\":4,\"root\":\"{root}\",\"audit_path\":[\"{p0}\",\"{p1}\",\"{p2}\",\"{p3}\"]}}",
        root = escape_every(ROOT_B8, 'e'),
        p0 = PATH_B9_M4[0],
        p1 = PATH_B9_M4[1],
        p2 = PATH_B9_M4[2],
        p3 = PATH_B9_M4[3],
    );
    assert_verification_failed("escaped valid-but-untrusted root", b"alpha", proof.as_bytes(), "9", ROOT_B9);

    // An escaped audit_path element decoding to valid hex with one nibble
    // changed: the recomputed root cannot match.
    let mut bad_p0 = PATH_B9_M4[0].to_string();
    bad_p0.replace_range(0..1, if &PATH_B9_M4[0][..1] == "0" { "1" } else { "0" });
    let proof = format!(
        "{{\"tree_size\":9,\"leaf_index\":4,\"root\":\"{h}\",\"audit_path\":[\"{p0}\",\"{p1}\",\"{p2}\",\"{p3}\"]}}",
        h = ROOT_B9,
        p0 = escape_every(&bad_p0, 'a'),
        p1 = PATH_B9_M4[1],
        p2 = PATH_B9_M4[2],
        p3 = PATH_B9_M4[3],
    );
    assert_verification_failed("escaped valid-but-wrong path hash", b"alpha", proof.as_bytes(), "9", ROOT_B9);
}

// --- Record bytes and prove interop are unaffected ---------------------------

#[test]
fn record_file_stays_raw_and_plain_prove_output_still_verifies() {
    // A binary record (NUL/CR/non-UTF-8 bytes, ending on a non-text byte)
    // verifies against an escape-spelled proof: the escapes live only in the
    // proof file, the record file is hashed byte for byte as always.
    let proof = format!(
        "{{\"tr\\u0065e_size\":10,\"leaf_ind\\u0065x\":8,\"root\":\"{root}\",\"audit_path\":[\"{p0}\",\"{p1}\"]}}",
        root = escape_every(ROOT_MIXED, 'e'),
        p0 = escape_every(PATH_MIXED_M8[0], 'b'),
        p1 = escape_every(PATH_MIXED_M8[1], '8'),
    );
    assert_verified("binary record, escaped proof", REC_L65, proof.as_bytes(), "10", ROOT_MIXED);

    // Unmodified `prove` output (no escapes anywhere) remains directly
    // acceptable.
    let batch = TempFile::create(PAYLOAD_B9);
    let proved = Command::new(common::bin())
        .arg("prove")
        .arg(&batch.path)
        .arg("4")
        .output()
        .unwrap();
    assert_eq!(proved.status.code(), Some(0));
    assert_verified("plain prove output unchanged", b"alpha", &proved.stdout, "9", ROOT_B9);
}
