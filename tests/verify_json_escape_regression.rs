//! End-to-end regression tests for JSON string escapes in proof files fed to
//! `roottrace verify <record-file> <proof-file> <trusted-tree-size> <trusted-root>`.
//!
//! A proof that was re-saved by another JSON tool may spell any string
//! character as a `\uXXXX` escape (and may uppercase the hex letters inside
//! the escape). That is a change of representation, not of content: after
//! decoding, field names and hash characters must behave exactly as if they
//! had been written directly, and the decoded result must satisfy all the
//! rules that apply to directly written strings. This file pins that
//! distinction against the actual command:
//!
//!   * field names and root/audit_path hashes written with `\uXXXX` escapes
//!     (fully, or mixed with direct characters, uppercase hex letters in the
//!     escape) verify exactly like the canonical spelling: exit 0, stdout is
//!     precisely "verified\n", stderr is empty
//!   * duplicate fields are judged on the DECODED name: `root` next to
//!     `r\u006fot` is a duplicate even when both values are identical, and
//!     the proof is invalid (exit 1, empty stdout, "invalid proof" on
//!     stderr) rather than silently picking one value
//!   * invalid escapes, truncated `\u` escapes, lone or mis-paired
//!     surrogates, unescaped control bytes and invalid UTF-8 inside strings
//!     are format errors, not verification failures
//!   * escapes do not relax the hash rules: a decoded uppercase or non-hex
//!     character or a wrong decoded length is a format error, while a
//!     decoded valid hash that differs from the trusted root remains a
//!     verification failure
//!   * the record file is still used as raw bytes (never JSON-decoded) and
//!     canonical `prove` output keeps verifying directly

mod common;

use std::process::Command;

use common::TempFile;

// The same independently fixed vectors used by verify_regression.rs (from
// tests/reference/rfc6962_vectors.py).
const PAYLOAD_B9: &[u8] =
    b"alpha\nbeta\n\ngamma\nalpha\ndelta\r\n\xff\xfe\x00binary\nepsilon\nzeta\x01tail\n";
const ROOT_B8: &str = "80f3f98ae8d7d9d1d2139a6a2dc94628e02fba22e125f922ea8a4c10799cb912";
const ROOT_B9: &str = "a8a3e76ecf28b850e84cb5465729921212ffd07de3c0e6e170cd233bf723adc3";
const PATH_B9_M4: &[&str] = &[
    "4957faa551907820ed93a476704ffd826ea5502881876c87f3acefc0a8d29bce",
    "b739bc437ae5d551d144d1478ee16d1119ba15b2198a3a8b7c47976c36cb6639",
    "6f2bd73a7406c5089558c115aaae63a717e4c6947c44898e7d9600023ff15d10",
    "5cc496b84d9250622d5de1219d1f156e7973503fbd80f7f3364800bbfa2947d2",
];

fn proof_json(size: u64, index: u64, root: &str, path: &[&str]) -> String {
    let mut out =
        format!("{{\"tree_size\":{size},\"leaf_index\":{index},\"root\":\"{root}\",\"audit_path\":[");
    for (i, h) in path.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push('"');
        out.push_str(h);
        out.push('"');
    }
    out.push_str("]}");
    out
}

/// Spell every character for which `escape` holds as a `\uXXXX` escape with
/// UPPERCASE hex letters, mimicking a JSON tool that re-saves the proof.
fn escape_selected(s: &str, escape: impl Fn(char) -> bool) -> String {
    let mut out = String::new();
    for c in s.chars() {
        if escape(c) {
            out.push_str(&format!("\\u{:04X}", c as u32));
        } else {
            out.push(c);
        }
    }
    out
}

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

// --- Escaped spellings verify exactly like the canonical one -----------------

#[test]
fn escaped_field_names_and_hashes_verify_identically() {
    // The canonical proof for B9 position 4 ("alpha") is the baseline.
    let canonical = proof_json(9, 4, ROOT_B9, PATH_B9_M4);
    assert_verified("canonical baseline", b"alpha", canonical.as_bytes(), "9", ROOT_B9);

    // Every field name and every hash character written as a \uXXXX escape,
    // with uppercase hex letters inside the escapes (e.g. \u006F, \u005F).
    let fully_escaped = format!(
        "{{\"{}\":9,\"{}\":4,\"{}\":\"{}\",\"{}\":[\"{}\",\"{}\",\"{}\",\"{}\"]}}",
        escape_selected("tree_size", |_| true),
        escape_selected("leaf_index", |_| true),
        escape_selected("root", |_| true),
        escape_selected(ROOT_B9, |_| true),
        escape_selected("audit_path", |_| true),
        escape_selected(PATH_B9_M4[0], |_| true),
        escape_selected(PATH_B9_M4[1], |_| true),
        escape_selected(PATH_B9_M4[2], |_| true),
        escape_selected(PATH_B9_M4[3], |_| true),
    );
    assert_verified("fully escaped", b"alpha", fully_escaped.as_bytes(), "9", ROOT_B9);

    // Direct and escaped characters mixed within each string; the escapes
    // keep their uppercase hex letters.
    let mixed = format!(
        "{{\"tr\\u0065e_siz\\u0065\":9,\"\\u006Ceaf_ind\\u0065x\":4,\"r\\u006Fot\":\"{}\",\"audit_p\\u0061th\":[\"{}\",\"{}\",\"{}\",\"{}\"]}}",
        escape_selected(ROOT_B9, |c| matches!(c, 'a' | 'e')),
        escape_selected(PATH_B9_M4[0], |c| c.is_ascii_digit()),
        escape_selected(PATH_B9_M4[1], |c| matches!(c, 'b' | 'c' | 'd' | 'f')),
        escape_selected(PATH_B9_M4[2], |c| c == '0'),
        escape_selected(PATH_B9_M4[3], |c| matches!(c, '5' | 'a')),
    );
    assert_verified("mixed direct and escaped", b"alpha", mixed.as_bytes(), "9", ROOT_B9);

    // A single escape in an otherwise direct proof.
    let one_escape = canonical.replacen("\"root\"", "\"r\\u006fot\"", 1);
    assert_verified("single escaped letter", b"alpha", one_escape.as_bytes(), "9", ROOT_B9);
}

// --- Duplicates are judged on the decoded field name --------------------------

#[test]
fn duplicate_fields_after_escape_decoding_are_invalid() {
    let h = ROOT_B9;
    let p = PATH_B9_M4;
    let path_json = |path: &[&str]| {
        path.iter().map(|x| format!("\"{x}\"")).collect::<Vec<_>>().join(",")
    };
    let cases: Vec<String> = vec![
        // Same decoded name twice, identical values: still a duplicate.
        format!("{{\"tree_size\":9,\"tr\\u0065e_size\":9,\"leaf_index\":4,\"root\":\"{h}\",\"audit_path\":[{}]}}", path_json(p)),
        format!("{{\"tree_size\":9,\"leaf_index\":4,\"l\\u0065af_index\":4,\"root\":\"{h}\",\"audit_path\":[{}]}}", path_json(p)),
        format!("{{\"tree_size\":9,\"leaf_index\":4,\"root\":\"{h}\",\"r\\u006Fot\":\"{h}\",\"audit_path\":[{}]}}", path_json(p)),
        format!("{{\"tree_size\":9,\"leaf_index\":4,\"root\":\"{h}\",\"audit_path\":[{}],\"\\u0061udit_path\":[{}]}}", path_json(p), path_json(p)),
        // Same decoded name, different value: the file must be rejected as a
        // whole, never silently resolved to one of the two values.
        format!("{{\"tree_size\":9,\"leaf_index\":4,\"root\":\"{h}\",\"\\u0072oot\":\"{}\",\"audit_path\":[{}]}}", ROOT_B8, path_json(p)),
        format!("{{\"tree_size\":9,\"t\\u0072ee_size\":8,\"leaf_index\":4,\"root\":\"{h}\",\"audit_path\":[{}]}}", path_json(p)),
    ];
    for case in &cases {
        assert_invalid_proof(&format!("duplicate via escape {case}"), case.as_bytes());
    }
}

// --- Bad escapes and bad string bytes are format errors -----------------------

#[test]
fn bad_escapes_and_bad_string_bytes_are_invalid_proofs() {
    let h = ROOT_B9;
    let p0 = PATH_B9_M4[0];
    let with_root = |root_json: &str| {
        format!("{{\"tree_size\":9,\"leaf_index\":4,\"root\":{root_json},\"audit_path\":[]}}")
    };

    // Invalid or truncated escapes and surrogate problems inside the root
    // string (a format error, never a verification failure).
    for bad in [
        "\\x",            // unknown escape
        "\\u12",          // truncated unicode escape
        "\\u12g4",        // non-hex digit in the escape
        "\\uD800",        // lone high surrogate
        "\\uD800\\n",     // high surrogate not followed by \u
        "\\uD800\\u0041", // high surrogate followed by a non-low escape
        "\\uD800\\uD800", // high surrogate followed by another high one
        "\\uDC00",        // lone low surrogate
    ] {
        let case = with_root(&format!("\"{bad}\""));
        assert_invalid_proof(&format!("escape {bad:?} in root"), case.as_bytes());
    }

    // The same problems in a field NAME and in an audit_path element.
    assert_invalid_proof(
        "invalid escape in field name",
        format!("{{\"tre\\x65_size\":9,\"leaf_index\":4,\"root\":\"{h}\",\"audit_path\":[]}}").as_bytes(),
    );
    assert_invalid_proof(
        "lone surrogate in field name",
        format!("{{\"\\uD800\":9,\"leaf_index\":4,\"root\":\"{h}\",\"audit_path\":[]}}").as_bytes(),
    );
    assert_invalid_proof(
        "truncated escape in audit_path element",
        format!("{{\"tree_size\":9,\"leaf_index\":4,\"root\":\"{h}\",\"audit_path\":[\"\\uAB\"]}}").as_bytes(),
    );
    // A \u escape cut off by the end of the file.
    assert_invalid_proof(
        "escape truncated by end of file",
        format!("{{\"tree_size\":9,\"leaf_index\":4,\"root\":\"{h}\",\"audit_path\":[\"\\u12").as_bytes(),
    );

    // Unescaped control bytes and invalid UTF-8 bytes inside a string.
    for raw in [b"\x00".as_slice(), b"\x01", b"\x1f", b"\n", b"\t", b"\xff", b"\xc3"] {
        let mut case = with_root("\"").into_bytes();
        case.extend_from_slice(raw);
        case.extend_from_slice(b"\",\"audit_path\":[]}");
        assert_invalid_proof(&format!("raw byte {raw:?} in root string"), &case);

        let mut case = format!("{{\"tree_size\":9,\"leaf_index\":4,\"root\":\"{h}\",\"audit_path\":[\"").into_bytes();
        case.extend_from_slice(raw);
        case.extend_from_slice(b"\"]}");
        assert_invalid_proof(&format!("raw byte {raw:?} in audit_path element"), &case);
    }

    // Sanity next to all of the above: the canonical proof and a properly
    // escaped one are fine.
    assert_verified(
        "sanity: canonical",
        b"alpha",
        proof_json(9, 4, ROOT_B9, PATH_B9_M4).as_bytes(),
        "9",
        ROOT_B9,
    );
    let escaped_p0 = escape_selected(p0, |_| true);
    assert_verified(
        "sanity: escaped path element",
        b"alpha",
        format!("{{\"tree_size\":9,\"leaf_index\":4,\"root\":\"{h}\",\"audit_path\":[\"{escaped_p0}\",\"{}\",\"{}\",\"{}\"]}}",
            PATH_B9_M4[1], PATH_B9_M4[2], PATH_B9_M4[3]).as_bytes(),
        "9",
        ROOT_B9,
    );
}

// --- Escapes do not relax the hash content rules ------------------------------

#[test]
fn escapes_do_not_relax_hash_rules() {
    let h = ROOT_B9;
    let p = PATH_B9_M4;
    let path_json = || p.iter().map(|x| format!("\"{x}\"")).collect::<Vec<_>>().join(",");
    let wrap = |root_json: &str, path_json: &str| {
        format!("{{\"tree_size\":9,\"leaf_index\":4,\"root\":{root_json},\"audit_path\":[{path_json}]}}")
    };

    // \u0041 decodes to 'A': an uppercase hash character is rejected even
    // when it arrives as an escape.
    let upper = wrap(&format!("\"\\u0041{}\"", &h[1..]), &path_json());
    assert_invalid_proof("escaped uppercase hash character", upper.as_bytes());
    // \u0067 decodes to 'g': not a hex character.
    let non_hex = wrap(&format!("\"\\u0067{}\"", &h[1..]), &path_json());
    assert_invalid_proof("escaped non-hex hash character", non_hex.as_bytes());
    // Length is judged after decoding: 63 and 65 decoded characters.
    let short = wrap(&format!("\"\\u0061{}\"", &h[1..63]), &path_json());
    assert_invalid_proof("63 decoded hash characters", short.as_bytes());
    let long = wrap(&format!("\"{h}\\u0030\""), &path_json());
    assert_invalid_proof("65 decoded hash characters", long.as_bytes());
    // The same rules bind audit_path elements.
    let path_upper = wrap(&format!("\"{h}\""), &format!("\"\\u0041{}\"", &p[0][1..]));
    assert_invalid_proof("escaped uppercase in audit_path element", path_upper.as_bytes());

    // A decoded VALID hash that does not match the trusted root keeps the
    // ordinary verification-failure result (exit 1, "verification failed"),
    // it is not a format error.
    let other_root = wrap(
        &format!("\"{}\"", escape_selected(ROOT_B8, |c| c == 'b' || c == '8')),
        &path_json(),
    );
    assert_verification_failed(
        "escaped valid hash different from trusted root",
        b"alpha",
        other_root.as_bytes(),
        "9",
        ROOT_B9,
    );
    // Same for a proof tree_size that disagrees with the trusted size.
    let other_size = format!(
        "{{\"{}\":8,\"leaf_index\":4,\"root\":\"{h}\",\"audit_path\":[{}]}}",
        escape_selected("tree_size", |_| true),
        path_json(),
    );
    assert_verification_failed(
        "escaped tree_size different from trusted size",
        b"alpha",
        other_size.as_bytes(),
        "9",
        ROOT_B9,
    );
}

// --- The record file is raw bytes; prove output stays directly compatible -----

#[test]
fn record_file_is_never_json_decoded_and_prove_output_still_verifies() {
    // Real prove output for B9 position 0 verifies as-is.
    let batch = TempFile::create(PAYLOAD_B9);
    let proved = Command::new(common::bin())
        .arg("prove")
        .arg(&batch.path)
        .arg("0")
        .output()
        .unwrap();
    assert_eq!(proved.status.code(), Some(0));
    assert_verified("canonical prove output", b"alpha", &proved.stdout, "9", ROOT_B9);

    // The escape-looking byte sequence \u0061 in the RECORD file is just six
    // raw bytes, not the letter 'a': it is a different record and must fail.
    assert_verification_failed(
        "record bytes are not unescaped",
        b"\\u0061lpha",
        &proved.stdout,
        "9",
        ROOT_B9,
    );
}
