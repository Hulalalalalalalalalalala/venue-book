#!/usr/bin/env python3
"""Independent reference vectors for roottrace root-value regression tests.

This script is NOT the program under test and does not execute roottrace.  It
computes RFC 6962 section 2.1 SHA-256 Merkle Tree Hash roots with two
independently written algorithms over the standard library `hashlib.sha256`:

  * mth_recursive  - direct transcription of the RFC 6962 definition
                     (empty -> SHA-256(""); one leaf -> SHA-256(0x00||d);
                     n > 1 -> SHA-256(0x01 || MTH(0:k) || MTH(k:n)) with k the
                     largest power of two strictly smaller than n)
  * mth_fold       - order-sensitive left-to-right stack fold using the same
                     leaf/node prefixes (a structurally different computation
                     that must agree)

Records are split exactly as roottrace documents: raw bytes on LF, the
separator excluded, a trailing LF only terminates the last record, and an
empty file holds zero records.

Run:  python3 tests/reference/rfc6962_vectors.py
The printed constants are copied verbatim into tests/mth_vectors.rs.  Nothing
here reads roottrace output, so the expected roots are fixed independently of
the implementation being checked.
"""

import hashlib


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def mth_recursive(records):
    n = len(records)
    if n == 0:
        return sha256(b"")
    if n == 1:
        return sha256(b"\x00" + records[0])
    # Largest power of two strictly smaller than n.
    k = 1 << ((n - 1).bit_length() - 1)
    return sha256(b"\x01" + mth_recursive(records[:k]) + mth_recursive(records[k:]))


def mth_fold(records):
    # Iterative, structurally independent formulation: walk leaves left to
    # right, folding completed equal-height subtrees; a trailing uneven stack
    # is combined right-to-left.  Same RFC 6962 result, order sensitive.
    def node(left, right):
        return sha256(b"\x01" + left + right)

    stack = []  # (height, hash)
    for r in records:
        h, height = sha256(b"\x00" + r), 0
        while stack and stack[-1][0] == height:
            _, lh = stack.pop()
            h, height = node(lh, h), height + 1
        stack.append((height, h))
    if not stack:
        return sha256(b"")
    root = stack[-1][1]
    for _, h in reversed(stack[:-1]):
        root = node(h, root)
    return root if stack else sha256(b"")


def split_records(data: bytes):
    if not data:
        return []
    records = data.split(b"\n")
    if data.endswith(b"\n"):
        records.pop()
    return records


def root_of_file_bytes(data: bytes):
    recs = split_records(data)
    a, b = mth_recursive(recs), mth_fold(recs)
    assert a == b, "reference algorithms disagree"
    return a.hex(), recs


# ---------------------------------------------------------------------------
# Fixed batches. The first seven records are shared by the 7/8/9 batches;
# records include duplicated content at two distinct positions (r0 == r4),
# an empty record (r3), a CR-only distinction and non-UTF-8 bytes.
# ---------------------------------------------------------------------------
# No record may contain LF: LF is the record separator, not content.
R = [
    b"alpha",                # r0
    b"beta",                 # r1
    b"",                     # r2 empty record
    b"gamma",                # r3
    b"alpha",                # r4 == r0 byte-for-byte, different position
    b"delta\r",              # r5 trailing CR is part of the content
    b"\xff\xfe\x00binary",   # r6 non-UTF-8 and NUL bytes
    b"epsilon",              # r7 eighth record, distinct content
    b"zeta\x01tail",         # r8 ninth record, distinct from r7
]

BASE7 = R[:7]
BASE8 = R[:8]
BASE9 = R[:9]

# Variant A: change ONE position of the duplicated content (r4, equal to r0)
# to other bytes.
V_DUP = list(BASE9)
assert V_DUP[4] == V_DUP[0]
V_DUP[4] = b"alpha-changed"

# Variant B: swap two records holding different content (r1 and r5).
V_SWAP = list(BASE9)
V_SWAP[1], V_SWAP[5] = V_SWAP[5], V_SWAP[1]
assert V_SWAP != BASE9

# Variant C: omit the empty record r2 (8 records, but a different sequence
# from B8 - dropping an empty record must change the root).
V_DROP_EMPTY = [r for i, r in enumerate(BASE9) if i != 2]
assert len(V_DROP_EMPTY) == 8 and V_DROP_EMPTY != BASE8

# Variant D: include one record twice - append another copy of r0 (10 records).
V_DUP_INSERT = BASE9 + [BASE9[0]]
assert len(V_DUP_INSERT) == 10

# ---------------------------------------------------------------------------
# Long records straddling SHA-256 padding and block boundaries. The leaf
# input is 0x00 || record, so record lengths 54/55/56 put the leaf input at
# 55/56/57 bytes (the 56-byte padding boundary, where the 0x80 marker and
# 8-byte length field stop fitting in one block) and 63/64/65 put it at
# 64/65/66 bytes (the 64-byte block boundary). L146's leaf input spans
# three blocks and still has real content at its very end.
#
# NUL, non-UTF-8 and CR bytes appear inside the records and at their very
# ends; every byte is content. No record may contain LF (the separator).
# ---------------------------------------------------------------------------
L54 = b"boundary-54:" + b"a" * 38 + b"\x00\xff\xfe\r"      # ends with CR
L55 = b"boundary-55:" + b"b" * 39 + b"\x00\xff\xfe\r"      # ends with CR
L56 = b"boundary-56:" + b"c" * 40 + b"\xff\xfe\r\x00"      # ends with NUL
L63 = b"boundary-63:" + b"d" * 47 + b"\x00\xff\xfe\r"      # ends with CR
L64 = b"boundary-64:" + b"e" * 48 + b"\x00\xff\xfe\r"      # ends with CR
L65 = b"boundary-65:" + b"f" * 49 + b"\xff\xfe\r\x00"      # ends with NUL
L146 = (b"long-record-146:" + b"0123456789abcdef" * 7
        + b"\x00\xff\xfe\r" + b"TAIL-MARKER-\x00\xff")     # real content at end
LONG_RECORDS = [("L54", L54), ("L55", L55), ("L56", L56),
                ("L63", L63), ("L64", L64), ("L65", L65),
                ("L146", L146)]
assert [len(r) for _, r in LONG_RECORDS] == [54, 55, 56, 63, 64, 65, len(L146)]
assert len(L146) > 128
for name, rec in LONG_RECORDS:
    assert b"\n" not in rec, f"{name} must not contain the LF separator"
    assert b"\x00" in rec and b"\xff" in rec and b"\r" in rec

# Variant E: the SAME long record as L146 with ONE byte near the end changed
# (second-to-last). The root must reflect the full record including its
# tail; an implementation that only hashes a prefix cannot produce it.
V_TAIL = L146[:-2] + b"\x01" + L146[-1:]
assert len(V_TAIL) == len(L146) and V_TAIL != L146
assert V_TAIL[:-2] == L146[:-2] and V_TAIL[-1:] == L146[-1:]

# Fixed batch mixing long and short records: in a batch the long records
# must be hashed by the same standard as when each is the only record.
MIXED = [b"alpha", L54, b"", L65, b"delta\r", L146,
         b"\xff\xfe\x00binary", L56]
assert len(MIXED) == 8


def join_lf(records, trailing=True):
    data = b"\n".join(records)
    if trailing and records:
        data += b"\n"
    return data


BATCHES = [
    ("B7", join_lf(BASE7), "seven shared records", True),
    ("B8", join_lf(BASE8), "seven shared records + eighth (epsilon)", True),
    ("B9", join_lf(BASE9), "seven shared records + eighth + ninth (zeta...)", True),
    ("V_DUP", join_lf(V_DUP), "B9 with duplicate position r4 changed to other bytes", True),
    ("V_SWAP", join_lf(V_SWAP), "B9 with r1 and r5 (different content) swapped", True),
    ("V_DROP_EMPTY", join_lf(V_DROP_EMPTY), "B9 with the empty record r2 omitted (8 records, != B8)", True),
    ("V_DUP_INSERT", join_lf(V_DUP_INSERT), "B9 plus one extra duplicate of r0 (10 records)", True),
    ("L54", join_lf([L54]), "single 54-byte record (leaf input 55 bytes, padding boundary)", True),
    ("L55", join_lf([L55]), "single 55-byte record (leaf input 56 bytes, padding boundary)", True),
    ("L56", join_lf([L56]), "single 56-byte record (leaf input 57 bytes, padding boundary)", True),
    ("L63", join_lf([L63]), "single 63-byte record (leaf input 64 bytes, block boundary)", True),
    ("L64", join_lf([L64]), "single 64-byte record (leaf input 65 bytes, block boundary)", True),
    ("L65", join_lf([L65]), "single 65-byte record (leaf input 66 bytes, block boundary)", True),
    ("L146", join_lf([L146]), "single 146-byte record (leaf input spans three blocks)", True),
    ("V_TAIL", join_lf([V_TAIL]), "L146 with one byte near the end changed", True),
    ("MIXED", join_lf(MIXED), "long and short records in one 8-record batch", True),
    ("EMPTY", b"", "empty file: zero records", False),
    ("ONE_LF", b"\n", "single LF: one empty record", False),
]


def rust_byte_string(data: bytes) -> str:
    out = "b\""
    for byte in data:
        if byte == 0x0A:
            out += "\\n"
        elif byte == 0x0D:
            out += "\\r"
        elif byte == 0x00:
            out += "\\x00"
        elif byte == 0x01:
            out += "\\x01"
        elif byte == 0x22:
            out += "\\\""
        elif byte == 0x5C:
            out += "\\\\"
        elif 0x20 <= byte < 0x7F:
            out += chr(byte)
        else:
            out += "\\x%02x" % byte
    return out + "\""


def main():
    print("# Generated by tests/reference/rfc6962_vectors.py")
    print("# Two independent RFC 6962 implementations agree for every vector.")
    print()
    labels = []
    for name, data, desc, trailing in BATCHES:
        digest, recs = root_of_file_bytes(data)
        labels.append((name, digest))
        print(f"# {name}: {desc}")
        print(f"#   {len(recs)} record(s): {[r for r in recs]!r}")
        print(f"#   file bytes ({len(data)}): {data!r}")
        print(f"#   MTH = {digest}")
        print()

    print("# Rust constants (paste into tests/mth_vectors.rs):")
    for name, digest in labels:
        print(f"const ROOT_{name}: &str = \"{digest}\";")
    print()

    # Trailing-LF equivalence check for every nonempty batch.
    print("# trailing LF equivalence (same root with and without final LF):")
    for recs, tag in [(BASE7, "B7"), (BASE8, "B8"), (BASE9, "B9"),
                      (V_DUP, "V_DUP"), (V_SWAP, "V_SWAP"),
                      (V_DROP_EMPTY, "V_DROP_EMPTY"),
                      (V_DUP_INSERT, "V_DUP_INSERT"),
                      (MIXED, "MIXED")] + \
                     [([rec], name) for name, rec in LONG_RECORDS]:
        a, _ = root_of_file_bytes(join_lf(recs, trailing=True))
        b, _ = root_of_file_bytes(join_lf(recs, trailing=False))
        assert a == b
        print(f"#   {tag}: {a}")
    print()

    # Sanity assertions that the variants really differ and that order matters.
    roots = {name: digest for name, digest in labels}
    assert roots["B8"] != roots["B7"]
    assert roots["B9"] != roots["B8"]
    assert roots["V_DUP"] != roots["B9"]
    assert roots["V_SWAP"] != roots["B9"]
    assert roots["V_DROP_EMPTY"] != roots["B9"]
    assert roots["V_DROP_EMPTY"] != roots["B8"]
    assert roots["V_DUP_INSERT"] != roots["B9"]
    assert roots["EMPTY"] != roots["ONE_LF"]
    assert roots["EMPTY"] == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    # Long records: every length has its own root, the near-end single-byte
    # change gives a different root from the unmodified long record, and the
    # mixed batch collides with none of them.
    long_names = [name for name, _ in LONG_RECORDS]
    assert len({roots[n] for n in long_names}) == len(long_names)
    assert roots["V_TAIL"] != roots["L146"]
    assert roots["MIXED"] not in {roots[n] for n in long_names}

    # Rust literals for the long records themselves (the Rust tests rebuild
    # the batches from these exact bytes).
    print("# Rust long-record literals:")
    for name, rec in LONG_RECORDS + [("V_TAIL", V_TAIL)]:
        print(f"const REC_{name}: &[u8] = {rust_byte_string(rec)};")
    print()

    # Payload literal used by the Rust tests to materialise the batches.
    print("# Rust file payloads:")
    for name, data, desc, trailing in BATCHES:
        print(f"# {name} {desc}")
        print(f"const PAYLOAD_{name}: &[u8] = {rust_byte_string(data)};")
    print()
    # Trailing-LF variants of the three base batches.
    for recs, tag in [(BASE7, "B7"), (BASE8, "B8"), (BASE9, "B9")]:
        print(f"const PAYLOAD_{tag}_NOTRAIL: &[u8] = "
              f"{rust_byte_string(join_lf(recs, trailing=False))};")


if __name__ == "__main__":
    main()
