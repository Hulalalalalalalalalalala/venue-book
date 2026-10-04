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
                      (V_DUP_INSERT, "V_DUP_INSERT")]:
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
