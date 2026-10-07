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

It also computes RFC 6962 section 2.1.1 inclusion (audit) paths in two
structurally different ways:

  * audit_path_recursive - direct transcription of the PATH definition
  * audit_path_fold      - the stack fold builds explicit subtree nodes with
                           intervals; the path is collected by walking from
                           the root down to the leaf's node

A recursive RFC verifier (verify_inclusion) re-hashes every printed proof and
must arrive back at the batch root; proofs for duplicate content at another
position are additionally checked NOT to verify.

A final section covers trees too large to materialise (sizes 2**63, 2**63+1
and 2**64-1): the audit path is built from deterministic synthetic sibling
hashes and the root an honest verifier must recompute is derived two
structurally different ways (recursive descent, and an iterative top-down
turn walk folded leaf-to-root), which must agree.

A closing section fixes vectors for records whose CONTENT contains LF bytes
(unexpressible in a batch file): a 70-byte record with leading/consecutive/
trailing LFs plus CR, NUL and non-UTF-8 bytes, and a record that is exactly
one LF, each committed in a single-record tree and in an uneven 9-record
tree built from record lists. Tampered forms (trailing LF dropped, one
internal LF changed, any single LF-separated "line") are asserted to
recombine to different roots.

Records are split exactly as roottrace documents: raw bytes on LF, the
separator excluded, a trailing LF only terminates the last record, and an
empty file holds zero records.

Run:  python3 tests/reference/rfc6962_vectors.py
The printed constants are copied verbatim into tests/root_regression.rs and
tests/long_record_regression.rs.  Nothing here reads roottrace output, so the
expected roots are fixed independently of the implementation being checked.
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


# ---------------------------------------------------------------------------
# RFC 6962 section 2.1.1 inclusion (audit) paths.
# ---------------------------------------------------------------------------

def audit_path_recursive(records, m):
    """Direct transcription of the PATH definition, leaf-to-root order.

    PATH(m, [d0]) = []
    PATH(m, [d0..d(n-1)]) =
        PATH(m, d[0:k])       + [MTH(d[k:n])]   if m < k
        PATH(m - k, d[k:n])   + [MTH(d[0:k])]   if m >= k
    """
    n = len(records)
    if not 0 <= m < n:
        raise IndexError(f"index {m} out of range for {n} record(s)")
    if n == 1:
        return []
    k = 1 << ((n - 1).bit_length() - 1)
    if m < k:
        return audit_path_recursive(records[:k], m) + [mth_recursive(records[k:])]
    return audit_path_recursive(records[k:], m - k) + [mth_recursive(records[:k])]


def audit_path_fold(records, m):
    """Structurally different path producer: descend from the root to leaf m
    using the RFC split, computing each sibling subtree hash with the stack
    fold mth_fold (never mth_recursive), then reverse into leaf-to-root
    order. This shares no recursion structure with audit_path_recursive."""
    n = len(records)
    if not 0 <= m < n:
        raise IndexError(f"index {m} out of range for {n} record(s)")
    if n == 1:
        return []
    lo, hi = 0, n
    top_down = []
    while hi - lo > 1:
        size = hi - lo
        k = 1 << ((size - 1).bit_length() - 1)
        if m < lo + k:
            top_down.append(mth_fold(records[lo + k:hi]))
            hi = lo + k
        else:
            top_down.append(mth_fold(records[lo:lo + k]))
            lo = lo + k
    return list(reversed(top_down))


def verify_inclusion(leaf, m, n, path):
    """RFC 6962-bis recursive verifier: re-derive combination order from the
    tree geometry while consuming the supplied path. Returns the root."""
    def sub(mm, nn, pos):
        if nn == 1:
            return sha256(b"\x00" + leaf), pos
        k = 1 << ((nn - 1).bit_length() - 1)
        if mm < k:
            lh, pos = sub(mm, k, pos)
            rh = path[pos]
            pos += 1
        else:
            rh, pos = sub(mm - k, nn - k, pos)
            lh = path[pos]
            pos += 1
        return sha256(b"\x01" + lh + rh), pos

    root, pos = sub(m, n, 0)
    assert pos == len(path), "proof length mismatch"
    return root


def root_of_file_bytes(data: bytes):
    recs = split_records(data)
    a, b = mth_recursive(recs), mth_fold(recs)
    assert a == b, "reference algorithms disagree"
    return a.hex(), recs


# ---------------------------------------------------------------------------
# Big-tree inclusion proofs: tree sizes 2**63, 2**63+1 and 2**64-1 sit at or
# above the signed/unsigned 64-bit boundary, so no batch file can ever be
# materialised for them. The proof is therefore synthetic: one fixed target
# record, and an audit path whose element i is the deterministic 32-byte
# value written as the 64-character lowercase hex of i (reproduced in Rust
# as format!("{i:064x}")). The trusted root is whatever an honest RFC 6962
# verifier recombines from (record, leaf_index, tree_size, audit_path); it is
# derived here by two structurally different computations that must agree.
# ---------------------------------------------------------------------------

BIG_TREE_RECORD = b"big-tree-record\x00\xff\xfe"


def big_tree_path(depth):
    return [bytes.fromhex("%064x" % i) for i in range(depth)]


def big_tree_path_for(m, n):
    """The synthetic audit path for leaf m in a tree of n records: one
    element per level on the root-to-leaf descent."""
    depth = 0
    lo, hi = 0, n
    while hi - lo > 1:
        size = hi - lo
        k = 1 << ((size - 1).bit_length() - 1)
        if m < lo + k:
            hi = lo + k
        else:
            lo = lo + k
        depth += 1
    return big_tree_path(depth)


def big_root_recursive(record, m, n, path):
    """Direct transcription of the RFC 6962-bis recursive verifier: re-derive
    the combination order from the (uneven) subtree geometry while consuming
    the path in its given leaf-to-root order."""
    leaf = sha256(b"\x00" + record)

    def sub(mm, nn, pos):
        if nn == 1:
            return leaf, pos
        k = 1 << ((nn - 1).bit_length() - 1)
        if mm < k:
            lh, pos = sub(mm, k, pos)
            rh = path[pos]
            pos += 1
        else:
            rh, pos = sub(mm - k, nn - k, pos)
            lh = path[pos]
            pos += 1
        return sha256(b"\x01" + lh + rh), pos

    root, pos = sub(m, n, 0)
    assert pos == len(path), "proof length mismatch"
    return root


def big_root_turn_fold(record, m, n, path):
    """Structurally different: walk the containing interval from the root
    downward recording only left/right turns, then fold the path hashes
    leaf-to-root (deepest turn first) in a single pass."""
    turns = []
    lo, hi = 0, n
    while hi - lo > 1:
        size = hi - lo
        k = 1 << ((size - 1).bit_length() - 1)
        if m < lo + k:
            turns.append(True)   # accumulated hash will be the LEFT child
            hi = lo + k
        else:
            turns.append(False)  # accumulated hash will be the RIGHT child
            lo = lo + k
    assert len(turns) == len(path), "proof length mismatch"
    acc = sha256(b"\x00" + record)
    for i, is_left in enumerate(reversed(turns)):
        if is_left:
            acc = sha256(b"\x01" + acc + path[i])
        else:
            acc = sha256(b"\x01" + path[i] + acc)
    return acc


POW63 = 1 << 63
U64_MAX = (1 << 64) - 1

# (tag, tree_size, leaf_index): first and last records, both sides of the
# left/right subtree boundary k (largest power of two strictly below the
# size), and indices straddling the 32-bit boundary. Every index beyond
# 2**32-1 exercises exact 64-bit index handling.
BIG_TREE_CASES = [
    ("2**63 (power-of-two tree), first record", POW63, 0),
    ("2**63, record 2**32-1 (top of 32-bit range)", POW63, (1 << 32) - 1),
    ("2**63, record 2**32 (first index past 32 bits)", POW63, 1 << 32),
    ("2**63, record k-1 (last of left subtree)", POW63, (1 << 62) - 1),
    ("2**63, record k (first of right subtree)", POW63, 1 << 62),
    ("2**63, last record", POW63, POW63 - 1),
    ("2**63+1 (uneven), first record", POW63 + 1, 0),
    ("2**63+1 (uneven), record k-1 (last of left subtree)", POW63 + 1, POW63 - 1),
    ("2**63+1 (uneven), last record = k (lone right subtree)", POW63 + 1, POW63),
    ("2**64-1 (uneven), first record", U64_MAX, 0),
    ("2**64-1 (uneven), record k-1 (last of left subtree)", U64_MAX, POW63 - 1),
    ("2**64-1 (uneven), record k (first of right subtree)", U64_MAX, POW63),
    ("2**64-1 (uneven), last record", U64_MAX, U64_MAX - 1),
]


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


# ---------------------------------------------------------------------------
# Long-record batches.
#
# A leaf hashes SHA-256(0x00 || record), so record lengths 54/55/56 make the
# leaf input 55/56/57 bytes long (squeezed against the 56-byte SHA-256
# padding boundary, where the 0x80 terminator and length field spill into a
# second block), lengths 63/64/65 make it 64/65/66 bytes (exactly one block,
# then one and two bytes into a second block), and L135's leaf input is 136
# bytes (content runs into a third block). A truncating/duplicating block
# walk, or mistaking any content byte for a separator, shows up as a wrong
# fixed root.
#
# Every record carries NUL, non-UTF-8 (0xff/0xfe) and CR bytes INSIDE it and
# ends on a non-text byte (NUL, CR or non-UTF-8), so binary fidelity is
# exercised at both the interior and the tail. No record contains LF.
# ---------------------------------------------------------------------------

def make_long_record(n, tag, tail):
    # Explicit, deterministic construction (no randomness): fixed head with
    # the interior binary bytes, fixed ASCII fill, fixed tail byte.
    head = b"L" + tag + b":\x00\xff\xfe\r"
    alphabet = b"abcdefghijklmnopqrstuvwxyz0123456789"
    rec = head
    i = 0
    while len(rec) < n - 1:
        rec += bytes([alphabet[i % len(alphabet)]])
        i += 1
    rec += bytes([tail])
    assert len(rec) == n
    assert b"\n" not in rec
    assert 0x00 in rec and 0x0D in rec and any(b >= 0x80 for b in rec)
    return rec


L54 = make_long_record(54, b"54", 0x00)    # tail byte: NUL
L55 = make_long_record(55, b"55", 0x0D)    # tail byte: CR
L56 = make_long_record(56, b"56", 0xFF)    # tail byte: non-UTF-8
L63 = make_long_record(63, b"63", 0x00)    # tail byte: NUL
L64 = make_long_record(64, b"64", 0x0D)    # tail byte: CR
L65 = make_long_record(65, b"65", 0xFE)    # tail byte: non-UTF-8
L135 = make_long_record(135, b"135", 0xFF)  # 135 > 128, tail byte non-UTF-8

# Exactly ONE byte changed - the final byte - of the same long record. The
# fixed root must correspond to the whole MODIFIED record; an implementation
# that only processes the front part cannot tell these apart.
L65_M = L65[:-1] + b"Z"
L135_M = L135[:-1] + b"~"
assert len(L65_M) == len(L65) and L65_M[:-1] == L65[:-1] and L65_M[-1] != L65[-1]
assert len(L135_M) == len(L135) and L135_M[:-1] == L135[:-1] and L135_M[-1] != L135[-1]

# (Rust constant name, record) for every single-record long batch.
SINGLE_LONG = [
    ("L54", L54), ("L55", L55), ("L56", L56),
    ("L63", L63), ("L64", L64), ("L65", L65),
    ("L135", L135),
    ("L65_M", L65_M), ("L135_M", L135_M),
]
assert [len(r) for _, r in SINGLE_LONG[:6]] == [54, 55, 56, 63, 64, 65]
assert len(L135) > 128

# One fixed batch of long AND short records (10 records, so the RFC 6962
# subtree split k=8 puts long records on both sides: L54/L63/L135 in the
# left subtree, L65 in the right subtree). It also contains an empty record
# and a short record with binary bytes.
MIXED = [
    b"alpha",          # 0 short
    b"",               # 1 empty record
    L54,               # 2 long (54)
    b"beta\r",         # 3 short, trailing CR
    L63,               # 4 long (63)
    b"\xff\x00z",      # 5 short with non-UTF-8 and NUL
    L135,              # 6 long (>128)
    b"middle",         # 7 short
    L65,               # 8 long (65), right subtree
    b"end-record\x01", # 9 short, right subtree
]
assert len(MIXED) == 10
# Same mixed batch with only the final byte of the L65 record (position 8)
# changed: long records inside a batch must follow the same byte-exact rule
# as single-record batches.
MIXED_M = list(MIXED)
MIXED_M[8] = L65_M


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

# Single-record long batches, each written with and without a trailing LF.
for name, rec in SINGLE_LONG:
    BATCHES.append(
        (name, join_lf([rec]), f"one long record of {len(rec)} bytes "
         f"(leaf input {1 + len(rec)} bytes)", True)
    )

# Fixed mixed batch of long and short records, plus its one-tail-byte variant.
BATCHES += [
    ("MIXED", join_lf(MIXED),
     "fixed batch of 10 long and short records (long records in both k=8 subtrees)", True),
    ("MIXED_M", join_lf(MIXED_M),
     "MIXED with only the final byte of the L65 record changed", True),
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

    print("# Rust constants (paste into tests/root_regression.rs or")
    print("# tests/long_record_regression.rs):")
    for name, digest in labels:
        print(f"const ROOT_{name}: &str = \"{digest}\";")
    print()

    # Trailing-LF equivalence check for every nonempty batch.
    print("# trailing LF equivalence (same root with and without final LF):")
    equiv = [(BASE7, "B7"), (BASE8, "B8"), (BASE9, "B9"),
             (V_DUP, "V_DUP"), (V_SWAP, "V_SWAP"),
             (V_DROP_EMPTY, "V_DROP_EMPTY"),
             (V_DUP_INSERT, "V_DUP_INSERT"),
             (MIXED, "MIXED"), (MIXED_M, "MIXED_M")]
    equiv += [([rec], name) for name, rec in SINGLE_LONG]
    for recs, tag in equiv:
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

    # Long-record sanity: every boundary length has its own root, the tail-byte
    # variants differ from their originals (and from one another), and the
    # mixed batch differs from every single-record batch and its variant.
    for name, _ in SINGLE_LONG:
        assert all(roots[name] != roots[other]
                   for other, _ in SINGLE_LONG if other != name), name
    assert roots["L65_M"] != roots["L65"]
    assert roots["L135_M"] != roots["L135"]
    assert roots["MIXED"] != roots["MIXED_M"]
    for name, _ in SINGLE_LONG:
        assert roots["MIXED"] != roots[name]
        assert roots["MIXED_M"] != roots[name]

    # ------------------------------------------------------------------
    # Inclusion proofs: the two structurally different path producers must
    # agree at every position of every fixed sequence, and each path must
    # verify back to the batch root via the recursive verifier.
    # ------------------------------------------------------------------
    proof_sequences = [
        ("B7", BASE7), ("B8", BASE8), ("B9", BASE9),
        ("V_DUP", V_DUP), ("V_SWAP", V_SWAP),
        ("V_DROP_EMPTY", V_DROP_EMPTY), ("V_DUP_INSERT", V_DUP_INSERT),
        ("MIXED", MIXED), ("MIXED_M", MIXED_M),
        ("ONE_LF", [b""]),
    ] + [(name, [rec]) for name, rec in SINGLE_LONG]

    for tag, recs in proof_sequences:
        root = bytes.fromhex(roots[tag])
        n = len(recs)
        for m in range(n):
            p1 = audit_path_recursive(recs, m)
            p2 = audit_path_fold(recs, m)
            assert p1 == p2, f"path producers disagree for {tag} m={m}"
            got = verify_inclusion(recs[m], m, n, p1)
            assert got == root, f"proof does not verify for {tag} m={m}"
            # Every element is a 32-byte node hash; the single-record path
            # is empty.
            assert all(isinstance(h, bytes) and len(h) == 32 for h in p1)
        if n == 1:
            assert audit_path_recursive(recs, 0) == []

    # Duplicate content at positions 0 and 4 of BASE9: the proof for one
    # position must NOT verify the same bytes at the other position.
    p_dup_0 = audit_path_recursive(BASE9, 0)
    p_dup_4 = audit_path_recursive(BASE9, 4)
    assert p_dup_0 != p_dup_4
    assert verify_inclusion(BASE9[4], 0, 9, p_dup_4) != mth_recursive(BASE9)
    assert verify_inclusion(BASE9[0], 4, 9, p_dup_0) != mth_recursive(BASE9)

    # Fixed proof vectors emitted for the Rust prove regression tests:
    # B9 (uneven, n=9) at its first, duplicate-content and last positions;
    # B8 (balanced) mid-tree; and a single empty record (empty path).
    def emit_proof(const_tag, seq_name, recs, m):
        root = mth_recursive(recs)
        path = audit_path_recursive(recs, m)
        print(f"# Inclusion proof for {seq_name} (n={len(recs)}) at m={m}; "
              f"two independent path producers agree and the path verifies.")
        print(f"const PROOF_{const_tag}_TREE_SIZE: u64 = {len(recs)};")
        print(f"const PROOF_{const_tag}_LEAF_INDEX: u64 = {m};")
        print(f"const PROOF_{const_tag}_ROOT: &str = \"{root.hex()}\";")
        elems = ", ".join(f"\"{h.hex()}\"" for h in path)
        print(f"const PROOF_{const_tag}_AUDIT_PATH: &[&str] = &[{elems}];")
        print()

    print("# Fixed inclusion-proof vectors (RFC 6962 section 2.1.1,")
    print("# leaf-to-root order; hashes are lowercase hex):")
    print()
    emit_proof("B9_M0", "BASE9", BASE9, 0)
    emit_proof("B9_M4", "BASE9 (duplicate 'alpha' position)", BASE9, 4)
    emit_proof("B9_M8", "BASE9 (last record, uneven right subtree)", BASE9, 8)
    emit_proof("B8_M3", "BASE8 (balanced 8-record tree)", BASE8, 3)
    emit_proof("MIXED_M8", "MIXED (long record L65 in the k=8 right subtree)", MIXED, 8)
    emit_proof("ONE_LF_M0", "single LF (one empty record)", [b""], 0)

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
    print()

    # Long-record byte literals (records, not file payloads) and the fixed
    # long/short mixed batches as record-slice constants.
    print("# Rust long-record literals (raw record bytes, no separators):")
    for name, rec in SINGLE_LONG:
        print(f"# {name}: {len(rec)}-byte record, root ROOT_{name} = {roots[name]}")
        print(f"const REC_{name}: &[u8] = {rust_byte_string(rec)};")
    print()
    print("# Fixed mixed batches as record sequences:")
    single_by_value = {rec: name for name, rec in SINGLE_LONG}

    def rust_record_list(records, const_name):
        print(f"const {const_name}: &[&[u8]] = &[")
        for rec in records:
            if rec in single_by_value:
                print(f"    REC_{single_by_value[rec]},")
            else:
                print(f"    {rust_byte_string(rec)},")
        print("];")

    rust_record_list(MIXED, "MIXED_RECORDS")
    print(f"#   root ROOT_MIXED = {roots['MIXED']}")
    rust_record_list(MIXED_M, "MIXED_M_RECORDS")
    print(f"#   root ROOT_MIXED_M = {roots['MIXED_M']}")

    # ------------------------------------------------------------------
    # Big-tree synthetic proofs. First anchor the two big-tree root
    # computations to the already cross-validated small-tree machinery:
    # on every real batch they must recompute the batch root from the real
    # audit path, exactly like verify_inclusion.
    # ------------------------------------------------------------------
    for tag, recs in proof_sequences:
        n = len(recs)
        expected = bytes.fromhex(roots[tag])
        for m in range(n):
            path = audit_path_recursive(recs, m)
            assert big_root_recursive(recs[m], m, n, path) == expected
            assert big_root_turn_fold(recs[m], m, n, path) == expected

    # Depth sanity: a balanced 2**63 tree has depth 63 everywhere; 2**63+1
    # puts the first record at depth 64 and its lone last record at depth 1
    # (the uneven split, never padding); 2**64-1 keeps its last record at
    # depth 63.
    depth_of = lambda m, n: len(big_tree_path_for(m, n))
    assert depth_of(0, POW63) == 63 and depth_of(POW63 - 1, POW63) == 63
    assert depth_of(0, POW63 + 1) == 64 and depth_of(POW63, POW63 + 1) == 1
    assert depth_of(U64_MAX - 1, U64_MAX) == 63

    print()
    print("# Big-tree inclusion proofs (synthetic paths; sizes at the 64-bit")
    print("# boundary cannot be materialised as batches). Both independent root")
    print("# computations agree on every case. audit_path element i is the")
    print("# 64-char lowercase hex of i (Rust: format!(\"{i:064x}\")).")
    print("# Record bytes: %r" % BIG_TREE_RECORD)
    print()
    print("const BIG_TREE_CASES: &[BigCase] = &[")
    for tag, n, m in BIG_TREE_CASES:
        path = big_tree_path_for(m, n)
        r1 = big_root_recursive(BIG_TREE_RECORD, m, n, path)
        r2 = big_root_turn_fold(BIG_TREE_RECORD, m, n, path)
        assert r1 == r2, f"big-tree root computations disagree for {tag}"
        print(f"    // {tag}; audit_path depth {len(path)}")
        print(f"    BigCase {{ size: {n}, index: {m}, depth: {len(path)}, "
              f"root: \"{r1.hex()}\" }},")
    print("];")

    # ------------------------------------------------------------------
    # Records whose CONTENT contains LF bytes.
    #
    # verify's record file and the library's record slice are the whole
    # record: an LF inside is content, never a separator; a trailing LF is
    # content, never a terminator. Such a record cannot be expressed in a
    # root/prove batch file (LF is the record separator there), but an
    # external system can commit to the raw bytes directly and produce an
    # RFC 6962 inclusion proof for them. The trees below are therefore
    # built from record LISTS, never from join_lf file bytes, and are
    # cross-checked by the same two independent algorithm pairs as above.
    # ------------------------------------------------------------------

    # LF_REC: starts with an LF, holds a run of consecutive LFs inside,
    # ends with an LF, and also carries CR, NUL and non-UTF-8 bytes. Its 70
    # bytes (leaf input 0x00 || record = 71 bytes) cross the 64-byte
    # SHA-256 block boundary.
    LF_REC = (
        b"\n"                    # leading LF: content, not a separator
        b"LF:\x00\xff\xfe\r"     # tag plus NUL, non-UTF-8 and CR content
        b"\n\n\n"                # consecutive LFs: content, not empty records
    )
    fill = b"abcdefghijklmnopqrstuvwxyz0123456789"
    i = 0
    while len(LF_REC) < 69:
        LF_REC += bytes([fill[i % len(fill)]])
        i += 1
    LF_REC += b"\n"              # trailing LF: content, not a terminator
    assert len(LF_REC) == 70 and 1 + len(LF_REC) > 64
    assert LF_REC[0] == 0x0A and LF_REC[-1] == 0x0A
    assert 0x00 in LF_REC and 0x0D in LF_REC and any(b >= 0x80 for b in LF_REC)

    # A record that is exactly one LF: neither the zero-byte empty record
    # nor the empty record a batch file containing one LF denotes.
    ONE_LF_REC = b"\n"

    # Uneven 9-record tree (RFC split k=8) holding both LF-containing
    # records at positions 2 and 5. No batch file can denote this sequence.
    LF9 = [
        b"alpha",             # 0
        b"",                  # 1 empty record
        ONE_LF_REC,           # 2 exactly one LF
        b"gamma",             # 3
        b"\xff\xfe\x00bin",   # 4 NUL + non-UTF-8 bytes
        LF_REC,               # 5 the LF-laden record
        b"delta\r",           # 6 trailing CR is content
        b"epsilon",           # 7
        b"zeta\x01tail",      # 8
    ]

    lf9_root_a, lf9_root_b = mth_recursive(LF9), mth_fold(LF9)
    assert lf9_root_a == lf9_root_b, "reference algorithms disagree"
    for m in (2, 5):
        p1 = audit_path_recursive(LF9, m)
        p2 = audit_path_fold(LF9, m)
        assert p1 == p2, f"path producers disagree for LF9 m={m}"
        assert verify_inclusion(LF9[m], m, 9, p1) == lf9_root_a

    # Single-record trees: empty audit path, root is the leaf hash itself.
    lf_single_root = mth_recursive([LF_REC])
    assert lf_single_root == sha256(b"\x00" + LF_REC)
    one_lf_single_root = mth_recursive([ONE_LF_REC])
    assert one_lf_single_root == sha256(b"\x00" + ONE_LF_REC)
    # The one-LF record is not the empty record: different roots, and the
    # empty record does not verify against the one-LF record's proof.
    assert one_lf_single_root != mth_recursive([b""])
    assert verify_inclusion(b"", 0, 1, []) != one_lf_single_root

    # Tampered forms must recombine to a different root: dropping the
    # trailing LF, or changing one internal LF (index 9, the middle of the
    # consecutive run) while keeping every other byte.
    lf_no_tail = LF_REC[:-1]
    assert LF_REC[9] == 0x0A
    lf_swap = LF_REC[:9] + b"X" + LF_REC[10:]
    assert len(lf_swap) == len(LF_REC) and lf_swap != LF_REC
    path_m5 = audit_path_recursive(LF9, 5)
    for tampered in (lf_no_tail, lf_swap):
        assert verify_inclusion(tampered, 0, 1, []) != lf_single_root
        assert verify_inclusion(tampered, 5, 9, path_m5) != lf9_root_a
    # No single "line" of LF_REC verifies as the record: verification must
    # not fall back to matching one of the LF-separated pieces.
    for line in LF_REC.split(b"\n"):
        assert verify_inclusion(line, 5, 9, path_m5) != lf9_root_a

    print()
    print("# Records containing LF bytes (every LF is content; unexpressible")
    print("# in a batch file). Roots and paths are fixed by the same two")
    print("# independent algorithm pairs as above; tampered forms and single")
    print("# LF-separated 'lines' re-verify to different roots.")
    print("# Used by tests/verify_record_lf_regression.rs.")
    print(f"const REC_LF: &[u8] = {rust_byte_string(LF_REC)};")
    print(f"const REC_ONE_LF: &[u8] = {rust_byte_string(ONE_LF_REC)};")
    print(f"const ROOT_LF_REC_SINGLE: &str = \"{lf_single_root.hex()}\";")
    print(f"const ROOT_ONE_LF_REC_SINGLE: &str = \"{one_lf_single_root.hex()}\";")
    print(f"const ROOT_LF9: &str = \"{lf9_root_a.hex()}\";")
    for m, name in ((2, "PATH_LF9_M2"), (5, "PATH_LF9_M5")):
        path = audit_path_recursive(LF9, m)
        elems = ", ".join(f"\"{h.hex()}\"" for h in path)
        print(f"const {name}: &[&str] = &[{elems}];")


if __name__ == "__main__":
    main()
