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


# ---------------------------------------------------------------------------
# Chunked-read batches.
#
# # `roottrace root` reads the batch file through a FIXED 64 KiB buffer
# (CLI_READ, mirroring src/main.rs), so a batch larger than one read length
# forces several read() calls. CHUNK below is a non-power-of-two (7-record)
# batch whose middle record is 200_000 bytes: it alone spans the 64 KiB,
# 128 KiB and 192 KiB read boundaries. Records sit before and after it, the
# batch contains an empty record and duplicated content, and the long record
# carries byte-distinctive markers in its first half, second half and tail,
# with NUL/CR/non-UTF-8 bytes throughout and no LF anywhere. CHUNK_M changes
# exactly one non-LF byte in the long record's SECOND half.
#
# LF_BOUNDARY places runs of four consecutive LFs with separators landing at
# file offsets k*CLI_READ-2 .. k*CLI_READ+1 (k = 1,2,3), i.e. straddling a
# read boundary on both sides: three empty records per run must each occupy
# exactly one position, neither lost nor doubled.
#
# The long record is built from explicit construction parameters (not a
# 200 KiB literal); the Rust regression mirrors them byte for byte, and both
# the one-record root ROOT_CHUNK_LONG and the batch root pin every byte
# independently of roottrace.
# ---------------------------------------------------------------------------

CLI_READ = 64 * 1024  # mirrors the read buffer in src/main.rs

CHUNK_LONG_LEN = 200_000  # > 2 * CLI_READ and > 128 KiB
CHUNK_LONG_HEAD = b"S200:\x00\xff\xfe\r"
CHUNK_FILL_ALPHABET = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
# (offset, marker): distinctive bytes in the FIRST half, the SECOND half and
# the tail of the long record. Each marker keeps NUL, CR and a non-UTF-8 byte.
CHUNK_MARK_FIRST = (10_000, b"@FIRST-HALF@\x00\r\xff")
CHUNK_MARK_SECOND = (120_000, b"@SECOND-HALF@\x00\r\xfe")
CHUNK_TAIL_MARK = b"@TAIL-REGION@\x00\r\xfd"
# Exactly one changed byte: the 'S' of the second-half marker becomes 'X'.
CHUNK_MUT_OFFSET = 120_001
assert CHUNK_MARK_SECOND[1][CHUNK_MUT_OFFSET - CHUNK_MARK_SECOND[0]] == ord("S")


def make_chunk_long_record():
    # Deterministic, explicit construction (no randomness): fixed head with
    # NUL/CR/non-UTF-8 bytes, cyclic ASCII fill, then fixed markers overwrite
    # fill bytes at fixed offsets. No byte is ever LF.
    rec = bytearray(CHUNK_LONG_HEAD)
    i = 0
    while len(rec) < CHUNK_LONG_LEN:
        b = CHUNK_FILL_ALPHABET[i % len(CHUNK_FILL_ALPHABET)]
        rec.append(b)
        i += 1
    for off, marker in (CHUNK_MARK_FIRST, CHUNK_MARK_SECOND):
        rec[off:off + len(marker)] = marker
    rec[CHUNK_LONG_LEN - len(CHUNK_TAIL_MARK):] = CHUNK_TAIL_MARK
    assert len(rec) == CHUNK_LONG_LEN
    assert b"\n" not in rec
    assert 0x00 in rec and 0x0D in rec and any(x >= 0x80 for x in rec)
    return bytes(rec)


LONG_CHUNK = make_chunk_long_record()
LONG_CHUNK_M = (
    LONG_CHUNK[:CHUNK_MUT_OFFSET]
    + b"X"
    + LONG_CHUNK[CHUNK_MUT_OFFSET + 1:]
)
assert len(LONG_CHUNK_M) == len(LONG_CHUNK)
assert LONG_CHUNK_M != LONG_CHUNK
assert LONG_CHUNK_M[:CHUNK_MUT_OFFSET] == LONG_CHUNK[:CHUNK_MUT_OFFSET]
assert LONG_CHUNK_M[CHUNK_MUT_OFFSET + 1:] == LONG_CHUNK[CHUNK_MUT_OFFSET + 1:]
assert LONG_CHUNK_M[CHUNK_MUT_OFFSET] == ord("X")

# 7 records (non-power-of-two): short records on both sides of the long one,
# an empty record (position 2), duplicated content (positions 3 and 5), a
# short record with a NUL byte, and a final short record that must still take
# part in the root.
CHUNK = [
    b"before-a",          # 0 short, before the long record
    LONG_CHUNK,           # 1 200_000-byte record spanning 3+ reads
    b"",                  # 2 empty record
    b"dup",               # 3 first occurrence
    b"after-b\x01",       # 4 short, after the long record
    b"dup",               # 5 same bytes as position 3, separate position
    b"tail-final",        # 6 trailing short record
]
CHUNK_M = [r if i != 1 else LONG_CHUNK_M for i, r in enumerate(CHUNK)]
assert len(CHUNK) == len(CHUNK_M) == 7
assert CHUNK_M[1] is not LONG_CHUNK
assert CHUNK_M[:1] == CHUNK[:1] and CHUNK_M[2:] == CHUNK[2:]

# Fixed variants proving record POSITIONS and MULTIPLICITY survive the read
# boundaries: same long record, but the empty record (position 2), the second
# copy of the duplicated content (position 5) or the trailing short record
# (position 6) removed. Each is a different record sequence with its own root.
CHUNK_NO_EMPTY = [r for i, r in enumerate(CHUNK) if i != 2]
CHUNK_NO_DUP = [r for i, r in enumerate(CHUNK) if i != 5]
CHUNK_NO_TAIL = CHUNK[:6]
assert [len(v) for v in (CHUNK_NO_EMPTY, CHUNK_NO_DUP, CHUNK_NO_TAIL)] == [6, 6, 6]
# CHUNK_NO_EMPTY / CHUNK_NO_DUP differ from one another too: empty position vs
# duplicate multiplicity are distinct structural changes.
assert CHUNK_NO_EMPTY != CHUNK_NO_DUP

# Geometry checks against the actual file bytes: the long record crosses all
# three read boundaries; the trailing LF is the only difference between the
# two file forms.
CHUNK_FILE = join_lf(CHUNK, trailing=False)
CHUNK_FILE_TRAILING = join_lf(CHUNK, trailing=True)
_long_lo = len(b"before-a\n")
_long_hi = _long_lo + CHUNK_LONG_LEN
assert _long_lo == 9 and _long_hi == 200_009
for k in (1, 2, 3):
    assert _long_lo < k * CLI_READ < _long_hi, f"long record must cross {k}*64KiB"
assert CHUNK_FILE_TRAILING == CHUNK_FILE + b"\n"
assert CHUNK_FILE_TRAILING.count(b"\n") == 7
# Two consecutive LFs end the long record and the empty record after it.
assert CHUNK_FILE_TRAILING[_long_hi:_long_hi + 2] == b"\n\n"


def make_lf_boundary_batch():
    # Padding records chosen so four consecutive LFs land on file offsets
    # k*CLI_READ-2 .. k*CLI_READ+1 for k = 1,2,3: the separator of the padding
    # record plus three empty-record separators, straddling the boundary on
    # both sides (two LFs just before, one exactly on it, one just after).
    records = []
    pos = 0  # byte offset at which the next record starts
    lf_offsets = []
    for k in (1, 2, 3):
        first_lf = k * CLI_READ - 2
        pad_len = first_lf - pos
        prefix = f"CLUSTER{k}-PADDING:".encode() + b"\x00\r\xff"
        pad = prefix + b"p" * (pad_len - len(prefix))
        assert len(pad) == pad_len and b"\n" not in pad
        records.append(pad)
        # The padding record's LF plus three empty records' LFs.
        lf_offsets += [first_lf, first_lf + 1, first_lf + 2, first_lf + 3]
        records += [b"", b"", b""]
        pos = first_lf + 4
    records.append(b"end")
    data = join_lf(records, trailing=True)
    actual = [i for i, x in enumerate(data) if x == 0x0A]
    for want in lf_offsets:
        assert want in actual, f"missing separator at {want}"
        assert data[want] == 0x0A
    # Exactly the intended offsets around each boundary.
    for k in (1, 2, 3):
        assert [o for o in actual if k * CLI_READ - 2 <= o <= k * CLI_READ + 1] == [
            k * CLI_READ - 2, k * CLI_READ - 1, k * CLI_READ, k * CLI_READ + 1
        ]
    assert len(records) == 13
    return records


LF_BOUNDARY = make_lf_boundary_batch()


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

# Chunked-read batches (files larger than the CLI's 64 KiB read length; the
# long record itself is generated from fixed parameters, so no 200 KiB literal
# needs to be copied around). Both trailing-LF file forms share one root.
BATCHES += [
    ("CHUNK", CHUNK_FILE,
     "7-record batch whose 200_000-byte middle record spans three 64 KiB reads; "
     "empty record, duplicated content and a trailing short record included", False),
    ("CHUNK_TRAIL", CHUNK_FILE_TRAILING,
     "CHUNK with a terminating LF: byte-identical record sequence", True),
    ("CHUNK_M", join_lf(CHUNK_M),
     "CHUNK with exactly one non-LF byte changed in the long record's second half", False),
    ("CHUNK_NO_EMPTY", join_lf(CHUNK_NO_EMPTY, trailing=False),
     "CHUNK with the empty record at position 2 removed (6 records)", False),
    ("CHUNK_NO_DUP", join_lf(CHUNK_NO_DUP, trailing=False),
     "CHUNK with the second duplicate of b\"dup\" (position 5) removed (6 records)", False),
    ("CHUNK_NO_TAIL", join_lf(CHUNK_NO_TAIL, trailing=False),
     "CHUNK with the trailing short record at position 6 removed (6 records)", False),
    ("LF_BOUNDARY", join_lf(LF_BOUNDARY),
     "13 records: four consecutive LFs straddle each of three 64 KiB read boundaries", True),
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
             (MIXED, "MIXED"), (MIXED_M, "MIXED_M"),
             (CHUNK, "CHUNK"), (CHUNK_M, "CHUNK_M"),
             (LF_BOUNDARY, "LF_BOUNDARY")]
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

    # Chunked-read sanity: the two trailing-LF file forms are byte-identical
    # apart from the final LF and share a root; the one-byte second-half
    # mutation changes it; the boundary batch has its own root.
    assert roots["CHUNK"] == roots["CHUNK_TRAIL"]
    assert CHUNK_FILE_TRAILING[:-1] == CHUNK_FILE
    assert roots["CHUNK"] != roots["CHUNK_M"]
    assert roots["CHUNK"] != roots["LF_BOUNDARY"]
    assert roots["CHUNK_M"] != roots["LF_BOUNDARY"]
    assert CHUNK_MUT_OFFSET > CHUNK_LONG_LEN // 2, "mutation must be in the second half"
    chunk_root = bytes.fromhex(roots["CHUNK"])
    # The long record alone is a different (one-record) tree.
    assert mth_recursive([LONG_CHUNK]) != chunk_root
    assert mth_recursive([LONG_CHUNK_M]) != bytes.fromhex(roots["CHUNK_M"])
    assert mth_recursive([LONG_CHUNK]) != mth_recursive([LONG_CHUNK_M])
    # Record ORDER and MULTIPLICITY participate across read boundaries:
    # dropping the empty record, the second duplicate, or the trailing short
    # record each yields a different independently-fixed root.
    assert roots["CHUNK_NO_EMPTY"] == mth_recursive(CHUNK_NO_EMPTY).hex()
    assert roots["CHUNK_NO_DUP"] == mth_recursive(CHUNK_NO_DUP).hex()
    assert roots["CHUNK_NO_TAIL"] == mth_recursive(CHUNK_NO_TAIL).hex()
    for tag in ("CHUNK_NO_EMPTY", "CHUNK_NO_DUP", "CHUNK_NO_TAIL"):
        assert roots[tag] != roots["CHUNK"], tag
    assert roots["CHUNK_NO_EMPTY"] != roots["CHUNK_NO_DUP"]
    assert len(CHUNK) == len(CHUNK_M) == 7
    # The LF_BOUNDARY roots with/without trailing LF also agree.
    assert mth_recursive(split_records(join_lf(LF_BOUNDARY, trailing=False))) == bytes.fromhex(
        roots["LF_BOUNDARY"]
    )

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

    # Payload literal used by the Rust tests to materialise the batches. The
    # chunked-read batches are skipped: materialising them as 200 KiB literals
    # would be pointless; the Rust tests rebuild them from the construction
    # parameters emitted below.
    SKIP_PAYLOAD = {
        "CHUNK", "CHUNK_TRAIL", "CHUNK_M",
        "CHUNK_NO_EMPTY", "CHUNK_NO_DUP", "CHUNK_NO_TAIL",
        "LF_BOUNDARY",
    }
    print("# Rust file payloads:")
    for name, data, desc, trailing in BATCHES:
        if name in SKIP_PAYLOAD:
            continue
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

    # Chunked-read construction parameters and independently fixed roots for
    # tests/chunked_read_regression.rs. The batches are rebuilt from these
    # parameters rather than pasted as 200 KiB byte literals; every value here
    # mirrors make_chunk_long_record/make_lf_boundary_batch above.
    print("# Chunked-read vectors (files larger than one 64 KiB read):")
    print(f"const ROOT_CHUNK: &str = \"{roots['CHUNK']}\";")
    print(f"# CHUNK with a terminating LF is the same record sequence:")
    print(f"const ROOT_CHUNK_TRAIL: &str = \"{roots['CHUNK_TRAIL']}\";")
    print(f"const ROOT_CHUNK_M: &str = \"{roots['CHUNK_M']}\";")
    print(f"const ROOT_CHUNK_NO_EMPTY: &str = \"{roots['CHUNK_NO_EMPTY']}\";")
    print(f"const ROOT_CHUNK_NO_DUP: &str = \"{roots['CHUNK_NO_DUP']}\";")
    print(f"const ROOT_CHUNK_NO_TAIL: &str = \"{roots['CHUNK_NO_TAIL']}\";")
    print(f"const ROOT_LF_BOUNDARY: &str = \"{roots['LF_BOUNDARY']}\";")
    print(f"const CLI_READ_LEN: usize = {CLI_READ};")
    print(f"const CHUNK_LONG_LEN: usize = {CHUNK_LONG_LEN};")
    print(f"const CHUNK_LONG_HEAD: &[u8] = {rust_byte_string(CHUNK_LONG_HEAD)};")
    print(f"const CHUNK_FILL_ALPHABET: &[u8] = {rust_byte_string(CHUNK_FILL_ALPHABET)};")
    print(f"const CHUNK_MARK_FIRST_OFFSET: usize = {CHUNK_MARK_FIRST[0]};")
    print(f"const CHUNK_MARK_FIRST: &[u8] = {rust_byte_string(CHUNK_MARK_FIRST[1])};")
    print(f"const CHUNK_MARK_SECOND_OFFSET: usize = {CHUNK_MARK_SECOND[0]};")
    print(f"const CHUNK_MARK_SECOND: &[u8] = {rust_byte_string(CHUNK_MARK_SECOND[1])};")
    print(f"const CHUNK_TAIL_MARK: &[u8] = {rust_byte_string(CHUNK_TAIL_MARK)};")
    print(f"const CHUNK_MUT_OFFSET: usize = {CHUNK_MUT_OFFSET};")
    print(f"# CHUNK record count: {len(CHUNK)}; file bytes: "
          f"{len(CHUNK_FILE)} (no trailing LF) / {len(CHUNK_FILE_TRAILING)} (trailing LF)")
    print(f"# the long record occupies file offsets {_long_lo}..{_long_hi}")
    # LF_BOUNDARY padding records: (fixed prefix incl. NUL/CR/non-UTF-8,
    # total padding length); the remainder up to the total length is filled
    # with LF_BOUNDARY_FILL bytes.
    print(f"const LF_BOUNDARY_FILL: u8 = b'p';")
    print(f"const LF_BOUNDARY_PAD: &[(&[u8], usize)] = &[")
    pad_lens = [len(LF_BOUNDARY[0]), len(LF_BOUNDARY[4]), len(LF_BOUNDARY[8])]
    for k, plen in zip((1, 2, 3), pad_lens):
        prefix = f"CLUSTER{k}-PADDING:".encode() + b"\x00\r\xff"
        print(f"    ({rust_byte_string(prefix)}, {plen}),")
    print("];")
    lf_offsets = []
    for k in (1, 2, 3):
        lf_offsets += [k * CLI_READ - 2, k * CLI_READ - 1, k * CLI_READ, k * CLI_READ + 1]
    print("# exact file offsets of the twelve clustered separators:")
    print(f"const LF_BOUNDARY_SEPARATORS: &[usize] = &{lf_offsets};")
    print(f"# LF_BOUNDARY record count: {len(LF_BOUNDARY)}; "
          f"file bytes: {len(join_lf(LF_BOUNDARY))}")
    print()

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


if __name__ == "__main__":
    main()
