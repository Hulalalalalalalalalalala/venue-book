#!/usr/bin/env python3
"""Independent reference vectors for the MULTI-READ root regression tests.

This script is NOT the program under test and does not execute roottrace.  It
computes the expected RFC 6962 section 2.1 SHA-256 Merkle Tree Hash roots for
a batch whose file is large enough that `roottrace root` (which streams the
file through a fixed 64 KiB read buffer) cannot see any whole record in one
read: one record is 140000 bytes (> 128 KiB) and spans several reads, and two
record-separating LFs land exactly on the last/first byte of a read boundary.

The roots are computed with the two structurally different, already
cross-validated reference algorithms from rfc6962_vectors.py (the RFC's
recursive definition and an order-sensitive stack fold over the standard
library `hashlib.sha256`); they must agree.  The Rust test
tests/multi_read_regression.rs rebuilds the exact same bytes with the same
deterministic construction and pins the printed constants, so the expected
roots are fixed independently of the implementation being checked.

Batch record sequence (10 records, a non-power-of-two count; RFC 6962 splits
k=8, so the long record at position 4 sits in the left subtree and the
trailing short record at position 9 in the right one):

    0  b"alpha"              short; duplicated byte-for-byte at position 6
    1  b""                   empty record
    2  PAD                   65528 bytes: b"pad:" + b"p" * 65524, placed so
                             its terminating LF is the LAST byte of the first
                             64 KiB read (file offset 65535)
    3  b""                   empty record; its LF is the FIRST byte of the
                             second read (offset 65536), so two consecutive
                             LFs straddle the read boundary
    4  LONG                  140000 bytes (> 128 KiB), spanning reads; NUL,
                             CR and non-UTF-8 bytes in both halves and at the
                             tail; distinct head/mid/tail markers
    5  b"beta\\r"            short, trailing CR is content
    6  b"alpha"              duplicate of position 0 (must not be merged)
    7  b""                   empty record
    8  b"\\xff\\x00z"        short, non-UTF-8 and NUL bytes
    9  b"end-record\\x01"    trailing short record, must reach the final root

Run:  python3 tests/reference/rfc6962_multiread_vectors.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from rfc6962_vectors import (
    audit_path_fold,
    audit_path_recursive,
    mth_fold,
    mth_recursive,
    split_records,
    verify_inclusion,
)

READ_BUF = 64 * 1024  # the fixed read buffer `roottrace root` streams through

LONG_LEN = 140_000  # > 128 KiB: the record spans several consecutive reads
# Bytes before PAD: b"alpha\n" (6) + b"\n" (1) = 7.  PAD's terminating LF must
# land at offset READ_BUF - 1 (the last byte the first read returns).
PAD_LEN = READ_BUF - 1 - 7  # 65528
# Position of the single changed content byte inside LONG: in the second half
# of the record and (as a file offset) inside a later read than the record's
# first bytes.
MOD_POS = 100_000


def fill_byte(i: int) -> int:
    """Deterministic pseudo-random content byte; LF is remapped so the long
    record never contains its own separator.  Identical to the Rust
    `fill_byte` in tests/multi_read_regression.rs."""
    b = ((i * 2654435761) & 0xFFFFFFFF) >> 13 & 0xFF
    return 0x0B if b == 0x0A else b


def long_record() -> bytes:
    rec = bytearray(fill_byte(i) for i in range(LONG_LEN))
    rec[0:13] = b"MREAD\x00\xff\xfe\rHEAD"          # first-half marker
    mid = LONG_LEN // 2
    marker = b"\x00\xff\rSECOND-HALF"               # second-half marker
    rec[mid:mid + len(marker)] = marker
    tail = b"\x00TAIL\r\xff"                        # tail marker, non-text end
    rec[LONG_LEN - len(tail):] = tail
    return bytes(rec)


def long_record_m() -> bytes:
    """The same record with exactly ONE non-LF content byte changed, at
    MOD_POS in the second half; record length and every other byte kept."""
    rec = bytearray(LONG)
    old = rec[MOD_POS]
    rec[MOD_POS] = 0x41 if old != 0x41 else 0x42  # 'A' or 'B', never LF
    assert rec[MOD_POS] != old
    return bytes(rec)


PAD = b"pad:" + b"p" * (PAD_LEN - 4)
LONG = long_record()
LONG_M = long_record_m()

RECORDS = [
    b"alpha",
    b"",
    PAD,
    b"",
    LONG,
    b"beta\r",
    b"alpha",
    b"",
    b"\xff\x00z",
    b"end-record\x01",
]
RECORDS_M = [
    b"alpha",
    b"",
    PAD,
    b"",
    LONG_M,
    b"beta\r",
    b"alpha",
    b"",
    b"\xff\x00z",
    b"end-record\x01",
]


def join_lf(records, trailing=True):
    data = b"\n".join(records)
    if trailing and records:
        data += b"\n"
    return data


def root_of(records):
    a, b = mth_recursive(records), mth_fold(records)
    assert a == b, "reference algorithms disagree"
    return a.hex()


def describe(records):
    out = []
    for i, r in enumerate(records):
        if len(r) <= 32:
            out.append(f"    {i}: {len(r)} byte(s) {r!r}")
        else:
            out.append(f"    {i}: {len(r)} byte(s) {r[:16]!r} ... {r[-8:]!r}")
    return "\n".join(out)


def main():
    n = len(RECORDS)
    assert n == 10 and n & (n - 1) != 0, "record count must be a non-power of two"
    assert RECORDS[0] == RECORDS[6], "duplicate content at positions 0 and 6"
    assert RECORDS[1] == RECORDS[3] == RECORDS[7] == b"", "empty records"

    # Long-record shape: > 128 KiB, no LF anywhere, NUL/CR/non-UTF-8 in both
    # halves and at the tail, distinct markers in each region.
    half = LONG_LEN // 2
    assert LONG_LEN > 128 * 1024
    assert b"\n" not in LONG
    for region in (LONG[:half], LONG[half:]):
        assert 0x00 in region and 0x0D in region
        assert any(b >= 0x80 for b in region)
    assert LONG[:13] == b"MREAD\x00\xff\xfe\rHEAD"
    assert LONG[half:half + 14] == b"\x00\xff\rSECOND-HALF"
    assert LONG[-7:] == b"\x00TAIL\r\xff"

    # The one-byte modification: second half, non-LF, everything else equal.
    assert MOD_POS > half
    assert LONG_M != LONG and len(LONG_M) == len(LONG)
    diffs = [i for i in range(LONG_LEN) if LONG[i] != LONG_M[i]]
    assert diffs == [MOD_POS] and LONG_M[MOD_POS] != 0x0A

    # File layout: LFs at offsets 65535/65536 are consecutive and straddle
    # the 64 KiB read boundary; the long record spans several reads.
    data = join_lf(RECORDS)
    assert data[65535] == 0x0A and data[65536] == 0x0A
    assert data[65534] != 0x0A and data[65537] != 0x0A
    long_start = 7 + PAD_LEN + 1 + 1  # after PAD's LF and the empty record's LF
    long_end = long_start + LONG_LEN - 1
    assert long_start // READ_BUF < long_end // READ_BUF
    assert long_end // READ_BUF - long_start // READ_BUF >= 2, "must span >= 3 reads"
    assert split_records(data) == RECORDS
    assert split_records(join_lf(RECORDS, trailing=False)) == RECORDS

    root = root_of(RECORDS)
    root_m = root_of(RECORDS_M)
    assert root != root_m, "one content byte in the second half must matter"
    # Trailing-LF equivalence: both file forms encode the same sequence.
    assert split_records(data) == split_records(join_lf(RECORDS, trailing=False))

    print("# Generated by tests/reference/rfc6962_multiread_vectors.py")
    print("# Two independent RFC 6962 implementations agree for every vector.")
    print("#")
    print("# MREAD batch record sequence (10 records, non-power-of-two):")
    print(describe(RECORDS))
    print("#")
    print("# MREAD_M: identical except LONG[100000] changed")
    print(f"#   {LONG[MOD_POS]:#04x} -> {LONG_M[MOD_POS]:#04x} (second half of the long record)")
    print("#")
    print(f"# file bytes: {len(data)} (with trailing LF), "
          f"read buffer {READ_BUF}; long record at file offsets "
          f"{long_start}..{long_end} (reads {long_start // READ_BUF}..{long_end // READ_BUF});")
    print("# record-separating LFs at offsets 65535 and 65536 straddle the "
          "first read boundary")
    print()
    print(f"const ROOT_MREAD: &str = \"{root}\";")
    print(f"const ROOT_MREAD_M: &str = \"{root_m}\";")

    # ------------------------------------------------------------------
    # Inclusion (membership) proofs for the multi-read batch. The two
    # structurally different path producers from rfc6962_vectors.py (the
    # RFC 6962 section 2.1.1 recursive PATH definition, and a top-down
    # descent whose sibling subtree hashes come from the stack fold) must
    # agree at every one of the ten positions of both batches, and every
    # path must hash back to the batch root through the independent
    # recursive inclusion verifier. Nothing here reads roottrace output.
    #
    # The fixed vectors emitted for the Rust regression tests cover:
    #   * m=4 - the 140000-byte record itself (left k=8 subtree)
    #   * m=9 - the trailing short record (right subtree)
    # of the original batch MREAD and its one-byte variant MREAD_M.
    # ------------------------------------------------------------------
    proof_sequences = [("MREAD", RECORDS, root), ("MREAD_M", RECORDS_M, root_m)]
    for tag, recs, root_hex in proof_sequences:
        root_bytes = bytes.fromhex(root_hex)
        n = len(recs)
        for m in range(n):
            p1 = audit_path_recursive(recs, m)
            p2 = audit_path_fold(recs, m)
            assert p1 == p2, f"path producers disagree for {tag} m={m}"
            assert verify_inclusion(recs[m], m, n, p1) == root_bytes, (
                f"proof does not verify for {tag} m={m}"
            )
            assert all(len(h) == 32 for h in p1)

    # Geometry pin-downs for the uneven 10-record tree (split k=8): the long
    # record at m=4 sits deep in the left subtree, the trailing record m=9 is
    # in the two-record right subtree. No padding leaf, no duplicated last
    # record - the unevenness stays inside the tree shape.
    p4 = audit_path_recursive(RECORDS, 4)
    p9 = audit_path_recursive(RECORDS, 9)
    p4m = audit_path_recursive(RECORDS_M, 4)
    p9m = audit_path_recursive(RECORDS_M, 9)
    assert len(p4) == 4, f"m=4 in the size-8 left subtree needs 4 siblings, got {len(p4)}"
    assert len(p9) == 2, f"m=9 in the 2-record right subtree needs 2 siblings, got {len(p9)}"

    # The modified byte lies inside the long record (position 4). Its own
    # audit path consists solely of sibling SUBTREE hashes, none of which
    # cover position 4, so that path must be byte-identical after the change.
    assert p4 == p4m, "the long record's sibling subtrees do not change with its content"
    # The trailing short record's path contains the left size-8 subtree hash,
    # which commits to the long record, so its deepest sibling must change.
    assert p9 != p9m, "the last record's path must commit to the changed long subtree"
    # Leaf-to-root order: for m=9 the last sibling is the size-8 left subtree.
    assert p9[-1] == mth_recursive(RECORDS[:8])
    assert p9m[-1] == mth_recursive(RECORDS_M[:8])
    assert p9[:-1] == p9m[:-1], "only the long-record subtree hash changes for m=9"

    def emit_proof(const_tag, recs, m, root_hex):
        path = audit_path_recursive(recs, m)
        print(f"# Inclusion proof for {const_tag}: n={len(recs)}, m={m}; "
              f"both independent path producers agree and the path verifies "
              f"back to the fixed root.")
        elems = ",\n    ".join(f"\"{h.hex()}\"" for h in path)
        print(f"const PATH_{const_tag}: &[&str] = &[\n    {elems},\n];")
        print()

    print()
    print("# Fixed inclusion-proof vectors (RFC 6962 section 2.1.1,")
    print("# leaf-to-root order, lowercase hex): m=4 is the 140000-byte")
    print("# record, m=9 the trailing short record.")
    print()
    emit_proof("MREAD_M4", RECORDS, 4, root)
    emit_proof("MREAD_M9", RECORDS, 9, root)
    emit_proof("MREAD_M_M4", RECORDS_M, 4, root_m)
    emit_proof("MREAD_M_M9", RECORDS_M, 9, root_m)

    # Cross-case negative check: the ORIGINAL m=4 proof must NOT verify the
    # modified long record against the original (still trusted) root.
    assert verify_inclusion(LONG_M, 4, 10, audit_path_recursive(RECORDS, 4)) \
        != bytes.fromhex(root), "the stale proof unexpectedly verifies"
    print("# Negative vector: PATH_MREAD_M4 + modified record LONG_M + trusted")
    print("# ROOT_MREAD must NOT verify (verification failure, not a malformed proof).")


if __name__ == "__main__":
    main()
