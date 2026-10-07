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
library `hashlib.sha256`); they must agree.  Inclusion (audit) paths for the
long record (position 4) and the trailing short record (position 9) - in both
the original and the one-byte-modified batch - are likewise produced by the
two structurally different path builders from rfc6962_vectors.py (the
recursive PATH transcription and the top-down descent whose sibling hashes
come from the stack fold), must agree, and are re-hashed back to the batch
root by the independent recursive inclusion verifier; every other position of
both batches is checked the same way before the constants are printed.  The
Rust tests tests/multi_read_regression.rs and
tests/prove_multi_read_regression.rs rebuild the exact same bytes with the
same deterministic construction and pin the printed constants, so the
expected roots and audit paths are fixed independently of the implementation
being checked.

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
    print()

    # ------------------------------------------------------------------
    # Inclusion proofs for the long record (position 4) and the trailing
    # short record (position 9), in the original and the modified batch.
    # First cross-check EVERY position of both batches: the two structurally
    # different path producers must agree and each path must re-hash to the
    # batch root via the independent recursive inclusion verifier.
    # ------------------------------------------------------------------
    for tag, recs, expected in (("MREAD", RECORDS, root), ("MREAD_M", RECORDS_M, root_m)):
        for m in range(len(recs)):
            p1 = audit_path_recursive(recs, m)
            p2 = audit_path_fold(recs, m)
            assert p1 == p2, f"path producers disagree for {tag} m={m}"
            assert verify_inclusion(recs[m], m, len(recs), p1) == bytes.fromhex(expected), \
                f"proof does not verify for {tag} m={m}"

    # The one-byte change sits INSIDE leaf 4, so the long record's own audit
    # path (sibling subtree hashes only) must be identical in both batches,
    # while the trailing record's path contains the left-subtree hash covering
    # the long record and must change.
    p4 = audit_path_recursive(RECORDS, 4)
    p4_m = audit_path_recursive(RECORDS_M, 4)
    p9 = audit_path_recursive(RECORDS, 9)
    p9_m = audit_path_recursive(RECORDS_M, 9)
    assert p4 == p4_m, "long record's sibling subtrees are untouched"
    assert p9 != p9_m, "trailing record's path must bind the changed subtree"
    assert p9[0] == p9_m[0] and p9[1] != p9_m[1], \
        "leaf-to-root: the sibling leaf hash stays, the left-subtree hash " \
        "covering leaf 4 changes"
    # Position 9 is the lone record of the k=8 right subtree's deeper split:
    # path = [MTH(records[8:9]), MTH(records[0:8])] (leaf-to-root) - two
    # elements, no padding.
    # Position 4 sits at depth 3 of the balanced size-8 left subtree, plus the
    # right-subtree hash: four elements.
    assert len(p9) == 2 and len(p4) == 4

    def emit_path(const_tag, seq_tag, recs, m):
        path = audit_path_recursive(recs, m)
        print(f"# Audit path for {seq_tag} m={m} (leaf-to-root; two independent")
        print(f"# producers agree and the path verifies against ROOT_{seq_tag}):")
        elems = ", ".join(f"\"{h.hex()}\"" for h in path)
        print(f"const PATH_{const_tag}_M{m}: &[&str] = &[{elems}];")
        print()

    print("# Fixed inclusion-proof audit paths (RFC 6962 section 2.1.1):")
    print()
    emit_path("MREAD", "MREAD", RECORDS, 4)
    emit_path("MREAD", "MREAD", RECORDS, 9)
    emit_path("MREAD_MOD", "MREAD_M", RECORDS_M, 4)
    emit_path("MREAD_MOD", "MREAD_M", RECORDS_M, 9)


if __name__ == "__main__":
    main()
