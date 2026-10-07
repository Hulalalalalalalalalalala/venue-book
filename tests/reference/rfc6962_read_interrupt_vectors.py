#!/usr/bin/env python3
"""Independent reference vectors for the roottrace root-command read-fault
regression tests (tests/read_fault_regression.rs).

This script is NOT the program under test and never executes roottrace.  It
fixes, from the exact file bytes only, the RFC 6962 section 2.1 SHA-256
Merkle Tree Hash of the batch the read-fault tests feed through interrupted
and failing reads.  The roots are computed with two structurally different
implementations over the standard library `hashlib.sha256`:

  * mth_recursive - direct transcription of the RFC 6962 definition
  * mth_fold      - order-sensitive left-to-right stack fold

and the two must agree for every vector.  Because a *recoverable* read
interruption changes only HOW the bytes arrive (one read reports EINTR, the
remaining bytes arrive on later reads) and never the bytes themselves, the
fixed root below is both the uninterrupted-read root and the
interrupted-then-recovered root: recovery must reproduce the complete
original record sequence.

Records are split exactly as roottrace documents: raw bytes on LF, the
separator excluded, a trailing LF only terminates the last record (it adds
no empty record), and a file without a trailing LF still includes its last
record in full.

The file is laid out against a small forced read size (8 bytes, imposed by
the test preload shim on the target descriptor) so the interesting points
sit exactly where the tests interrupt or fail a read:

    offset 0..4  b"alpha"      r0
    offset 5     LF
    offset 6     LF            r1 = "" (empty record)
    offset 7     LF            r2 = "" (empty record); this LF is the LAST
                                byte of the first forced 8-byte read, so the
                                next read attempt comes immediately after a
                                record-separating LF
    offset 8..33 LONG (26)     r3, spans forced reads [8,16),[16,24),
                                [24,32) and into [32,40); carries NUL, CR
                                and non-UTF-8 bytes in both halves and ends
                                on a non-text byte, with no LF anywhere in it
    offset 34    LF
    offset 35..40 b"end\\x01\\xffz"  r4, the final short record
    offset 41    LF            only in the trailing-LF file form

Run:  python3 tests/reference/rfc6962_read_interrupt_vectors.py
The printed constants are copied verbatim into
tests/read_fault_regression.rs.
"""

import hashlib

READ_CAP = 8

LONG_LEN = 26
LONG_HEAD = b"LO\x00\xff\rREC"          # 8 bytes: NUL, non-UTF-8, CR
LONG_TAIL = b"\xfe"                     # final byte, non-UTF-8
LONG = LONG_HEAD + b"q" * (LONG_LEN - len(LONG_HEAD) - 1) + LONG_TAIL

# One non-LF content byte changed in the LONG record's SECOND half (record
# index 20, file offset 28, inside the forced read [24,32)): a root computed
# over a lost or duplicated prefix cannot distinguish this batch.
MOD_INDEX = 20
LONG_M = LONG[:MOD_INDEX] + b"Z" + LONG[MOD_INDEX + 1:]

R0 = b"alpha"
R1 = b""
R2 = b""
R4 = b"end\x01\xffz"

IREC = [R0, R1, R2, LONG, R4]
IREC_M = [R0, R1, R2, LONG_M, R4]

# Fixed offsets (0-based), see the layout in the module docstring.
OFF_R0_LF = 5
OFF_R1_LF = 6
OFF_R2_LF = 7
LONG_START = 8
LONG_END = LONG_START + LONG_LEN - 1
OFF_LONG_LF = LONG_START + LONG_LEN
R4_START = OFF_LONG_LF + 1
OFF_TRAILING_LF = R4_START + len(R4)


def join_lf(records, trailing=True):
    data = b"\n".join(records)
    if trailing and records:
        data += b"\n"
    return data


def split_records(data: bytes):
    if not data:
        return []
    records = data.split(b"\n")
    if data.endswith(b"\n"):
        records.pop()
    return records


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def mth_recursive(records):
    n = len(records)
    if n == 0:
        return sha256(b"")
    if n == 1:
        return sha256(b"\x00" + records[0])
    k = 1 << ((n - 1).bit_length() - 1)
    return sha256(b"\x01" + mth_recursive(records[:k]) + mth_recursive(records[k:]))


def mth_fold(records):
    def node(left, right):
        return sha256(b"\x01" + left + right)

    stack = []
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
    return root


def root_of(data: bytes) -> str:
    recs = split_records(data)
    a, b = mth_recursive(recs), mth_fold(recs)
    assert a == b, "reference algorithms disagree"
    return a.hex()


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


def self_check():
    assert len(LONG) == LONG_LEN == 26
    assert b"\n" not in LONG
    assert LONG[:8] == b"LO\x00\xff\rREC"
    assert LONG[-1] == 0xFE
    assert 0x00 in LONG and 0x0D in LONG and any(b >= 0x80 for b in LONG)
    assert LONG_M != LONG and len(LONG_M) == len(LONG)
    assert LONG_M[MOD_INDEX] == ord("Z") and LONG_M[MOD_INDEX] != LONG[MOD_INDEX]
    assert MOD_INDEX >= LONG_LEN // 2

    trailing = join_lf(IREC, True)
    no_trailing = join_lf(IREC, False)
    assert len(trailing) == OFF_TRAILING_LF + 1 == 42
    assert len(no_trailing) == OFF_TRAILING_LF == 41
    assert trailing[OFF_R2_LF] == ord("\n") and OFF_R2_LF == READ_CAP - 1
    assert trailing[OFF_R2_LF - 1] == ord("\n")
    assert trailing[LONG_START:LONG_END + 1] == LONG
    assert trailing[OFF_LONG_LF] == ord("\n")
    assert trailing[R4_START:OFF_TRAILING_LF] == R4
    assert trailing[OFF_TRAILING_LF] == ord("\n")
    assert no_trailing[-len(R4):] == R4
    # Trailing LF only terminates; both file forms are the same sequence.
    assert root_of(trailing) == root_of(no_trailing)
    assert root_of(join_lf(IREC_M, True)) == root_of(join_lf(IREC_M, False))
    # The modified byte really changes the fixed root.
    assert root_of(trailing) != root_of(join_lf(IREC_M, True))


def main():
    self_check()
    root_irec = root_of(join_lf(IREC, True))
    root_irec_m = root_of(join_lf(IREC_M, True))

    print("# Generated by tests/reference/rfc6962_read_interrupt_vectors.py")
    print("# Two independent RFC 6962 implementations agree for every vector.")
    print("# A recoverable interruption changes read chunking only, never the")
    print("# bytes, so the interrupted-then-recovered root equals this root.")
    print()
    print(f"# IREC: {len(IREC)} records; {len(join_lf(IREC, True))} bytes with the")
    print(f"# trailing LF, {len(join_lf(IREC, False))} without.")
    print(f"#   records: {IREC!r}")
    print(f"#   file bytes (trailing LF): {join_lf(IREC, True)!r}")
    print(f"#   MTH = {root_irec}")
    print(f"# IREC_M: one non-LF byte changed at LONG[{MOD_INDEX}] (file offset "
          f"{LONG_START + MOD_INDEX}).")
    print(f"#   MTH = {root_irec_m}")
    print()
    print("const READ_CAP: usize = %d;" % READ_CAP)
    print("const LONG_LEN: usize = %d;" % LONG_LEN)
    print("const MOD_INDEX: usize = %d;" % MOD_INDEX)
    print("const OFF_R2_LF: usize = %d;        // LF ending the first forced read"
          % OFF_R2_LF)
    print("const LONG_START: usize = %d;" % LONG_START)
    print("const LONG_END: usize = %d;" % LONG_END)
    print("const OFF_LONG_LF: usize = %d;" % OFF_LONG_LF)
    print("const R4_START: usize = %d;" % R4_START)
    print("const OFF_TRAILING_LF: usize = %d;" % OFF_TRAILING_LF)
    print("const TRAILING_FILE_LEN: usize = %d;" % len(join_lf(IREC, True)))
    print("const NOTRAILING_FILE_LEN: usize = %d;" % len(join_lf(IREC, False)))
    print()
    print(f"const ROOT_IREC: &str = \"{root_irec}\";")
    print(f"const ROOT_IREC_M: &str = \"{root_irec_m}\";")
    print()
    print(f"const LONG_REC: &[u8] = {rust_byte_string(LONG)};")
    print(f"const LONG_REC_M: &[u8] = {rust_byte_string(LONG_M)};")
    print(f"const R4_REC: &[u8] = {rust_byte_string(R4)};")


if __name__ == "__main__":
    main()
