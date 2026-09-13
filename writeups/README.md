# Coast & Campus: Blind Solves

**Blind solves from Windhoek labs to the Skeleton Coast**

Author: **John_x9**

These writeups assume what CTFd actually gave you: a port, a banner, and whatever the process prints back. No ELF attachment. No source. You sit in a Windhoek lab (or anywhere with `nc`), talk to the service, and work out the bug from behavior.

Where a challenge is **no-PIE** and the remote never leaks gadgets, the writeup is honest: you need the matching binary from organizers, or the fixed build table for this deploy. Guessing every code address blind is not a real solve path.

Standalone remote scripts (pwntools only, hardcoded addresses): [`solves/`](solves/)

```bash
python3 writeups/solves/01-swakop-solve.py
```

## Challenge table

| # | Challenge | Diff | Port | Writeup | Technique |
|---|-----------|------|------|---------|-----------|
| 01 | Swakop Gate | Easy | 9001 | [01-swakop.md](01-swakop.md) | Stack overflow + short ROP into `vault_open` (skip decoy `win`) |
| 02 | RotWind | Easy+ | 9002 | [02-rotwind.md](02-rotwind.md) | ROT13 then format string; leak flag from stack (fully blind) |
| 03 | SandCSV | Medium | 9003 | [03-sandcsv.md](03-sandcsv.md) | Overflow global `rowbuf` into `outpath` → `"flag.txt"` |
| 04 | Roster | Medium | 9004 | [04-roster.md](04-roster.md) | Heap name overflow into `printme` → `give_flag` (banner leaks code) |
| 05 | CanaryPost | Med-Hard | 9005 | [05-canarypost.md](05-canarypost.md) | `%15$p` canary leak, then overflow + ROP `win(token)` |
| 06 | NamPack | Hard | 9006 | [06-nampack.md](06-nampack.md) | NAMP header; trusted `len`; smash RIP → `give_flag` |
| 07 | Locker | Very Hard | 9007 | [07-locker.md](07-locker.md) | UAF + `scratch` reclaim; fake `show` = `win_real` |
| 08 | SkeletonKey | Insane | 9008 | [08-skeleton.md](08-skeleton.md) | Filtered ROT13 canary leak + dual-arg ROP |

Connect pattern:

```bash
nc 167.86.100.57 PORT
```

## Theme map (campus → coast)

| Challenge | Campus / coast vibe |
|-----------|---------------------|
| Swakop Gate | Meetup gate on the Swakopmund road: wrong door, right vault key |
| RotWind | Dorm LAN "privacy" that is just ROT13 over the Windhoek night |
| SandCSV | Desert survey CSV exporter; wrong dump paths blow sand in your eyes |
| Roster | NUST club roster with a debug leftover on the projector |
| CanaryPost | Guestbook that stamps a canary before your final message |
| NamPack | Campus telemetry packets that trust the shipping label |
| Locker | Campus locker notes: free the card, leave the sticky note |
| SkeletonKey | Skeleton Coast vault: filtered radio, short PIN, two exact args |

## Fake flags

John_x9 left honeypots on every beach. If CTFd rejects a `nustCTF{...}`, keep going. Real flags open `flag.txt` or leak the secret loaded from it.

## After the event

Each writeup ends with **After the event: vulnerable code and how to fix**. That section is for the after-party and for people who want secure-coding takeaways. During the CTF, solve from the wire.
