---
title: "Neon Nights"

difficulty: Easy
description: "Welcome to the Neon Nights Arcade, the hottest retro gaming spot in town! The arcade's high score board has a special validation system to prevent cheaters. A friend slipped you a copy of their score validator program. Can you crack the validation code and prove you're the ultimate arcade champion?"
flag: CSC{x0r_th3_n30n_l1ght5}
---

> *Welcome to the Neon Nights Arcade, the hottest retro gaming spot in town! The arcade's high score board has a special validation system to prevent cheaters. A friend slipped you a copy of their score validator program. Can you crack the validation code and prove you're the ultimate arcade champion?*

64-bit ELF, statically linked, not stripped, debug symbols present.

```
$ file neon_nights
neon_nights: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux),
             statically linked, for GNU/Linux 3.2.0, with debug_info, not stripped
```

```
$ strings neon_nights 
[...]
=== TOP SCORES ===
*    NEON NIGHTS ARCADE     *
Enter score validation code:
SCORE VALIDATED! You're a true arcade champion!
INVALID CODE. Nice try, challenger.
[...]
```

Arcade score validator. enter a code, it checks it.

Not stripped means we get symbol names:

```
$ nm neon_nights | grep -i ' T '
[...]
00000000004017d6 T validate_score
0000000000401850 T main
[...]
```

two interesting ones: `validate_score` and `main`.

`main` just reads input and calls `validate_score`:

```
00000000004017d6 <validate_score>:
  4017e2:   c7 45 f8 18 00 00 00    movl   $0x18,-0x8(%rbp)
  4017f0:   e8 d3 f8 ff ff          call   4010c8 <_init+0xc8>
  4017fb:   48 39 c2                cmp    %rax,%rdx
  4017fe:   74 07                   je     401807
  401800:   b8 00 00 00 00          mov    $0x0,%eax
  401805:   eb 47                   jmp    40184e
```

first it stores `0x18` (24) as the expected length and calls strlen. if length != 24, return 0. then the loop:

```
  401810:   8b 55 fc                mov    -0x4(%rbp),%edx
  401817:   48 01 d0                add    %rdx,%rax
  40181a:   0f b6 00                movzbl (%rax),%eax
  40181d:   89 c1                   mov    %eax,%ecx
  40181f:   8b 45 fc                mov    -0x4(%rbp),%eax
  401822:   0f b6 90 d0 60 4a 00    movzbl 0x4a60d0(%rax),%edx
  401829:   0f b6 05 b8 48 0a 00    movzbl 0xa48b8(%rip),%eax    # 4a60e8 <xor_key>
  401830:   31 d0                   xor    %edx,%eax
  401832:   38 c1                   cmp    %al,%cl
  401834:   74 07                   je     40183d
```

loads input byte into `ecx`. loads `secret_data[i]` from `0x4a60d0` into `edx`. loads `xor_key` from `0x4a60e8` into `eax`. XORs `edx` with `eax`, compares to `cl`. `input[i] == secret_data[i] ^ xor_key`.

dump the .data section:

```
$ objdump -s -j .data neon_nights | grep "4a60d0\|4a60e0"
 4a60d0 01110139 2c71722c 1d2e7336 1d2a7325  ...9,qr,..s6.*s%
 4a60e0 2a1d3121 7230713f 42000000 00000000  *.1!r0q?B.......
```

`secret_data` at `0x4a60d0`: `01 11 01 39 2c 71 72 2c 1d 2e 73 36 1d 2a 73 25 2a 1d 31 21 72 30 71 3f`

`xor_key` at `0x4a60e8`: `0x42`

```python
secret = bytes.fromhex('011101392c71722c1d2e73361d2a73252a1d31217230713f')
key = 0x42
flag = ''.join(chr(b ^ key) for b in secret)
print(flag)
```

`CSC{x0r_th3_n30n_l1ght5}`
