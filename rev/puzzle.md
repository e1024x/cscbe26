---
title: "Puzzle"

difficulty: Hard
description: "Push all the boxes onto a goal. Simple enough, ...right?"
flag: "CSC{E4sy_p3asy_pls_g1ve_me_4noTh3R_0ne!}"
---

64-bit stripped ELF. Sokoban game.

```
$ file puzzle
puzzle: ELF 64-bit LSB executable, x86-64, version 1 (SYSV),
        dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2,
        for GNU/Linux 3.2.0, stripped
```

```
$ strings puzzle 
[...]
puts
putchar
system
getchar
printf
tcgetattr
tcsetattr
clear || cls
[47m
[44m
[45m
[40m
[43m
[42m
[46m
Legend:
[47m  [0m Floor
[44m  [0m Player
[45m  [0m Player on Goal
[40m  [0m Wall
[43m  [0m Box
[42m  [0m Goal
[46m  [0m Box on Goal
WASD/Arrow keys to move, Q to quit
####.
# .########
#.** $    #
# .. ##   #
###  @# ###
  # $   #
 $###$ $#
    #   #
    #####
[...]
```


stripped binary, but `_start` tells us main is at `0x40194b`. the game loop:

```
  40194b:   push   %rbp
  401953:   call   401221        # clear + draw board
  401958:   call   4017d6        # compute_hash (returns initial board hash)
  40195d:   mov    %rax,-0x8(%rbp)
  401961:   call   401186        # getchar (raw terminal mode)
  401966:   mov    %eax,-0xc(%rbp)
  401969:   cmpl   $0x71,-0xc(%rbp)    # 'q' = quit
  40196d:   je     401a37
  401973:   cmpl   $0x51,-0xc(%rbp)    # 'Q' = quit
  401982:   call   40167c              # process_input (movement + easter egg)
  401987:   cmpl   $0x77,-0xc(%rbp)    # 'w' = up
  40198d:   cmpl   $0x57,-0xc(%rbp)    # 'W' = up
  401993:   cmpl   $0x41,-0xc(%rbp)    # arrow up
  401999:   mov    $0xffffffff,%esi    # dy=-1, dx=0
  4019aa:   cmpl   $0x73,-0xc(%rbp)    # 's' = down
  4019bc:   mov    $0x1,%esi           # dy=1, dx=0
  ...
  401a16:   call   401419              # check_win
  401a1b:   test   %eax,%eax
  401a1d:   je     401961              # not won, loop
  401a23:   mov    -0x8(%rbp),%rax     # pass initial hash
  401a2a:   call   40188f              # decrypt_and_print_flag
```

so when you win, it calls `decrypt_and_print_flag` with the initial board hash. let me look at `check_win` at `0x401419`:

```
  401419 <check_win>:
  40142f:   movzbl (%rax),%eax      # load board cell
  40144a:   cmp    $0x24,%al        # '$' = box not on goal
  40144c:   jne    401455           # if not a bare box, continue
  40144e:   mov    $0x0,%eax        # found bare box -> not won
  401453:   jmp    40146e           # return 0
  401463:   cmpl   $0xa,-0x4(%rbp)  # row < 11
  401467:   jle    401426           # loop
  401469:   mov    $0x1,%eax        # no bare boxes -> won
```

scans the board for any `$` (box not on goal). if none found, you win.

now `compute_hash` at `0x4017d6`:

```
  4017d6 <compute_hash>:
  4017da:   movq   $0x0,-0x8(%rbp)     # h = 0
  4017e2:   movl   $0x0,-0xc(%rbp)     # row = 0
  4017f4:   movzbl (%rax),%eax         # load cell
  401812:   cmpb   $0x40,-0x11(%rbp)   # '@' player
  401818:   cmpb   $0x2b,-0x11(%rbp)   # '+' player on goal
  40181e:   movb   $0x20,-0x11(%rbp)   # replace with ' '
  401829:   shl    $0x5,%rax           # h * 32
  40182d:   sub    %rdx,%rax           # h * 32 - h = h * 31
  40183a:   add    %rcx,%rax           # h = h * 31 + cell
  401845:   cmpl   $0xa,-0x10(%rbp)    # col <= 10 (11 cols)
  40184f:   cmpl   $0x8,-0xc(%rbp)     # row <= 8 (9 rows)
```

hash = iterate rows 0..8, cols 0..10, do `h = h * 31 + cell_value` (with player replaced by floor). standard polynomial hash

and the PRNG at `0x40185b`:

```
  40185b <prng>:
  40186a:   imul   $0x41c64e6d,%rax,%rax   # seed * 1103515245
  401871:   add    $0x3039,%rax             # + 12345
  401877:   and    $0x7fffffff,%eax         # & 0x7FFFFFFF
```

textbook LCG. `decrypt_and_print_flag` at `0x40188f`:

```
  40188f <decrypt>:
  40189b:   call   4017d6               # initial_hash = compute_hash(board)
  4018a4:   movabs $0xd49491766e1c6e60,%rax  # encrypted bytes 0-7
  4018ae:   movabs $0x6d583c40949c9d5c,%rdx  # encrypted bytes 8-15
  4018c0:   movabs $0x32825362d2e06e4f,%rax  # encrypted bytes 16-23
  4018ca:   movabs $0xd593eabd21f0c8ae,%rdx  # encrypted bytes 24-31
  4018dc:   movabs $0x9086001da580af50,%rax  # encrypted bytes 32-39
  4018f3:   lea    -0x48(%rbp),%rax
  4018fa:   call   40185b               # a = prng(seed1)
  401909:   call   40185b               # b = prng(seed2)
  401915:   xor    -0x6(%rbp),%al       # a ^= b
  401924:   xor    %edx,%eax            # result = encrypted[i] ^ (a ^ b)
  40192f:   call   401030 <putchar>     # print decrypted byte
  401938:   cmpl   $0x27,-0x4(%rbp)     # loop 0..39 (40 bytes)
```

so the flag is 40 bytes encrypted with dual-PRNG XOR. PRNG1 is seeded from the initial board hash (known). PRNG2 is seeded from the solved board hash.

there's a hidden command though. in `process_input` at `0x40167c`:

```
  4016a1:   cmpl   $0x11,-0xc(%rbp)    # check some state == 0x11
  4016ad:   cmp    $0x6f,%eax          # 'o' = open
  4016b0:   jne    4016cd
  4016c7:   mov    %eax,0x2a3b(%rip)   # toggle flag
```

both PRNGs are LCGs. only the low byte of each output is used. PRNG2's seed lives in a 31-bit space but the low-byte truncation collapses it massively. and we have known plaintext: `CSC{`.

```python
encrypted = bytes([
    0x60, 0x6e, 0x1c, 0x6e, 0x76, 0x91, 0x94, 0xd4,
    0x5c, 0x9d, 0x9c, 0x94, 0x40, 0x3c, 0x58, 0x6d,
    0x4f, 0x6e, 0xe0, 0xd2, 0x62, 0x53, 0x82, 0x32,
    0xae, 0xc8, 0xf0, 0x21, 0xbd, 0xea, 0x93, 0xd5,
    0x50, 0xaf, 0x80, 0xa5, 0x1d, 0x00, 0x86, 0x90,
])

def prng(seed):
    seed = (seed * 0x41c64e6d + 0x3039) & 0x7FFFFFFF
    return seed, seed & 0xFF

initial_hash = 0xd07b6ca1b52da5e1

for seed2 in range(2**31):
    s1, s2 = initial_hash, seed2
    s1, a = prng(s1)
    s2, b = prng(s2)
    if encrypted[0] ^ (a ^ b) != ord('C'):
        continue
    s1, a = prng(s1)
    s2, b = prng(s2)
    if encrypted[1] ^ (a ^ b) != ord('S'):
        continue
    s1, a = prng(s1)
    s2, b = prng(s2)
    if encrypted[2] ^ (a ^ b) != ord('C'):
        continue
    s1, a = prng(s1)
    s2, b = prng(s2)
    if encrypted[3] ^ (a ^ b) != ord('{'):
        continue

    sa, sb = initial_hash, seed2
    flag = []
    for i in range(40):
        sa, a = prng(sa)
        sb, b = prng(sb)
        flag.append(encrypted[i] ^ (a ^ b))
    print(bytes(flag).decode())
    break
```

every candidate seed that passes the `CSC{` check produces the same flag. the low-byte truncation means many seeds collapse to identical output sequences. 

```
CSC{E4sy_p3asy_pls_g1ve_me_4noTh3R_0ne!}
```
