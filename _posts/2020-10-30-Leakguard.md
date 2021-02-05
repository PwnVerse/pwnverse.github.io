---
layout: "post"
title: Leakguard - HackTheVote 2020
date: 2020-10-30 14:20:00
tags: [Heap,UAF,Integer Overflow,CTF]
---

# tl;dr

+ overflow the `char` candle counter stored in the wax structure and trigger uaf.
+ Use the uaf to trigger double free and get shell.

**Challenge Points:** 385
**Solves:** 2

We had a great time this weekend playing this year's edition of HackTheVote. Since the CTF was conducted by RPISEC , nothing easy could be expected. I spent most of my time during the CTF on the challenge leakguard but we couldn't solve it during the CTF. But when I took sometime off and tried it , I finally solved it :). 

## Challenge description

We'd been given the challenge binary , the **libc 2.27** and a mysterious library which is being preloaded to run with the binary , the **leakguard.so**.

## Initial analysis

Let's have a quick look at `checksec`.

```sh
CANARY    : disabled
FORTIFY   : disabled
NX        : ENABLED
PIE       : ENABLED
RELRO     : FULL
```

## Reversing the shared object

An interesting share object is shipped along with the binary executable. Here's what it does:

+ Wrapper around `__GI_libc_write` internally called in every call to `puts`.
+ Reads data from `/proc/self/maps` which contains the virtual memory maps of the binary. (Pretty much `vmmap` of `gdb`)
+ Parse through the string which contains the data to be printed and check if anywhere , a valid memory address is present, if so , null the address number of bytes. It stops at null.

## Reversing the binary

The `candles` binary has standard heap functions which are as follows : 

1. `Add_wax`

+ Check for an empty element in the bss `wax` table.
+ Subsequently,  take input for choice of `oil` and `dye`.
+ Malloc a chunk of size `0x18` , then create a structure as follows -

```c
struct wax{
candle_count;
long* ptr_to_oil_name;
long* ptr_to_dye_name;
};
```

Initially , while adding a wax , the `candle_count` is set to **1**.

2. `Remove_wax`

+ Reduce the candle reference counter , check if it is 0 , and if so , free the wax structure ,else return without freeing the wax structure.
+ Null out the wax pointer in the `wax` bss table.

3. `Add candle`

+ Take input of the index of wax to be associated with the candle. 
+ Malloc a candle structure of size `0x18`.
+ Read `0x10` into the candle structure.
+ Increment the candle reference counter in the respective `wax` structure.

The structure of candle structure is as follows :

```c
struct candle {

char name[0x10];
unsigned char* reference_counter_ptr;
};
```

4. `View candle`

+ Print data of all candles but there's an additional check here. The `leakguard.so` comes into picture in the every call to `puts`. Since `puts` internally calls `__GI_libc_write` and `leakguard` is basically a wrapper around `__GI_libc_write` function.
+ If data contains a memory address , it gets nulled out :(.

5. `Remove_candle`

+ Check if candle reference pointer is null or not , if null , reduce the candle count in the linked structure.
+ Check if the candle count linked to the wax structure is 0 or not , if 0 , free the wax structure **without nulling out** the wax pointer on the wax `bss` table.
+ Finally, free the `candle` and null out the candle pointer.

Enough of reversing , let's get to some pwn business.

## Vulnerability

During the CTF , we were able to find out the bug but there's a cool way by which it has to be triggered. The bug is that , if we give `0x10` bytes for the candle name,  and try to print name , `puts` nulls out the `candle reference count` pointer. So you might ask , what is so useful about it? Well , remember in the `Remove candle` function , if this reference pointer is found to be nulled, we skip the whole part of decrementing the count altogether. We only free the candle pointer and null out it's subsequent bss entry.

## Triggering the char overflow

Another important thing to note is that candle count is a `char` meaning it is bound to overflow. Now that we can prevent the decrement of candle count , we can very well trigger the overflow , all thanks to the leakguard :).

Once we trigger the overflow,  the candle counter resets and finally we can free the `wax` pointer without nulling out it's subsequent memory. Hence we triggered a use after free.

But wait , we're missing out on something very important , the **leaks**.

## Leaks

Even if leakguard does a good job by nulling a valid memory address , it cannot prevent partial memory leaks. Yes , you heard it right.

We can leak by overwriting the last 2 bytes of a heap address to make it an invalid memory address thus safely bypassing leakguard.
To get proper leaks , we might have to resort to methods like binary search to fix the invalid addresses that we leak or in worst cases , bruteforce. So, what about libc??

Leak code segment address , then when we add a candle , the **free wax structure** is taken for allocation. Hence , we can change the contents of the structure. Recollect that the structure has pointers to the names of oil and dye. If we overwrite any of the pointer to the GOT address of `stdout` (which is there in bss) , we can leak libc in the subsequent printing of candle names.

## Getting that shell

Now that you have a Use After Free , a libc leak and what's more, the provided libc is 2.27 hence no double free checks (phew!),
Isn't that enough to pwn this binary now?

Once we get libc leak , we take the following steps to get shell :

+ Overwrite the reference counter in the wax structure with `0x100` such that last byte is null.
+ Delete wax structure to free it.
+ Delete an intermediate candle.
+ Now delete a candle linked to the wax structure which was freed , since reference counter was 1 , it will become 0 and free the struct again.
+ Now add candle to get our free wax structure back.
+ Overwrite `fd` with `__free_hook`.
+ After another allocation , we get allocation at `__free_hook` itself,  overwrite that with `system`.

Wait,  doing that will null the address of `system` since `__free_hook` is now a candle. Thinking a little , we can get allocation at `__free_hook - 1` , overwrite first byte with `\x00` so that we bypass the leakguard and hence overwrite `__free_hook` with system.

Add a candle with data as `/bin/sh\0` and free that candle to get shell.

## Conclusion

The idea of triggering a uaf with a char overflow is really novel. I had a great time solving the challenge. All in all ,awesome challenge , awesome idea , kudos to the author **pernicious** for such a good challenge and kudos to **RPISEC** for such a wonderful CTF.

Here's the exploit script - [Exploit](https://gist.github.com/PwnVerse/b455bc609f5f95e7808b4c0789f8ff13)
