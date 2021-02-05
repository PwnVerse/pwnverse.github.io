---
layout: "post"
title: UAF - HackTheBox 2020
date: 2020-11-22 24:00:00
tags: [Heap, tcache dup to stack, CTF]
---

# tl;dr

+ Leak `libc` and `heap` addresses , use the edit option to get allocation at tcache structure.
+ Create fake tcache entry for `stdout` file structure , get allocation at `stdout` to leak `stack` from `environ`.
+ Free and allocate tcache structure to re-edit , this time get allocation at `return address` on stack , finally execute mprotect rop chain and `orw` shellcode.

**Challenge Points:** 1000
**Solves:** 5

HackTheBox had really interesting heap challenges and this is one of the challenges we solved during the CTF.

## Initial analysis

We had been provided with the binary as well as the source code for a standard CTF-style menu driven program. The libc provided inside the docker was `2.32`.

```sh
CANARY    : ENABLED
FORTIFY   : disabled
NX        : ENABLED
PIE       : ENABLED
RELRO     : FULL
```

## Reversing

Since source code was provided , it was pretty self explanatory. The program implements `seccomp rules` and the following system calls have been allowed.

```sh
	Allow(brk),
	Allow(mmap),
	Allow(exit_group),
	Allow(mmap),
	Allow(munmap),
	Allow(read),
	Allow(write),
	Allow(getdents),
	Allow(mprotect),
	Allow(open),
	Allow(sendfile),
``` 

The program implements the structure of a custom chunk provided by malloc.

```c
typedef struct _chunk {
	uint32_t size;
	void * ptr;
	bool in_use;
} chunk;
```

It has `size`, a void* `ptr` and a flag `in_use`.

`Alloc` :

+ The maximum size of an allocated chunk should not exceed `0x400`.
+ After allocation, chunk's first field `ptr` is set to NULL , data is read into the memory.
+ Subsequently , the `in_use` flag is set to true and size is set.

`Delete` : 

+ `idx` should be less than or equal to `0x10`.
+ This option prints data and then frees the memory without nulling out the pointer.
+ Finally , it sets the `in_use` flag to false.

`Edit` :

+ Lets us edit a byte of a chunk at an index only once.

## Bug

The `Delete` option has a simple Use after free.

## Getting heap and libc leak

We can only view a chunk we are about to free. To get libc leak , we can simply fill a tcache bin corresponding to small bin size. Then, after we have a chunk in the unsorted bin  ,we can add a small chunk , which will be allocated from the unsorted bin , free it to get libc.

For heap , its actually a little more complicated than we expected. Since libc is 2.32 , the `fd` pointer of a tcache chunk will be encoded with this algorithm.

![](https://lh5.googleusercontent.com/proxy/6WVq2hd0LuqnQLN0K6xkaYaZ1DtYaQPW9I-svrS95apQQI_sw16cnQ6iNaKfYRN_cZr1kV947ps16uBDo6VB0GhjzytXx3yJgPg7zE93jBZ8Tp3xQfhdYEgXJn3-s4vH=w1200-h630-p-k-no-nu)
{: .image-pull-right}

We can't use tcache bins to leak heap as in tcache , the first 8 bytes will be encoded , and the next 8 bytes which stores the address of `tcache structure`. Moreover , the malloc algorithm clears the address of `tcache structure` and hence , we can't leak heap.So , our only option is to use unsorted bins as malloc does not clear addresses of unsorted bin. If we send two chunks into unsorted bin , the fd and bk pointers will be libc and heap. So , there's a chance we can leak libc here.

When we allocate memory from unsorted bin , for some reason , it replaces the heap pointer with a libc pointer thus taking us further away from leaking heap.

During the CTF , we were stuck here for sometime. Soon enough , we realized that if we can merge **two unsorted bin** chunks , the fd and bk of the chunk being merged are not cleared. Hence , in the next allocation ,we can actually overlap with our heap leak.

```sh
0x561195df27b0:	0x0000000000000000	0x0000000000000141 -> consolidated unsorted bin ( 0xa0 + 0xa0 )
0x561195df27c0:	0x0000561195df26f0	0x00007f0be6ddec00
0x561195df27d0:	0x0000000000000000	0x0000000000000000
0x561195df27e0:	0x0000000000000000	0x0000000000000000
0x561195df27f0:	0x0000000000000000	0x0000000000000000
0x561195df2800:	0x0000000000000000	0x0000000000000000
0x561195df2810:	0x0000000000000000	0x0000000000000000
0x561195df2820:	0x0000000000000000	0x0000000000000000
0x561195df2830:	0x0000000000000000	0x0000000000000000
0x561195df2840:	0x0000000000000000	0x0000000000000000
0x561195df2850:	0x0000000000000000	0x00000000000000a1 -> Overlapping chunk that is merged with the above chunk
0x561195df2860:	0x0000561195df26f0	0x00007f0be6ddec00 -> fd (heap) and bk are not cleared
0x561195df2870:	0x0000000000000000	0x0000000000000000
0x561195df2880:	0x0000000000000000	0x0000000000000000
0x561195df2890:	0x0000000000000000	0x0000000000000000
0x561195df28a0:	0x0000000000000000	0x0000000000000000
0x561195df28b0:	0x0000000000000000	0x0000000000000000
0x561195df28c0:	0x0000000000000000	0x0000000000000000
0x561195df28d0:	0x0000000000000000	0x0000000000000000
0x561195df28e0:	0x0000000000000000	0x0000000000000000
0x561195df28f0:	0x0000000000000140	0x0000000000000020
```

Now , we can fill memory until the heap address , and then free it to leak heap.

## Allocation at stack

We have libc and heap leaks ,now what? The next step is to use our vulnerable edit function to edit a byte of forward pointer. We could choose to target malloc or free hook , but remember , there's seccomp enabled and I honestly was too lazy to find gadgets for following a jump oriented programming approach with complex rop.

So again , we were stuck at this point. One idea which we were pondering upon was to get allocation at stdout `vtables` [vtables are writeable in libc 2.32 surprisingly]. We could get code execution multiple times , but we could not chain any stack pivoting gadgets since registers were being corrupted before getting code execution multiple times. Hence,  we had to drop this idea as well.

Finally , we planned to get allocation at tcache structure. We can do something like this. 

+ Edit the last byte of a free chunk to point to a fake chunk whose `fd` pointer is encoded with the address of tcache structure.
 
This way , we had leveraged arbitrary write using a single byte edit. But , we needed more than one arbitrary writes , the answer to which was the tcache structure.

We could free the tcache structure and reallocate it to edit it as many times as we want.

Our idea was to get allocation the return address of the `alloc` function so that we can rop and mprotect heap to get shellcode execution. For that , what we can do is -

+ Edit tcache count and the corresponding tcache entry to that count with the address of `stdout` file structure.
+ Get allocation at `stdout` , the plan is to leak stack from `environ`. 
+ Overwrite `stdout->flags` with `0xfbad3887` 
+ Overwrite `IO_read_ptr` , `IO_read_end` and `_IO_read_base` with NULL.
+ Overwrite `IO_write_base` with address of `environ`.
+ Overwrite `IO_write_end` with address of `environ+0x10`.

Detailed information about arbitrary memory read from file structures [here](https://gsec.hitb.org/materials/sg2018/D1%20-%20FILE%20Structures%20-%20Another%20Binary%20Exploitation%20Technique%20-%20An-Jie%20Yang.pdf)

Awesome , we have stack leak , now , re-edit tcache structure to get allocation at return address. Make sure the stack address should be 16-byte aligned else malloc will abort due to alignment issues.

## Shellcode and flag

All set and done , we get allocation at return address. From here , it's a fairly simple problem to mprotect `heap` and give an `orw` shellcode. But wait , there is one problem.

Looking at the `Dockerfile` we saw , this line

```sh
CMD mv /home/ctf/flag.txt /home/ctf/[REDACTED]_flag.txt
```

So , the flag file name is unknown now. Looking at seccomp filters , we see that , we have `getdents` syscall allowed which is exactly what we need now. 

Getdents allows us to list all files in a directory. We will choose `.` directory and get all file names.

The shellcode for getdents is 

```sh

        /* open('.') */
        mov rdi, 0x2e
        push 0
        push rdi
        push rsp
        pop rdi
        mov rax, 2
        xor rsi, rsi
        cdq
        syscall

        /* getdents */
        mov rdi, rax
        mov rax, 0x4e
        lea rsi, [rbp-0x70]
        cdq
        mov dh, 0x10
        syscall

        /* write */
        mov rdi, 1
        lea rsi, [rbp-0x70]
        mov rdx, rax
        mov rax, 1
        syscall
```

Once , we get the flag file name , we can do a simple `orw` shellcode.

PS : In the end , we found out that flag file name is `/home/ctf/flag.txt` itself , which was pretty frustrating :/

## Conclusion

There could have been many possibilities to mprotect and execute shellcode , we choose the good old stack to get it done. All in all , it was a really good challenge.

[Here](https://gist.github.com/PwnVerse/2f1fea428f3850d72d2ac9ac3d9c2c78) is the exploit script.

