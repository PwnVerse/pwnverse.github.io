---
layout: "post"
title: "Mitigations of the Linux Kernel"
date: 2021-2-26
tags: [Linux Kernel,Mitigations]
---

I've been looking into some linux kernel lately and this blog post is to get familiar with all kernel mitigations like `SMEP` , `SMAP` , `KPTI` and `FG-KASLR`. This post is a beginner friendly one (as I myself am a noob).

# The story of kernel mitigations

The linux kernel has come a long way from being a primitive micro kernel to a super powerful (and relatively secure) micro kernel. Back in the early 90's there were almost no protections in the baby linux kernel. If an attacker gets code execution in the kernel , the attacker becomes capable of running code in the very ring zero ie, with highest possible privileges (root). Since the linux kernel is a large piece of software, so it has a lot of attack vectors/structures which can be used to immediately escalate our privileges to root (another post on attack vectors in kernel soon).

One thing that makes kernel exploitation so interesting is that you control the entire userspace operations , you have to make any possible function calls, leak kernel pointers, overwrite useful structures in the kernel and get root.

## Mitigation #1 - Ret2user

For those familiar with the technique of `ret2shellcode` in userspace exploitation , this is almost the same stuff. If you have a null pointer dereference in older kernels , you can easily get root as the saying goes "One null deref can root them all". 

So, a mitigation against this technique was `KERNEXEC` which basically sets syscall table, Interrupt Descriptor Table, Global Descriptor Table, some page tables to `RO` and set `data pages` to NX. As we can see, making kernel pages RO is super helpful to minimizing the attack surfaces and [ret2dir](https://cs.brown.edu/~vpk/papers/ret2dir.sec14.pdf) attacks.

Following `KERNEXEC`, the well known `SMEP` mitigation had rolled out to provide a subset of functions of `KERNEXEC`. `SMEP` prevents stuff like mmaping and executing shellcode to get root. It basically prevents execution of any page which is not a part of the kernel space. But unlike `KERNEXEC`, it doesnt prevent exploitation of `RWX` or important kernel data structure. In kernel, this is enabled by setting the `20th bit` of the `CR4` control register.

## Bypassing SMEP

With some ROP , we can unset the 20th of the CR4 register, and to our delight, there's a function in the kernel which does exactly the same thing, `mov cr4,edi`and the function is `native_write_cr4`. 

But wait there's a cakehole we're going towards. In reality, the latest kernels have this super cool feature which `pins` or `hardcodes` the `CR4` register thus attempting to change it is practically impossible. Hence, we'll have to ROP our way to previlege escalation with `commit_creds(prepare_kernel_cred(0))`.

Here's the relevant code to end our ecstasy.

```c
void native_write_cr4(unsigned long val)
{
	unsigned long bits_changed = 0;

set_register:
	asm volatile("mov %0,%%cr4": "+r" (val) : : "memory");

	if (static_branch_likely(&cr_pinning)) {
		if (unlikely((val & cr4_pinned_mask) != cr4_pinned_bits)) {
			bits_changed = (val & cr4_pinned_mask) ^ cr4_pinned_bits;
			val = (val & ~cr4_pinned_mask) | cr4_pinned_bits;
			goto set_register;
		}
		/* Warn after we've corrected the changed bits. */
		WARN_ONCE(bits_changed, "pinned CR4 bits changed: 0x%lx!?\n",
			  bits_changed);
	}
}
```

Hence, to bypass `SMEP`, we can do some ROP to set `commit_creds(prepare_kernel_creds(0))`.

## Mitigation #2 - Accessing User memory when executing kernel code

Any attempt by user space program to examine or modify the kernel's part of the address space will result in a plain segfault as we've seen until now. But the access in the other direction (kernel modifying userspace memory) is much less controlled. when the processor is in kernel mode, it has full access to any address that is valid in the page tables. Or nearly full access; the processor will still not normally allow writes to read-only memory, but that check can be disabled when the need arises.

Intel's `Supervisor Mode Access Prevention` (SMAP) which came in around 2012  with the linux kernel 3.7 completely changed this situation. This extension defines a new SMAP bit in the `CR4 control register` (21st bit) which when set, any attempt to access user-space memory while running in a privileged mode will lead to a page fault.

Naturally, there are times when the kernel needs to work with user-space memory. To that end, Intel has defined a separate `AC` flag that controls the SMAP feature. If the AC flag is set, SMAP protection is in force, otherwise access to user-space memory is allowed. To achieve this , two new instructions (`STAC` and `CLAC`) were introduced to modify that flag quickly. User-space access functions (`get_user()`, for example, or `copy_to_user()`) clearly need to have user-space access enabled.

Well, now you may ask, why do we even need this mitigation if the kernel itself can modify it's own access to the userspace memory. The answer is it can block a whole class of exploits where the kernel is fooled into reading from (or **writing** to) user-space memory by mistake. 

## Bypassing SMAP

The `SMAP` can be bypassed with kernel based `Return oriented Programming` only in the kernel space to get root.

## Mitigation #3 - Address Space Randomization in the kernel

Not very long from now, in 2014, the `KASLR` was finally merged into the mainstream vanilla linux kernel 3.14. As one can expects, it randomizes entire address space from the base address. But as you can probably think now, defeating KASLR is pretty trivial since virtually every kernel address is offsetable from the base address. So, this technique wasn't really a hit in the community.

## Mitigation #4 - Page Table Isolation

Page Table Isolation (pti, previously known as KAISER) is a countermeasure against attacks on the shared user/kernel address space such as the [Meltdown](https://meltdownattack.com/). This mitigation came into the linux kernel 4.15. `Page-table` entries contain permission bits describing how the memory they describe can be accessed; these bits are, naturally, set to prevent user space from accessing kernel pages, even though those pages are mapped into the address space.

But, a number of hardware level bugs allow a user-space hacker to determine whether a given kernel-space address is mapped or not, regardless of whether any page mapped at that address is accessible. This basic information can be used to defeat KASLR.

On a system with 4 levels of page tables ,the top level is the `Page Global Directory` (PGD), below that come the `Page upper directory` (PUD), `Page Middle Directory` (PMD)  and `Page Table Entries` (PTE). Page-table resolution normally traverses the entire page table tree to find the `PTE` of interest. The `PTE` is actually used to translate `virtual memory address` (CPU generated) to `physical memory address`(actual location on RAM).

One of the first steps taken in the `KPTI` patch is to create a second `Page Global Directory` one for kernel space and the other one when the program is running in userspace. So , in whole, the KPTI separates kernel and user page tables.

## Bypassing KPTI

+ Using a `KPTI trampoline` this method is based on the idea that if a syscall returns normally, there must be a piece of code in the kernel that will swap the page tables back to the userland ones, so we will try to reuse that code to our purpose. The function is `swapgs_restore_regs_and_return_to_usermode`, and what it does is to swap page tables, `swapgs` and `iretq`.

+ Another weird technique is leveraging the power of `signal handlers`. So, when we try to return to usermode and execute code, the page table still being used is the `kernel page table` which is by default prevented to execute code in the usermode and hence a `segfault` happens in the **userspace**. If a segfault handler is used instead, and to handle the `SIGSEGV` signal, if we call our `shell` function, we get root shell given that we have already set the `commit_creds(prepare_kernel_creds(0))`.

## Mitigation #5 - Function Granular Kernel Address Space Randomization

This is the latest mitigation of the linux kernel version 5.11. With FGKASLR, individual kernel functions are reordered so that even if the kernel's randomized based address is revealed, an attacker still wouldn't know the location in memory of particular kernel functions as the relative addresses will be different. `FGKASLR` reorders the functions at boot time and is a further improvement to Linux security for attacks that require known positions within the kernel memory.

## Bypassing FG-KASLR

The only way to bypass FGKASLR is to search for constant offset functions by leaking multiple pointers in various parts of the desired kernel memory. There are a few functions which are not effected by the FGKASLR at all, so we hunt for such functions.


# Conclusion

Linux has come a long way now with all these mitigations. Yet, vulnerabilites and bypasses never stop coming into the way of security and hence newer mitigations are only a few lines of code away.

### References

+ [FGKASLR](https://www.phoronix.com/scan.php?page=news_item&px=Intel-Linux-FGKASLR-Proposal)
+ [KPTI Trampoline](https://trungnguyen1909.github.io/blog/post/matesctf/KSMASH/)
+ [KPTI](https://lwn.net/Articles/741878/)
+ [SMAP](https://lwn.net/Articles/517475/)
+ [SMEP](https://github.com/pr0cf5/kernel-exploit-practice/tree/master/bypass-smep)
+ [An Awesome blog post](https://lkmidas.github.io/posts/20210128-linux-kernel-pwn-part-2/)
