---
layout: "post"
title: "Understanding the Userfaultfd Syscall"
date: 2020-8-04
exerpt: ""
tags: [Linux, OS]
---

Linux provides a bunch of syscalls among which only a few are known and used often.Most of the syscalls we use are always wrapped around cheesy glibc wrappers (functions). But there are a few syscalls which have no such glibc wrappers and one of the most interesting of them is the **Userfaultfd** syscall.

Hence , I dedicate this post to kind of clear my own bemusement of this wonderful syscall.

Ok so the very first thing that comes to the mind of any layperson.

## WHAT IS USERFAULTFD SYSCALL

I would like to shamelessly site the definition of userfaultfd from its very own **man** page (trust me, there's no better definition available other than this one :).

```sh
userfaultfd()  creates a new userfaultfd object that can be used for delegation of page-fault handling
to a user-space application, and returns a file descriptor that refers to the  new  object.

```

Hey wait , what is a page fault?

In the event of an attempt of accessing a page which is no longer available in main memory , a kernel interrupt called **page fault** is setup which kind of gets back the page you were trying to access back into main memory from the secondary memory.
{: .notice}


So basically , we use userfaultfd to keep track of page faults , which is kernel level stuff. 

But how does userfaultfd do that??

## How Does USERFAULTFD do what it does?

So once we create the userfaultfd object , we have to configure it using **ioctl**.

Once the userfaultfd object is configured , the application can use **read** to recieve userfaultfd notifications. The read can be blocking or non-blocking depending on the flags.

### Some intricate internals

The userfaultfd is designed to allow a separate thread in a multithreaded program to perform user-space paging for other threads in the process.

When a page that is registered with userfaultfd gives a page fault , the faulting thread is put to sleep and an event is generated that can be read via the userfaultfd file descriptor.

The fault handling thread reads events from this file descriptor and services them using the operations described in **ioctl\_userfaultfd**. Also , while servicing the page fault events , the fault-handling thread can trigger a wake-up for the sleeping thread.

### An Ambiguity

It is possible for the faulting threads and the faul-handling threads to run in context of different processes. 

In this case, these threads may belong to different programs, and the program that executes the faulting threads will not necessarily cooperate with the thread that handles page faults.
{: .notice}

In such a non-cooperative mode , the process that monitors userfaultfd and handles page faults needs to be aware of the changes in the virtual memory layout of the faulting process to avoid memory corruption.

### What all information Userfaultfd notifies us

1. Notify the faulting threads about changes in virtual memory layout of the faulting process.

2. If faulting thread invokes **fork()** , the userfaultfd objects maybe duplicated in the child process and we get notified about the uffd objects in the child processes using **UFFD\_EVENT\_FORK**. This allows user-space paging in the child process.


### SYNCHRONIZING Userfaultfd

The userfaultfd manager should carefully synchronize calls to **UFFDIO\_COPY** with the processing of events.The noncooperative events asynchronously resume execution once the userfaultfd reads into its file descriptor.

### Handshake Between Kernel and Userspace

1. After the creation of userfaultfd object , the application must enable it using the **UFFDIO\_API\_ioctl** operation. This operation allows handshake between kernel and userspace to determine the API version and supported features.

2. Then , the application registers memory address ranges using **UFFDIO\_REGISTER\ ioctl**. 

3. After successful completion of **UFFDIO\_REGISTER** , a page fault occuring in the requested memory range , will be forwarded by the kernel to the user-space application. The application can then use the **UFFDIO\_COPY** or **UFFDIO\_ZEROPAGE ioctl** operations to resolve page faults.

### Using Userfaultfd only to detect pagefaults

If the application sets **UFFD\_FEATURE\_SIGBUS** using **UFFDIO\_API ioctl** , a **SIGBUS** is delivered instead of any other notifications about page faults. 

### Reading from the userfaultfd structure

Each read from the userfaultfd fd returns one or more **uffd\_msg** structs, each of which describe a page-fault event or an even required for the non-cooperative userfaultfd usage.


```c
         struct uffd_msg {
               __u8  event;            /* Type of event */
               ...
               union {
                   struct {
                       __u64 flags;    /* Flags describing fault */
                       __u64 address;  /* Faulting address */
                   } pagefault;

                   struct {            /* Since Linux 4.11 */
                       __u32 ufd;      /* Userfault file descriptor
                                          of the child process */
                   } fork;

                   struct {            /* Since Linux 4.11 */
                       __u64 from;     /* Old address of remapped area */
                       __u64 to;       /* New address of remapped area */
                       __u64 len;      /* Original mapping length */
                   } remap;

                   struct {            /* Since Linux 4.11 */
                       __u64 start;    /* Start address of removed area */
                       __u64 end;      /* End address of removed area */
                   } remove;
                   ...
               } arg;

               /* Padding fields omitted */
           } __packed;



```

If multiple events are available and the supplied buffer is large enough , read returns as many events as the size of the buffer. Else if the buffer is smaller than the size of the uffd_msg struct , then it returns error.

Each of the fields of the structure have been described in detail in the man page of userfaultfd.


