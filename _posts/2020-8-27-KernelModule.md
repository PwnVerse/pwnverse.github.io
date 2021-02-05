---
layout: "post"
title: "Kernel Module Programming - 1"
date: 2020-8-27
excerpt: ""
---

# Intro to a kernel module

Modules are pieces of code that can be loaded and unloaded into the kernel upon Demand. They extend the functionality of the kernel without needing to reboot the system. 

Device Driver is also a kernel module. Without modules , we would have to build monolithic kernels and add new functionality directly into the kernel image.

## How do kernel modules get into kernel

When kernel needs a feature that is not present in the kernel , it runs **kernel module daemon** kmod execs **modprobe** to load the module in. modprobe is passed a string in one of two forms. 

1. A module name like `softdog` or `ppp`.
2. A more generic identifier like `char-major-10-30`.


If generic identifiers have aliases , then modprobe knows what the identifier is referring to.

Next it has to checks for any dependencies that the module being loaded has , ie , whether it requires any pther modules to be loaded.

Lastly , modprobe uses **insmod** to first load the prerequisite modules into the kernel and finally the requested module. modprobe directs **insmod** to **/lib/modules/version/**.

insmod -> dumb about location of modules

modprobe -> aware of default location of modules , order of inserting modules etc.

modprobe knows all that as it parses **/lib/modules/version/modules.dep**. For the kernel , I'll be using the now latest linux kernel 5.8 to compile and insert my modules into.

# Kernel Module Programming

## Hello World

Kernel modules must have atleast 2 functions - **init\_module** (called when the module is insmoded into the kernel) and **cleanup\_module** called when the module is rmmoded.

```c

#include <linux/header.h> /*Needed by all modules*/
#include <linux/kernel.h> /* Needed for kernel_info */

int init_module(void)
{
    printk(KERN_INFO "Hello World \n");
    return 0;
}

void cleanup_module(void)
{
    printk(KERN_INFO "Goodbye\n");
}

```

cleanup_module -> undoes whatever init_module did so that the module can be unloaded safely.

## printk()

It's not meant for communication with user , but for logging information or give warnings. Each printk() statement comes with a priority. There are 8 priorities and the kernel has macros for them, which are a part of **linux/kernel.h**. We use high priority printk **KERN\_ALERT** to make printk() print to screen rather than just log to files.

## Info about modules

use **modinfo** to see information of a kernel object file.

Additional details of Makefiles for kernel modules are available at -> `Documentation/kbuild/makefiles.txt`.

All loaded modules are loaded into the kernel and listed in **lsmod** or **cat /proc/modules**.

+ We can rename our init and cleanup modules with **module\_init()** and **module\_exit** macros defined in *linux/init.h*.

```c
/* 
 * hello2.c 
*/

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

static int __init hello2_init(void)
{
    printk(KERN_INFO,"Hello world\n");
    return 0;
}

static int __init hello2_exit(void)
{
    printk(KERN_INFO,"Goodbye\n");
}

module_init(hello2_init);
module_exit(hello2_exit);

```

+ The `__init` macro -> causes init function to be discarded and it's memory be freed once the init function finishes for built-in-drivers but not loadable modules.
+ `__initdata` is for initialising data.
+ `__exit` macro -> built-in-drivers dont require a cleanup function while loadable modules do.

```c

#include <linux/module.h>
/* Needed by all modules */
#include <linux/kernel.h>
/* Needed for KERN_INFO */
#include <linux/init.h>
/* Needed for the macros */

static int hello3_data __initdata = 3;

static int __init hello3_init(void)
{
    printk(KERN_INFO,"Hello world %d\n",hello3_data);
    return 0;
}

static void __exit hello3_exit(void)
{
    printk(KERN_INFO,"Goodbye\n");
}

module_init(hello3_init);
module_exit(hello3_exit);

```

### Licensing of modules

+ MODULE_DESCRIPTION()
+ MODULE_AUTHOR()

```c
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#define DRIVER_AUTHOR "Peter Jay Salzman <p@dirac.org>"
#define DRIVER_DESC "A sample driver"

static int __init init_hello4()
{
    printk(KERN_INFO,"hello\n");
    return 0;
}

static void __exit exit_hello4()
{
    printk("KERN_INFO,"goodbye\n");
}

module_init(init_hello4);
module_exit(exit_hello4);

/* To get rid of taint messages */

MODULE_LICENSE("GPL");

// or

MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESC);

```

### Passing cmd args to module

Declare the variables that will take the args as global and then use **module\_param()** macro.


```c

/*
 * Demontrating command line arguments passing to a module
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/stat.h>
#include <linux/moduleparam.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Cyb0rG");

static short int myshort = 1;
static int myint = 123;
static long int mylong = 4324324;
static char* mystring = "bacdd";
static int myinitArray[2] = {-1, -1};
static int arr_argc = 0;

module_param(myshort, short, S_IUSR | S_IWSUR | S_IRGRP | S_IWGRP);
MODULE_PARAM_DESC(myshort,"A short integer");
module_param(myint, int , S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
MODULE_PARAM_DESC(myint, "An integer");
module_param(mylong, long, S_IRUSR);
MODULE_PARM_DESC(mylong, "A long integer");
module_param(mystring, charp, 0000);
MODULE_PARM_DESC(mystring, "A character string");


/* Description of module param array
 * 
 * module_param_array(name,type,num,perm)
 * name -> array's name
 * type -> data type of it's elements
 * num  -> pointer to number of elements of array initialized by user at module load time
 * perms -> permission bits
 */

module_param_arrar(myintArray,int,&arr_argc,0000);
MODULE_PARAM_DESC(myintArray,"Array of Integers");

static int __init hello5_init(void)
{
    int i;
    printk(KERN_INFO "Hello, world 5\n=============\n");
    printk(KERN_INFO "myshort is a short integer: %hd\n", myshort);
    printk(KERN_INFO "myint is an integer: %d\n", myint);
    printk(KERN_INFO "mylong is a long integer: %ld\n", mylong);
    printk(KERN_INFO "mystring is a string: %s\n", mystring);
    for(i = 0; i< sizeof myintArray/ sizeof(int); i++)
    {
        printk(KERN_INFO, "myintArray[%d] = %d\n",i, myintArray[i]);
    }
    printk(KERN_INFO,"got %d args for myintArray \n",arr_argc);
    return 0;
}

static void __exit hello5_exit(void)
{
    printk(KERN_INFO,"Goodbye");
}

module_init(hello5_init);
module_init(hello5_exit);

```

and finally, compiling all the hello-worlds , we can create a Makefile specifying the kernel source that we're gonna be compiling the modules for.

```c
ifneq (${KERNELRELEASE},)
obj-m += helloworld.o
obj-m += hello2.o
obj-m += hello3.o
obj-m += hello4.o
obj-m += hello5.o
# Assignment module here
else
KERNEL_SOURCE := ../kernel_source/linux-4.18.16/
PWD := $(shell pwd)
default:
	# Compile for the same architecture as the host machine
	$(MAKE) -C $(KERNEL_SOURCE) SUBDIRS=${PWD} modules
arm:
	# Cross compile for arm64/aarch64 architecture - Cross compiler needed !!!  
	ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- $(MAKE) -C $(KERNEL_SOURCE) SUBDIRS=${PWD} modules
clean:
# Cleans the Directory - removes all the files that were created
	$(MAKE) -C $(KERNEL_SOURCE) SUBDIRS=${PWD} clean

endif

```

## Compiling the custom kernel and booting into it with qemu

For now , I've compiled linux kernel 4.18 , which is condiderably old , but enough to run my modules.

Inside the source directory , we just have to do **sudo make -j $(nproc)** to compile the kernel for us. The *nproc* specifying the make process to run in multiple threads for faster compilation speeds.

Now comes the tricky part. To boot into the kernel , all you need is 

+ A kernel **bzImage** which is short for a compressed kernel image. 
+ We'll also need a init directory which would run an **init** script for us to get our kernel to boot. This is where we copy our compiled modules and they get insmoded through the init script inside the rootfs.img.

We can acquire a rootfs.img from any of the CTF challenges and work with it for now from [here](https://drive.google.com/file/d/1kwOjYVNHyaplhzbKRZFJ_wcIuUwVKXwL/view?usp=sharing)

### Extracting rootfs.img

```sh
$ mkdir rootfs && cd rootfs
$ cat ../rootfs.cpio | cpio --extract

```

Now you can copy your modules into the rootfs directory and pack it again into it's compresses *img* format.

Dont forget to edit the **init** script to insmod the modules that you've copied to the rootfds folder
{: .notice}

### Packing rootfs.img

From the directory *rootfs* that we created just a few moments ago , do 

```sh
$ find . | cpio -o -H newc > ../rootfs.cpio
$ cd ../ && rm -dR rootfs
```

Now we're ready to boot into our newly compiled kernel with our modules loaded.

### Booting with qemu

From inside the kernel source directory, fire up qemu with appropriate paths for all arguments.

Make sure you specify the path of rootfs.img that we acquired just now.
{: .notice}

```sh
#!/bin/bash

qemu-system-x86_64 \
    -kernel arch/x86_64/boot/bzImage \
    -nographic \
    -append "console=ttyS0" \
    -initrd rootfs.img \
    -m 512 \
    --enable-kvm \
    -cpu host \

```
This script should fire up our kernel , **lsmod** should successfully show our loaded modules and **dsmg -r | tail -20** should be sufficient to show the functionality of our loaded modules.

### No headers and we use printk??

In the hello world example, you might have noticed that we used a function, printk() but didn't include a standard I/O library. That's because modules are object files whose symbols get resolved upon insmod'ing. The definition of these functions comes from the kernel itself.
