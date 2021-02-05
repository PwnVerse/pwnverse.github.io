---
layout: post
title: "Short Notes on Internals Of the Intel PIN"
date: 2020-06-10
tags: [PIN, Basics]
---

I had a little introduction to a bit of formal Binary Instrumentation and was very fascinated by how PIN works in Dynamic Binary Instrumentation.

In this post , I would like to discuss a few internals of how PIN works.

## TL;DR OF WHAT EXACTLY IS PIN

**Dynamic Binary Instrumentation** [DBI] Engines monitor binaries as they execute and instrument the instruction stream, they dont require disassembly or binary rewriting like **Static Binary Instrumentation** [SBI] which makes them **less** error-prone.

Pin is one such famous DBI Engine.

Before heading on , let us know about the architecture of a DBI system.

### Architecture Of A DBI System

The DBI engine exposes an **API** that lets programmers write *user-defined DBI tools* that specify which code should be instrumented and how.

* Before DBI engine starts the main application process, it allows the DBI tool to initialize itself.
* Next , the function tells DBI engine that it's done initializing and ready to start the app.

The DBI engine never runs the application process directly but instead runs code in a [code cache](https://www.baeldung.com/jvm-code-cache#:~:text=What%20Is%20the%20Code%20Cache,of%20the%20code%20cache%20area.) that contains all the instrumented code.
{: .notice}

* After instrumenting the code , the DBI engine compiles it with a **Just-In Time [JIT]** compiler which re-optimizes the code and stores the compiled code in code cache.

> Note that unlike most compilers , the JIT compiler in DBI engine doesn't translate the code into a different language; it just compiles from native machine code to native machine code.

Once compiled code is stored and used from code cache and doesn't have to be recompiled again.

* DBI engines like **PIN** , **DynamoRIO** , **Dyninst** and **PEBIL** reduce runtime overhead by rewriting control-flow instructions when possible , so they jump directly , to the next block in the code cache without any intervention of the DBI system.

* When the direct jumps to code cache are not possible , the rewritten instructions return control to the DBI engine so that it can prepare and start the next code chunk.

While most instructions run natively in the code cache , the DBI engine may emulate some instructions instead of running them directly. **PIN** does this exquisitely for system calls like **execve** that require special handling by DBI engine.
{: .notice}

* The instrumented code contains **Callbacks** to functions in the DBI tool that observe or modify the code's behaviour.

Now that we're familiar with the workings DBI engine , let's get our hands dirty with **PIN internals**.

## PIN INTERNALS

Pin fetches and JIT-compiles at **trace granularity** , a basic block-like abstraction that can be entered only at top but may contain multiple exits, unlike regular basic blocks.

### TRACE

Pin defines a trace as a straight-line instruction sequence that ends when it hits an unconditional control transfer or reaches a predefined maximum length or number of conditional control-flow instructions.

> Although PIN always JIT-compiles code at trace granularity , it allows you to instrument code at many granularities , including **instruction**, **basic block** , **trace** , **function** and **complete executable[image]**.

The DBI tools we implement with PIN are called **Pintools** , which are shared libraries that we write with in C/C++ using Pin API.

The Pintool consists of 2 components.

1. **Instrumentation Routines**

    * Tell which Pin which instrumentation code to add where.
    * These functions run only the first time Pin encounters a particular piece of code that's not yet instrumented.

2. **Analysis Routines**

    * To instrument code , the instrumentation routines install **callbacks** to analysis routines.

**CallBacks** contain the actual instrumentation code and are called everytime an instrumented code sequence runs.
{: .notice}

Well, now it's time to play around with Pin. I came across a practical example to learn a bit more on the internals of PIN.
Let's see what that is.

## PROFILING WITH PIN

* The profiling tool records statistics about a program's execution to help optimize that program.

* It counts the number of executed instructions and the no. of times basic blocks , functions and syscalls are involved.

* Pintools can implement tool-specific command line options , which are called **knobs** in pin's slang.

* There is a dedicated class called **KNOB Class** that we can use to create command line options. We'll analyse the example implementations in detail.

```cpp

//profiler.cpp

#include "pin.H"

KNOB<bool> ProfileCalls(KNOB_MODE_WRITEONCE,"pintool","c","o","Profile function calls");
KNOB<bool> ProfileSyscalls(KNOB_MODE_WRITEONCE,"pintool","s","o","Profile syscalls");

```

Here there are two options of the type **KNOB<bool>** called **ProfileCalls** and **ProfileSyscalls**.

> The options use mode **KNOB\_MODE\_WRITEONCE** because they're Boolean Flags that are set only **once** when we supply the flag.

* We can enable **ProfileCalls** flag by passing `-c` flag.
* We can enable **ProfileSyscalls** flag by passing `-s` flag.

Both flags are by default set to **false** , means if we dont pass the command-line flags, they remain disabled throughout the course of the execution of our pintool.

We can also create other types of command line args , like *str* or *int*.

```cpp
//continuation of profiler.cpp

std::map<ADDRINT,std::map<ADDRINT,unsigned long> > cflows;
std::map<ADDRINT,std::map<ADDRINT,unsigned long> > calls;
std::map<ADDRINT,unsigned long> syscalls;
std::map<ADDRINT,std::string> funcnames;

```
     
Our profiler uses multiple **std::map** data structures and counters to keep track of program's runtime statistics.

The **cflows** and **calls** data structures map addresses of control flow targets to another map that inturn tracks the address of  the control flow instructions that invoke each target and counts how often that control transfer was taken.

The **syscall** map simply tracks how often a syscall was triggered and the **funcnames** maps function address to symbolic names.

```cpp

//continuation of profiler.cpp

unsigned long insn_count = 0;
unsigned long cflow_count = 0;
unsigned long call_count = 0;
unsigned long syscall_count = 0;
```

These counters are self-explanatory.

### Initializing PIN

Like normal programs written in C/C++ , pintools also start with a `main` function.

```cpp
//continuation of profiler.cpp

int main(int argc,char *argv[])
{
    PIN_InitSymbols(); //Reads the application's symbol tables
    if(PIN_Init(argc,argv)) //Initializes PIN , has all cmd-line options as well as PINtool's options while creating knobs
    {
        print_Usage();
        return 1;
    }
}
```

So we have setup PIN , and now the most important part of initializing pintool is **registering the instrumentation routines** that are responsible for instrumenting the application.

The profiler registers three instrumentation routines.

1. **parse\_funcsyms** , instruments at image(executable) granularity.
2. **instrument\_trace** and **instrument\_insn** instrument at **trace** and **instruction** granularity.

To register these with PIN , we call **IMG\_AddInstrument Function**, **TRACE\_AddInstrument Function** and **INS\_AddInstrument Function** .

The 3 instrumentation routines that we've seen just now take an *IMG* ,a *TRACE* and an *INS* object as their first parameter, respectively depending on their type. As a second arg , these functions take a `void *` which allow us to specify when we register the instrumentation routines using `*_AddInstrument Function`.

### SYSCALL ENTRY FUNCTION

Pin also allows us to call functions before or after every syscall , in the same way we register instrumentation callbacks.

> Note that we can't specify callbacks for some syscalls but we can differentiate between syscalls inside the callback function.

The Profiler uses **Pin\_AddSyscallEntryFunction** to register a function named **log\_syscall** that's called whenever a syscall is entered.

> To register a callback that triggers when a syscall exits , we can use **PIN\_AddSyscallExitFunction** instead.

Note that profile registers the callback only if the value of **ProfileSyscall** is true.

### FINI FUNCTION

The final callback that the profile registers is a *fini function* , which is called when the app exits or when the PIN is detached from it.

This function is responsible for printing profiling results.
{: .notice}

```cpp
//continuation of profiler.cpp

    IMG_AddInstrumentFunction(parse_funcsyms,NULL); //second arg is passed as NULL here
    TRACE_AddInstrumentFunction(instrument_trace,NULL);
    INS_AddInstrumentFunction(instrument_insn,NULL);

    if(ProfileSyscalls.value())
    {
        PIN_AddSyscallEntryFunction(log_syscall,NULL); //logging syscalls
    }
    PIN_AddFiniFunction(print_results,NULL);

    PIN_StartProgram(); //Never returns and hence return 0 is never reached

    return 0;

```

Let's look at a few details of Parsing Function Symbols.

## PARSING FUNCTION SYMBOLS

We recall that **parse\_funcsyms** is an **image-granularity** instrumentation routine. Such routines are called when a new image(binary/library) is loaded, allowing us to instrument the image as a whole.

This also lets us loop over all the functions in the image and add analysis routines before or after a function.

> Note that function instrumentation is reliabel only if the binary contains **symbolic info**.
> Also note that **after-function** instrumentation doesn't work with some optimizations , such as **tail calls**.

```cpp
//continuation of profiler.cpp

static void parse_funcsyms(IMG img,void *v)
{
    if(!IMG_valid(img)) //checks for a valid image
        return;
}

```

If the image is valid , **parse\_funcsyms** loops over all **SEC** objects in the image , which represent all sections.

```cpp
    for(SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec))
    {
        for(RTN rtn = SEC_RtnHead(sec) ; RTN_Valid(rtn); rtn = RTN_Next(rtn))
        {
            funcnames[RTN_Address(rtn)] = RTN_Name(rtn);
        }
    }

```

For each section , *parse_funcsyms* iterates over all the functions (represented by **RTN** objects , meaning **Routine** ) and maps each function's address in the *funcnames* map to the symbolic name of the function , if the function name is unknown then it returns an empty string.

**REMARK** -> This kind of function based instrumentation is rendered useless in stripped binaries which are devoid of any symbols.

## IMPLEMENTING BASIC BLOCK INSTRUMENTATION

Unfortunately , we can't implement basic blocks in PIN API directly , ie , there's no **BBL\_AddInstrumentFunction**.

To instrument basic blocks , you have to add a **Trace level** instrumentation routine and then loop over all basic blocks in trace , instrumenting each one.

```cpp
static void instrument_trace(TRACE trace , void *v)
{
    IMG img = IMG_FindByAddress(TRACE_Address(trace));
    if(!IMG_Valid(img) || !IMG_IsMainExecutable(img))
        return;
    for(BBL bb = TRACE_BblHead(trace) ; BBL_valid(bb) ; bb = BBL_Next(bb))
    {
        instrument_bb(bb);
    }
}

```

1. First , the **instrument\_trace** calls **IMG\_FindByAddress** to find the IMG that the trace is part of.
2. If the trace is valid and part of main application , **instrument\_trace** loops over all Basic Blocks , **BBL** objects in the trace.
3. For each **BBL** it calls **instrument\_bb** which performs the instrumentation of each basic block.
4. To instrument a given BBL , **instrument\_bb** calls **BBL\_InsertCall** which is PIN's API function to instrument a basic block with an **analysis routine callback**.

**BBL\_InsertCall** takes 3 args , one **bb** , two an **insertion point** and third a **function pointer** to the analysis routine we wish to add.

```cpp
static void instrument_bb(BBL bb)
{
    BBL_InsertCall(bb,IPOINT_ANYWHERE,(AFUNPTR)count_bb_insns,IARG_UINT32,BBL_NumIns(bb),IARG_END);
}

```

In this case , the insertion point is **IPOINT\_ANYWHERE** because it doesn't matter at what point in the basic block the instruction counter is updated.

Here's a table which has information of a few insertion points.

|**Insertion Point** | **Analysis CallBack**| **Validity** |        
|:--------|:-------:|--------:|        
| IPOINT\_BEFORE   | Before Instrumented object   | Always valid   |        
| IPOINT\_AFTER   | On fallthrough edge of a branch or a regular instruction   | If INS\_HasFallThrough is true  |                                         
| IPOINT\_ANYWHERE  | Anywhere in instrumented object   | For Trace or BBL   |        
| IPOINT\_TAKEN\_BRANCH   | On taken edge of a branch   | If INS\_isBranchOrCall is true   |        
|=====                                 
{: rules="groups"}                     

In our implementation , there's an option argument of type **IAARG\_UINT32** with value **BBL\_NumIns** and **IARG\_END** is to specofy the end of args.

## INSTRUMENTING CONTROL FLOW INSTRUCTIONS

The profiler can count the *number of control flow transfers* and optionally , the number of calls.

Our **instrument\_insn** takes **INS** ins and a void* as args.

1. Initially , it checks whether our **INS** object is a control-flow instruction or not. 

```cpp
static void instrument_insn(INS ins , void *v)
{
    if(!INS_isBranchOrCall(ins))
        return;
}

```

2. After that , it checks whether the instruction is a part of the main application or not.

```cpp
    IMG img = IMG_FindByAddress(INS_Address(ins));
    if(!IMG_Valid(img) || !IMG_isMainExecutable(img))
        return;

    INS_InsertPredicatedCall(ins,IPOINT_TAKEN_BRANCH,(AFUNPTR)count_cflow,IARG_INST_PTR,IARG_BRANCH_TARGET_ADDR,IARG_END);

```

## INSTRUMENTING THE TAKEN EDGE

To record control transfers and calls , **instrument\_insn** inserts three different analysis callbacks.

1. First, it uses **INS\_InsertPredicatedCall** to insert a callback on the instruction's taken edge.
2. The inserted analysis callback to *count_cflow* increments the control-flow counter in case the branch is taken and records the source and target addresses of control flow.


Note that **instrument\_insn** uses **INS\_InsertPredicatedCall** to insert a callback instead of **INS\_InsertCall**.Analysis callbacks inserted with **INS\_PredicatedCall** only if the condition holds and the instruction is executed.
{: .notice}

> In contrast to the above fact , callbacks inserted with **INS\_InsertCall** are called even if the repeat condition doesn't hold , leading to an *overestimation* of instruction count.


## INSTRUMENTING THE FALL THROUGH EDGE

The profiler should record control transfer regardless of the **branch direction**.

> Note that some instructions such as **unconditional jumps** have **no** fallthrough edges meaning that we have to explicitly check **INS\_HasFallthrough** before we try to instrument an instruction's fallthrough edge.

> Also Note that According to Pin's definition , **non-control flow instructions** that just continue to the next instruction **do have a fallthrough edge**.

```cpp

// Previously we just declared INS_PredicatedCall , now let's define it

    if(INS_HasFallThrough(ins))
    {
        INS_PredicatedCall(IPOINT_AFTER,(AFUNPTR)count_cflow,IARG_INST_PTR,IARG_FALLTHROUGH_ADDR,IARG_END);
    }

```

As we can see from the above code , if the given instruction turns out to have a Fallthrough Edge , **instrument\_insn** inserts an analysis callback to **count\_cflow** on that edge as it did for taken edge also. The only difference is that this new callback uses insertion point **IPOINT\_AFTER** and passes **fallthrough's address** as the target address to record

## INSTRUMENTING CALLS

The profiler keeps a separate counter and mapping to track called functions so that we can see which functions are more better for our application.

Recall that we have to pass **-c** flag to enable tracking called functions.
{: .notice}

To instrument calls , our **instrument\_insn** uses **INS\_IsCall** to separate calls from other instructions.

```cpp

if(INS_IsCall(ins))
{
    if(ProfileCalls.Value())
    {
        INS_InsertCall(ins,IPOINT_BEFORE,(AFUNPTR)count_call,IARG_INST_PTR,IARG,BRANCH_TARGET_ADDR,IARG_END);

    }
}

```

If the instruction is a call , then the profiler inserts an analysis callback before the call instruction at **IPOINT\_BEFORE** to an analysis routine called **count\_call** passing in the call's source , ie the Instruction Pointer and target address.

Here it's safe to use **INS\_InsertCall** instead of **INS\_InsertPredicatedCall** because there are no call instructions with built-in conditionals.

Now let's see a few analysis routines that we've used so far.

```cpp

static void count_bb_insn(UNINT32 n)
{
    insn_count += n
}

static void count_cflow(ADDRINT ip, ADDRINT target)
{
    cflows[target][ip]++;
    cflow_count++;
}

static void count_call(ADDRINT ip, ADDRINT target)
{
    calls[target][ip]++;
    call_count++;
}

static void log_syscall(THREADID tid , CONTEXT *ctx, SYSCALL_STANDARD std , VOID *v)
{
    syscalls[PIN_GetSyscallNumber(ctx,std)]++;
    syscall_count++;
}
```

The function **log\_syscall** is not a regular analysis routine but a callback for syscall entry events.

In PIN , syscall handlers take 4 args , a **THREADID** identifying the thread that made the syscall ; a `CONTEXT *` containing things like syscall number , arguments , and return value (only for syscall exit handlers) ; a **SYSCALL\_STANDARD** argument that verifies the syscall's calling convention and finally the `void*` which allows us to pass user-defined data structure.

Recall that purpose of  **log\_syscall** is to record how often each syscall is called. 

It calls **Get\_SyscallNumber** to get the current syscall's number and records a hit for that syscall in *syscalls* map.



