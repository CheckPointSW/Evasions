---
layout: post
title:  "Anti-Debug: Assembly instructions"
title-image: "/assets/icons/assembly.svg"
categories: anti-debug 
tags: assembly
---

<h1>Contents</h1>

[Assembly instructions](#assembly)

* [1. INT 3](#int3)
* [2. INT 2D](#int2d)
* [3. DebugBreak](#debugbreak)
* [4. ICE](#ice)
* [5. Stack Segment Register](#ss_register)
* [6. Instruction Counting](#instruction-counting)
* [7. POPF and Trap Flag](#popf_and_trap_flag)
* [8. Instruction Prefixes](#instruction_prefixes)
* [Mitigations](#mitigations)
<br />

<hr class="space">

<h2><a class="a-dummy" name="assembly">Assembly instructions</a></h2>
The following techniques are intended to detect a debugger presence based on how debuggers behave when the CPU executes a certain instruction.

<br />
<h3><a class="a-dummy" name="int3">1. INT 3</a></h3>
Instruction <tt>INT3</tt> is an interruption which is used as a software breakpoint. Without a debugger present, after getting to the <tt>INT3</tt> instruction, the exception <tt>EXCEPTION_BREAKPOINT</tt> (<tt>0x80000003</tt>) is generated and an exception handler will be called. If the debugger is present, the control won't be given to the exception handler.

<hr class="space">

<b>C/C++ Code</b>
<p></p>

{% highlight c %}

bool IsDebugged()
{
    __try
    {
        __asm int 3;
        return true;
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}

{% endhighlight %}

<br />Besides the short form of <tt>INT3</tt> instruction (<tt>0xCC</tt> opcode), there is also a long form of this instruction: <tt>CD 03</tt> opcode.

When the exception <tt>EXCEPTION_BREAKPOINT</tt> occurs, the Windows decrements <tt>EIP</tt> register to the assumed location of the <tt>0xCC</tt> opcode and pass the control to the exception handler. In the case of the long form of the <tt>INT3</tt> instruction, <tt>EIP</tt> will point to the middle of the instruction (i.e. to <tt>0x03</tt> byte). Therefore, <tt>EIP</tt> should be edited in the exception handler if we want to continue execution after the <tt>INT3</tt> instruction (otherwise we'll most likely get an <tt>EXCEPTION_ACCESS_VIOLATION</tt> exception). If not, we can neglect the instruction pointer modification.

<hr class="space">

<b>C/C++ Code</b>
<p></p>

{% highlight c %}

bool g_bDebugged = false;

int filter(unsigned int code, struct _EXCEPTION_POINTERS *ep)
{
    g_bDebugged = code != EXCEPTION_BREAKPOINT;
    return EXCEPTION_EXECUTE_HANDLER;
}

bool IsDebugged()
{
    __try
    {
        __asm __emit(0xCD);
        __asm __emit(0x03);
    }
    __except (filter(GetExceptionCode(), GetExceptionInformation()))
    {
        return g_bDebugged;
    }
}

{% endhighlight %}


<hr class="space">

<br />
<h3><a class="a-dummy" name="int2d">2. INT 2D</a></h3>
Just like in the case of <tt>INT3</tt> instruction when the instruction <tt>INT2D</tt> is executed, the exception <tt>EXCEPTION_BREAKPOINT</tt> is raised as well. But with <tt>INT2D</tt>, Windows uses the <tt>EIP</tt> register as an exception address and then increments the <tt>EIP</tt> register value. Windows also examines the value of the <tt>EAX</tt> register while <tt>INT2D</tt> is executed. If it's 1, 3 or 4 on all versions of Windows, or 5 on Vista+, the exception address will be increased by one.

This instruction can cause problems for some debuggers because after the <tt>EIP</tt> incrimination, the byte which follows the <tt>INT2D</tt> instruction will be skipped and the execution might continue from the damaged instruction.

In the example, we put one-byte <tt>NOP</tt> instruction after <tt>INT2D</tt> to skip it in any case. If the program is executed without a debugger, the control will be passed to the exception handler.

<hr class="space">

<b>C/C++ Code</b>
<p></p>

{% highlight c %}

bool IsDebugged()
{
    __try
    {
        __asm xor eax, eax;
        __asm int 0x2d;
        __asm nop;
        return true;
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}

{% endhighlight %}

<hr class="space">

<br />
<h3><a class="a-dummy" name="debugbreak">3. DebugBreak</a></h3>
As written in <a href="https://docs.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-debugbreak">DebugBreak documentation</a>, "<tt>DebugBreak</tt> causes a breakpoint exception to occur in the current process. This allows the calling thread to signal the debugger to handle the exception".

If the program is executed without a debugger, the control will be passed to the exception handler. Otherwise, the execution will be intercepted by the debugger.

<hr class="space">

<b>C/C++ Code</b>
<p></p>

{% highlight c %}

bool IsDebugged()
{
    __try
    {
        DebugBreak();
    }
    __except(EXCEPTION_BREAKPOINT)
    {
        return false;
    }
    
    return true;
}

{% endhighlight %}

<hr class="space">

<br />
<h3><a class="a-dummy" name="ice">4. ICE</a></h3>
"<tt>ICE</tt>" is one of Intel's undocumented instructions. Its opcode is <tt>0xF1</tt>. It can be used to detect if the program is traced.

If <tt>ICE</tt> instruction is executed, the <tt>EXCEPTION_SINGLE_STEP</tt> (<tt>0x80000004</tt>) exception will be raised.

However, if the program has been already traced, the debugger will consider this exception as the normal exception generated by executing the instruction with the <a href="https://en.wikipedia.org/wiki/Trap_flag#Single-step_interrupt">SingleStep</a> bit set in the Flags registers. Therefore, under a debugger, the exception handler won't be called and execution will continue after the <tt>ICE</tt> instruction.

<hr class="space">

<b>C/C++ Code</b>
<p></p>

{% highlight c %}

bool IsDebugged()
{
    __try
    {
        __asm __emit 0xF1;
        return true;
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}

{% endhighlight %}

<hr class="space">

<br />
<h3><a class="a-dummy" name="ss_register">5. Stack Segment Register</a></h3>
This is a trick that can be used to detect if the program is being traced.
The trick consists of tracing over the following sequence of assembly instructions:
{% highlight asm %}
push ss 
pop ss 
pushf
{% endhighlight %}

<br />After single-stepping in a debugger through this code, the <a href="https://en.wikipedia.org/wiki/Trap_flag">Trap Flag</a> will be set. Usually it's not visible as debuggers clear the Trap Flag after each debugger event is delivered. However, if we previously save <tt>EFLAGS</tt> to the stack, we'll be able to check whether the Trap Flag is set.

<hr class="space">

<b>C/C++ Code</b>
<p></p>

{% highlight c %}

bool IsDebugged()
{
    bool bTraced = false;

    __asm
    {
        push ss
        pop ss
        pushf
        test byte ptr [esp+1], 1
        jz movss_not_being_debugged
    }

    bTraced = true;

movss_not_being_debugged:
    // restore stack
    __asm popf;

    return bTraced;
}

{% endhighlight %}

<hr class="space">

<br />
<h3><a class="a-dummy" name="instruction-counting">6. Instruction Counting</a></h3>
This technique abuses how some debuggers handle <tt>EXCEPTION_SINGLE_STEP</tt> exceptions.

The idea of this trick is to set hardware breakpoints to each instruction in some predefined sequence (e.g. sequence of <tt>NOP</tt>s). Execution of the instruction with a hardware breakpoint on it raises the <tt>EXCEPTION_SINGLE_STEP</tt> exception which can be caught by a vectored exception handler. In the exception handler, we increment a register which plays the role of instruction counter (<tt>EAX</tt> in our case) and the instruction pointer <tt>EIP</tt> to pass the control to the next instruction in the sequence. Therefore, each time the control is passed to the next instruction in our sequence, the exception is raised and the counter is incremented. After the sequence is finished, we check the counter and if it is not equal to the length of our sequence, we consider it as if the program is being debugged.

<hr class="space">

<b>C/C++ Code</b>
<p></p>

{% highlight c %}

#include "hwbrk.h"

static LONG WINAPI InstructionCountingExeptionHandler(PEXCEPTION_POINTERS pExceptionInfo)
{
    if (pExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP)
    {
        pExceptionInfo->ContextRecord->Eax += 1;
        pExceptionInfo->ContextRecord->Eip += 1;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

__declspec(naked) DWORD WINAPI InstructionCountingFunc(LPVOID lpThreadParameter)
{
    __asm
    {
        xor eax, eax
        nop
        nop
        nop
        nop
        cmp al, 4
        jne being_debugged
    }

    ExitThread(FALSE);

being_debugged:
    ExitThread(TRUE);
}

bool IsDebugged()
{
    PVOID hVeh = nullptr;
    HANDLE hThread = nullptr;
    bool bDebugged = false;

    __try
    {
        hVeh = AddVectoredExceptionHandler(TRUE, InstructionCountingExeptionHandler);
        if (!hVeh)
            __leave;

        hThread = CreateThread(0, 0, InstructionCountingFunc, NULL, CREATE_SUSPENDED, 0);
        if (!hThread)
            __leave;

        PVOID pThreadAddr = &InstructionCountingFunc;
        // Fix thread entry address if it is a JMP stub (E9 XX XX XX XX)
        if (*(PBYTE)pThreadAddr == 0xE9)
            pThreadAddr = (PVOID)((DWORD)pThreadAddr + 5 + *(PDWORD)((PBYTE)pThreadAddr + 1));

        for (auto i = 0; i < m_nInstructionCount; i++)
            m_hHwBps[i] = SetHardwareBreakpoint(
                hThread, HWBRK_TYPE_CODE, HWBRK_SIZE_1, (PVOID)((DWORD)pThreadAddr + 2 + i));

        ResumeThread(hThread);
        WaitForSingleObject(hThread, INFINITE);

        DWORD dwThreadExitCode;
        if (TRUE == GetExitCodeThread(hThread, &dwThreadExitCode))
            bDebugged = (TRUE == dwThreadExitCode);
    }
    __finally
    {
        if (hThread)
            CloseHandle(hThread);

        for (int i = 0; i < 4; i++)
        {
            if (m_hHwBps[i])
                RemoveHardwareBreakpoint(m_hHwBps[i]);
        }

        if (hVeh)
            RemoveVectoredExceptionHandler(hVeh);
    }

    return bDebugged;
}

{% endhighlight %}

<hr class="space">

<br />
<h3><a class="a-dummy" name="popf_and_trap_flag">7. POPF and Trap Flag</a></h3>
This is another trick that can indicate whether a program is being traced.

There is a Trap Flag in the Flags register. When the Trap Flag is set, the exception <tt>SINGLE_STEP</tt> is raised. However, if we traced the code, the Trap Flag will be cleared by a debugger so we won't see the exception.

<hr class="space">

<b>C/C++ Code</b>
<p></p>

{% highlight c %}

bool IsDebugged()
{
    __try
    {
        __asm
        {
            pushfd
            mov dword ptr [esp], 0x100
            popfd
            nop
        }
        return true;
    }
    __except(GetExceptionCode() == EXCEPTION_SINGLE_STEP
        ? EXCEPTION_EXECUTE_HANDLER
        : EXCEPTION_CONTINUE_EXECUTION)
    {
        return false;
    }
}

{% endhighlight %}

<hr class="space">

<br />
<h3><a class="a-dummy" name="instruction_prefixes">8. Instruction Prefixes</a></h3>
This trick works only in some debuggers. It abuses the way how these debuggers handle instruction prefixes.

If we execute the following code in OllyDbg, after stepping to the first byte <tt>F3</tt>, we'll immediately get to the end of <tt>try</tt> block. The debugger just skips the prefix and gives the control to the <tt>INT1</tt> instruction.

If we run the same code without a debugger, an exception will be raised and we'll get to <tt>except</tt> block.

<hr class="space">

<b>C/C++ Code</b>
<p></p>

{% highlight c %}

bool IsDebugged()
{
    __try
    {
        // 0xF3 0x64 disassembles as PREFIX REP:
        __asm __emit 0xF3
        __asm __emit 0x64
        // One byte INT 1
        __asm __emit 0xF1
        return true;
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}

{% endhighlight %}

<hr class="space">

<br />
<h3><a class="a-dummy" name="mitigations">Mitigations</a></h3>
* During debugging:
    * The best way to mitigate all the following checks is to patch them with <tt>NOP</tt> instructions.
    * Regarding anti-tracing techniques: instead of patching the code, we can simply set a breakpoint in the code which follows the check and run the program till this breakpoint.
* For anti-anti-debug tool development: No mitigation.
