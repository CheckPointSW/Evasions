---
layout: post
title:  "Anti-Debug: Exceptions"
title-image: "/assets/icons/exceptions.svg"
categories: anti-debug 
tags: exceptions
---

<h1>Contents</h1>

[Exceptions](#exceptions)

* [1. UnhandledExceptionFilter()](#unhandledexceptionfilter)
* [2. RaiseException()](#raiseexception)
* [3. Hiding Control Flow with Exception Handlers](#hiding-cf-with-eh)
* [Mitigations](#mitigations)
<br />

<hr class="space">

<h2><a class="a-dummy" name="exceptions">Exceptions</a></h2>
The following methods deliberately cause exceptions to verify if the further behavior is not typical for a process running without a debugger.

<br />
<h3><a class="a-dummy" name="unhandledexceptionfilter">1. UnhandledExceptionFilter()</a></h3>
If an exception occurs and no exception handler is registered (or it is registered but doesn't handle such an exception), the <tt>kernel32!UnhandledExceptionFilter()</tt> function will be called. It is possible to register a custom unhandled exception filter using the <tt>kernel32!SetUnhandledExceptionFilter()</tt>. But if the program is running under a debugger, the custom filter won't be called and the exception will be passed to the debugger. Therefore, if the unhandled exception filter is registered and the control is passed to it, then the process is not running with a debugger.

<hr class="space">

<b>x86 Assembly (FASM)</b>
<p></p>

{% highlight asm %}
include 'win32ax.inc'

.code

start:
        jmp begin

not_debugged:
        invoke  MessageBox,HWND_DESKTOP,"Not Debugged","",MB_OK
        invoke  ExitProcess,0

begin:
        invoke SetUnhandledExceptionFilter, not_debugged
        int  3
        jmp  being_debugged

being_debugged:
        invoke  MessageBox,HWND_DESKTOP,"Debugged","",MB_OK
        invoke  ExitProcess,0

.end start
{% endhighlight %}

<hr class="space">

<b>C/C++ Code</b>
<p></p>

{% highlight c %}

LONG UnhandledExceptionFilter(PEXCEPTION_POINTERS pExceptionInfo)
{
    PCONTEXT ctx = pExceptionInfo->ContextRecord;
    ctx->Eip += 3; // Skip \xCC\xEB\x??
    return EXCEPTION_CONTINUE_EXECUTION;
}

bool Check()
{
    bool bDebugged = true;
    SetUnhandledExceptionFilter((LPTOP_LEVEL_EXCEPTION_FILTER)UnhandledExceptionFilter);
    __asm
    {
        int 3                      // CC
        jmp near being_debugged    // EB ??
    }
    bDebugged = false;

being_debugged:
    return bDebugged;
}

{% endhighlight %}

<hr class="space">

<br />
<h3><a class="a-dummy" name="raiseexception">2. RaiseException()</a></h3>
Exceptions such as <tt>DBC_CONTROL_C</tt> or <tt>DBG_RIPEVENT</tt> are not passed to exception handlers of the current process and are consumed by a debugger. This lets us register an exception handler, raise these exceptions using the <tt>kernel32!RaiseException()</tt> function, and check whether the control is passed to our handler. If the exception handler is not called, the process is likely under debugging.

<hr class="space">

<b>C/C++ Code</b>
<p></p>

{% highlight c %}

bool Check()
{
    __try
    {
        RaiseException(DBG_CONTROL_C, 0, 0, NULL);
        return true;
    }
    __except(DBG_CONTROL_C == GetExceptionCode()
        ? EXCEPTION_EXECUTE_HANDLER 
        : EXCEPTION_CONTINUE_SEARCH)
    {
        return false;
    }
}

{% endhighlight %}

<hr class="space">

<br />
<h3><a class="a-dummy" name="hiding-cf-with-eh">3. Hiding Control Flow with Exception Handlers</a></h3>
This approach does not check whether a debugger is present, but it helps to hide the control flow of the program in the sequence of exception handlers.

We can register an exception handler (structured or vectored) which raises another exception which is passed to the next handler which raises the next exception, and so on. Finally, the sequence of handlers should lead to the procedure that we wanted to hide.

<br />Using Structured Exception Handlers:

<hr class="space">

<b>C/C++ Code</b>
<p></p>

{% highlight c %}

#include <Windows.h>

void MaliciousEntry()
{
    // ...
}

void Trampoline2()
{
    __try
    {
        __asm int 3;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        MaliciousEntry();
    }
}

void Trampoline1()
{
    __try 
    {
        __asm int 3;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        Trampoline2();
    }
}

int main(void)
{
    __try
    {
        __asm int 3;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
    {
        Trampoline1();
    }

    return 0;
}

{% endhighlight %}

<br />Using Vectored Exception Handlers:

<hr class="space">

<b>C/C++ Code</b>
<p></p>

{% highlight c %}

#include <Windows.h>

PVOID g_pLastVeh = nullptr;

void MaliciousEntry()
{
    // ...
}

LONG WINAPI ExeptionHandler2(PEXCEPTION_POINTERS pExceptionInfo)
{
    MaliciousEntry();
    ExitProcess(0);
}

LONG WINAPI ExeptionHandler1(PEXCEPTION_POINTERS pExceptionInfo)
{
    if (g_pLastVeh)
    {
        RemoveVectoredExceptionHandler(g_pLastVeh);
        g_pLastVeh = AddVectoredExceptionHandler(TRUE, ExeptionHandler2);
        if (g_pLastVeh)
            __asm int 3;
    }
    ExitProcess(0);
}


int main(void)
{
    g_pLastVeh = AddVectoredExceptionHandler(TRUE, ExeptionHandler1);
    if (g_pLastVeh)
        __asm int 3;

    return 0;
}

{% endhighlight %}

<hr class="space">

<br />
<h3><a class="a-dummy" name="mitigations">Mitigations</a></h3>
* During debugging: 
    * For debugger detection checks: Just fill the corresponding check with <tt>NOP</tt>s.
    * For Control Flow hiding: You have to manually trace the program till the payload.
* For anti-anti-debug tool development: The issue with these type of techniques is that different debuggers consume different exceptions and do not return them to the debugger. This means that you have to implement a plugin for a specific debugger and change the behavior of the event handlers which are triggered after the corresponding exceptions.
