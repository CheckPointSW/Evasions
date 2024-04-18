---
layout: post
title:  "Anti-Debug: Timing"
title-image: "/assets/icons/timing.svg"
categories: anti-debug 
tags: timing
---

<h1>Contents</h1>

[Timing](#timing)

* [1. RDPMC/RDTSC](#rdpmc_rdtsc)
* [2. GetLocalTime()](#getlocaltime)
* [3. GetSystemTime()](#getsystemtime)
* [4. GetTickCount()](#gettickcount)
* [5. ZwGetTickCount() / KiGetTickCount()](#kernel-timing)
* [6. QueryPerformanceCounter()](#queryperformancecounter)
* [7. timeGetTime()](#timegettime)
* [Mitigations](#mitigations)
<br />

<hr class="space">

<h2><a class="a-dummy" name="timing">Timing</a></h2>
When a process is traced in a debugger, there is a huge delay between instructions and execution. The "native" delay between some parts of code can be measured and compared with the actual delay using several approaches.

<br />
<h3><a class="a-dummy" name="rdpmc_rdtsc">1. RDPMC/RDTSC</a></h3>
These instructions require the flag <tt>PCE</tt> to be set in <tt>CR4</tt> register.

<hr class="space">

<tt>RDPMC</tt> instruction can be used only in Kernel Mode.

<b>C/C++ Code</b>
<p></p>

{% highlight c %}

bool IsDebugged(DWORD64 qwNativeElapsed)
{
    ULARGE_INTEGER Start, End;
    __asm
    {
        xor  ecx, ecx
        rdpmc
        mov  Start.LowPart, eax
        mov  Start.HighPart, edx
    }
    // ... some work
    __asm
    {
        xor  ecx, ecx
        rdpmc
        mov  End.LowPart, eax
        mov  End.HighPart, edx
    }
    return (End.QuadPart - Start.QuadPart) > qwNativeElapsed;
}

{% endhighlight %}

<hr class="space">

<tt>RDTSC</tt> is a User Mode instruction.

<b>C/C++ Code</b>
<p></p>

{% highlight c %}

bool IsDebugged(DWORD64 qwNativeElapsed)
{
    ULARGE_INTEGER Start, End;
    __asm
    {
        xor  ecx, ecx
        rdtsc
        mov  Start.LowPart, eax
        mov  Start.HighPart, edx
    }
    // ... some work
    __asm
    {
        xor  ecx, ecx
        rdtsc
        mov  End.LowPart, eax
        mov  End.HighPart, edx
    }
    return (End.QuadPart - Start.QuadPart) > qwNativeElapsed;
}

{% endhighlight %}

<hr class="space">

<br />
<h3><a class="a-dummy" name="getlocaltime">2. GetLocalTime()</a></h3>

<b>C/C++ Code</b>
<p></p>

{% highlight c %}
bool IsDebugged(DWORD64 qwNativeElapsed)
{
    SYSTEMTIME stStart, stEnd;
    FILETIME ftStart, ftEnd;
    ULARGE_INTEGER uiStart, uiEnd;

    GetLocalTime(&stStart);
    // ... some work
    GetLocalTime(&stEnd);

    if (!SystemTimeToFileTime(&stStart, &ftStart))
        return false;
    if (!SystemTimeToFileTime(&stEnd, &ftEnd))
        return false;

    uiStart.LowPart  = ftStart.dwLowDateTime;
    uiStart.HighPart = ftStart.dwHighDateTime;
    uiEnd.LowPart  = ftEnd.dwLowDateTime;
    uiEnd.HighPart = ftEnd.dwHighDateTime;
    return (uiEnd.QuadPart - uiStart.QuadPart) > qwNativeElapsed;
}

{% endhighlight %}

<hr class="space">

<br />
<h3><a class="a-dummy" name="getsystemtime">3. GetSystemTime()</a></h3>

<b>C/C++ Code</b>
<p></p>

{% highlight c %}

bool IsDebugged(DWORD64 qwNativeElapsed)
{
    SYSTEMTIME stStart, stEnd;
    FILETIME ftStart, ftEnd;
    ULARGE_INTEGER uiStart, uiEnd;

    GetSystemTime(&stStart);
    // ... some work
    GetSystemTime(&stEnd);

    if (!SystemTimeToFileTime(&stStart, &ftStart))
        return false;
    if (!SystemTimeToFileTime(&stEnd, &ftEnd))
        return false;

    uiStart.LowPart  = ftStart.dwLowDateTime;
    uiStart.HighPart = ftStart.dwHighDateTime;
    uiEnd.LowPart  = ftEnd.dwLowDateTime;
    uiEnd.HighPart = ftEnd.dwHighDateTime;
    return (uiEnd.QuadPart - uiStart.QuadPart) > qwNativeElapsed;
}

{% endhighlight %}

<hr class="space">

<br />
<h3><a class="a-dummy" name="gettickcount">4. GetTickCount()</a></h3>

<b>C/C++ Code</b>
<p></p>

{% highlight c %}

bool IsDebugged(DWORD dwNativeElapsed)
{
    DWORD dwStart = GetTickCount();
    // ... some work
    return (GetTickCount() - dwStart) > dwNativeElapsed;
}

{% endhighlight %}

<hr class="space">

<br />
<h3><a class="a-dummy" name="kernel-timing">5. ZwGetTickCount() / KiGetTickCount()</a></h3>
Both functions are used only from Kernel Mode.

Just like User Mode <tt>GetTickCount()</tt> or <tt>GetSystemTime()</tt>, Kernel Mode <tt>ZwGetTickCount()</tt> reads from the <tt>KUSER_SHARED_DATA</tt> page. This page is mapped read-only into the user mode range of the virtual address and read-write in the kernel range. The system clock tick updates the system time, which is stored directly in this page.

<tt>ZwGetTickCount()</tt> is used the same way as <tt>GetTickCount()</tt>. Using <tt>KiGetTickCount()</tt> is faster than calling <tt>ZwGetTickCount()</tt>, but slightly slower than reading from the <tt>KUSER_SHARED_DATA</tt> page directly.

<b>C/C++ Code</b>
<p></p>

{% highlight c %}

bool IsDebugged(DWORD64 qwNativeElapsed)
{
    ULARGE_INTEGER Start, End;
    __asm
    {
        int  2ah
        mov  Start.LowPart, eax
        mov  Start.HighPart, edx
    }
    // ... some work
    __asm
    {
        int  2ah
        mov  End.LowPart, eax
        mov  End.HighPart, edx
    }
    return (End.QuadPart - Start.QuadPart) > qwNativeElapsed;
}

{% endhighlight %}

<hr class="space">

<br />
<h3><a class="a-dummy" name="queryperformancecounter">6. QueryPerformanceCounter()</a></h3>

<b>C/C++ Code</b>
<p></p>

{% highlight c %}

bool IsDebugged(DWORD64 qwNativeElapsed)
{
    LARGE_INTEGER liStart, liEnd;
    QueryPerformanceCounter(&liStart);
    // ... some work
    QueryPerformanceCounter(&liEnd);
    return (liEnd.QuadPart - liStart.QuadPart) > qwNativeElapsed;
}

{% endhighlight %}

<hr class="space">

<br />
<h3><a class="a-dummy" name="timegettime">7. timeGetTime()</a></h3>

<b>C/C++ Code</b>
<p></p>

{% highlight c %}

bool IsDebugged(DWORD dwNativeElapsed)
{
    DWORD dwStart = timeGetTime();
    // ... some work
    return (timeGetTime() - dwStart) > dwNativeElapsed;
}

{% endhighlight %}

<hr class="space">

<br />
<h3><a class="a-dummy" name="mitigations">Mitigations</a></h3>
* During debugging: Just fill timing checks with <tt>NOP</tt>s and set the result of these checks to the appropriate value.
* For anti-anti-debug solution development: There is no great need to do anything with it, as all timing checks are not very reliable. You can still hook timing functions and accelerate the time between calls.

