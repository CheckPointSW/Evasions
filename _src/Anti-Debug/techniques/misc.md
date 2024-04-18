---
layout: post
title:  "Anti-Debug: Misc"
title-image: "/assets/icons/misc.svg"
categories: anti-debug 
tags: misc
---

<h1>Contents</h1>

[Misc](#misc)

* [1. FindWindow()](#findwindow)
* [2. Parent Process Check](#parent-process-check)
    * [2.1. NtQueryInformationProcess()](#parent-process-check-ntqueryinformationprocess)
    * [2.2. CreateToolhelp32Snapshot()](#parent-process-check-createtoolhelp32snapshot)
* [3. Selectors](#selectors)
* [4. DbgPrint()](#dbgprint)
* [5. DbgSetDebugFilterState()](#dbgsetdebugfilterstate)
* [6. NtYieldExecution() / SwitchToThread()](#switchtothread)
* [7. VirtualAlloc() / GetWriteWatch()](#getwritewatch)
* [Mitigations](#mitigations)
<br />

<hr class="space">

<h2><a class="a-dummy" name="misc">Misc</a></h2>

<br />
<h3><a class="a-dummy" name="findwindow">1. FindWindow()</a></h3>
This technique includes the simple enumeration of window classes in the system and comparing them with known windows classes of debuggers.

The following functions can be used:

* <tt>user32!FindWindowW()</tt>
* <tt>user32!FindWindowA()</tt>
* <tt>user32!FindWindowExW()</tt>
* <tt>user32!FindWindowExA()</tt>

<hr class="space">

<b>C/C++ Code</b>
<p></p>

{% highlight c %}

const std::vector<std::string> vWindowClasses = {
    "antidbg",
    "ID",               // Immunity Debugger
    "ntdll.dll",        // peculiar name for a window class
    "ObsidianGUI",
    "OLLYDBG",
    "Rock Debugger",
    "SunAwtFrame",
    "Qt5QWindowIcon"
    "WinDbgFrameClass", // WinDbg
    "Zeta Debugger",
};

bool IsDebugged()
{
    for (auto &sWndClass : vWindowClasses)
    {
        if (NULL != FindWindowA(sWndClass.c_str(), NULL))
            return true;
    }
    return false;
}

{% endhighlight %}

<hr class="space">

<br />
<h3><a class="a-dummy" name="parent-process-check">2. Parent Process Check</a></h3>
Normally, a user-mode process is executed by double-clicking on a file icon. If the process is executed this way, its parent process will be the shell process (<b>"explorer.exe"</b>).

The main idea of the two following methods is to compare the PID of the parent process with the PID of <b>"explorer.exe"</b>.

<br />
<h4><a class="a-dummy" name="parent-process-check-ntqueryinformationprocess">2.1. NtQueryInformationProcess()</a></h4>
This method includes obtaining the shell process window handle using <tt>user32!GetShellWindow()</tt> and obtaining its process ID by calling <tt>user32!GetWindowThreadProcessId()</tt>.

Then, the parent process ID can be obtained from the <tt>PROCESS_BASIC_INFORMATION</tt> structure by calling <tt>ntdll!NtQueryInformationProcess()</tt> with the <tt>ProcessBasicInformation</tt> class.

<hr class="space">

<b>C/C++ Code</b>
<p></p>

{% highlight c %}

bool IsDebugged()
{
    HWND hExplorerWnd = GetShellWindow();
    if (!hExplorerWnd)
        return false;

    DWORD dwExplorerProcessId;
    GetWindowThreadProcessId(hExplorerWnd, &dwExplorerProcessId);

    ntdll::PROCESS_BASIC_INFORMATION ProcessInfo;
    NTSTATUS status = ntdll::NtQueryInformationProcess(
        GetCurrentProcess(),
        ntdll::PROCESS_INFORMATION_CLASS::ProcessBasicInformation,
        &ProcessInfo,
        sizeof(ProcessInfo),
        NULL);
    if (!NT_SUCCESS(status))
        return false;

    return (DWORD)ProcessInfo.InheritedFromUniqueProcessId != dwExplorerProcessId;
}

{% endhighlight %}

<br />
<h4><a class="a-dummy" name="parent-process-check-createtoolhelp32snapshot">2.2. CreateToolhelp32Snapshot()</a></h4>
The parent process ID and the parent process name can be obtained using the <tt>kernel32!CreateToolhelp32Snapshot()</tt> and <tt>kernel32!Process32Next()</tt> functions.

<hr class="space">

<b>C/C++ Code</b>
<p></p>

{% highlight c %}

DWORD GetParentProcessId(DWORD dwCurrentProcessId)
{
    DWORD dwParentProcessId = -1;
    PROCESSENTRY32W ProcessEntry = { 0 };
    ProcessEntry.dwSize = sizeof(PROCESSENTRY32W);

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if(Process32FirstW(hSnapshot, &ProcessEntry))
    {
        do
        {
            if (ProcessEntry.th32ProcessID == dwCurrentProcessId)
            {
                dwParentProcessId = ProcessEntry.th32ParentProcessID;
                break;
            }
        } while(Process32NextW(hSnapshot, &ProcessEntry));
    }

    CloseHandle(hSnapshot);
    return dwParentProcessId;
}

bool IsDebugged()
{
    bool bDebugged = false;
    DWORD dwParentProcessId = GetParentProcessId(GetCurrentProcessId());

    PROCESSENTRY32 ProcessEntry = { 0 };
    ProcessEntry.dwSize = sizeof(PROCESSENTRY32W);

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if(Process32First(hSnapshot, &ProcessEntry))
    {
        do
        {
            if ((ProcessEntry.th32ProcessID == dwParentProcessId) &&
                (strcmp(ProcessEntry.szExeFile, "explorer.exe")))
            {
                bDebugged = true;
                break;
            }
        } while(Process32Next(hSnapshot, &ProcessEntry));
    }

    CloseHandle(hSnapshot);
    return bDebugged;
}

{% endhighlight %}

<hr class="space">

<br />
<h3><a class="a-dummy" name="selectors">3. Selectors</a></h3>
Selector values might appear to be stable, but they are actually volatile in certain circumstances, and also depending on the version of Windows. For example, a selector value can be set within a thread, but it might not hold that value for very long. Certain events might cause the selector value to be changed back to its default value. One such event is an exception. In the context of a debugger, the single-step exception is still an 
exception, which can cause some unexpected behavior.

<b>x86 Assembly</b>
<p></p>

{% highlight nasm %}
    xor  eax, eax 
    push fs 
    pop  ds 
l1: xchg [eax], cl 
    xchg [eax], cl
{% endhighlight %}

<hr class="space">

On the 64-bit versions of Windows, single-stepping through this code will cause an access violation exception at <tt>l1</tt> because the DS selector will be restored to its default value even before <tt>l1</tt> is reached. On the 32-bit versions of Windows, the <tt>DS</tt> selector will not have its value restored, unless a non-debugging exception occurs. The version-specific difference in behaviors expands even further if the <tt>SS</tt> selector is used. On the 64-bit versions of Windows, the <tt>SS</tt> selector will be restored to its default value, as in the <tt>DS</tt> selector case. However, on the 32-bit versions of Windows, the <tt>SS</tt> selector value will not be restored, even if an exception occurs.

<b>x86-64 Assembly</b>
<p></p>

{% highlight nasm %}
    xor  eax, eax 
    push offset l2 
    push d fs:[eax] 
    mov  fs:[eax], esp 
    push fs 
    pop  ss 
    xchg [eax], cl 
    xchg [eax], cl 
l1: int  3 ;force exception to occur 
l2: ;looks like it would be reached 
    ;if an exception occurs 
    ...
{% endhighlight %}

<hr class="space">

then when the "<tt>int 3</tt>" instruction is reached at <tt>l1</tt> and the breakpoint exception occurs, the exception handler at <tt>l2</tt> is not called as expected. Instead, the process is simply terminated.

A variation of this technique detects the single-step event by simply checking if the assignment was successful.

{% highlight nasm %}
push 3 
pop  gs 
mov  ax, gs 
cmp  al, 3 
jne  being_debugged
{% endhighlight %}

<hr class="space">

The <tt>FS</tt> and <tt>GS</tt> selectors are special cases. For certain values, they will be affected by the single-step event, even on the 32-bit versions of Windows. However, in the case of the <tt>FS</tt> selector (and, technically, the <tt>GS</tt> selector), it will be not restored to its default value on the 32-bit versions of Windows, if it was set to a value from zero to three. Instead, it will be set to zero (the <tt>GS</tt> selector is affected in the same way, but the default value for the <tt>GS</tt> selector is zero). On the 64-bit versions of Windows, it (they) will be restored to its (their) default value.

This code is also vulnerable to a race condition caused by a thread-switch event. When a thread-switch event occurs, it behaves like an exception, and will cause the selector values to be altered, which, in the case of the <tt>FS</tt> selector, means that it will be set to zero.

A variation of this technique solves that problem by waiting intentionally for a thread-switch event to occur.

{% highlight nasm %}
    push 3 
    pop  gs 
l1: mov  ax, gs 
    cmp  al, 3 
    je   l1
{% endhighlight %}

<hr class="space">

However, this code is vulnerable to the problem that it was trying to detect in the first place, because it does not check if the original assignment was successful. Of course, the two code snippets can be combined to produce the desired effect, by waiting until the thread-switch event occurs, and then performing the assignment within the window of time that should exist until the next one occurs. <a href="http://pferrie.host22.com/papers/antidebug.pdf">[Ferrie]</a>

<hr class="space">

<b>C/C++ Code</b>
<p></p>

{% highlight c %}

bool IsTraced()
{
    __asm
    {
        push 3
        pop  gs

    __asm SeclectorsLbl:
        mov  ax, gs
        cmp  al, 3
        je   SeclectorsLbl

        push 3
        pop  gs
        mov  ax, gs
        cmp  al, 3
        jne  Selectors_Debugged
    }

    return false;

Selectors_Debugged:
    return true;
}

{% endhighlight %}

<hr class="space">

<br />
<h3><a class="a-dummy" name="dbgprint">4. DbgPrint()</a></h3>
The debug functions such as <tt>ntdll!DbgPrint()</tt> and <tt>kernel32!OutputDebugStringW()</tt> cause the exception <tt>DBG_PRINTEXCEPTION_C</tt> (<tt>0x40010006</tt>). If a program is executed with an attached debugger, then the debugger will handle this exception. But if no debugger is present, and an exception handler is registered, this exception will be caught by the exception handler.

<hr class="space">

<b>C/C++ Code</b>
<p></p>

{% highlight c %}

bool IsDebugged()
{
    __try
    {
        RaiseException(DBG_PRINTEXCEPTION_C, 0, 0, 0);
    }
    __except(GetExceptionCode() == DBG_PRINTEXCEPTION_C)
    {
        return false;
    }

    return true;
}

{% endhighlight %}

<hr class="space">

<br />
<h3><a class="a-dummy" name="dbgsetdebugfilterstate">5. DbgSetDebugFilterState()</a></h3>
The functions <tt>ntdll!DbgSetDebugFilterState()</tt> and <tt>ntdll!NtSetDebugFilterState()</tt> only set a flag which will be checked be a kernel-mode debugger if it is present. Therefore, if a kernel debugger is attached to the system, these functions will succeed. However, the functions can also succeed because of side-effects caused by some user-mode debuggers. These functions require administrator privileges.

<hr class="space">

<b>C/C++ Code</b>
<p></p>

{% highlight c %}

bool IsDebugged()
{
    return NT_SUCCESS(ntdll::NtSetDebugFilterState(0, 0, TRUE));
}

{% endhighlight %}

<hr class="space">

<br />
<h3><a class="a-dummy" name="switchtothread">6. NtYieldExecution() / SwitchToThread()</a></h3>
This method is not really reliable because it only shows if there a high priority thread in the current process. However, it could be used as an anti-tracing technique.

When an application is traced in a debugger and a single-step is executed, the context can't be switched to other thread. This means that <tt>ntdll!NtYieldExecution()</tt> returns <tt>STATUS_NO_YIELD_PERFORMED</tt> (<tt>0x40000024</tt>), which leads to <tt>kernel32!SwitchToThread()</tt> returning zero.

The strategy of using this technique is that there is a loop which modifies some counter if <tt>kernel32!SwitchToThread()</tt> returns zero, or <tt>ntdll!NtYieldExecution()</tt> returns <tt>STATUS_NO_YIELD_PERFORMED</tt>. This can be a loop which decrypts strings or some other loop which is supposed to be analyzed manually in a debugger. If the counter has the expected value (expected i.e. the value if all <tt>kernel32!SwitchToThread()</tt> returned zero) after leaving the loop, we consider that the debugger is present.

In the example below, we define a one-byte counter (initialized with 0) which shifts one bit to the left if <tt>kernel32!SwitchToThread</tt> returns zero. If it shifts 8 times, then the value of the counter will become 0 and the debugger is considered to be present.

<hr class="space">

<b>C/C++ Code</b>
<p></p>

{% highlight c %}

bool IsDebugged()
{
    BYTE ucCounter = 1;
    for (int i = 0; i < 8; i++)
    {
        Sleep(0x0F);
        ucCounter <<= (1 - SwitchToThread());
    }

    return ucCounter == 0;
}

{% endhighlight %}

<hr class="space">

<br />
<h3><a class="a-dummy" name="getwritewatch">7. VirtualAlloc() / GetWriteWatch()</a></h3>
This technique was described as a <a href="https://codeinsecurity.wordpress.com/2018/01/24/anti-debug-with-virtualallocs-write-watch/">suggestion</a> for a famous al-khaser solution, a tool for testing VMs, debuggers, sandboxes, AV, etc. against many malware-like defences.

The idea is drawn from the <a href="https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-getwritewatch">documentation</a>  for <tt>GetWriteWatch</tt> function where the following is stated in a "Remarks" section:

<i>"When you call the <b>VirtualAlloc</b>  function to reserve or commit memory, you can specify <b>MEM_WRITE_WATCH</b>. This value causes the system to keep track of the pages that are written to in the committed memory region. You can call the <b>GetWriteWatch</b> function to retrieve the addresses of the pages that have been written to since the region has been allocated or the write-tracking state has been reset".</i>

This feature can be used to track debuggers that may modify memory pages outside the expected pattern.

<hr class="space">

<b>C/C++ Code (variant 1)</b>
<p></p>

{% highlight c %}

bool Generic::CheckWrittenPages1() const {
    const int SIZE_TO_CHECK = 4096;

    PVOID* addresses = static_cast<PVOID*>(VirtualAlloc(NULL, SIZE_TO_CHECK * sizeof(PVOID), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    if (addresses == NULL)
    {
        return true;
    }

    int* buffer = static_cast<int*>(VirtualAlloc(NULL, SIZE_TO_CHECK * SIZE_TO_CHECK, MEM_RESERVE | MEM_COMMIT | MEM_WRITE_WATCH, PAGE_READWRITE));
    if (buffer == NULL)
    {
        VirtualFree(addresses, 0, MEM_RELEASE);
        return true;
    }

    // Read the buffer once
    buffer[0] = 1234;

    ULONG_PTR hits = SIZE_TO_CHECK;
    DWORD granularity;
    if (GetWriteWatch(0, buffer, SIZE_TO_CHECK, addresses, &hits, &granularity) != 0)
    {
        return true;
    }
    else
    {
        VirtualFree(addresses, 0, MEM_RELEASE);
        VirtualFree(buffer, 0, MEM_RELEASE);

        return (hits == 1) ? false : true;
    }
}

{% endhighlight %}

<hr class="space">

<b>C/C++ Code (variant 2)</b>
<p></p>

{% highlight c %}

bool Generic::CheckWrittenPages2() const {
    BOOL result = FALSE, error = FALSE;

    const int SIZE_TO_CHECK = 4096;

    PVOID* addresses = static_cast<PVOID*>(VirtualAlloc(NULL, SIZE_TO_CHECK * sizeof(PVOID), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    if (addresses == NULL)
    {
        return true;
    }

    int* buffer = static_cast<int*>(VirtualAlloc(NULL, SIZE_TO_CHECK * SIZE_TO_CHECK, MEM_RESERVE | MEM_COMMIT | MEM_WRITE_WATCH, PAGE_READWRITE));
    if (buffer == NULL)
    {
        VirtualFree(addresses, 0, MEM_RELEASE);
        return true;
    }

    // Make some calls where a buffer *can* be written to, but isn't actually edited because we pass invalid parameters    
    if (GlobalGetAtomName(INVALID_ATOM, (LPTSTR)buffer, 1) != FALSE
        || GetEnvironmentVariable("This variable does not exist", (LPSTR)buffer, 4096 * 4096) != FALSE
        || GetBinaryType("This name does not exist", (LPDWORD)buffer) != FALSE
        || HeapQueryInformation(0, (HEAP_INFORMATION_CLASS)69, buffer, 4096, NULL) != FALSE
        || ReadProcessMemory(INVALID_HANDLE_VALUE, (LPCVOID)0x69696969, buffer, 4096, NULL) != FALSE
        || GetThreadContext(INVALID_HANDLE_VALUE, (LPCONTEXT)buffer) != FALSE
        || GetWriteWatch(0, &result, 0, NULL, NULL, (PULONG)buffer) == 0)
    {
        result = false;
        error = true;
    }

    if (error == FALSE)
    {
        // A this point all calls failed as they're supposed to
        ULONG_PTR hits = SIZE_TO_CHECK;
        DWORD granularity;
        if (GetWriteWatch(0, buffer, SIZE_TO_CHECK, addresses, &hits, &granularity) != 0)
        {
            result = FALSE;
        }
        else
        {
            // Should have zero reads here because GlobalGetAtomName doesn't probe the buffer until other checks have succeeded
            // If there's an API hook or debugger in here it'll probably try to probe the buffer, which will be caught here
            result = hits != 0;
        }
    }

    VirtualFree(addresses, 0, MEM_RELEASE);
    VirtualFree(buffer, 0, MEM_RELEASE);

    return result;
}

{% endhighlight %}

<hr class="space">

<br />
<h3><a class="a-dummy" name="mitigations">Mitigations</a></h3>
During debugging: Fill anti-debug pr anti-traced checks with <tt>NOP</tt>s.

 For anti-anti-debug tool development:

1. For <tt>FindWindow()</tt>: Hook <tt>user32!NtUserFindWindowEx()</tt>. In the hook, call the original <tt>user32!NtUserFindWindowEx()</tt> function. If it is called from the debugged process and the parent process looks suspicious, then return unsuccessfully from the hook.

2. For Parent Process Checks: Hook <tt>ntdll!NtQuerySystemInformation()</tt>. If <tt>SystemInformationClass</tt> is one of the following values:
* <tt>SystemProcessInformation</tt>
* <tt>SystemSessionProcessInformation</tt>
* <tt>SystemExtendedProcessInformation</tt>

   and the process name looks suspicious, then the hook must modify the process name.

3. For Selectors: No mitigations.

4. For <tt>DbgPrint</tt>: you have to implement a plugin for a specific debugger and change the behavior of event handler which is triggered after the <tt>DBG_PRINTEXCEPTION_C</tt> exception has arrived.

5. For <tt>DbgSetDebugFilterState()</tt>: Hook <tt>ntdll!NtSetDebugFilterState()</tt>. If the process is running with debug privileges, return unsuccessfully from the hook.

6. For <tt>SwitchToThread</tt>: Hook <tt>ntdll!NtYieldExecution()</tt> and return an unsuccessful status from the hook.

7. For <tt>GetWriteWatch</tt>: Hook <tt>VirtualAlloc()</tt> and <tt>GetWriteWatch()</tt> to track if <tt>VirtualAlloc()</tt> is called with <tt>MEM_WRITE_WATCH</tt> flag. If it is the case, check what is the region to track and return the expected value in <tt>GetWriteWatch()</tt>.
