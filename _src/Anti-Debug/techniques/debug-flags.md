---
layout: post
title:  "Anti-Debug: Debug Flags"
title-image: "/assets/icons/debug-flags.svg"
categories: anti-debug 
tags: debug-flags
---

<h1>Contents</h1>

[Debug Flags](#debug-flags)

* [1. Using Win32 API](#using-win32-api)
    * [1.1. IsDebuggerPresent()](#using-win32-api-isdebuggerpresent)
    * [1.2. CheckRemoteDebuggerPresent()](#using-win32-api-checkremotedebuggerpresent)
    * [1.3. NtQueryInformationProcess()](#using-win32-api-ntqueryinformationprocess)
        * [1.3.1. ProcessDebugPort](#using-win32-api-ntqueryinformationprocess-processdebugport)
        * [1.3.2. ProcessDebugFlags](#using-win32-api-ntqueryinformationprocess-processdebugflags)
        * [1.3.3. ProcessDebugObjectHandle](#using-win32-api-ntqueryinformationprocess-processdebugobjecthandle)
    * [1.4. RtlQueryProcessHeapInformation()](#using-win32-api-checks-rtlqueryprocessheapinformation)
    * [1.5. RtlQueryProcessDebugInformation()](#using-win32-api-checks-rtlqueryprocessdebuginformation)
    * [1.6. NtQuerySystemInformation()](#using-win32-api-checks-ntquerysysteminformation)
    * [Mitigations](#mitigations-using-win32-api)
* [2. Manual checks](#manual-checks)
    * [2.1. PEB!BeingDebugged Flag](#manual-checks-peb-beingdebugged-flag)
    * [2.2. NtGlobalFlag](#manual-checks-ntglobalflag)
    * [2.3. Heap Flags](#manual-checks-heap-flags)
    * [2.4. Heap Protection](#manual-checks-heap-protection)
    * [2.5. Check KUSER_SHARED_DATA structure](#kuser_shared_data)
    * [Mitigations](#mitigations-manual-checks)
<br />

<hr class="space">

<h2><a class="a-dummy" name="debug-flags">Debug Flags</a></h2>
Special flags in system tables, which dwell in process memory and which an operation system sets, can be used to indicate that the process is being debugged. The states of these flags can be verified either by using specific API functions or examining the system tables in memory.

These techniques are the most commonly used by malware.

<br />
<h3><a class="a-dummy" name="using-win32-api">1. Using Win32 API</a></h3>
The following techniques use existing API functions (WinAPI or NativeAPI) that check system structures in the process memory for particular flags that indicate the process is being debugged right now.

<br />
<h4><a class="a-dummy" name="using-win32-api-isdebuggerpresent">1.1. IsDebuggerPresent()</a></h4>
The function <tt>kernel32!IsDebuggerPresent()</tt> determines whether the current process is being debugged by a user-mode debugger such as OllyDbg or x64dbg. Generally, the function only checks the <tt>BeingDebugged</tt> flag of the <a href="https://www.nirsoft.net/kernel_struct/vista/PEB.html">Process Environment Block</a> (PEB).

The following code can be used to terminate process if it is being debugged:

<hr class="space">

<b>Assembly Code</b>
<p></p>

{% highlight nasm %}
    call IsDebuggerPresent    
    test al, al
    jne  being_debugged
    ...
being_debugged:
    push 1
    call ExitProcess
{% endhighlight %}

<hr class="space">

<b>C/C++ Code</b>
<p></p>

{% highlight c %}
if (IsDebuggerPresent())
    ExitProcess(-1);
{% endhighlight %}

<hr class="space">

<br />
<h4><a class="a-dummy" name="using-win32-api-checkremotedebuggerpresent">1.2. CheckRemoteDebuggerPresent()</a></h4>
The function <tt>kernel32!CheckRemoteDebuggerPresent()</tt> checks if a debugger (in a different process on the same machine) is attached to the current process.

<hr class="space">

<b>C/C++ Code</b>
<p></p>

{% highlight c %}

BOOL bDebuggerPresent;
if (TRUE == CheckRemoteDebuggerPresent(GetCurrentProcess(), &bDebuggerPresent) &&
    TRUE == bDebuggerPresent)
    ExitProcess(-1);

{% endhighlight %}

<hr class="space">

<b>x86 Assembly</b>
<p></p>

{% highlight nasm %}
    lea eax, bDebuggerPresent]
    push eax
    push -1  ; GetCurrentProcess()
    call CheckRemoteDebuggerPresent
    cmp [bDebuggerPresent], 1
    jz being_debugged
    ...
being_debugged:
    push -1
    call ExitProcess
{% endhighlight %}

<hr class="space">

<b>x86-64 Assembly</b>
<p></p>

{% highlight nasm %}
    lea rdx, [bDebuggerPresent]
    mov rcx, -1 ; GetCurrentProcess()
    call CheckRemoteDebuggerPresent
    cmp [bDebuggerPresent], 1
    jz being_debugged
    ...
being_debugged:
    mov ecx, -1
    call ExitProcess
{% endhighlight %}

<br />
<h4><a class="a-dummy" name="using-win32-api-ntqueryinformationprocess">1.3. NtQueryInformationProcess()</a></h4>
The function <tt>ntdll!NtQueryInformationProcess()</tt> can retrieve a different kind of information from a process. It accepts a <tt>ProcessInformationClass</tt> parameter which specifies the information you want to get and defines the output type of the <tt>ProcessInformation</tt> parameter.

<hr class="space">

<h5><a class="a-dummy" name="using-win32-api-ntqueryinformationprocess-processdebugport">1.3.1. ProcessDebugPort</a></h5>
It is possible to retrieve the port number of the debugger for the process using the <tt>ntdll!NtQueryInformationProcess()</tt>. There is a <a href="https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess#PROCESSDEBUGPORT">documented</a> class ProcessDebugPort, which retrieves a <tt>DWORD</tt> value equal to <tt>0xFFFFFFFF</tt> (decimal <tt>-1</tt>) if the process is being debugged.

<hr class="space">

<b>C/C++ Code</b>
<p></p>

{% highlight c %}

typedef NTSTATUS (NTAPI *TNtQueryInformationProcess)(
    IN HANDLE           ProcessHandle,
    IN PROCESSINFOCLASS ProcessInformationClass,
    OUT PVOID           ProcessInformation,
    IN ULONG            ProcessInformationLength,
    OUT PULONG          ReturnLength
    );

HMODULE hNtdll = LoadLibraryA("ntdll.dll");
if (hNtdll)
{
    auto pfnNtQueryInformationProcess = (TNtQueryInformationProcess)GetProcAddress(
        hNtdll, "NtQueryInformationProcess");
    
    if (pfnNtQueryInformationProcess)
    {
        DWORD dwProcessDebugPort, dwReturned;
        NTSTATUS status = pfnNtQueryInformationProcess(
            GetCurrentProcess(),
            ProcessDebugPort,
            &dwProcessDebugPort,
            sizeof(DWORD),
            &dwReturned);

        if (NT_SUCCESS(status) && (-1 == dwProcessDebugPort))
            ExitProcess(-1);
    }
}

{% endhighlight %}

<hr class="space">

<b>x86 Assembly</b>
<p></p>

{% highlight nasm %}
    lea eax, [dwReturned]
    push eax ; ReturnLength
    push 4   ; ProcessInformationLength
    lea ecx, [dwProcessDebugPort]
    push ecx ; ProcessInformation
    push 7   ; ProcessInformationClass
    push -1  ; ProcessHandle
    call NtQueryInformationProcess
    inc dword ptr [dwProcessDebugPort]
    jz being_debugged
    ...
being_debugged:
    push -1
    call ExitProcess 
{% endhighlight %}

<hr class="space">

<b>x86-64 Assembly</b>
<p></p>

{% highlight nasm %}
    lea rcx, [dwReturned]
    push rcx    ; ReturnLength
    mov r9d, 4  ; ProcessInformationLength
    lea r8, [dwProcessDebugPort] 
                ; ProcessInformation
    mov edx, 7  ; ProcessInformationClass
    mov rcx, -1 ; ProcessHandle
    call NtQueryInformationProcess
    cmp dword ptr [dwProcessDebugPort], -1
    jz being_debugged
    ...
being_debugged:
    mov ecx, -1
    call ExitProcess
{% endhighlight %}

<hr class="space">

<h5><a class="a-dummy" name="using-win32-api-ntqueryinformationprocess-processdebugflags">1.3.2. ProcessDebugFlags</a></h5>
A kernel structure called <a href="https://www.nirsoft.net/kernel_struct/vista/EPROCESS.html">EPROCESS</a>, which represents a process object, contains the field <tt>NoDebugInherit</tt>. The inverse value of this field can be retrieved using an undocumented class <tt>ProcessDebugFlags</tt> (<tt>0x1f</tt>). Therefore, if the return value is <tt>0</tt>, a debugger is present.

<hr class="space">

<b>C/C++ Code</b>
<p></p>

{% highlight c %}

typedef NTSTATUS(NTAPI *TNtQueryInformationProcess)(
    IN HANDLE           ProcessHandle,
    IN DWORD            ProcessInformationClass,
    OUT PVOID           ProcessInformation,
    IN ULONG            ProcessInformationLength,
    OUT PULONG          ReturnLength
    );

HMODULE hNtdll = LoadLibraryA("ntdll.dll");
if (hNtdll)
{
    auto pfnNtQueryInformationProcess = (TNtQueryInformationProcess)GetProcAddress(
        hNtdll, "NtQueryInformationProcess");

    if (pfnNtQueryInformationProcess)
    {
        DWORD dwProcessDebugFlags, dwReturned;
        const DWORD ProcessDebugFlags = 0x1f;
        NTSTATUS status = pfnNtQueryInformationProcess(
            GetCurrentProcess(),
            ProcessDebugFlags,
            &dwProcessDebugFlags,
            sizeof(DWORD),
            &dwReturned);

        if (NT_SUCCESS(status) && (0 == dwProcessDebugFlags))
            ExitProcess(-1);
    }
}

{% endhighlight %}

<hr class="space">

<b>x86 Assembly</b>
<p></p>

{% highlight nasm %}
    lea eax, [dwReturned]
    push eax ; ReturnLength
    push 4   ; ProcessInformationLength
    lea ecx, [dwProcessDebugPort]
    push ecx ; ProcessInformation
    push 1Fh ; ProcessInformationClass
    push -1  ; ProcessHandle
    call NtQueryInformationProcess
    cmp dword ptr [dwProcessDebugPort], 0
    jz being_debugged
    ...
being_debugged:
    push -1
    call ExitProcess
{% endhighlight %}

<hr class="space">

<b>x86-64 Assembly</b>
<p></p>

{% highlight nasm %}
    lea rcx, [dwReturned]
    push rcx     ; ReturnLength
    mov r9d, 4   ; ProcessInformationLength
    lea r8, [dwProcessDebugPort] 
                 ; ProcessInformation
    mov edx, 1Fh ; ProcessInformationClass
    mov rcx, -1  ; ProcessHandle
    call NtQueryInformationProcess
    cmp dword ptr [dwProcessDebugPort], 0
    jz being_debugged
    ...
being_debugged:
    mov ecx, -1
    call ExitProcess
{% endhighlight %}

<hr class="space">

<h5><a class="a-dummy" name="using-win32-api-ntqueryinformationprocess-processdebugobjecthandle">1.3.3. ProcessDebugObjectHandle</a></h5>
When debugging begins, a kernel object called "debug object" is created. It is possible to query for the value of this handle by using the undocumented <tt>ProcessDebugObjectHandle</tt> (<tt>0x1e</tt>) class.

<hr class="space">

<b>C/C++ Code</b>
<p></p>

{% highlight c %}

typedef NTSTATUS(NTAPI * TNtQueryInformationProcess)(
    IN HANDLE           ProcessHandle,
    IN DWORD            ProcessInformationClass,
    OUT PVOID           ProcessInformation,
    IN ULONG            ProcessInformationLength,
    OUT PULONG          ReturnLength
    );

HMODULE hNtdll = LoadLibraryA("ntdll.dll");
if (hNtdll)
{
    auto pfnNtQueryInformationProcess = (TNtQueryInformationProcess)GetProcAddress(
        hNtdll, "NtQueryInformationProcess");

    if (pfnNtQueryInformationProcess)
    {
        DWORD dwReturned;
        HANDLE hProcessDebugObject = 0;
        const DWORD ProcessDebugObjectHandle = 0x1e;
        NTSTATUS status = pfnNtQueryInformationProcess(
            GetCurrentProcess(),
            ProcessDebugObjectHandle,
            &hProcessDebugObject,
            sizeof(HANDLE),
            &dwReturned);

        if (NT_SUCCESS(status) && (0 != hProcessDebugObject))
            ExitProcess(-1);
    }
}

{% endhighlight %}

<hr class="space">

<b>x86 Assembly</b>
<p></p>

{% highlight nasm %}
    lea eax, [dwReturned]
    push eax ; ReturnLength
    push 4   ; ProcessInformationLength
    lea ecx, [hProcessDebugObject]
    push ecx ; ProcessInformation
    push 1Eh ; ProcessInformationClass
    push -1  ; ProcessHandle
    call NtQueryInformationProcess
    cmp dword ptr [hProcessDebugObject], 0
    jnz being_debugged
    ...
being_debugged:
    push -1
    call ExitProcess
{% endhighlight %}

<hr class="space">

<b>x86-64 Assembly</b>
<p></p>

{% highlight nasm %}
    lea rcx, [dwReturned]
    push rcx     ; ReturnLength
    mov r9d, 4   ; ProcessInformationLength
    lea r8, [hProcessDebugObject] 
                 ; ProcessInformation
    mov edx, 1Fh ; ProcessInformationClass
    mov rcx, -1  ; ProcessHandle
    call NtQueryInformationProcess
    cmp dword ptr [hProcessDebugObject], 0
    jnz being_debugged
    ...
being_debugged:
    mov ecx, -1
    call ExitProcess
{% endhighlight %}

<br />
<h4><a class="a-dummy" name="using-win32-api-checks-rtlqueryprocessheapinformation">1.4. RtlQueryProcessHeapInformation()</a></h4>
The <tt>ntdll!RtlQueryProcessHeapInformation()</tt> function can be used to read the heap flags from the process memory of the current process.

<hr class="space">

<b>C/C++ Code</b>
<p></p>

{% highlight c %}

bool Check()
{
    ntdll::PDEBUG_BUFFER pDebugBuffer = ntdll::RtlCreateQueryDebugBuffer(0, FALSE);
    if (!SUCCEEDED(ntdll::RtlQueryProcessHeapInformation((ntdll::PRTL_DEBUG_INFORMATION)pDebugBuffer)))
        return false;

    ULONG dwFlags = ((ntdll::PRTL_PROCESS_HEAPS)pDebugBuffer->HeapInformation)->Heaps[0].Flags;
    return dwFlags & ~HEAP_GROWABLE;
}

{% endhighlight %}

<br />
<h4><a class="a-dummy" name="using-win32-api-checks-rtlqueryprocessdebuginformation">1.5. RtlQueryProcessDebugInformation()</a></h4>
The <tt>ntdll!RtlQueryProcessDebugInformation()</tt> function can be used to read certain fields from the process memory of the requested process, including the heap flags.

<hr class="space">

<b>C/C++ Code</b>
<p></p>

{% highlight c %}

bool Check()
{
    ntdll::PDEBUG_BUFFER pDebugBuffer = ntdll::RtlCreateQueryDebugBuffer(0, FALSE);
    if (!SUCCEEDED(ntdll::RtlQueryProcessDebugInformation(GetCurrentProcessId(), ntdll::PDI_HEAPS | ntdll::PDI_HEAP_BLOCKS, pDebugBuffer)))
        return false;

    ULONG dwFlags = ((ntdll::PRTL_PROCESS_HEAPS)pDebugBuffer->HeapInformation)->Heaps[0].Flags;
    return dwFlags & ~HEAP_GROWABLE;
}

{% endhighlight %}

<br />
<h4><a class="a-dummy" name="using-win32-api-checks-ntquerysysteminformation">1.6. NtQuerySystemInformation()</a></h4>
The <tt>ntdll!NtQuerySystemInformation()<tt> function accepts a parameter which is the class of information to query. Most of the classes are not documented. This includes the <tt>SystemKernelDebuggerInformation</tt> (<tt>0x23</tt>) class, which has existed since Windows NT. The <tt>SystemKernelDebuggerInformation</tt> class returns the value of two flags: <tt>KdDebuggerEnabled</tt> in <tt>al</tt>, and <tt>KdDebuggerNotPresent</tt> in <tt>ah</tt>. Therefore, the return value in <tt>ah</tt> is zero if a kernel debugger is present.

<hr class="space">

<b>C/C++ Code</b>
<p></p>

{% highlight c %}

enum { SystemKernelDebuggerInformation = 0x23 };

typedef struct _SYSTEM_KERNEL_DEBUGGER_INFORMATION { 
    BOOLEAN DebuggerEnabled; 
    BOOLEAN DebuggerNotPresent; 
} SYSTEM_KERNEL_DEBUGGER_INFORMATION, *PSYSTEM_KERNEL_DEBUGGER_INFORMATION; 

bool Check()
{
    NTSTATUS status;
    SYSTEM_KERNEL_DEBUGGER_INFORMATION SystemInfo;
    
    status = NtQuerySystemInformation(
        (SYSTEM_INFORMATION_CLASS)SystemKernelDebuggerInformation,
        &SystemInfo,
        sizeof(SystemInfo),
        NULL);

    return SUCCEEDED(status)
        ? (SystemInfo.DebuggerEnabled && !SystemInfo.DebuggerNotPresent)
        : false;
}

{% endhighlight %}

<br />
<h4><a class="a-dummy" name="mitigations-using-win32-api">Mitigations</a></h4>
<ul>

<li>For <tt>IsDebuggerPresent()</tt>: Set the <tt>BeingDebugged</tt> flag of the Process Environment Block (PEB) to 0. See <a href="#beingdebugged_mitigation">BeingDebugged Flag Mitigation</a> for further information.</li>

<li>For <tt>CheckRemoteDebuggerPresent()</tt> and <tt>NtQueryInformationProcess()</tt>: <br />As <tt>CheckRemoteDebuggerPresent()</tt> calls <tt>NtQueryInformationProcess()</tt>, the only way is to hook the <tt>NtQueryInformationProcess()</tt> and set the following values in return buffers:</li>

  <ul>
    <li>0 (or any value except -1) in case of a <tt>ProcessDebugPort</tt> query.</li>
    <li>Non-zero value in case of a <tt>ProcessDebugFlags</tt> query.</li>
    <li>0 in case of a <tt>ProcessDebugObjectHandle</tt> query.</li>
  </ul>

<li> The only way to mitigate these checks with <tt>RtlQueryProcessHeapInformation()</tt>, <tt>RtlQueryProcessDebugInformation()</tt> and <tt>NtQuerySystemInformation()</tt> functions is to hook them and modify the returned values:</li>
  <ul>
    <li><tt>RTL_PROCESS_HEAPS::HeapInformation::Heaps[0]::Flags</tt> to <tt>HEAP_GROWABLE</tt> for <br />
        <tt>RtlQueryProcessHeapInformation()</tt> and <tt>RtlQueryProcessDebugInformation()</tt>.</li>
    <li><tt>SYSTEM_KERNEL_DEBUGGER_INFORMATION::DebuggerEnabled</tt> to 0 and <br />
        <tt>SYSTEM_KERNEL_DEBUGGER_INFORMATION::DebuggerNotPresent</tt> to 1 for the <br />
        <tt>NtQuerySystemInformation()</tt> function in case of a <tt>SystemKernelDebuggerInformation</tt> query.</li>
  </ul>
</ul>

<br />
<h3><a class="a-dummy" name="manual-checks">2. Manual checks</a></h3>
The following approaches are used to validate debugging flags in system structures. They examine the process memory manually without using special debug API functions.

<br />
<h4><a class="a-dummy" name="manual-checks-peb-beingdebugged-flag">2.1. PEB!BeingDebugged Flag</a></h4>
This method is just another way to check <tt>BeingDebugged</tt> flag of PEB without calling <tt>IsDebuggerPresent()</tt>.

<hr class="space">

<b>32Bit Process</b>
<p></p>

{% highlight nasm %}
mov eax, fs:[30h]
cmp byte ptr [eax+2], 0
jne being_debugged
{% endhighlight %}

<hr class="space">

<b>64Bit Process</b>
<p></p>

{% highlight nasm %}
mov rax, gs:[60h]
cmp byte ptr [rax+2], 0
jne being_debugged
{% endhighlight %}

<hr class="space">

<b>WOW64 Process</b>
<p></p>

{% highlight nasm %}
mov eax, fs:[30h]
cmp byte ptr [eax+1002h], 0
{% endhighlight %}

<hr class="space">

<b>C/C++ Code</b>
<p></p>

{% highlight c %}

#ifndef _WIN64
PPEB pPeb = (PPEB)__readfsdword(0x30);
#else
PPEB pPeb = (PPEB)__readgsqword(0x60);
#endif // _WIN64
 
if (pPeb->BeingDebugged)
    goto being_debugged;

{% endhighlight %}

<br />
<h4><a class="a-dummy" name="manual-checks-ntglobalflag">2.2. NtGlobalFlag</a></h4>
The <tt>NtGlobalFlag</tt> field of the Process Environment Block (<tt>0x68</tt> offset on 32-Bit and <tt>0xBC</tt> on 64-bit Windows) is 0 by default. Attaching a debugger doesn't change the value of <tt>NtGlobalFlag</tt>. However, if the process was created by a debugger, the following flags will be set:
<ul>
<li><tt>FLG_HEAP_ENABLE_TAIL_CHECK</tt> (0x10)</li>
<li><tt>FLG_HEAP_ENABLE_FREE_CHECK</tt> (0x20)</li>
<li><tt>FLG_HEAP_VALIDATE_PARAMETERS</tt> (0x40)</li>
</ul>

<hr class="space">

The presence of a debugger can be detected by checking a combination of those flags.

<hr class="space">

<b>32Bit Process</b>
<p></p>

{% highlight nasm %}
mov eax, fs:[30h]
mov al, [eax+68h]
and al, 70h
cmp al, 70h
jz  being_debugged
{% endhighlight %}

<hr class="space">

<b>64Bit Process</b>
<p></p>

{% highlight nasm %}
mov rax, gs:[60h]
mov al, [rax+BCh]
and al, 70h
cmp al, 70h
jz  being_debugged
{% endhighlight %}

<hr class="space">

<b>WOW64 Process</b>
<p></p>

{% highlight nasm %}
mov eax, fs:[30h]
mov al, [eax+10BCh]
and al, 70h
cmp al, 70h
jz  being_debugged
{% endhighlight %}

<hr class="space">

<b>C/C++ Code</b>
<p></p>

{% highlight c %}

#define FLG_HEAP_ENABLE_TAIL_CHECK   0x10
#define FLG_HEAP_ENABLE_FREE_CHECK   0x20
#define FLG_HEAP_VALIDATE_PARAMETERS 0x40
#define NT_GLOBAL_FLAG_DEBUGGED (FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS)

#ifndef _WIN64
PPEB pPeb = (PPEB)__readfsdword(0x30);
DWORD dwNtGlobalFlag = *(PDWORD)((PBYTE)pPeb + 0x68);
#else
PPEB pPeb = (PPEB)__readgsqword(0x60);
DWORD dwNtGlobalFlag = *(PDWORD)((PBYTE)pPeb + 0xBC);
#endif // _WIN64
 
if (dwNtGlobalFlag & NT_GLOBAL_FLAG_DEBUGGED)
    goto being_debugged;


{% endhighlight %}

<br />
<h4><a class="a-dummy" name="manual-checks-heap-flags">2.3. Heap Flags</a></h4>
The heap contains two fields which are affected by the presence of a debugger. Exactly how they are affected depends on the Windows version. These fields are <tt>Flags</tt> and <tt>ForceFlags</tt>.

The values of <tt>Flags</tt> and <tt>ForceFlags</tt> are normally set to <tt>HEAP_GROWABLE</tt> and <tt>0</tt>, respectively.

<hr class="space">

When a debugger is present, the <tt>Flags</tt> field is set to a combination of these flags on Windows NT, Windows 2000, and 32-bit Windows XP:
<ul>
<li><tt>HEAP_GROWABLE</tt> (2)</li>
<li><tt>HEAP_TAIL_CHECKING_ENABLED</tt> (0x20)</li>
<li><tt>HEAP_FREE_CHECKING_ENABLED</tt> (0x40)</li>
<li><tt>HEAP_SKIP_VALIDATION_CHECKS</tt> (0x10000000)</li>
<li><tt>HEAP_VALIDATE_PARAMETERS_ENABLED</tt> (0x40000000)</li>
</ul>

<hr class="space">

On 64-bit Windows XP, and Windows Vista and higher, if a debugger is present, the <tt>Flags</tt> field is set to a combination of these flags:
<ul>
<li><tt>HEAP_GROWABLE</tt> (2)</li>
<li><tt>HEAP_TAIL_CHECKING_ENABLED</tt> (0x20)</li>
<li><tt>HEAP_FREE_CHECKING_ENABLED</tt> (0x40)</li>
<li><tt>HEAP_VALIDATE_PARAMETERS_ENABLED</tt> (0x40000000)</li>
</ul>

<hr class="space">

When a debugger is present, the <tt>ForceFlags</tt> field is set to a combination of these flags:
<ul>
<li><tt>HEAP_TAIL_CHECKING_ENABLED</tt> (0x20)</li>
<li><tt>HEAP_FREE_CHECKING_ENABLED</tt> (0x40)</li>
<li><tt>HEAP_VALIDATE_PARAMETERS_ENABLED</tt> (0x40000000)</li>
</ul>

<hr class="space">

<b>C/C++ Code</b>
<p></p>

{% highlight c %}

bool Check()
{
#ifndef _WIN64
    PPEB pPeb = (PPEB)__readfsdword(0x30);
    PVOID pHeapBase = !m_bIsWow64
        ? (PVOID)(*(PDWORD_PTR)((PBYTE)pPeb + 0x18))
        : (PVOID)(*(PDWORD_PTR)((PBYTE)pPeb + 0x1030));
    DWORD dwHeapFlagsOffset = IsWindowsVistaOrGreater()
        ? 0x40
        : 0x0C;
    DWORD dwHeapForceFlagsOffset = IsWindowsVistaOrGreater()
        ? 0x44 
        : 0x10;
#else
    PPEB pPeb = (PPEB)__readgsqword(0x60);
    PVOID pHeapBase = (PVOID)(*(PDWORD_PTR)((PBYTE)pPeb + 0x30));
    DWORD dwHeapFlagsOffset = IsWindowsVistaOrGreater()
        ? 0x70 
        : 0x14;
    DWORD dwHeapForceFlagsOffset = IsWindowsVistaOrGreater()
        ? 0x74 
        : 0x18;
#endif // _WIN64

    PDWORD pdwHeapFlags = (PDWORD)((PBYTE)pHeapBase + dwHeapFlagsOffset);
    PDWORD pdwHeapForceFlags = (PDWORD)((PBYTE)pHeapBase + dwHeapForceFlagsOffset);
    return (*pdwHeapFlags & ~HEAP_GROWABLE) || (*pdwHeapForceFlags != 0);
}

{% endhighlight %}

<br />
<h4><a class="a-dummy" name="manual-checks-heap-protection">2.4. Heap Protection</a></h4>
If the <tt>HEAP_TAIL_CHECKING_ENABLED</tt> flag is set in <tt>NtGlobalFlag</tt>, the sequence <tt>0xABABABAB</tt> will be appended (twice in 32-Bit and 4 times in 64-Bit Windows) at the end of the allocated heap block.

If the <tt>HEAP_FREE_CHECKING_ENABLED</tt> flag is set in <tt>NtGlobalFlag</tt>, the sequence <tt>0xFEEEFEEE</tt> will be appended if additional bytes are required to fill in the empty space until the next memory block.

<hr class="space">

<b>C/C++ Code</b>
<p></p>

{% highlight c %}

bool Check()
{
    PROCESS_HEAP_ENTRY HeapEntry = { 0 };
    do
    {
        if (!HeapWalk(GetProcessHeap(), &HeapEntry))
            return false;
    } while (HeapEntry.wFlags != PROCESS_HEAP_ENTRY_BUSY);

    PVOID pOverlapped = (PBYTE)HeapEntry.lpData + HeapEntry.cbData;
    return ((DWORD)(*(PDWORD)pOverlapped) == 0xABABABAB);
}

{% endhighlight %}

<br />
<h4><a class="a-dummy" name="kuser_shared_data">2.5. Check KUSER_SHARED_DATA structure</a></h4>
This technique was originally described as an <a href="https://github.com/mrexodia/TitanHide/issues/18">issue for TitanHide</a>, a kernel driver to hide debuggers from detection. The detailed documentation for the structure <tt>KUSER_SHARED_DATA</tt> and its fields is available  <a href="https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/ntexapi_x/kuser_shared_data/index.htm">here</a>.

Here is what the author of the issue wrote in the post regarding the features of the structure and its appropriate field:
<i>"0x7ffe02d4 is actually 0x7ffe0000 + 0x2d4. 0x7ffe0000 is the fixed user mode address of the KUSER_SHARED_DATA structure that contains data that is shared between user mode and the kernel (though user mode doesn't have write access to it). The struct has some interesting properties:</i>
<li><i>its address is fixed and has been in all Windows versions since it was introduced</i></li>
<li><i>its user mode address is the same in 32 bit and 64 bit mode</i></li>
<li><i>all offsets and sizes are strictly fixed, and new fields are only ever appended or added in place of unused padding space</i></li>

<br>
<i>Hence this program will work in 32 bit Windows 2000 and 64 bit Windows 10 without recompiling".
</i>

<hr class="space">

<b>C/C++ Code</b>
<p></p>

{% highlight c %}

bool check_kuser_shared_data_structure()
{
    unsigned char b = *(unsigned char*)0x7ffe02d4;
    return ((b & 0x01) || (b & 0x02));
}

{% endhighlight %}

<br />
<h4><a class="a-dummy" name="mitigations-manual-checks">Mitigations</a></h4>

<br />
<b id="beingdebugged_mitigation">For PEB!BeingDebugged Flag:</b>
<p></p>
Set the <tt>BeingDebugged</tt> flag to 0. This can be done by DLL injection. If you use OllyDbg or x32/64dbg as a debugger, you can choose various Anti-Debug plugins such as <a href="https://github.com/x64dbg/ScyllaHide">ScyllaHide</a>.

<hr class="space">

{% highlight c %}

#ifndef _WIN64
PPEB pPeb = (PPEB)__readfsdword(0x30);
#else
PPEB pPeb = (PPEB)__readgsqword(0x60);
#endif // _WIN64
pPeb->BeingDebugged = 0;

{% endhighlight %}

<br />
<b>For NtGlobalFlag:</b>
<p></p>
Set the <tt>NtGlobalFlag</tt> to 0. This can be done by DLL injection. If you use OllyDbg or x32/64dbg as a debugger, you can choose various Anti-Debug plugins such as <a href="https://github.com/x64dbg/ScyllaHide">ScyllaHide</a>.

<hr class="space">

{% highlight c %}

#ifndef _WIN64
PPEB pPeb = (PPEB)__readfsdword(0x30);
*(PDWORD)((PBYTE)pPeb + 0x68) = 0;
#else
PPEB pPeb = (PPEB)__readgsqword(0x60);
*(PDWORD)((PBYTE)pPeb + 0xBC); = 0;
#endif // _WIN64

{% endhighlight %}

<br />
<b>For Heap Flags:</b>
<p></p>
Set the <tt>Flags</tt> value to <tt>HEAP_GROWABLE</tt>, and the <tt>ForceFlags</tt> value to 0. This can be done by DLL injection. If you use OllyDbg or x32/64dbg as a debugger, you can choose various Anti-Debug plugins such as <a href="https://github.com/x64dbg/ScyllaHide">ScyllaHide</a>.

<hr class="space">

{% highlight c %}

#ifndef _WIN64
PPEB pPeb = (PPEB)__readfsdword(0x30);
PVOID pHeapBase = !m_bIsWow64
    ? (PVOID)(*(PDWORD_PTR)((PBYTE)pPeb + 0x18))
    : (PVOID)(*(PDWORD_PTR)((PBYTE)pPeb + 0x1030));
DWORD dwHeapFlagsOffset = IsWindowsVistaOrGreater()
    ? 0x40
    : 0x0C;
DWORD dwHeapForceFlagsOffset = IsWindowsVistaOrGreater()
    ? 0x44 
    : 0x10;
#else
PPEB pPeb = (PPEB)__readgsqword(0x60);
PVOID pHeapBase = (PVOID)(*(PDWORD_PTR)((PBYTE)pPeb + 0x30));
DWORD dwHeapFlagsOffset = IsWindowsVistaOrGreater()
    ? 0x70 
    : 0x14;
DWORD dwHeapForceFlagsOffset = IsWindowsVistaOrGreater()
    ? 0x74 
    : 0x18;
#endif // _WIN64

*(PDWORD)((PBYTE)pHeapBase + dwHeapFlagsOffset) = HEAP_GROWABLE;
*(PDWORD)((PBYTE)pHeapBase + dwHeapForceFlagsOffset) = 0;

{% endhighlight %}

<br />
<b>For Heap Protection:</b>
<p></p>
Manually patch 12 bytes for 32-bit and 20 bytes in a 64-bit environment after the heap. Hook <tt>kernel32!HeapAlloc()</tt> and patch the heap after its allocation.

<hr class="space">

{% highlight c %}

#ifndef _WIN64
SIZE_T nBytesToPatch = 12;
#else
SIZE_T nBytesToPatch = 20;
#endif // _WIN64

SIZE_T nDwordsToPatch = nBytesToPatch / sizeof(DWORD);
PVOID pHeapEnd = (PBYTE)HeapEntry.lpData + HeapEntry.cbData;
for (SIZE_T offset = 0; offset < nDwordsToPatch; offset++)
    *((PDWORD)pHeapEnd + offset) = 0;

{% endhighlight %}

<br />
<b>For KUSER_SHARED_DATA:</b>
<p></p>
For a possible mitigation, please check the link when the technique is described (with the issue for TitanHide) and also a draft code for patching <tt>kdcom.dll</tt> <a href="https://gist.github.com/anonymous/b5024c25634fc36e699cd9d041224531">here</a>.
