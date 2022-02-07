---
layout: post
title:  "Evasions: Hooks"
title-image: "/assets/icons/hooks.svg"
categories: evasions 
tags: hooks
---

<h1>Contents</h1>

[Hooks detection methods](#hooks-detection-methods)
<br />
  [1. Check whether hooks are set within system functions](#check-whether-hooks-are-set-within-system-functions)
<br />
  [2. Check user clicks via mouse hooks](#check-user-clicks-via-mouse-hooks)
<br />
  [3. Check for incorrectly hooked functions](#check-incorrectly-hooked-functions)
<br />
  [Signature recommendations](#signature-recommendations)
<br />
  [Countermeasures](#countermeasures)
<br />
  [Credits](#credits)
<br />
<br />

<hr class="space">

<h2><a class="a-dummy" name="hooks-detection-methods">Hooks detection methods</a></h2>
Techniques described here make use of hooks either to detect user presence or as means to be checked whether some unusual-for-host-OS hooks installed.

<br />
<h3><a class="a-dummy" name="check-whether-hooks-are-set-within-system-functions">1. Check whether hooks are set within system functions</a></h3>
Malware reads memory at specific addresses to check if Windows API functions are hooked.
<br />
This method is based on the fact, that emulation environments are most likely to hook these functions to be able to gather data and statistics during an emulation.

<hr class="space">

Popular functions to be checked:
<p></p>
<ul>
<li><tt>ReadFile</tt></li>
<li><tt>DeleteFile</tt></li>
<li><tt>CreateProcessA/W</tt></li>
</ul>

<hr class="space">

Reading memory is accomplished via the following functions:
<p></p>
<ul>
<li><tt>ReadProcessMemory</tt></li>
<li><tt>NtReadVirtualMemory</tt></li>
</ul>

<hr class="space">

Then different algorithms may be used for checking:
<p></p>
<ul>
<li>Comparing first two bytes with <tt>\x8B\xFF (mov edi, edi)</tt> — typical prologue start for <tt>kernel32</tt> functions.</li>
<li>Comparing first N bytes with <tt>\xCC</tt> - software breakpoint (<tt>int 3</tt>), not connected with hooks directly but still a suspicious behavior.</li>
<li>Comparing first N bytes with <tt>\xE9</tt> (<tt>call</tt>) or with <tt>\xEB</tt> (<tt>jmp</tt> instruction) — typical instructions for redirecting execution.</li>
<li>Checking for <tt>push/ret</tt> combo for execution redirection.</li>
</ul>
and so on.

<hr class="space">

It's pretty tricky to count for every possible comparison so general indication of something unusual in application's behavior is reading memory where OS libraries reside. If to be more precise: reading memory where "interesting" functions are situated.

<hr class="space">

<a href="https://0x00sec.org/t/defeating-userland-hooks-ft-bitdefender/12496">This atricle</a> explains how to detect user-mode hooks and remove them. The following code samples are taken from the article.

<hr class="space">

<b>Example of hook detection</b>
<p></p>

{% highlight c %}

HOOK_TYPE IsHooked(LPCVOID lpFuncAddress, DWORD_PTR *dwAddressOffset) {
    LPCBYTE lpBytePtr = (LPCBYTE)lpFuncAddress;

    if (lpBytePtr[0] == 0xE9) {
        *dwAddressOffset = 1;
        return HOOK_RELATIVE;    // E9 jmp is relative.
    } else if (lpBytePtr[0] == 0x68 &&  lpBytePtr[5] == 0xC3) {
        *dwAddressOffset = 1;
        return HOOK_ABOLSUTE;    // push/ret is absolute.
    }

    return HOOK_NONE;            // No hook.
}

LPVOID lpFunction = ...;
DWORD_PTR dwOffset = 0;
LPVOID dwHookAddress = 0;

HOOK_TYPE ht = IsHooked(lpFunction, &dwOffset);
if (ht == HOOK_ABSOLUTE) {
    // 1. Get the pointer to the address (lpFunction + dwOffset)
    // 2. Cast it to a DWORD pointer
    // 3. Dereference it to get the DWORD value
    // 4. Cast it to a pointer
    dwHookAddress = (LPVOID)(*(LPDWORD)((LPBYTE)lpFunction + dwOffset));
} else if (ht == HOOK_RELATIVE) {
    // 1. Get the pointer to the address (lpFunction + dwOffset)
    // 2. Cast it to an INT pointer
    // 3. Dereference it to get the INT value (this can be negative)
    INT nJumpSize = (*(PINT)((LPBYTE)lpFunction  + dwOffset);
    // 4. E9 jmp starts from the address AFTER the jmp instruction
    DWORD_PTR dwRelativeAddress = (DWORD_PTR)((LPBYTE)lpFunction + dwOffset + 4));
    // 5. Add the relative address and jump size
    dwHookAddress = (LPVOID)(dwRelativeAddress + nJumpSize);
}
{% endhighlight %}

<hr class="space">

<b>Example of unhooking functions</b>
<p></p>

{% highlight c %}

// Parse the PE headers.
PIMAGE_DOS_HEADER pidh = (PIMAGE_DOS_HEADER)lpMapping;
PIMAGE_NT_HEADERS pinh = (PIMAGE_NT_HEADERS)((DWORD_PTR)lpMapping + pidh->e_lfanew);

// Walk the section headers and find the .text section.
for (WORD i = 0; i < pinh->FileHeader.NumberOfSections; i++) {
    PIMAGE_SECTION_HEADER pish = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(pinh) + 
                                 ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));
    if (!strcmp(pish->Name, ".text")) {
        // Deprotect the module's memory region for write permissions.
        DWORD flProtect = ProtectMemory(
            (LPVOID)((DWORD_PTR)hModule + (DWORD_PTR)pish->VirtualAddress),    // Address to protect.
            pish->Misc.VirtualSize,                        // Size to protect.
            PAGE_EXECUTE_READWRITE                         // Desired protection.
        );

        // Replace the hooked module's .text section with the newly mapped module's.
        memcpy(
            (LPVOID)((DWORD_PTR)hModule + (DWORD_PTR)pish->VirtualAddress),
            (LPVOID)((DWORD_PTR)lpMapping + (DWORD_PTR)pish->VirtualAddress),
            pish->Misc.VirtualSize
        );

        // Reprotect the module's memory region.
        flProtect = ProtectMemory(
            (LPVOID)((DWORD_PTR)hModule + (DWORD_PTR)pish->VirtualAddress),    // Address to protect.
            pish->Misc.VirtualSize,                        // Size to protect.
            flProtect                                      // Revert to old protection.
        );
    }
}
{% endhighlight %}

<hr class="space">

<br />
<h3><a class="a-dummy" name="check-user-clicks-via-mouse-hooks">2. Check user clicks via mouse hooks</a></h3>
This technique is described <a href="https://www.fireeye.com/content/dam/fireeye-www/current-threats/pdfs/pf/file/fireeye-hot-knives-through-butter.pdf">by this link</a> (p.4, p.7).

<hr class="space">

Malware sets mouse hook to detect a click (or more) if it occurs. If it's the case malware treats the host a usual one, i.e., with end user behind the screen - not a virtual environment. If no mouse click is detected then it's very likely a virtual environment.

<hr class="space">

Functions used:
<p></p>
<ul>
<li><tt>SetWindowsHookExA/W (WH_MOUSE_LL, ...)</tt></li>
<li><tt>GetAsyncKeyState</tt></li>
</ul>

<hr class="space">

<b>Code sample (<tt>SetWindowsHookExA</tt>)</b>
<p></p>

{% highlight c %}

HHOOK g_hhkMouseHook = NULL;

LRESULT CALLBACK mouseHookProc(int nCode, WPARAM wParam, LPARAM lParam)
{
  switch (wParam)
  {
  case WM_MOUSEMOVE:
    // ...
    break;
  case WM_NCLBUTTONDOWN:
    // ...
    break;
  case WM_LBUTTONUP:
    UnhookWindowsHookEx(g_hhkMouseHook);
    CallMaliciousCode();
    ExitProcess(0);
  }
  return CallNextHookEx(g_hhkMouseHook, nCode, wParam, lParam);
}

g_hhkMouseHook = SetWindowsHookEx(WH_MOUSE_LL, mouseHookProc, GetModuleHandleA(NULL), NULL);
{% endhighlight %}

<hr class="space">

<b>Code sample (<tt>GetAsyncKeyState</tt>)</b>
<p></p>

{% highlight c %}

std::thread t([]()
{
  int count = 0;
  while (true)
  {
    if (GetAsyncKeyState(VK_LBUTTON) || GetAsyncKeyState(VK_RBUTTON) || GetAsyncKeyState(VK_MBUTTON))
    {
      if (++count == 2)
        break;
    }
    Sleep(100);
  }
  CallMaliciousCode();
});
t.join();
{% endhighlight %}

<br />
<h3><a class="a-dummy" name="check-incorrectly-hooked-functions">3. Check for incorrectly hooked functions</a></h3>
There are more than 400 Native API functions (or Nt-functions) in <tt>ntdll.dll</tt> that are usually hooked in sandboxes. 
In such a large list, there is enough space for different kinds of mistakes. We checked the hooked Nt-functions in popular sandboxes 
and found several issues. On of them is a lack of necessary checks for arguments in a hooked function. This case is
described our article "<a href="timing.html#call-hooked-function-with-invalid-arguments">Timing: Call a potentially hooked delay function with invalid arguments evasions</a>"
<br />
Another issue we found is a discrepancy in the number of arguments in a hooked and an original function. 
If a function is hooked incorrectly, in kernel mode this may lead an operating system to crash. Incorrect user-mode 
hooks are not as critical. However, they may lead an analyzed application to crash or can be easily detected.
For example, let’s look at the <tt>NtLoadKeyEx</tt> function. It was first introduced in Windows Server 2003 and had 
only 4 arguments. Starting from Windows Vista up to the latest version of Windows 10, it has 8 arguments:
    
    ; Exported entry 318. NtLoadKeyEx
    ; Exported entry 1450. ZwLoadKeyEx
    ; __stdcall NtLoadKeyEx(x, x, x, x, x, x, x, x)
    public _NtLoadKeyEx@32
    
However, in the Cuckoo monitor, the <tt>NtLoadKeyEx</tt> declaration still has only 
<a href="https://github.com/cuckoosandbox/monitor/blob/8c419e6216f379e01ea0caa3a71142543e10fc04/sigs/registry_native.rst#ntloadkeyex">4 arguments</a>:

    *  POBJECT_ATTRIBUTES TargetKey
    *  POBJECT_ATTRIBUTES SourceFile
    ** ULONG Flags flags
    ** HANDLE TrustClassKey trust_class_key
    
We found this legacy prototype used in other sources as well. For example, 
<a href="https://github.com/ctxis/capemon/blob/e541d7ccd41d519de4198f7965c5b584d2a66ed6/hooks.h#L710">CAPE monitor</a>
has the same issue:

{% highlight c %}
extern HOOKDEF(NTSTATUS, WINAPI, NtLoadKeyEx,
    __in      POBJECT_ATTRIBUTES TargetKey,
    __in      POBJECT_ATTRIBUTES SourceFile,
    __in      ULONG Flags,
    __in_opt  HANDLE TrustClassKey
);
{% endhighlight %}

Therefore, if a sandbox uses any recent Windows OS, this function is hooked incorrectly. After the call to the 
incorrectly hooked function, the stack pointer value becomes invalid. Therefore, a totally "legitimate" call to the 
<tt>RegLoadAppKeyW</tt> function, which calls <tt>NtLoadKeyEx</tt>, leads to an exception. This fact can be used to 
evade Cuckoo and CAPE sandbox with just a single call to the <tt>RegLoadAppKeyW</tt> function.

<b>Code sample</b>
<p></p>
{% highlight c %}

RegLoadAppKeyW(L"storage.dat", &hKey, KEY_ALL_ACCESS, 0, 0);
// If the application is running in a sandbox an exception will occur
// and the code below will not be executed.

// Some legitimate code that works with hKey to distract attention goes here
// ...
RegCloseKey(hKey);
// Malicious code goes here
// ...

{% endhighlight %}

Instead of using <tt>RegLoadAppKeyW</tt>, we can call the <tt>NtLoadKeyEx</tt> function directly and check the ESP 
value after the call.

<b>Code sample</b>
<p></p>
{% highlight c %}
__try
{
    _asm mov old_esp, esp
    NtLoadKeyEx(&TargetKey, &SourceFile, 0, 0, 0, KEY_ALL_ACCESS, &hKey, &ioStatus);
    _asm mov new_esp, esp
    _asm mov esp, old_esp
    if (old_esp != new_esp)
        printf("Sandbox detected!");
}
__except (EXCEPTION_EXECUTE_HANDLER)
{
    printf("Sandbox detected!");
}
{% endhighlight %}


<br />
<h3><a class="a-dummy" name="signature-recommendations">Signature recommendations</a></h3>
<i>No signature recommendations are provided for this evasion group as it's hard to make a difference between the code which aims for some evasion technique and the one which is "legally used".</i>

<br />
<h3><a class="a-dummy" name="countermeasures">Countermeasures</a></h3>

<ul>
<li><tt>versus function hook checks:</tt> set kernel mode hooks; second solution is to use stack routing to implement function hooking;</li>
<li><tt>versus mouse click checks via hooks:</tt> use mouse movement emulation module.</li>
<li><tt>versus incorrect function hooks:</tt> ensure all the hooked function have the same number of arguments as the original functions</li> 
</ul>

<br />
<h3><a class="a-dummy" name="credits">Credits</a></h3>

Credits go to user <tt>dtm</tt> from  <a href="https://0x00sec.org/">0x00sec.org</a> forum.

Due to modular code structure of the Check Point's tool called InviZzzible it would require more space to show a code sample from this tool for the same purposes. That's why we've decided to use other great open-source projects for examples throughout the encyclopedia.
