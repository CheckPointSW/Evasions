---
layout: post
title:  "Evasions: Bypassing Security Solutions"
title-image: "/assets/icons/AVBypass.svg"
categories: evasions
tags: AVBypass
---

<h1>Contents</h1>

[Bypassing Security Solutions detection methods](#avbypass-detection-methods)
<br />
[1. Detect Wine](#detect-wine)
<br />
[2. Add to Windows defender exclusion list](#add-to-windows-defender-exclusion-list)
<br />
[3. Patch EtwEventWrite](#patch-etweventwrite)
<br />
[Signature recommendations](#signature-recommendations)
<br />
[Countermeasures](#countermeasures)
<br />
<br />

<hr class="space">

<h2><a class="a-dummy" name="avbypass-detection-methods">Bypassing Security Solutions detection methods</a></h2>
Techniques described in this group abuse different vendors and AVs and try to bypass them without being detected.
<br />
<h3><a class="a-dummy" name="detect-wine">1. Detect Wine</a></h3>

<hr class="space">

The <tt>MulDiv</tt> [API](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-muldiv) is being called with specific arguments (<tt>`MulDiv(1, 0x80000000, 0x80000000)`</tt>) which should logically return 1 - however, due to a bug with the ancient implementation on Windows, it returns 2.

There are more known evasion methods to detect Wine like the good old check of searching for the existence of one of Wine’s exclusive APIs such as <tt>`kernel32.dll!wine_get_unix_file_name`</tt> or <tt>`ntdll.dll!wine_get_host_version`</tt>).

<br />

<h3><a class="a-dummy" name="add-to-windows-defender-exclusion-list">2. Add to Windows defender exclusion list</a></h3> 
One way to evade Windows Defender is by adding its processes and paths to its exclusion list. 
It is being done by adding the values to the registry keys: <tt>HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths</tt> and <tt>HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Processes</tt>.


<br />

<h3><a class="a-dummy" name="patch-etweventwrite">3. Patch EtwEventWrite</a></h3>
<tt>EtwEventWrite</tt> is a function used for logging events in the Event Tracing for Windows (ETW) system.
Malware may patch this function to prevent its own activities from being logged or detected by security monitoring tools that rely on ETW for event logging and analysis.
By intercepting calls to <tt>EtwEventWrite</tt>, malware can suppress or alter the events that would otherwise be recorded, making it more difficult for security analysts to detect and analyze the malware's behavior.

<hr class="space">

<b>C/C++ Code</b>
<p></p>

{% highlight c %}

void Patch_DbgBreakPoint()
{
HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
if (!hNtdll)
return;

    FARPROC pDbgBreakPoint = GetProcAddress(hNtdll, "EtwEventWrite");
    if (!pDbgBreakPoint)
        return;

    DWORD dwOldProtect;
    if (!VirtualProtect(pDbgBreakPoint, 1, PAGE_EXECUTE_READWRITE, &dwOldProtect))
        return;

    *(PBYTE)pDbgBreakPoint = (BYTE)0xC3; // ret
}

{% endhighlight %}

<br />

<h3><a class="a-dummy" name="signature-recommendations">Signature recommendations</a></h3>
<li><tt>versus Detect Wine:</tt> Check if <tt>`MulDiv(1, 0x80000000, 0x80000000)`</tt> is being called</li> 
<li><tt>versus Add to Windows defender exclusion list</tt> Check if those registry keys are set with new values of untrusted files</li> 
<li><tt>versus Patch EtwEventWrite</tt> Check if first byte of EtwEventWrite  is changed to <tt>C3</tt></li> 

<br />
<h3><a class="a-dummy" name="countermeasures">Countermeasures</a></h3>

<ul>
<li><tt>versus Detect Wine:</tt>If Using Wine, hook MulDiv to return 2 or modify the implementation as it works in Windows.</li> 
</ul>

<br />
