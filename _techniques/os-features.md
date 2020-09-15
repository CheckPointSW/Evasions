---
layout: post
title:  "Evasions: OS features"
title-image: "/assets/icons/os-features.svg"
categories: evasions 
tags: os-features
---

<h1>Contents</h1>

[OS features detection methods](#os-features-detection-methods)
<br />
  [1. Checking debug privileges](#checking-debug-privileges)
<br />
  [2. Using unbalanced stack](#using-unbalanced-stack)
<br />
  [Countermeasures](#countermeasures)
<br />
  [Credits](#credits)
<br />
<br />

<hr class="space">

<h2><a class="a-dummy" name="os-features-detection-methods">OS features detection methods</a></h2>
Evasions in this group use peculiarities of how OS work.

<br />
<h3><a class="a-dummy" name="checking-debug-privileges">1. Checking debug privileges</a></h3>
If the malware is running under debugger or in a sandbox like Cuckoo its process token will have a debug privilege in the enabled state. It happens because this privilege is enabled in the parent process and inherited by the malware process.

<hr class="space">

The malware tries to open crucial system processes like <tt>csrss.exe</tt>, <tt>smss.exe</tt>, <tt>lsass.exe</tt> with <tt>PROCESS_ALL_ACCESS</tt> access right and then tries to terminate them. This will fail in a normal case when the malware is executed from the explorer or command line because even an Administrator user can't terminate those processes. But this will succeed if the process token has the debug privilege in the enabled state. Termination of crucial system process leads OS to crash into BSOD with an error <tt>0x000000F4</tt> so the emulation process will be aborted.

<hr class="space">

Functions to get snapshot of running processes:
<ul>
  <li><tt>CreateToolhelp32Snapshot</tt></li> 
  <li><tt>psapi.EnumProcesses (WinXP, Vista)</tt></li> 
  <li><tt>kernel32.EnumProcesses (Win7+)</tt></li> 
</ul>

<hr class="space">

Function used to open the process:
<ul>
  <li><tt>OpenProcess(PROCESS_ALL_ACCESS, ..., pid)  // track for PIDs of 'csrss.exe', 'smss.exe', 'lsass.exe'</tt></li> 
</ul>

<hr class="space">

<b>Code sample</b>
<p></p>

{% highlight c %}

/*
If we're being debugged and the process has SeDebugPrivileges 
privileges then OpenProcess call will be successful.
This requires administrator privilege!
In Windows XP, Vista and 7, calling OpenProcess with 
PROCESS_ALL_ACCESS will fait even with SeDebugPrivilege enabled,
That's why I used PROCESS_QUERY_LIMITED_INFORMATION
*/

DWORD GetCsrssProcessId()
{
  if (API::IsAvailable(API_IDENTIFIER::API_CsrGetProcessId))
  {
    auto CsrGetProcessId = static_cast<pCsrGetId>(API::GetAPI(API_IDENTIFIER::API_CsrGetProcessId));

    return CsrGetProcessId();
  }
  else
    return GetProcessIdFromName(_T("csrss.exe"));
}


BOOL CanOpenCsrss()
{
   HANDLE hCsrss = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, GetCsrssProcessId());
   if (hCsrss != NULL)
  {
    CloseHandle(hCsrss);
    return TRUE;
  }
  else
    return FALSE;
}
{% endhighlight %}

<i>Credits for this code sample: <a href="https://github.com/LordNoteworthy/al-khaser">al-khaser project</a></i>

<hr class="space">

<b>Signature recommendations</b>
<p></p>
If <tt>OpenProcess</tt> requests all the possible rights when opening one of the critical system processes — it's a strong indicator of malware trying to apply this evasion technique.

<br />
<h3><a class="a-dummy" name="using-unbalanced-stack">2. Using unbalanced stack</a></h3>
This technique was presented at Virus Bulletin 2016 by Check Point Malware Reverse Engineering Team. It is described <a href="https://www.virusbulletin.com/uploads/pdf/magazine/2016/VB2016-Chailytko-Skuratovich.pdf">by this link</a>.

<hr class="space">

To track process behaviour, the CuckooMon/Cuckoo Monitor module hooks relevant functions. In this type of architecture, the hook is called before the original function. A hooked function may use some space on the stack in addition to that used by the original function. Therefore, the total space on the stack used by the hooked function may be larger than the space used only by the original function.

<hr class="space">

<b>Problem:</b> The malware has information about how much space the called function uses on the stack. It can therefore move the stack pointer towards lower addresses at an offset that is sufficient to store the function arguments, local variables and return address to reserve space for them. The malware fills the space below the stack pointer with some relevant data. It then moves the stack pointer to the original location and calls the library function. If the function is not hooked, the malware fills in the reserved space before the relevant data (see Figure 1). If the function is hooked, the malware overlaps relevant data, because the space that was reserved for the original function’s local variables is smaller than the space occupied by the hook and the original function’s local variables combined. The relevant data is therefore corrupted (see Figure 2). If it stores pointers to some functions that are used later during the execution process, the malware jumps to arbitrary code, occasionally crashing the application.

<hr class="space">

<div style="text-align: center; margin: auto">
  <img src="{{site.baseurl}}/assets/images/unbalanced_stack_unhook.png" height="300px">
  <img src="{{site.baseurl}}/assets/images/unbalanced_stack_hook.png" height="300px"><br />
  <i>Stack on non-hooked and on hooked function call.</i>
</div>

<hr class="space">

<b>Solution:</b> To avoid this behaviour, the Cuckoo Monitor/CuckooMon module can use a two-stage hooking process. In the fi rst stage, instead of the hook’s code execution, it can move the stack pointer towards lower addresses of a specifi c size that will be enough for the malware’s relevant data. Then, the function’s arguments are copied under the new stack pointer. Only after these preparatory operations have been completed is the second stage hook (which performs the real hooking) called. Relevant data fi lled in by the malware resides on upper stack addresses, thus it is not affected in any way by the called function.

<hr class="space">

<b>Code sample</b>
<p></p>

{% highlight c %}

bool Cuckoo::CheckUnbalancedStack() const {
  usf_t f = {
    { lib_name_t(L"ntdll"), { 
      {sizeof(void *), NULL, "ZwDelayExecution", ARG_ITEM(kZwDelayExecutionArgs) }
    } }
  };
  const uint8_t canary[8] = { 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF };

  uint32_t args_size;
  const void *args_buff;
  uint32_t reserved_size;
  uint32_t reserved_size_after_call;
  uint32_t canary_size;
  FARPROC func;
  bool us_detected;
  void *canary_addr = (void *)&canary[0];
  
  static_assert((sizeof(canary) % sizeof(void *)) == 0, "Invalid canary alignement");
  
  for (auto it = f.begin(), end = f.end(); it != end; ++it) {
    for (auto &vi : it->second) {
      vi.func_addr = GetProcAddress(GetModuleHandleW(it->first.c_str()), vi.func_name.c_str());

      // call to Unbalanced Stack
      args_size = vi.args_size;
      args_buff = vi.args_buff;
      canary_size = sizeof(canary);
      reserved_size = sizeof(void *) + vi.local_vars_size + canary_size;
      reserved_size_after_call = reserved_size + args_size;
      func = vi.func_addr;
      us_detected = false;

      __asm {
        pusha
        mov ecx, args_size
        sub esp, ecx
        mov esi, args_buff
        mov edi, esp
        cld
        rep movsb
        sub esp, reserved_size
        mov ecx, canary_size
        mov esi, canary_addr
        mov edi, esp
        rep movsb
        add esp, reserved_size
        mov eax, func
        call eax
        sub esp, reserved_size_after_call
        mov ecx, canary_size
        mov esi, canary_addr
        mov edi, esp
        repz cmpsb
        cmp ecx, 0
        setnz us_detected
        add esp, reserved_size_after_call
        popa
      }

      if (us_detected)
        return true;
    }
  }

  return false;  
}
{% endhighlight %}

<hr class="space">

<b>Signature recommendations</b>
<p></p>
Signature recommendations are not provided as it's pretty tricky to track such a behavior on malware side.

<br />
<h3><a class="a-dummy" name="countermeasures">Countermeasures</a></h3>

<ul>
<li><tt>versus checking debug privileges:</tt> hook <tt>OpenProcess</tt> and track for critical system processes PIDs — then return an error.</li> 
<li><tt>versus using unbalanced stack:</tt> 1) stack adjusting before function call; 2) kernel-mode hooking.</li> 
</ul>

<br />
<h3><a class="a-dummy" name="credits">Credits</a></h3>

Credits go to open-source project from where code samples were taken:
<ul>
<li>al-khaser project on <a href="https://github.com/LordNoteworthy/al-khaser">github</a></li>
</ul>

Though Check Point tool InviZzzible has them all implemented, due to modular structure of the code it would require more space to show a code sample from this tool for the same purposes. That's why we've decided to use other great open-source projects for examples throughout the encyclopedia.
