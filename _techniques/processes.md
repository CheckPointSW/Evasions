---
layout: post
title:  "Evasions: Processes"
title-image: "/assets/icons/processes.svg"
categories: evasions 
tags: processes
---

<h1>Contents</h1>

[Processes and libraries detection methods](#process-detection-methods)
<br />
  [1. Check specific running processes and loaded libraries](#check-specific-running-processes-and-loaded-libraries)
<br />
  [1.1. Check if specific processes are running](#check-if-specific-processes-are-running)
<br />
  [1.2. Check if specific libraries are loaded in the process address space](#check-if-specific-libraries-are-loaded)
<br />
  [1.3. Check if specific functions are present in specific libraries](#check-if-specific-functions-are-present-in-specific-libraries)
<br />
  [1.4. Countermeasures](#countermeasures)
<br />
  [2. Check if specific artifacts are present in process address space (Sandboxie only)](#check-if-specific-artifacts-are-present-in-process)
<br />
  [2.1. Countermeasures](#countermeasures-sandboxie)
<br />
  [Credits](#credits)
<br />
<br />


<h2><a class="a-dummy" name="process-detection-methods">Processes and libraries detection methods</a></h2>
Virtual environment launches some specific helper processes which are not being executed in usual host OS. There are also some specific modules which are loaded into processes address spaces.

<br />
<h3><a class="a-dummy" name="check-specific-running-processes-and-loaded-libraries">1. Check specific running processes and loaded libraries</a></h3>

<br />
<h4><a class="a-dummy" name="check-if-specific-processes-are-running">1.1. Check if specific processes are running</a></h4>

Functions used:
<ul>
  <li><tt>CreateToolhelp32Snapshot</tt></li> 
  <li><tt>psapi.EnumProcesses <i>(WinXP, Vista)</i></tt></li> 
  <li><tt>kernel32.EnumProcesses <i>(Win7+)</i></tt></li> 
</ul>

<hr class="space">

<b>Code sample</b>
<p></p>

{% highlight c %}

check_process_is_running("vmtoolsd.exe");  // sample value from the table

bool check_process_is_running(const std::string &proc_name) {
    HANDLE hSnapshot;
    PROCESSENTRY32 pe = {};

    pe.dwSize = sizeof(pe);
    bool present = false;
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hSnapshot == INVALID_HANDLE_VALUE)
        return false;

    if (Process32First(hSnapshot, &pe)) {
        do {
            if (!StrCmpI(pe.szExeFile, proc_name.c_str())) {
                present = true;
                break;
            }
        } while (Process32Next(hSnapshot, &pe));
    }
    CloseHandle(hSnapshot);

    return present;
}

{% endhighlight %}

<hr class="space">

<b>Signature recommendations</b>
<p></p>
<i>Signature recommendations are not provided as it's hard to say what exactly is queried in the processes' snapshot.</i>

<hr class="space">

<b>Detections table</b>

<table style="width:60%">
  <tr>
    <td colspan="2">Check if the following processes are running:</td>
  </tr>
  <tr>
    <th style="text-align:center">Detect</th>
    <th style="text-align:center">Process</th>
  </tr>
  <tr>
    <th rowspan="2">JoeBox</th>
    <td>joeboxserver.exe</td>
  </tr>
  <tr>
    <td>joeboxcontrol.exe</td>
  </tr>
  <tr>
    <th rowspan="2">Parallels</th>
    <td>prl_cc.exe</td>
  </tr>
  <tr>
    <td>prl_tools.exe</td>
  </tr>
  <tr>
    <th rowspan="2">VirtualBox</th>
    <td>vboxservice.exe</td>
  </tr>
  <tr>
    <td>vboxtray.exe</td>
  </tr>
  <tr>
    <th rowspan="2">VirtualPC</th>
    <td>vmsrvc.exe</td>
  </tr>
  <tr>
    <td>vmusrvc.exe</td>
  </tr>
  <tr>
    <th rowspan="6">VMware</th>
    <td>vmtoolsd.exe</td>
  </tr>
  <tr>
    <td>vmacthlp.exe</td>
  </tr>
  <tr>
    <td>vmwaretray.exe</td>
  </tr>
  <tr>
    <td>vmwareuser.exe</td>
  </tr>
  <tr>
    <td>vmware.exe</td>
  </tr>
  <tr>
    <td>vmount2.exe</td>
  </tr>
  <tr>
    <th rowspan="2">Xen</th>
    <td>xenservice.exe</td>
  </tr>
  <tr>
    <td>xsvc_depriv.exe</td>
  </tr>
  <tr>
    <th>WPE Pro</th>
    <td>WPE Pro.exe</td>
  </tr>
</table>

<br />
<i>Note: WPE Pro is a sniffer, not VM, however it is used along with VM detects.</i>

<br />
<h4><a class="a-dummy" name="check-if-specific-libraries-are-loaded">1.2. Check if specific libraries are loaded in the process address space</a></h4>

Functions used:
<ul>
  <li><tt>GetModuleHandle</tt></li> 
</ul>

<hr class="space">

<b>Code sample</b>
<p></p>

{% highlight c %}

VOID loaded_dlls()
{
    /* Some vars */
    HMODULE hDll;

    /* Array of strings of blacklisted dlls */
    TCHAR* szDlls[] = {
        _T("sbiedll.dll"),
        _T("dbghelp.dll"),
        _T("api_log.dll"),
        _T("dir_watch.dll"),
        _T("pstorec.dll"),
        _T("vmcheck.dll"),
        _T("wpespy.dll"),
    };

    WORD dwlength = sizeof(szDlls) / sizeof(szDlls[0]);
    for (int i = 0; i < dwlength; i++)
    {
        TCHAR msg[256] = _T("");
        _stprintf_s(msg, sizeof(msg) / sizeof(TCHAR), _T("Checking if process loaded modules contains: %s "), 
                    szDlls[i]);

        /* Check if process loaded modules contains the blacklisted dll */
        hDll = GetModuleHandle(szDlls[i]);
        if (hDll == NULL)
            print_results(FALSE, msg);
        else
            print_results(TRUE, msg);
    }
}

{% endhighlight %}

<i>Credits for this code sample: <a href="https://github.com/LordNoteworthy/al-khaser">al-khaser project</a></i>

<hr class="space">

<b>Signature recommendations</b>
<p></p>
If the following function contains its only argument from the table column <font face="Courier New">`Library`</font>:
<p></p>
<ul>
<li><tt>GetModuleHandle(module_name)</tt></li> 
</ul>
then it's an indication of application trying to use this evasion technique.

<hr class="space">

<b>Detections table</b>

<table style="width:60%">
  <tr>
    <td colspan="2">Check if the following libraries are loaded in the process address space:</td>
  </tr>
  <tr>
    <th style="text-align:center">Detect</th>
    <th style="text-align:center">Library</th>
  </tr>
  <tr>
    <th rowspan="3">CWSandbox</th>
    <td>api_log.dll</td>
  </tr>
  <tr>
    <td>dir_watch.dll</td>
  </tr>
  <tr>
    <td>pstorec.dll</td>
  </tr>
  <tr>
    <th>Sandboxie</th>
    <td>sbiedll.dll</td>
  </tr>
  <tr>
    <th>ThreatExpert</th>
    <td>dbghelp.dll</td>
  </tr>
  <tr>
    <th>VirtualPC</th>
    <td>vmcheck.dll</td>
  </tr>
  <tr>
    <th>WPE Pro</th>
    <td>wpespy.dll</td>
  </tr>
</table>

<br />
<i>Note: WPE Pro is a sniffer, not VM, however it is used along with VM detects.</i>

<br />
<h4><a class="a-dummy" name="check-if-specific-functions-are-present-in-specific-libraries">1.3. Check if specific functions are present in specific libraries</a></h4>

Functions used (see note about native functions):
<ul>
  <li><tt>kernel32.GetProcAddress</tt></li> 
  <li><tt>kernel32.LdrGetProcedureAddress <i>(called internally)</i></tt></li> 
  <li><tt>ntdll.LdrGetProcedureAddress</tt></li> 
  <li><tt>ntdll.LdrpGetProcedureAddress <i>(called internally)</i></tt></li> 
</ul>

<hr class="space">

<b>Code sample</b>
<p></p>

{% highlight c %}

BOOL wine_exports()
{
    /* Some vars */
    HMODULE hKernel32;

    /* Get kernel32 module handle */
    hKernel32 = GetModuleHandle(_T("kernel32.dll"));
    if (hKernel32 == NULL) {
        print_last_error(_T("GetModuleHandle"));
        return FALSE;
    }

    /* Check if wine_get_unix_file_name is exported by this dll */
    if (GetProcAddress(hKernel32, "wine_get_unix_file_name") == NULL)  // sample value from the table
        return FALSE;
    else
        return TRUE;
}

{% endhighlight %}

<i>Credits for this code sample: <a href="https://github.com/LordNoteworthy/al-khaser">al-khaser project</a></i>

<hr class="space">

<b>Signature recommendations</b>
<p></p>
If the following functions contain 2nd argument from the table column "Function" and the 1st argument is the 
address of matching "Library" name from the table:
<p></p>
<ul>
<li><tt>kernel32.GetProcAddress(lib_handle, func_name)</tt></li> 
<li><tt>kernel32.LdrGetProcedureAddress(lib_handle, func_name)</tt></li> 
<li><tt>ntdll.LdrGetProcedureAddress(lib_handle, func_name)</tt></li> 
<li><tt>ntdll.LdrpGetProcedureAddress(lib_handle, func_name)</tt></li> 
</ul>
then it's an indication of application trying to use this evasion technique.

<hr class="space">

<b>Detections table</b>

<table style="width:60%">
  <tr>
    <td colspan="3">Check if the following functions are present in the following libraries:</td>
  </tr>
  <tr>
    <th style="text-align:center">Detect</th>
    <th style="text-align:center">Library</th>
    <th style="text-align:center">Function</th>
  </tr>
  <tr>
    <th rowspan="2">Wine</th>
    <td>kernel32.dll</td>
    <td>wine_get_unix_file_name</td>
  </tr>
  <tr>
    <td>ntdll.dll</td>
    <td>wine_get_version</td>
  </tr>
</table>

<br />
<h4><a class="a-dummy" name="countermeasures">1.4. Countermeasures</a></h4>

<ul>
<li><tt>for processes:</tt> exclude target processes from enumeration or terminate them;</li> 
<li><tt>for libraries:</tt> exclude them from <a href="http://www.codereversing.com/blog/archives/265">enumeration lists in PEB</a>;</li> 
<li><tt>for functions in libraries:</tt> hook appropriate functions and compare their arguments against target ones.</li> 
</ul>

<hr class="space">

<br />
<h3><a class="a-dummy" name="check-if-specific-artifacts-are-present-in-process">2. Check if specific artifacts are present in process address space (Sandboxie only)</a></h3>

Functions used:
<ul>
  <li><tt>NtQueryVirtualMemory</tt></li> 
</ul>

<hr class="space">

<b>Code sample</b>
<p></p>

{% highlight c %}

BOOL AmISandboxied(LPVOID lpMinimumApplicationAddress, LPVOID lpMaximumApplicationAddress)
{
  BOOL IsSB = FALSE;
  MEMORY_BASIC_INFORMATION RegionInfo;
  ULONG_PTR i, k;
  SIZE_T Length = 0L;

  i = (ULONG_PTR)lpMinimumApplicationAddress;
  do {

    NTSTATUS Status = NtQueryVirtualMemory(GetCurrentProcess(), 
                                           (PVOID)i, 
                                           MemoryBasicInformation,
                                           &RegionInfo, 
                                           sizeof(MEMORY_BASIC_INFORMATION), 
                                           &Length);
    if (NT_SUCCESS(Status)) {

      // Check if executable code
      if (((RegionInfo.AllocationProtect & PAGE_EXECUTE_READWRITE) == PAGE_EXECUTE_READWRITE) &&
          ((RegionInfo.State & MEM_COMMIT) == MEM_COMMIT)) {

        for (k = i; k < i + RegionInfo.RegionSize; k += sizeof(DWORD)) {
          if (
            (*(PDWORD)k == 'kuzt') ||
            (*(PDWORD)k == 'xobs')
            )
          {
            IsSB = TRUE;
            break;
          }
        }
      }
      i += RegionInfo.RegionSize;
    }
    else {
      i += 0x1000;
    }
  } while (i < (ULONG_PTR)lpMaximumApplicationAddress);

  return IsSB;
}

{% endhighlight %}

<i>Take a look at <a href="https://github.com/hfiref0x/VMDE/blob/c1f439fbe58eaa83a09aa5804c4dd45de967337e/src/vmde/detect.c#L676">VMDE project sources</a>.</i>

<hr class="space">

<b>Signature recommendations</b>
<p></p>
<i>Signature recommendations are not provided as it's hard to say what exactly is queried when memory buffer is being examined.</i>

<br />
<h4><a class="a-dummy" name="countermeasures-sandboxie">2.1. Countermeasures</a></h4>

Erase present artifacts from memory. 

<br />
<h3><a class="a-dummy" name="credits">Credits</a></h3>

Credits go to open-source project from where code samples were taken: 
<ul>
<li>al-khaser project on <a href="https://github.com/LordNoteworthy/al-khaser">github</a></li>
<li>VMDE project on <a href="https://github.com/hfiref0x/VMDE">github</a></li>
</ul>

Though Check Point tool InviZzzible has them all implemented, due to modular structure of the code it would require more space to show a code sample from this tool for the same purposes. That's why we've decided to use other great open-source projects for examples throughout the encyclopedia.

