---
layout: post
title:  "Evasions: Generic OS queries"
categories: evasions 
tags: generic-os-queries
---

<h1>Contents</h1>

[Generic OS queries](#generic-os-queries)
<br />
  [1. Check if the username is specific](#check-if-username-is-specific)
<br />
  [2. Check if the computer name is specific](#check-if-computer-name-is-specific)
<br />
  [3. Check if the host name is specific](#check-if-host-name-is-specific)
<br />
  [4. Check if the total RAM is low](#check-if-total-ram-is-low)
<br />
  [5. Check if the screen resolution is non-usual for host OS](#check-if-screen-res)
<br />
  [6. Check if the number of processors is low](#check-if-number-of-processors)
<br />
  [7. Check if the quantity of monitors is small](#check-if-quantity-of-monitors)
<br />
  [8. Check if the hard disk drive size and free space are small](#check-if-hard-disk)
<br />
  [9. Check if the system uptime is small](#check-if-system-uptime)
<br />
  [10. Check if the OS was boot from virtual hard disk (Win8+)](#check-if-os-was-boot-from-virtual-disk)
<br />
[Countermeasures](#countermeasures)
<br />
[Credits](#credits)
<br />
<br />


<h3>Signature recommendations are general</h3>
Signature recommendations are general for each technique: hook the function used and track if it is called. It's pretty hard to tell why application wants to get user name, for example. It doesn't necessarily mean applying evasion technique. So the best what can be done in this situation is intercepting target functions and tracking their calls.

<br />
<h2><a class="a-dummy" name="generic-os-queries">Detection via generic OS checks</a></h2>

Usual hosts have meaningful and non-standard usernames/computer names. Particular virtual environments assign some predefined names to default users as well as computer names.
Other differences between host OS and VMs include RAM size, HDD size, quantity of monitors - and so on.
While these may be not the most reliable ways to detect virtual environments, they are still commonly used in malware samples.


<br />
<h3><a class="a-dummy" name="check-if-username-is-specific">1. Check if the username is specific</a></h3>

Please note that checks are not case-sensitive.

Function used:
<ul>
<li><tt>GetUserNameA/W</tt></li> 
</ul>

<hr class="space">

<b>Code sample</b>
<p></p>

{% highlight c %}

bool is_user_name_match(const std::string &s) {
    auto out_length = MAX_PATH;
    std::vector<uint8_t> user_name(out_length, 0);
    ::GetUserNameA((LPSTR)user_name.data(), (LPDWORD)&out_length);

    return (!lstrcmpiA((LPCSTR)user_name.data(), s.c_str()));
}

{% endhighlight %}

<i>Code sample is taken from <a href="https://github.com/CheckPointSW/InviZzzible">InviZzzible tool</a> </i>

<hr class="space">

<b>Countermeasures</b>
<p></p>
Change user name to non-suspicious one.
<p></p>

<hr class="space">

<b>Detections table</b>

<table style="width:62%">
  <tr>
  	<td colspan="2">Check if username is one of the following:</td>
  </tr>
  <tr>
  	<th style="text-align:center">Detect</th>
  	<th style="text-align:center">String</th>
  </tr>
  <tr>
  	<th rowspan="16">[general]</th>
  	<td>admin</td>
  </tr>
  <tr>
  	<td>andy</td>
  </tr>
  <tr>
  	<td>honey</td>
  </tr>
  <tr>
  	<td>john</td>
  </tr>
  <tr>
  	<td>john doe</td>
  </tr>
  <tr>
  	<td>malnetvm</td>
  </tr>
  <tr>
  	<td>maltest</td>
  </tr>
  <tr>
  	<td>malware</td>
  </tr>
  <tr>
  	<td>roo</td>
  </tr>
  <tr>
  	<td>sandbox</td>
  </tr>
  <tr>
  	<td>snort</td>
  </tr>
  <tr>
  	<td>tequilaboomboom</td>
  </tr>
  <tr>
  	<td>test</td>
  </tr>
  <tr>
  	<td>virus</td>
  </tr>
  <tr>
  	<td>virusclone</td>
  </tr>
  <tr>
  	<td>wilbert</td>
  </tr>
  <tr>
  	<th rowspan="1">Nepenthes</th>
  	<td>nepenthes</td>
  </tr>
  <tr>
  	<th rowspan="1">Norman</th>
  	<td>currentuser</td>
  </tr>
  <tr>
  	<th rowspan="1">ThreatExpert</th>
  	<td>username</td>
  </tr>
  <tr>
  	<th rowspan="1">Sandboxie</th>
  	<td>user</td>
  </tr>
  <tr>
  	<th rowspan="1">VMware</th>
  	<td>vmware</td>
  </tr>
</table>


<br />
<h3><a class="a-dummy" name="check-if-computer-name-is-specific">2. Check if the computer name is specific</a></h3>

Please note that checks are not case-sensitive.

Function used:
<ul>
<li><tt>GetComputerNameA/W</tt></li>
</ul>

<hr class="space">

<b>Code sample</b>
<p></p>

{% highlight c %}

bool is_computer_name_match(const std::string &s) {
    auto out_length = MAX_PATH;
    std::vector<uint8_t> comp_name(out_length, 0);
    ::GetComputerNameA((LPSTR)comp_name.data(), (LPDWORD)&out_length);

    return (!lstrcmpiA((LPCSTR)comp_name.data(), s.c_str()));
}

{% endhighlight %}

<i>Code sample is taken from <a href="https://github.com/CheckPointSW/InviZzzible">InviZzzible tool</a> </i>

<hr class="space">

<b>Countermeasures</b>
<p></p>
Change computer name to non-suspicious one.
<p></p>

<hr class="space">

<b>Detections table</b>

<table style="width:62%">
  <tr>
  	<td colspan="2">Check if computer name is one of the following:</td>
  </tr>
  <tr>
  	<th style="text-align:center">Detect</th>
  	<th style="text-align:center">String</th>
  </tr>
  <tr>
  	<th rowspan="2">[generic]</th>
  	<td>klone_x64-pc</td>
  </tr>
  <tr>
  	<td>tequilaboomboom</td>
  </tr>

  <tr>
  	<th rowspan="2">Anubis</th>
  	<td>TU-4NH09SMCG1HC</td>
  </tr>
  <tr>
  	<td>InsideTm</td>
  </tr>
</table>


<br />
<h3><a class="a-dummy" name="check-if-host-name-is-specific">3. Check if the host name is specific</a></h3>

Please note that checks are not case-sensitive.

Function used:
<ul>
<li><tt>GetComputerNameExA/W</tt></li> 
</ul>

<hr class="space">

<b>Code sample</b>
<p></p>

{% highlight c %}

bool is_host_name_match(const std::string &s) {
    auto out_length = MAX_PATH;
    std::vector<uint8_t> dns_host_name(out_length, 0);
    ::GetComputerNameExA(ComputerNameDnsHostname, (LPSTR)dns_host_name.data(), (LPDWORD)&out_length);

    return (!lstrcmpiA((LPCSTR)dns_host_name.data(), s.c_str()));
}

{% endhighlight %}

<i>Code sample is taken from <a href="https://github.com/CheckPointSW/InviZzzible">InviZzzible tool</a> </i>

<hr class="space">

<b>Countermeasures</b>
<p></p>
Change host name to non-suspicious one.
<p></p>

<hr class="space">

<b>Detections table</b>

<table style="width:62%">
  <tr>
  	<td colspan="2">Check if host name is one of the following:</td>
  </tr>
  <tr>
  	<th style="text-align:center">Detect</th>
  	<th style="text-align:center">String</th>
  </tr>
  <tr>
  	<th rowspan="1">[generic]</th>
  	<td>SystemIT</td>
  </tr>
</table>


<br />
<h3><a class="a-dummy" name="check-if-total-ram-is-low">4. Check if the total RAM is low</a></h3>

Functions used to get executable path:
<ul>
<li><tt>GetMemoryStatusEx</tt></li>
</ul>

<hr class="space">

<b>Code sample</b>
<p></p>

{% highlight c %}
BOOL memory_space()
{
    DWORDLONG ullMinRam = (1024LL * (1024LL * (1024LL * 1LL))); // 1GB
    
    MEMORYSTATUSEX statex = {0};
    statex.dwLength = sizeof(statex);
    GlobalMemoryStatusEx(&statex); // calls NtQuerySystemInformation
    
    return (statex.ullTotalPhys < ullMinRam) ? TRUE : FALSE;
}
{% endhighlight %}

<i>Credits for this code sample: <a href="https://github.com/LordNoteworthy/al-khaser">al-khaser project</a> </i>

<hr class="space">

<b>Countermeasures</b>
<p></p>
Patch/hook <font face="Courier New">NtQuerySystemInformation</font> to return new number of <font face="Courier New">PhysicalPages</font> in <font face="Courier New">SystemBasicInformation</font>.

<p></p>
Tip: in this case its 1st argument is equal to 2 - SystemPerformanceInformation enum value.

<p></p>
Alternatively, patch <font face="Courier New">NumberOfPhysicalPages</font> in <font face="Courier New">KUSER_SHARED_DATA</font>.
<p></p>


<br />
<h3><a class="a-dummy" name="check-if-screen-res">5. Check if the screen resolution is non-usual for host OS</a></h3>

The following set of functions is used:
<ul>
<li><tt>GetDesktopWindow</tt></li>
<li><tt>GetWindowRect</tt></li> 
</ul>

Alternatively:
<ul>
<li><tt>GetSystemMetrics</tt></li>
<li><tt>SystemParametersInfo</tt></li> 
<li><tt>GetMonitorInfo</tt></li> 
</ul>

<hr class="space">

<b>Code sample</b>
<p></p>

Take a look at this <a href="https://stackoverflow.com/questions/4631292/how-detect-current-screen-resolution">StackOverflow thread</a>.

<hr class="space">

<b>Countermeasures</b>
<p></p>

Change screen resolution for it to match the resolution of usual host (1600x900, for example).


<br />
<h3><a class="a-dummy" name="check-if-number-of-processors">6. Check if the number of processors is low</a></h3>

Function used:
<ul>
<li><tt>GetSystemInfo</tt></li>
</ul>

Besides this function numbers of processors can be obtained from PEB, via either asm inline or intrinsic function, see code samples below.

<hr class="space">

<b>Code sample (variant 1, al-khaser project)</b>
<p></p>

{% highlight c %}

BOOL NumberOfProcessors()
{
#if defined (ENV64BIT)
	PULONG ulNumberProcessors = (PULONG)(__readgsqword(0x30) + 0xB8);
#elif defined(ENV32BIT)
	PULONG ulNumberProcessors = (PULONG)(__readfsdword(0x30) + 0x64);
#endif

    if (*ulNumberProcessors < 2)
        return TRUE;
    else
        return FALSE;
}

{% endhighlight %}

<i>Credits for this code sample: <a href="https://github.com/LordNoteworthy/al-khaser">al-khaser project</a> </i>

<hr class="space">

<b>Code sample (variant 2, al-khaser project, asm inline)</b>
<p></p>

{% highlight c %}

__declspec(naked)
DWORD get_number_of_processors() {
    __asm {
        ; get pointer to Process Environment Block (PEB)
        mov eax, fs:0x30

        ; read the field containing target number
        mov eax, [eax + 0x64]

        ; return from function
        retn
    }
}

{% endhighlight %}

<i>Credits for this code sample: <a href="https://github.com/LordNoteworthy/al-khaser">al-khaser project</a> </i>

<hr class="space">

<b>Code sample (variant 3, pafish project)</b>
<p></p>

{% highlight c %}

int gensandbox_one_cpu_GetSystemInfo() {
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    return si.dwNumberOfProcessors < 2 ? TRUE : FALSE;
}

{% endhighlight %}

<i>Credits for this code sample: <a href="https://github.com/a0rtega/pafish">pafish project</a> </i>

<hr class="space">

<b>Countermeasures</b>
<p></p>

Assign two or more cores for Virtual Machine.
<p></p>
As an alternative solution, patch/hook <font face="Courier New">NtCreateThread</font> to assign specific core for each new thread.


<br />
<h3><a class="a-dummy" name="check-if-quantity-of-monitors">7. Check if the quantity of monitors is small</a></h3>

Functions used:
<ul>
<li><tt>EnumDisplayMonitors</tt></li>
<li><tt>GetSystemMetrics (SM_MONITOR)</tt></li> 
</ul>

<hr class="space">

<b>Code sample</b>
<p></p>

{% highlight c %}

BOOL CALLBACK MonitorEnumProc(HMONITOR hMonitor, HDC hdcMonitor, LPRECT lprcMonitor, LPARAM dwData)
{
    int *Count = (int*)dwData;
    (*Count)++;
    return TRUE;
}

int MonitorCount()
{
    int Count = 0;
    if (EnumDisplayMonitors(NULL, NULL, MonitorEnumProc, (LPARAM)&Count))
        return Count;
    return -1; // signals an error
}

{% endhighlight %}

<i>Credits for this code sample: <a href="https://stackoverflow.com/questions/7767036/how-do-i-get-the-number-of-displays-in-windows">StackOverflow forum</a> </i>

<hr class="space">

<b>Countermeasures</b>
<p></p>

Add at least one monitor to virtual environment.


<br />
<h3><a class="a-dummy" name="check-if-hard-disk">8. Check if the hard disk drive size and free space are small</a></h3>

Functions used:
<ul>
<li><tt>DeviceIoControl(..., IOCTL_DISK_GET_LENGTH_INFO, ...)</tt></li>
<li><tt>GetDiskFreeSpaceExA/W</tt></li>
</ul>

<hr class="space">

<b>Code sample (checking drive total size)</b>
<p></p>

{% highlight c %}

int gensandbox_drive_size() {
    GET_LENGTH_INFORMATION size;
    DWORD lpBytesReturned;

    HANDLE drive = CreateFile("\\\\.\\PhysicalDrive0", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (drive == INVALID_HANDLE_VALUE) {
        // Someone is playing tricks. Or not enough privileges.
        CloseHandle(drive);
        return FALSE;
    }
    BOOL result = DeviceIoControl(drive, IOCTL_DISK_GET_LENGTH_INFO, NULL, 0, &size, sizeof(GET_LENGTH_INFORMATION), &lpBytesReturned, NULL);
    CloseHandle(drive);

    if (result != 0) {
        if (size.Length.QuadPart / 1073741824 <= 60) /* <= 60 GB */
        return TRUE;
    }

    return FALSE;
}

{% endhighlight %}

<i>Credits for this code sample: <a href="https://github.com/LordNoteworthy/al-khaser">al-khaser project</a> </i>

<hr class="space">

<b>Code sample (checking drive free space)</b>
<p></p>

{% highlight c %}

int gensandbox_drive_size2() {
    ULARGE_INTEGER total_bytes;

    if (GetDiskFreeSpaceExA("C:\\", NULL, &total_bytes, NULL))
    {
        if (total_bytes.QuadPart / 1073741824 <= 60) /* <= 60 GB */
        return TRUE;
    }

    return FALSE;
}

{% endhighlight %}

<i>Credits for this code sample: <a href="https://github.com/LordNoteworthy/al-khaser">al-khaser project</a> </i>

<hr class="space">

<b>Countermeasures</b>
<p></p>

<i>Against checking disk size:</i> filter <font face="Courier New">IRP</font> device control requests to <font face="Courier New"> \\Device\\HarddiskN</font> with specific CTL-codes:
<ul>
<li><tt>DRIVE_GEOMETRY_EX</tt></li>
<li><tt>DRIVE_LAYOUT_EX</tt></li>
<li><tt>PARTITION_INFO_EX</tt></li>
</ul>

<i>Against checking free space:</i> patch/hook <font face="Courier New">NtQueryVolumeInformationFile</font> to process these classes: 
<ul>
<li><tt>FileFsSizeInformation</tt></li>
<li><tt>FileFsFullSizeInformation</tt></li>
</ul>
in case if handle points to <font face="Courier New">\\Device\\HarddiskVolumeN</font>.


<br />
<h3><a class="a-dummy" name="check-if-system-uptime">9. Check if the system uptime is small</a></h3>

Function used:
<ul>
<li><tt>GetTickCount</tt></li>
<li><tt>GetTickCount64</tt></li>
<li><tt>NtQuerySystemInformation</tt></li>
</ul>

<b>Code sample</b>
<p></p>

{% highlight c %}

bool Generic::CheckSystemUptime() const {
    const DWORD uptime = 1000 * 60 * 12; // 12 minutes
    return GetTickCount() < uptime;
}

{% endhighlight %}

<i>Code sample is taken from <a href="https://github.com/CheckPointSW/InviZzzible">InviZzzible tool</a></i>

<b>Code sample</b>
{% highlight c %}
#define MIN_UPTIME_MINUTES 12
BOOL uptime_check()
{
    ULONGLONG uptime_minutes = GetTickCount64() / (60 * 1000);
    return uptime_minutes < MIN_UPTIME_MINUTES;
}
{% endhighlight %}
<br />
<b>Code sample</b>
{% highlight c %}
BOOL uptime_check2()
{
    SYSTEM_TIME_OF_DAY_INFORMATION  SysTimeInfo;
    ULONGLONG uptime_minutes;
    NtQuerySystemInformation(SystemTimeOfDayInformation, &SysTimeInfo, sizeof(SysTimeInfo), 0);
    uptime_minutes = (SysTimeInfo.CurrentTime.QuadPart - SysTimeInfo.BootTime.QuadPart) / (60 * 1000 * 10000);
    return uptime_minutes < MIN_UPTIME_MINUTES;
}
{% endhighlight %}

<hr class="space">

<b>Countermeasures</b>
<p></p>

<ul>
<li>Adjust <tt>KeBootTime</tt> value</li>
<li>Adjust <tt>SharedUserData->TickCount</tt>, <tt>SharedUserData->TickCoundLowDeprecated</tt> values</li>
</ul>

<br />
<h3><a class="a-dummy" name="check-if-os-was-boot-from-virtual-disk">10. Check if the OS was boot from virtual hard disk (Win8+)</a></h3>

Function used:
<ul>
<li><tt>IsNativeVhdBoot  // false on host OS, true within VM</tt></li>
</ul>

<b>Code sample (excerpt from malware)</b>
<p></p>

Take a look at the excerpt from malware <a href="https://github.com/a0rtega/pafish/issues/46">here</a>.

<hr class="space">

<b>Code sample (pafish project)</b>
<p></p>

{% highlight c %}

int gensandbox_IsNativeVhdBoot() {
    BOOL isnative = FALSE;

    IsNativeVhdBoot fnnative = (IsNativeVhdBoot) GetProcAddress(
        GetModuleHandleA("kernel32"), "IsNativeVhdBoot");

    /* IsNativeVhdBoot always returns 1 on query success */
    if (fnnative)
        fnnative(&isnative);
		
    return (isnative) ? TRUE : FALSE;
}

{% endhighlight %}

<i>Credits for this code sample: <a href="https://github.com/a0rtega/pafish">pafish project</a> </i>

<hr class="space">

<b>Countermeasures</b>
<p></p>

Hook <font face="Courier New">IsNativeVhdBoot</font> and change its result to the one required.


<br />
<h3><a class="a-dummy" name="countermeasures">Countermeasures</a></h3>

Countermeasures are present in appropriate sub-sections, see above.

<br />
<h3><a class="a-dummy" name="credits">Credits</a></h3>

Credits go to open-source projects from where code samples were taken: 
<ul>
<li>al-khaser project on <a href="https://github.com/LordNoteworthy/al-khaser">github</a></li>
<li>pafish project on <a href="https://github.com/a0rtega/pafish">github</a></li>
</ul>

Though Check Point tool InviZzzible has them all implemented, due to modular structure of the code it would require more space to show a code sample from this tool for the same purposes. That's why we've decided to use other great open-source projects for examples throughout the encyclopedia.

[al-khaser-github]:   https://github.com/LordNoteworthy/al-khaser
[pafish-github]:      https://github.com/a0rtega/pafish
[github-excerpt-native-boot]: https://github.com/a0rtega/pafish/issues/46
