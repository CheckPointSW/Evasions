---
layout: post
title:  "Evasions: Firmware tables"
title-image: "/assets/icons/firmware-tables.svg"
categories: evasions 
tags: firmware-tables
---

<h1>Contents</h1>

[Firmware tables detection methods](#firmware-tables-detection-methods)
<br />
  [1. Check if specific strings are present in Raw Firmware Table](#check-specific-strings-in-raw-firmware-table)
<br />
  [1.1. Windows Vista+](#check-specific-strings-in-raw-firmware-table-vista)
<br />
  [1.2. Windows XP](#check-specific-strings-in-raw-firmware-table-xp)
<br />
  [2. Check if specific strings are present in Raw SMBIOS Firmware Table](#check-specific-strings-in-raw-smbios-firmware-table)
<br />
  [2.1. Windows Vista+](#check-specific-strings-in-raw-smbios-firmware-table-vista)
<br />
  [2.2. Windows XP](#check-specific-strings-in-raw-smbios-firmware-table-xp)
<br />
  [Countermeasures](#countermeasures)
<br />
  [Credits](#credits)
<br />
<br />

<hr class="space">

<h2><a class="a-dummy" name="firmware-tables-detection-methods">Firmware tables detection methods</a></h2>
There are special memory areas used by OS which contain specific artifacts if OS is run under virtual environment. These memory areas may be dumped using different methods depending on the OS version.

<hr class="space">

Firmware tables are retrieved via <tt>SYSTEM_FIRMWARE_TABLE_INFORMATION</tt> object. It's defined the following way:
<p></p>

{% highlight c %}

typedef struct _SYSTEM_FIRMWARE_TABLE_INFORMATION {
    ULONG ProviderSignature;
    SYSTEM_FIRMWARE_TABLE_ACTION Action;
    ULONG TableID;
    ULONG TableBufferLength;
    UCHAR TableBuffer[ANYSIZE_ARRAY];  // <- the result will reside in this field
} SYSTEM_FIRMWARE_TABLE_INFORMATION, *PSYSTEM_FIRMWARE_TABLE_INFORMATION;

// helper enum
typedef enum _SYSTEM_FIRMWARE_TABLE_ACTION
{
    SystemFirmwareTable_Enumerate,
    SystemFirmwareTable_Get
} SYSTEM_FIRMWARE_TABLE_ACTION, *PSYSTEM_FIRMWARE_TABLE_ACTION;

{% endhighlight %}


<br />
<h3><a class="a-dummy" name="check-specific-strings-in-raw-firmware-table">1. Check if specific strings are present in Raw Firmware Table</a></h3>
Retrieved firmware table is scanned for the presence of particular strings.

<hr class="space">

<i>Depending on Windows version different functions are used for this check. See code samples below.</i>

<br />
<h4><a class="a-dummy" name="check-specific-strings-in-raw-firmware-table-vista">1.1. Windows Vista+</a></h4>

<b>Code sample</b>
<p></p>

{% highlight c %}

// First, SYSTEM_FIRMWARE_TABLE_INFORMATION object is initialized in the following way:
SYSTEM_FIRMWARE_TABLE_INFORMATION *sfti = 
    (PSYSTEM_FIRMWARE_TABLE_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, Length);
sfti->Action = SystemFirmwareTable_Get;  // 1
sfti->ProviderSignature = 'FIRM';
sfti->TableID = 0xC0000;
sfti->TableBufferLength = Length;

// Then initialized SYSTEM_FIRMWARE_TABLE_INFORMATION object is used as an argument for
// the system information call in the following way in order to dump raw firmware table:
NtQuerySystemInformation(
    SystemFirmwareTableInformation,  // 76 
    sfti,
    Length,
    &Length);
{% endhighlight %}

<i>Credits for this code sample: <a href="https://github.com/hfiref0x/VMDE">VMDE project</a> </i>

<hr class="space">

<b>Signature recommendations</b>
<p></p>
If the function
<ul>
<li><tt>NtQuerySystemInformation</tt></li>
</ul>
contains:
<ul>
<li>1st argument equal to 76 (SystemFirmwareTableInformation)</li> 
<li>2nd argument has <tt>sfti->ProviderSignature</tt> field initialized to 'FIRM' and <tt>sfti->Action</tt> field initialized to 1</li> 
</ul>
then it's an indication of application trying to use this evasion technique.

<hr class="space">

<br />
<h4><a class="a-dummy" name="check-specific-strings-in-raw-firmware-table-xp">1.2. Windows XP</a></h4>

<b>Code sample</b>
<p></p>

{% highlight c %}

// In case if OS version is Vista+ csrss.exe memory space is read in order to dump raw firmware table:
hCSRSS = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, csrss_pid);

NtReadVirtualMemory( 
     hCSRSS, 
     0xC0000,
     sfti, 
     RegionSize, 
     &memIO);

{% endhighlight %}

<hr class="space">

<b>Signature recommendations</b>
<p></p>
If the following function contains PID of <tt>csrss.exe</tt> process as its 3rd argument:
<ul>
<li><tt>HANDLE hCSRSS = OpenProcess(..., csrss_pid)</tt></li>
</ul>
and is followed by the call to the following function:
<ul>
<li><tt>NtReadVirtualMemory(hCSRSS, 0xC0000, ...)</tt></li>
</ul>
which contains:
<ul>
<li>1st argument equal to <tt>csrss.exe</tt> handle</li> 
<li>2nd argument equal to <tt>0xC0000</tt></li> 
</ul>
then it's an indication of application trying to use this evasion technique.

<hr class="space">

<h3>Detections table</h3>

<table style="width:60%">
  <tr>
    <td colspan="2">Check if the following strings are present in Raw Firmware Table:</td>
  </tr>
  <tr>
    <th style="text-align:center">Detect</th>
    <th style="text-align:center">String</th>
  </tr>
  <tr>
    <th>Parallels</th>
    <td>Parallels(R)</td>
  </tr>
  <tr>
  	<th rowspan="3">VirtualBox</th>
    <td>Innotek</td>
  </tr>
  <tr>
    <td>Oracle</td>
  </tr>
  <tr>
    <td>VirtualBox</td>
  </tr>
  <tr>
    <th>VirtualPC</th>
    <td>S3 Corp.</td>
  </tr>
  <tr>
    <th>VMware</th>
    <td>VMware</td>
  </tr>
</table>

<br />
<h3><a class="a-dummy" name="check-specific-strings-in-raw-smbios-firmware-table">2. Check if specific strings are present in Raw SMBIOS Firmware Table</a></h3>
Retrieved firmware table is scanned for the presence of particular strings.

<hr class="space">

<i>Depending on Windows version different functions are used for this check. See code samples below.</i>

<br />
<h4><a class="a-dummy" name="check-specific-strings-in-raw-smbios-firmware-table-vista">2.1. Windows Vista+</a></h4>

<b>Code sample</b>
<p></p>

{% highlight c %}

// SYSTEM_FIRMWARE_TABLE_INFORMATION object is initialized in the following way:
SYSTEM_FIRMWARE_TABLE_INFORMATION *sfti = 
    (PSYSTEM_FIRMWARE_TABLE_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, Length);
sfti->Action = SystemFirmwareTable_Get; // 1
sfti->ProviderSignature = 'RSMB';
sfti->TableID = 0;
sfti->TableBufferLength = Length;

// Then initialized SYSTEM_FIRMWARE_TABLE_INFORMATION object is used as an argument for
// the system information call in the following way in order to dump raw firmware table:
NtQuerySystemInformation(
    SystemFirmwareTableInformation,  // 76 
    sfti,
    Length,
    &Length);
{% endhighlight %}

<i>Credits for this code sample: <a href="https://github.com/hfiref0x/VMDE">VMDE project</a> </i>

<hr class="space">

<b>Signature recommendations</b>
<p></p>
If the following function:
<ul>
<li><tt>NtQuerySystemInformation</tt></li>
</ul>
contains:
<ul>
<li>1st argument equal to 76 (SystemFirmwareTableInformation)</li>
<li>2nd argument has <tt>sfti->ProviderSignature</tt> field initialized to 'RSMB' and <tt>sfti->Action</tt> field initialized to 1</li>
</ul>
then it's an indication of application trying to use this evasion technique.

<hr class="space">

<br />
<h4><a class="a-dummy" name="check-specific-strings-in-raw-smbios-firmware-table-xp">2.2. Windows XP</a></h4>

<b>Code sample</b>
<p></p>

{% highlight c %}

// In case if OS version is Vista+ csrss.exe memory space is read in order to dump raw firmware table:
hCSRSS = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, csrss_pid);

NtReadVirtualMemory( 
     hCSRSS, 
     0xE0000,
     sfti, 
     RegionSize, 
     &memIO);
{% endhighlight %}

<hr class="space">

<b>Signature recommendations</b>
<p></p>
If the following function contains PID of <tt>csrss.exe</tt> process as its 3rd argument:
<ul>
<li><tt>HANDLE hCSRSS = OpenProcess(..., csrss_pid)</tt></li>
</ul>
and is followed by the call to the following function:
<ul>
<li><tt>NtReadVirtualMemory(hCSRSS, 0xE0000, ...)</tt></li>
</ul>
which contains:
<ul>
<li>1st argument equal to <tt>csrss.exe</tt> handle</li> 
<li>2nd argument equal to <tt>0xE0000</tt></li> 
</ul>
then it's an indication of application trying to use this evasion technique.

<hr class="space">

<h3>Detections table</h3>

<table style="width:60%">
  <tr>
    <td colspan="2">Check if the following strings are present in Raw SMBIOS Firmware Table:</td>
  </tr>
  <tr>
    <th style="text-align:center">Detect</th>
    <th style="text-align:center">String</th>
  </tr>
  <tr>
    <th>Parallels</th>
    <td>Parallels Software International</td>
  </tr>
  <tr>
  	<th rowspan="3">VirtualBox</th>
    <td>Innotek</td>
  </tr>
  <tr>
    <td>Oracle</td>
  </tr>
  <tr>
    <td>VirtualBox</td>
  </tr>
  <tr>
    <th>VirtualPC</th>
    <td>VS2005R2</td>
  </tr>
  <tr>
    <th rowspan="2">VMware</th>
    <td>VMware, Inc.</td>
  </tr>
  <tr>
    <td>VMware</td>
  </tr>
</table>

<br />
<h3><a class="a-dummy" name="countermeasures">Countermeasures</a></h3>

<ul>
<li>On systems older than Vista change memory content of <tt>csrss.exe</tt> at given addresses.</li> 
<li>On Vista+ OS hook <tt>NtQuerySystemInformation</tt> for retrieving <tt>SystemFirmwareTableInformation</tt> class and parse <tt>SFTI</tt> structure for provided field values.</li> 
</ul>

<br />
<h3><a class="a-dummy" name="credits">Credits</a></h3>

Credits go to open-source project from where code samples were taken: 
<ul>
<li>VMDE project on <a href="https://github.com/hfiref0x/VMDE">github</a></li>
</ul>

Though Check Point tool InviZzzible has them all implemented, due to modular structure of the code it would require more space to show a code sample from this tool for the same purposes. That's why we've decided to use other great open-source projects for examples throughout the encyclopedia.
