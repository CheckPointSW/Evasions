---
layout: post
title:  "Evasions: WMI"
title-image: "/assets/icons/wmi.svg"
categories: evasions 
tags: wmi
---

<h1>Contents</h1>

[WMI detection methods](#wmi-detection-methods)
<br />
[Background](#background)
<br />
  [1. Generic WMI queries](#generic-wmi-queries)
<br />
  [2. Escape from tracking using WMI](#escape-from-tracking)
<br />
  [2.1. Start process using WMI](#wmi-process)
<br />
  [2.2. Start process using Task Scheduler via WMI](#wmi-tsched)
<br />
  [3. Check the last boot time](#check-last-boot-time)
<br />
  [4. Check the network adapter last reset time](#check-network-adapter-reset-time)
<br />
  [Signature recommendations](#signature-recommendations)
<br />
  [Countermeasures](#countermeasures)
<br />
  [Credits](#credits)
<br />
<br />

<hr class="space">

<h2><a class="a-dummy" name="wmi-detection-methods">WMI detection methods</a></h2>
Windows Management Interface (WMI) queries are another way to get OS and hardware information. WMI uses COM interfaces and their methods.

<hr class="space">

<h2><a class="a-dummy" name="background">Background</a></h2>

Standard COM functions are used to process queries. They are called in the sequence described below and can be split into 6 steps.

<p>1. COM initialization:</p>
<ul>
<li><tt>CoInitialize/CoInitializeEx</tt></li> 
</ul>

<hr class="space">

<p>2. Create the required interface instance:</p> 
<ul>
<li><tt>CoCreateInstance/CoCreateInstanceEx</tt></li> 
</ul>

<hr class="space">

<p>3. Connect to the particular services via the interface instance with the following function:</p> 
<ul>
<li><tt>ConnectServer</tt></li> 
</ul>

<hr class="space">

<p>4. Get methods of the services and set their arguments with these functions:</p> 
<ul>
<li><tt>Method</tt> (to get methods)</li> 
<li><tt>Put</tt> (to set arguments)</li> 
</ul>

<hr class="space">

<p>5. Retrieve information from the services and execute the methods of the services with the functions below. The functions on the left are proxies for the functions on the right - which are called internally:</p> 
<ul>
<li><tt>ExecQuery -> IWbemServices_ExecQuery</tt> (retrieve information)</li>
<li><tt>ExecMethod -> IWbemServices_ExecMethod</tt> (execute method)</li>
<li><tt>ExecMethodAsync -> IWbemServices_ExecMethodAsync</tt> (execute method)</li>
</ul>

<hr class="space">

<p>6. Examine the result of the query with the following functions:</p> 
<ul>
<li><tt>[enumerator]->Next</tt></li> 
<li><tt>[object]->Get</tt></li> 
</ul>

<hr class="space">

To see how the described theory is applied to practice, please check the examples below.

<br />
<h3><a class="a-dummy" name="generic-wmi-queries">1. Generic WMI queries</a></h3>
As WMI provides another way to collect system information, it can be used to perform evasion techniques described in other articles, for example: 
<ul>
<li><a href="generic-os-queries.html#check-if-number-of-processors">Check if the number of processors is low</a></li>
<li><a href="generic-os-queries.html#check-if-hard-disk">Check if the hard disk size is small</a></li>
<li><a href="network.html#check-if-mac-address-is-specific">Check if the MAC address is specific</a></li>
<li><a href="hardware.html#check-if-cpu-temperature-information-is-available">Check if the CPU temperature information is available</a></li>
</ul>

<b>Code sample</b>
<p></p>

{% highlight c %}

/*
Check number of cores using WMI
*/
BOOL number_cores_wmi()
{
  IWbemServices *pSvc = NULL;
  IWbemLocator *pLoc = NULL;
  IEnumWbemClassObject *pEnumerator = NULL;
  BOOL bStatus = FALSE;
  HRESULT hRes;
  BOOL bFound = FALSE;

  // Init WMI
  bStatus = InitWMI(&pSvc, &pLoc);
  if (bStatus)
  {
    // If success, execute the desired query
    bStatus = ExecWMIQuery(&pSvc, &pLoc, &pEnumerator, _T("SELECT * FROM Win32_Processor"));
    if (bStatus)
    {
      // Get the data from the query
      IWbemClassObject *pclsObj = NULL;
      ULONG uReturn = 0;
      VARIANT vtProp;

      // Iterate over our enumator
      while (pEnumerator)
      {
        hRes = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
        if (0 == uReturn)
          break;

        // Get the value of the Name property
        hRes = pclsObj->Get(_T("NumberOfCores"), 0, &vtProp, 0, 0);
        if (V_VT(&vtProp) != VT_NULL) {

          // Do our comparaison
          if (vtProp.uintVal < 2) {
            bFound = TRUE; break;
          }

          // release the current result object
          VariantClear(&vtProp);
          pclsObj->Release();
        }
      }

      // Cleanup
      pEnumerator->Release();
      pSvc->Release();
      pLoc->Release();
      CoUninitialize();
    }
  }

  return bFound;
}


/*
Check hard disk size using WMI
*/
BOOL disk_size_wmi()
{
  IWbemServices *pSvc = NULL;
  IWbemLocator *pLoc = NULL;
  IEnumWbemClassObject *pEnumerator = NULL;
  BOOL bStatus = FALSE;
  HRESULT hRes;
  BOOL bFound = FALSE;
  INT64 minHardDiskSize = (80LL * (1024LL * (1024LL * (1024LL))));

  // Init WMI
  bStatus = InitWMI(&pSvc, &pLoc);
  if (bStatus)
  {
    // If success, execute the desired query
    bStatus = ExecWMIQuery(&pSvc, &pLoc, &pEnumerator, _T("SELECT * FROM Win32_LogicalDisk"));
    if (bStatus)
    {
      // Get the data from the query
      IWbemClassObject *pclsObj = NULL;
      ULONG uReturn = 0;
      VARIANT vtProp;

      // Iterate over our enumator
      while (pEnumerator)
      {
        hRes = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
        if (0 == uReturn)
          break;

        // Get the value of the Name property
        hRes = pclsObj->Get(_T("Size"), 0, &vtProp, 0, 0);
        if (V_VT(&vtProp) != VT_NULL) {

          // Do our comparaison
          if (vtProp.llVal < minHardDiskSize) { // Less than 80GB
            bFound = TRUE; break;
          }

          // release the current result object
          VariantClear(&vtProp);
          pclsObj->Release();
        }
      }

      // Cleanup
      pEnumerator->Release();
      pSvc->Release();
      pLoc->Release();
      CoUninitialize();
    }
  }

  return bFound;
}
{% endhighlight %}

<i>Credits for this code sample: <a href="https://github.com/LordNoteworthy/al-khaser">al-khaser project</a></i>

<hr class="space">
<b>Code sample (PowerShell)</b>

{% highlight powershell %}
(Get-CimInstance -ClassName Win32_BIOS -Property SerialNumber).SerialNumber
{% endhighlight %}

<hr class="space">

<b>Signature recommendations</b>
<p></p>
If the following function contains a 3rd argument from the table column <font face="Courier New">"Query"</font>:
<p></p>
<ul>
<li><tt>IWbemServices_ExecQuery(..., query, ...)</tt></li> 
</ul>
then it's an indicator of the application trying to use the evasion technique.

<hr class="space">

<b>Detections table</b>

<table>
  <tr>
    <td colspan="5">The following WMI queries may be used to detect virtual environment:</td>
  </tr>
  <tr>
    <th style="text-align:center">Query</th>
    <th style="text-align:center">Field</th>
    <th style="text-align:center">Value</th>
    <th style="text-align:center">Detect</th>
    <th style="text-align:center">Comments</th>
  </tr>
  <tr>
    <td rowspan="2">SELECT * FROM Win32_Processor</td>
    <td>NumberOfCores</td>
    <td>< 2</td>
    <th rowspan="6">[general]</th>
    <td></td>
  </tr>
  <tr>
    <td>ProcessorId</td>
    <td>[empty]</td>
    <td></td>
  </tr>
  <tr>
    <td>SELECT * FROM Win32_LogicalDisk</td>
    <td>Size</td>
    <td>< 60GB</td>
    <td></td>
  </tr>
  <tr>
    <td rowspan="2">SELECT * FROM Win32_BaseBoard</td>
    <td>SerialNumber</td>
    <td>None</td>
    <td></td>
  </tr>
  <tr>
    <td>Version</td>
    <td>None</td>
    <td></td>
  </tr>
  <tr>
    <td>SELECT * FROM MSAcpi_ThermalZoneTemperature</td>
    <td>CurrentTemperature</td>
    <td>"Not supported"</td>
    <td></td>
  </tr>
  <tr>
    <td rowspan="5">SELECT * FROM Win32_PnPEntity</td>
    <td rowspan="5">DeviceId</td>
    <td>PCI\VEN_80EE&DEV_CAFE</td>
    <th rowspan="3">VirtualBox</th>
    <td></td>
  </tr>
  <tr>
    <td>IDE\CDROOMVBOX</td>
    <td></td>
  </tr>
  <tr>
    <td>IDE\DISKVBOX*</td>
    <td></td>
  </tr>
  <tr>
    <td>VEN_VMWARE</td>
    <th rowspan="2">VMware</th>
    <td></td>
  </tr>
  <tr>
    <td>PROD_VMWARE_VIRTUAL</td>
    <td></td>
  </tr>
  <tr>
    <td rowspan="7">SELECT * FROM Win32_NetworkAdapterConfiguration</td>
    <td rowspan="7">MACAddress</td>
    <td>08:00:27</td>
    <th>VirtualBox</th>
    <td>See <a href="network.html#check-if-mac-address-is-specific">"Check if MAC address is specific"</a> section in "Network" chapter</td>
  </tr>
  <tr>
    <td>00:1C:42</td>
    <th>Parallels</th>
    <td></td>
  </tr>
  <tr>
    <td>00:05:69</td>
    <th rowspan="4">VMware</th>
    <td></td>
  </tr>
  <tr>
    <td>00:0C:29</td>
    <td></td>
  </tr>
  <tr>
    <td>00:1C:14</td>
    <td></td>
  </tr>
  <tr>
    <td>00:50:56</td>
    <td></td>
  </tr>
  <tr>
    <td>00:16:E3</td>
    <th>XEN</th>
    <td></td>
  </tr>
  <tr>
    <td rowspan="7">SELECT * FROM Win32_Bios</td>
    <td rowspan="2">Serial Number</td>
    <td>VMware-</td>
    <th>VMware</th>
    <td></td>
  </tr>
  <tr>
    <td>0</td>
    <th>VirtualBox</th>
    <td></td>
  </tr>
  <tr>
    <td rowspan="5">Version</td>
    <td>INTEL - 6040000</td>
    <th>VMware</th>
    <td>See "SystemBiosVersion" in <a href="registry.html#check-if-keys-contain-strings">"Check if particular registry keys contain specified strings"</a> section in "Registry" chapter</td>
  </tr>
  <tr>
    <td>BOCHS</td>
    <th>BOCHS</th>
    <td></td>
  </tr>
  <tr>
    <td>PARALLELS</td>
    <th>Parallels</th>
    <td></td>
  </tr>
  <tr>
    <td>QEMU</td>
    <th>QEMU</th>
    <td></td>
  </tr>
  <tr>
    <td>VBOX</td>
    <th>VirtualBox</th>
    <td></td>
  </tr>
  <tr>
    <td rowspan="4">SELECT * FROM Win32_ComputerSystem</td>
    <td rowspan="2">Model</td>
    <td>VMware</td>
    <th>VMware</th>
    <td></td>
  </tr>
  <tr>
    <td>VirtualBox</td>
    <th>VirtualBox</th>
    <td></td>
  </tr>
  <tr>
    <td rowspan="2">Manufacturer</td>
    <td>VMware</td>
    <th>VMware</th>
    <td></td>
  </tr>
  <tr>
    <td>innotek GmbH</td>
    <th>VirtualBox</th>
    <td></td>
  </tr>
  <tr>
    <td rowspan="8">SELECT * FROM Win32_VideoController</td>
    <td rowspan="2">AdapterCompatibility</td>
    <td>VMware</td>
    <th>VMware</th>
    <td></td>
  </tr>
  <tr>
    <td>Oracle Corporation</td>
    <th>VirtualBox</th>
    <td></td>
  </tr>
  <tr>
    <td rowspan="2">Caption</td>
    <td>VMware</td>
    <th>VMware</th>
    <td></td>
  </tr>
  <tr>
    <td>VirtualBox</td>
    <th>VirtualBox</th>
    <td></td>
  </tr>
  <tr>
    <td rowspan="2">Description</td>
    <td>VMware</td>
    <th>VMware</th>
    <td></td>
  </tr>
  <tr>
    <td>VirtualBox</td>
    <th>VirtualBox</th>
    <td></td>
  </tr>
  <tr>
    <td rowspan="2">Name</td>
    <td>VMware</td>
    <th>VMware</th>
    <td></td>
  </tr>
  <tr>
    <td>VirtualBox</td>
    <th>VirtualBox</th>
    <td></td>
  </tr>
  <tr>
    <td>SELECT * FROM Win32_PointingDevice</td>
    <td>Description</td>
    <td>VMware</td>
    <th>VMware</th>
    <td></td>
  </tr>
</table>

<hr class="space">

<i>Queries listed in the table are not the only ones possible, and are presented to give an idea of how they work and what information can be retrieved with these calls.</i>

<p></p>
<b>Countermeasures</b>
<p></p>
Countermeasures depend on the particular checks implemented via the WMI method and they are the same as for the corresponding methods described in the relevant articles. Additionally, you must restart the "<tt>winmgmt</tt>" service.

<hr class="space">

<br />
<h3><a class="a-dummy" name="escape-from-tracking">2. Escape from tracking using WMI</a></h3>
WMI provides a way to create new processes and to schedule tasks. Sandboxes usually use the <tt>CreateProcessInternalW</tt> function hooking to track child processes. However, when you create the process using WMI the function <tt>CreateProcessInternalW</tt> is not called in the parent process. Therefore, the processes created using WMI may not be tracked by a sandbox and their behavior will not be recorded.
<br />
<h4><a class="a-dummy" name="wmi-process">2.1. Start process using WMI</a></h4>
You can create a new process with WMI using the "<tt>Win32_Process</tt>" class with the method "<tt>Create</tt>".


<b>Code sample</b>
<p></p>

{% highlight c %}

// Initialize COM
CoInitializeEx(NULL, COINIT_MULTITHREADED);

//  Set general COM security levels
hres = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, 0, NULL);
if (FAILED(hres) && hres != RPC_E_TOO_LATE)
    break;

// create an instance of WbemLocator
CoCreateInstance(CLSID_WbemLocator, NULL, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&wbemLocator);
wbemLocator->ConnectServer(CComBSTR("ROOT\\CIMV2"), NULL, NULL, NULL, 0, NULL, NULL, &wbemServices);

// get Win32_Process object
wbemServices->GetObject(CComBSTR("Win32_Process"), 0, NULL, &oWin32Process, &callResult);
wbemServices->GetObject(CComBSTR("Win32_ProcessStartup"), 0, NULL, &oWin32ProcessStartup, &callResult);
oWin32Process->GetMethod(CComBSTR("Create"), 0, &oMethCreate, &oMethCreateSignature);
oMethCreate->SpawnInstance(0, &instWin32Process);
oWin32ProcessStartup->SpawnInstance(0, &instWin32ProcessStartup);
// set startup information for process
instWin32ProcessStartup->Put(CComBSTR("CreateFlags"), 0, &varCreateFlags, 0);
instWin32Process->Put(CComBSTR("CommandLine"), 0, &varCmdLine, 0);
instWin32Process->Put(CComBSTR("CurrentDirectory"), 0, &varCurDir, 0);
CComVariant varStartupInfo(instWin32ProcessStartup);
instWin32Process->Put(CComBSTR("ProcessStartupInformation"), 0, &varStartupInfo, 0);
wbemServices->ExecMethod(CComBSTR("Win32_Process"), CComBSTR("Create"), 0, NULL, instWin32Process, &pOutParams, &callResult);

{% endhighlight %}
<i>Code sample is taken from <a href="https://github.com/CheckPointSW/InviZzzible">InviZzzible tool</a> </i>

<hr class="space">

<b>Signature recommendations</b>
<p></p>
If one of the following functions is called with the 2nd argument "<tt>Win32_Process</tt>" and the 3rd argument "<tt>Create</tt>":
<p></p>
<ul>
<li><tt>IWbemServices_ExecMethod(..., BSTR("Win32_Process"), BSTR("Create"), ...)</tt></li>
<li><tt>IWbemServices_ExecMethodAsync(..., BSTR("Win32_Process"), BSTR("Create"), ...)</tt></li> 
</ul>
then it's an indicator of the application trying to use the evasion technique.
<p></p>
<b>Countermeasures</b>
<p></p>
If you use a kernel-mode monitor, hook target functions or register callback on the process creation with <tt>PsSetCreateProcessNotifyRoutineEx</tt>.

<hr class="space">

<h4><a class="a-dummy" name="wmi-tsched">2.2. Start process using Task Scheduler via WMI (Windows 7)</a></h4>
The technique is essentially the same as described in the <a href="timing.html#deferred-execution-using-task-scheduler">"Deferred execution using Task Scheduler"</a> section in the "Timing" chapter. WMI just provides another way to schedule a task.

You can create a new task with WMI using the "<tt>Win32_ScheduledJob</tt>" class with the method "<tt>Create</tt>".

However, the "<tt>Win32_ScheduledJob</tt>" WMI class was designed to work with the AT command, which is deprecated since Windows 8.

In Windows 8 and higher, you can only create scheduled jobs with WMI if the registry key "<tt>HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Configuration</tt>" has a value "<tt>EnableAt</tt>"="1" of type <tt>REG_DWORD</tt>. Therefore, this technique is unlikely to be found in the wild.

<b>Code sample (VB)</b>
<p></p>

{% highlight vb %}

strComputer = "."
Set objWMIService = GetObject("winmgmts:" & "{impersonationLevel=Impersonate}!\\" & strComputer & "\root\cimv2") 
Set objSWbemDateTime = CreateObject("WbemScripting.SWbemDateTime")
objSWbemDateTime.SetVarDate(DateAdd("n", 1, Now()))
Set objNewJob = objWMIService.Get("Win32_ScheduledJob")
errJobCreate = objNewJob.Create("malware.exe", objSWbemDateTime.Value, False, , , True, "MaliciousJob") 

{% endhighlight %}

<hr class="space">

<b>Signature recommendations</b>
<p></p>
If one of the following functions is called with the 2nd argument "Win32_ScheduledJob" and the 3rd argument "Create":
<p></p>
<ul>
<li><tt>IWbemServices_ExecMethod(..., BSTR("Win32_ScheduledJob"), BSTR("Create"), ...)</tt></li>
<li><tt>IWbemServices_ExecMethodAsync(..., BSTR("Win32_ScheduledJob"), BSTR("Create"), ...)</tt></li> 
</ul>
then it's an indicator of the application trying to use the evasion technique.
<p></p>
<b>Countermeasures</b>
<p></p>
Use a kernel-mode monitor, and register callback on the process creation with PsSetCreateProcessNotifyRoutineEx.
<p></p>

<hr class="space">

<br />
<h3><a class="a-dummy" name="check-last-boot-time">3. Check the last boot time</a></h3>
If the last boot time is queried immediately after restoring a VM from a snapshot, the WMI database may contain the value saved at the moment the VM snapshot was created. If the snapshot was created a year ago, the calculated system uptime will be a year as well even if a sandbox updates the last boot time.

This fact can be used to detect a virtual machine restored from a snapshot. Also, any anomalies in the last boot time can be used as sandbox indicators:
<ul>
<li>The system uptime is too big (months or even years)</li>
<li>The system uptime is to small (less than several minutes)</li>
<li>The last boot time obtained using <a href="timing.html#get-system-time">other methods</a> differs from the last boot time obtained using WMI</li>
</ul>

<b>Code sample (VB)</b>
<p></p>

{% highlight vb %}

strComputer = "."
Set objWMIService = GetObject("winmgmts:" & "{impersonationLevel=impersonate}!\\" & strComputer & "\root\cimv2")
Set colOperatingSystems = objWMIService.ExecQuery ("Select * from Win32_OperatingSystem")
 
For Each objOS in colOperatingSystems
    dtmBootup = objOS.LastBootUpTime
    dtmLastBootUpTime = WMIDateStringToDate(dtmBootup)
    dtmSystemUptime = DateDiff("n", dtmLastBootUpTime, Now)
    Wscript.Echo "System uptime minutes: " & dtmSystemUptime 
Next
 
Function WMIDateStringToDate(dtm)
    WMIDateStringToDate =  CDate(Mid(dtm, 5, 2) & "/" & _
        Mid(dtm, 7, 2) & "/" & Left(dtm, 4) & " " & Mid (dtm, 9, 2) & ":" & _
        Mid(dtm, 11, 2) & ":" & Mid(dtm, 13, 2))
End Function

{% endhighlight %}

<i>Code sample is taken from <a href="https://docs.microsoft.com/en-us/windows/win32/wmisdk/wmi-tasks--desktop-management">Microsoft Docs</a> </i>

<hr class="space">

<b>Signature recommendations</b>
<p></p>
If the following function is called with the 3rd argument BSTR("Win32_OperatingSystem"):
<p></p>
<ul>
<li><tt>IWbemServices_ExecQuery(..., BSTR("Win32_OperatingSystem"), ...)</tt></li>
</ul>
then it's a possible indicator of the application trying to use the evasion technique.

<p></p>
<b>Countermeasures</b>
<p></p>
<ul>
<li>Adjust the <tt>KeBootTime</tt> value</li>
<li>Reset the WMI repository or restart the "<tt>winmgmt</tt>" service after you adjust the <tt>KeBootTime</tt> value</li>
</ul> 



<hr class="space">

<br />
<h3><a class="a-dummy" name="check-network-adapter-reset-time">4. Check the network adapters last reset time</a></h3>
We need to check if there are any adapters that were last reset a long time ago. This may indicate the application is running in a virtual machine restored from a snapshot.

<b>Code sample (VB)</b>
<p></p>


{% highlight vb %}

strComputer = "."
Set objWMIService = GetObject("winmgmts:" & "{impersonationLevel=impersonate}!\\" & strComputer & "\root\cimv2")
Set colOperatingSystems = objWMIService.ExecQuery ("Select * from Win32_NetworkAdapter")
 
For Each objOS in colNetworkAdapters
    dtmLastReset = objOS.TimeOfLastReset
    dtmLastResetTime = WMIDateStringToDate(dtmLastReset)  'WMIDateStringToDate function from the previous example
    dtmAdapterUptime = DateDiff("n", dtmLastResetTime, Now)
    Wscript.Echo "Adapter uptime minutes: " & dtmAdapterUptime 
Next

{% endhighlight %}

<b>Signature recommendations</b>
<p></p>
If the following function is called with the 3rd argument BSTR("Win32_OperatingSystem"):
<p></p>
<ul>
<li><tt>IWbemServices_ExecQuery(..., BSTR("Win32_NetworkAdapter"), ...)</tt></li>
</ul>
then it's a possible indicator of the application trying to use the evasion technique.

<p></p>
<b>Countermeasures</b>
<p></p>
<ul>
<li>Ensure an adequate last reset time for the network adapters</li>
<li>Reset the WMI repository or restart the "<tt>winmgmt</tt>" service </li>
</ul>


<br />
<h3><a class="a-dummy" name="countermeasures">Countermeasures</a></h3>
Countermeasures are presented in the appropriate sub-sections above.

<br />
<h3><a class="a-dummy" name="credits">Credits</a></h3>

<ul>
<li>al-khaser project on <a href="https://github.com/LordNoteworthy/al-khaser">GitHub</a></li>
<li>Microsoft Docs - <a href="https://docs.microsoft.com/en-us/windows/win32/wmisdk/">WMI Tasks: Desktop Management</a></li>
</ul>
