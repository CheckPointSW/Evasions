---
layout: post
title:  "Evasions: Global OS Objects"
categories: evasions 
tags: filesystem vmware virtualbox
---

<h1>Contents</h1>

[Global objects detection methods](#global-objects-detection-methods)
<br />
  [1. Check for specific global mutexes](#check-if-specific-mutexes-present)
<br />
  [2. Check for specific virtual devices](#check-if-specific-virtual-devices-present)
<br />
  [3. Check for specific global pipes](#check-if-pipes-present)
<br />
  [4. Check for specific global objects](#check-if-objects-present)
<br />
  [5. Check for specific object directory (Sandboxie only)](#check-if-object-directory-present)
<br />
  [6. Check if virtual registry is present in system (Sandboxie only)](#check-if-virtual-registry-present)
<br />
[Countermeasures](#countermeasures)
<br />
[Credits](#credits)
<br />
<br />


<h2><a class="a-dummy" name="global-objects-detection-methods">Global objects detection methods</a></h2>
The principle of all the global objects detection methods is the following: there are no such objects in usual host; however they exist in particular virtual environments and sandboxes. Virtual environment may be detected if such an artifact is present.


<br />
<h3><a class="a-dummy" name="check-if-specific-mutexes-present">1. Check for specific global mutexes</a></h3>

This method checks for particular mutexes which are present in virtual environments but not in usual host systems.

Functions used:
<ul>
<li><tt>CreateMutexA/W</tt></li> 
<li><tt>OpenMutexA/W</tt></li> 
</ul>

<hr class="space">

<b>Code sample</b>
<p></p>

{% highlight c %}

// usage sample:
supMutexExist(L"Sandboxie_SingleInstanceMutex_Control"); // sample value from the table below


BOOL supMutexExist(_In_ LPWSTR lpMutexName)
{
    DWORD dwError;
    HANDLE hObject = NULL;
    if (lpMutexName == NULL) {
        return FALSE;
    }

    SetLastError(0);
    hObject = CreateMutex(NULL, FALSE, lpMutexName); // define around A or W function version
    dwError = GetLastError();

    if (hObject) {
        CloseHandle(hObject);
    }

    return (dwError == ERROR_ALREADY_EXISTS);
}

{% endhighlight %}

<i>Credits for this code sample: <a href="https://github.com/hfiref0x/VMDE">VMDE project</a> </i>

<hr class="space">

<b>Signature recommendations</b>
<p></p>
If the following function contains 3rd argument from the table column <font face="Courier New">`Name`</font>:
<p></p>
<ul>
<li><tt>CreateMutexA/W(..., ..., registry_path)</tt></li> 
<li><tt>OpenMutexA/W(..., ..., registry_path)</tt></li> 
</ul>
then it's an indication of application trying to use the evasion technique.

<hr class="space">

<b>Detections table</b>

<table style="width:62%">
  <tr>
  	<td colspan="2">Check if the following global mutexes exist:</td>
  </tr>
  <tr>
  	<th style="text-align:center">Detect</th>
  	<th style="text-align:center">Name</th>
  </tr>
  <tr>
  	<th rowspan="1">DeepFreeze</th>
  	<td>Frz_State</td>
  </tr>
  <tr>
  	<th rowspan="2">Sandboxie</th>
  	<td>Sandboxie_SingleInstanceMutex_Control</td>
  </tr>
  <tr>
  	<td>SBIE_BOXED_ServiceInitComplete_Mutex1</td>
  </tr>
  <tr>
  	<th rowspan="1">VirtualPC</th>
  	<td>MicrosoftVirtualPC7UserServiceMakeSureWe'reTheOnlyOneMutex</td>
  </tr>
</table>

<br />
Note: DeepFreeze is an application restoring the system on each reboot.

<br />
<h3><a class="a-dummy" name="check-if-specific-virtual-devices-present">2. Check for specific virtual devices</a></h3>

This method checks for particular virtual devices which are present in virtual environments but not in usual host systems.

Function used:
<ul>
<li><tt>NtCreateFile</tt></li> 
</ul>

<hr class="space">

<b>Code sample</b>
<p></p>

{% highlight c %}

// usage sample:
HANDLE hDummy = NULL;
supOpenDevice(L"\\Device\\Null", GENERIC_READ, &hDummy); // sample values from the table below


BOOL supOpenDevice(
    _In_ LPWSTR lpDeviceName,
    _In_ ACCESS_MASK DesiredAccess,
    _Out_opt_ PHANDLE phDevice)
{
    OBJECT_ATTRIBUTES attr;
    IO_STATUS_BLOCK iost;
    UNICODE_STRING uDevName;
    HANDLE hDevice;
    NTSTATUS Status;

    if (phDevice) {
        *phDevice = NULL;
    }
    if (lpDeviceName == NULL) {
        return FALSE;
    }

    hDevice = NULL;
    RtlSecureZeroMemory(&uDevName, sizeof(uDevName));
    RtlInitUnicodeString(&uDevName, lpDeviceName);
    InitializeObjectAttributes(&attr, &uDevName, OBJ_CASE_INSENSITIVE, 0, NULL);

    Status = NtCreateFile(&hDevice, DesiredAccess, &attr, &iost, NULL, 0,
        0, FILE_OPEN, 0, NULL, 0);
    if (NT_SUCCESS(Status)) {
        if (phDevice != NULL) {
            *phDevice = hDevice;
        }
    }

    return NT_SUCCESS(Status);
}

{% endhighlight %}

<i>Credits for this code sample: <a href="https://github.com/hfiref0x/VMDE">VMDE project</a> </i>

<hr class="space">

<b>Signature recommendations</b>
<p></p>
If the following function contains 3rd argument with its field <font face="Courier New">`ObjectName->Buffer`</font> from the table column <font face="Courier New">`Name`</font>:
<p></p>
<ul>
<li><tt>NtCreateFile(..., ..., attr, ...)</tt></li>
</ul>
then it's an indication of application trying to use the evasion technique.

<br />
3rd argument is of the following type:
{% highlight c %}
typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES;
{% endhighlight %}

<hr class="space">

<b>Detections table</b>

<table style="width:62%">
  <tr>
  	<td colspan="3">Check if the following virtual devices exist:</td>
  </tr>
  <tr>
  	<th style="text-align:center">Detect</th>
  	<th style="text-align:center">Path</th>
  </tr>
  <tr>
  	<th rowspan="6">VirtualBox</th>
  	<td>\\.\VBoxMiniRdDN</td>
  </tr>
  <tr>
  	<td>\\.\VBoxMiniRdrDN</td>
  </tr>
  <tr>
  	<td>\\.\VBoxGuest</td>
  </tr>
  <tr>
  	<td>\\.\VBoxTrayIPC</td>
  </tr>
  <tr>
  	<td>\\.\VBoxMouse</td>
  </tr>
  <tr>
  	<td>\\.\VBoxVideo</td>
  </tr>
  <tr>
  	<th rowspan="2">VMware</th>
  	<td>\\.\HGFS</td>
  </tr>
  <tr>
  	<td>\\.\vmci</td>
  </tr>
</table>


<br />
<h3><a class="a-dummy" name="check-if-pipes-present">3. Check for specific global pipes</a></h3>

Pipes are just a particular case of virtual devices, please refer to the <a href="#check-if-specific-virtual-devices-present">previous section</a> for code sample and signature recommendations.

<hr class="space">

<b>Detections table</b>

<table style="width:62%">
  <tr>
  	<td colspan="2">Check if the following global pipes exist:</td>
  </tr>
  <tr>
  	<th style="text-align:center">Detect</th>
  	<th style="text-align:center">String</th>
  </tr>
  <tr>
  	<th rowspan="2">VirtualBox</th>
  	<td>\\.\pipe\VBoxMiniRdDN</td>
  </tr>
  <tr>
  	<td>\\.\pipe\VBoxTrayIPC</td>
  </tr>
</table>


<br />
<h3><a class="a-dummy" name="check-if-objects-present">4. Check for global objects</a></h3>

This method checks for particular global objects which are present in virtual environments but not in usual host systems.

Functions used:
<ul>
<li><tt>NtOpenDirectoryObject</tt></li> 
<li><tt>NtQueryDirectoryObject</tt></li> 
</ul>

<hr class="space">

<b>Code sample</b>
<p></p>

{% highlight c %}

// usage sample:
supIsObjectExists(L"\\Driver", L"SbieDrv"); // sample values from the table below


typedef struct _OBJECT_DIRECTORY_INFORMATION {
    UNICODE_STRING Name;
    UNICODE_STRING TypeName;
} OBJECT_DIRECTORY_INFORMATION, *POBJECT_DIRECTORY_INFORMATION;

BOOL supIsObjectExists(
    _In_ LPWSTR RootDirectory,
    _In_ LPWSTR ObjectName)
{
    OBJSCANPARAM Param;
    if (ObjectName == NULL) {
        return FALSE;
    }

    Param.Buffer = ObjectName;
    Param.BufferSize = (ULONG)_strlen_w(ObjectName);

    return NT_SUCCESS(supEnumSystemObjects(RootDirectory, NULL, supDetectObjectCallback, &Param));
}

NTSTATUS NTAPI supDetectObjectCallback(
    _In_ POBJECT_DIRECTORY_INFORMATION Entry,
    _In_ PVOID CallbackParam)
{
    POBJSCANPARAM Param = (POBJSCANPARAM)CallbackParam;
    if (Entry == NULL) {
        return STATUS_INVALID_PARAMETER_1;
    }
    if (CallbackParam == NULL) {
        return STATUS_INVALID_PARAMETER_2;
    }
    if (Param->Buffer == NULL || Param->BufferSize == 0) {
        return STATUS_MEMORY_NOT_ALLOCATED;
    }
    if (Entry->Name.Buffer) {
        if (_strcmpi_w(Entry->Name.Buffer, Param->Buffer) == 0) {
            return STATUS_SUCCESS;
        }
    }

    return STATUS_UNSUCCESSFUL;
}

NTSTATUS NTAPI supEnumSystemObjects(
    _In_opt_ LPWSTR pwszRootDirectory,
    _In_opt_ HANDLE hRootDirectory,
    _In_ PENUMOBJECTSCALLBACK CallbackProc,
    _In_opt_ PVOID CallbackParam)
{
    BOOL cond = TRUE;
    ULONG ctx, rlen;
    HANDLE hDirectory = NULL;
    NTSTATUS status;
    NTSTATUS CallbackStatus;
    OBJECT_ATTRIBUTES attr;
    UNICODE_STRING sname;
    POBJECT_DIRECTORY_INFORMATION objinf;

    if (CallbackProc == NULL) {
        return STATUS_INVALID_PARAMETER_4;
    }
    status = STATUS_UNSUCCESSFUL;
    
    __try {
        // We can use root directory.
        if (pwszRootDirectory != NULL) {
            RtlSecureZeroMemory(&sname, sizeof(sname));
            RtlInitUnicodeString(&sname, pwszRootDirectory);
            InitializeObjectAttributes(&attr, &sname, OBJ_CASE_INSENSITIVE, NULL, NULL);

            status = NtOpenDirectoryObject(&hDirectory, DIRECTORY_QUERY, &attr);
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }
        else {
            if (hRootDirectory == NULL) {
                return STATUS_INVALID_PARAMETER_2;
            }
            hDirectory = hRootDirectory;
        }

        // Enumerate objects in directory.
        ctx = 0;
        do {
            rlen = 0;
            status = NtQueryDirectoryObject(hDirectory, NULL, 0, TRUE, FALSE, &ctx, &rlen);
            if (status != STATUS_BUFFER_TOO_SMALL)
                    break;
            objinf = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, rlen);
            if (objinf == NULL)
                break;
                
            status = NtQueryDirectoryObject(hDirectory, objinf, rlen, TRUE, FALSE, &ctx, &rlen);
            if (!NT_SUCCESS(status)) {
                HeapFree(GetProcessHeap(), 0, objinf);
                break;
            }

            CallbackStatus = CallbackProc(objinf, CallbackParam);
            HeapFree(GetProcessHeap(), 0, objinf);
            if (NT_SUCCESS(CallbackStatus)) {
                status = STATUS_SUCCESS;
                break;
            }
        } while (cond);

        if (hDirectory != NULL) {
            NtClose(hDirectory);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = STATUS_ACCESS_VIOLATION;
    }

    return status;
}

{% endhighlight %}


<i>Credits for this code sample: <a href="https://github.com/hfiref0x/VMDE">VMDE project</a> </i>

<hr class="space">

<b>Detections table</b>

<table style="width:93%">
  <tr>
  	<td colspan="3">Check if the following global objects exist:</td>
  </tr>
  <tr>
  	<th style="text-align:center">Detect</th>
  	<th style="text-align:center">Path</th>
    <th style="text-align:center">Object</th>
  </tr>
  <tr>
  	<th rowspan="1">Hyper-V</th>
  	<td>VmGenerationCounter</td>
  	<td>\Device</td>
  </tr>
  <tr>
  	<th rowspan="3">Parallels</th>
  	<td>prl_pv</td>
  	<td>\Device</td>
  </tr>
  <tr>
  	<td>prl_tg</td>
  	<td>\Device</td>
  </tr>
  <tr>
  	<td>prl_time</td>
  	<td>\Device</td>
  </tr>
  <tr>
  	<th rowspan="3">Sandboxie</th>
  	<td>SandboxieDriverApi</td>
  	<td>\Device</td>
  </tr>
  <tr>
  	<td>SbieDrv</td>
  	<td>\Driver</td>
  </tr>
  <tr>
  	<td>SbieSvcPort</td>
  	<td>\RPC Control</td>
  </tr>
  <tr>
  	<th rowspan="4">VirtualBox</th>
  	<td>VBoxGuest</td>
  	<td>\Device</td>
  </tr>
  <tr>
  	<td>VBoxMiniRdr</td>
  	<td>\Device</td>
  </tr>
  <tr>
  	<td>VBoxVideo</td>
  	<td>\Driver</td>
  </tr>
  <tr>
  	<td>VBoxMouse</td>
  	<td>\Driver</td>
  </tr>
  <tr>
  	<th rowspan="2">VirtualPC</th>
  	<td>VirtualMachineServices</td>
  	<td>\Device</td>
  </tr>
  <tr>
  	<td>1-driver-vmsrvc</td>
  	<td>\Driver</td>
  </tr>
  <tr>
  	<th rowspan="1">VMware</th>
  	<td>vmmemctl</td>
  	<td>\Device</td>
  </tr>
</table>


<br />
<h3><a class="a-dummy" name="check-if-object-directory-present">5. Check for object directory (Sandboxie only)</a></h3>

This method checks for particular object directory which is present in Sandboxie virtual environment but not in usual host systems.

Function used:
<ul>
<li><tt>GetFileAttributes</tt></li> 
</ul>

<hr class="space">

<b>Code sample</b>
<p></p>

{% highlight c %}

#define DIRECTORY_QUERY (0x0001)
#define OBJ_CASE_INSENSITIVE 0x00000040L
#define DIRECTORY_SANDBOXIE L"\\Sandbox"

int check_if_obj_dir_present() {
    OBJECT_ATTRIBUTES attr;
    UNICODE_STRING ustrName;
    HANDLE hObject = NULL;

    RtlSecureZeroMemory(&ustrName, sizeof(ustrName));
    RtlInitUnicodeString(&ustrName, DIRECTORY_SANDBOXIE);
    InitializeObjectAttributes(&attr, &ustrName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    if (NT_SUCCESS(NtOpenDirectoryObject(&hObject, DIRECTORY_QUERY, &attr))) {
        NtClose(hObject);
        return TRUE;
    }
    
    return FALSE;
}

{% endhighlight %}

<i>Credits for this code sample: <a href="https://github.com/hfiref0x/VMDE">VMDE project</a> </i>

<hr class="space">

<b>Signature recommendations</b>
<p></p>
If the following function contains 3rd argument with its field <font face="Courier New">"ObjectName->Buffer"</font> from the table column <font face="Courier New">`Name`</font>:
<p></p>
<ul>
<li><tt>NtOpenDirectoryObject(..., ..., attr, ...)</tt></li> 
</ul>
then it's an indication of application trying to use the evasion technique.

<br />
3rd argument is of the following type:
{% highlight c %}
typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES;
{% endhighlight %}

<hr class="space">

<b>Detections table</b>

<table style="width:62%">
  <tr>
  	<td colspan="2">Check if the following object directory exists:</td>
  </tr>
  <tr>
  	<th style="text-align:center">Detect</th>
  	<th style="text-align:center">Path</th>
  </tr>
  <tr>
  	<th rowspan="1">Sandboxie</th>
  	<td>\Sandbox</td>
  </tr>
</table>


<br />
<h3><a class="a-dummy" name="check-if-virtual-registry-present">6. Check if virtual registry is present in OS (Sandboxie only)</a></h3>

This method checks for virtual registry which is present in Sandboxie virtual environment but not in usual host systems.

Application opens registry key <font face="Courier New">\REGISTRY\USER</font>. It uses the following function in order to check real object name:

{% highlight c %}
NtQueryObject(
    hUserKey,
    ObjectNameInformation,
    oni, // OBJECT_NAME_INFORMATION object
    Size,
    NULL);
{% endhighlight %}

If received <font face="Courier New">OBJECT_NAME_INFORMATION</font> object name does not equal to the <font face="Courier New">"\REGISTRY\USER"</font>, then application assumes that it runs inside Sandboxie environment.

<hr class="space">

<b>Signature recommendations</b>
<p></p>
If the following function is used for opening <font face="Courier New">\REGISTRY\USER</font>:
<p></p>
<ul>
<li><tt>NtOpenKey</tt></li> 
</ul>
and is followed by the call of the following function with its 1st argument being the handle of <font face="Courier New">\REGISTRY\USER</font> key:
<ul>
<li><tt>NtQueryObject(hUserKey, ...)</tt></li> 
</ul>
then it's an indication of application trying to use the evasion technique.


<br />
<h3><a class="a-dummy" name="countermeasures">Countermeasures</a></h3>

Hook target functions and return appropriate results if indicators (objects from tables) are triggered. In some cases stopping appropriate device may help — but it's not a universal counter-action: not all global objects are devices.

<br />
<h3><a class="a-dummy" name="credits">Credits</a></h3>

Credits go to open-source project from where code samples were taken: 
<ul>
<li>VMDE project on <a href="https://github.com/hfiref0x/VMDE">github</a></li>
</ul>

Though Check Point tool InviZzzible has them all implemented, due to modular structure of the code it would require more space to show a code sample from this tool for the same purposes. That's why we've decided to use other great open-source projects for examples throughout the encyclopedia.


[vmde-github]:      https://github.com/hfiref0x/VMDE
