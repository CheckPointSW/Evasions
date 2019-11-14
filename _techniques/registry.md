---
layout: post
title:  "Evasions: Registry"
title-image: "/assets/icons/registry.svg"
categories: evasions 
tags: registry
---

<h1>Contents</h1>

[Registry detection methods](#registry-detection-methods)
<br />
  [1. Check if particular registry paths exist](#check-if-particular-registry-paths-exist)
<br />
  [2. Check if particular registry keys contain specified strings](#check-if-keys-contain-strings)
<br />
[Countermeasures](#countermeasures)
<br />
[Credits](#credits)
<br />
<br />


<h2><a class="a-dummy" name="registry-detection-methods">Registry detection methods</a></h2>
The principle of all the registry detection methods is the following: there are no such registry keys and values in usual host. However they exist in particular virtual environments.

Sometimes usual system may cause false positives when these checks are applied because it has some virtual machines installed and thus some VM artifacts are present in the system. Though in all other aspects such a system is treated clean in comparison with virtual environments.

Registry keys may be queries via WinAPI calls.

Functions used in <font face="Courier New">kernel32.dll</font>:
<ul>
  <li><tt>RegOpenKey</tt></li> 
  <li><tt>RegOpenKeyEx</tt></li> 
  <li><tt>RegQueryValue</tt></li> 
  <li><tt>RegQueryValueEx</tt></li> 
  <li><tt>RegCloseKey</tt></li> 
  <li><tt>RegEnumKeyEx</tt></li> 
</ul>

Functions above are wrappers on top of the following <font face="Courier New">ntdll.dll</font> functions:
<ul>
  <li><tt>NtOpenKey</tt></li> 
  <li><tt>NtEnumerateKey</tt></li> 
  <li><tt>NtQueryValueKey</tt></li> 
  <li><tt>NtClose</tt></li> 
</ul>

<br />
<h3><a class="a-dummy" name="check-if-particular-registry-paths-exist">1. Check if particular registry paths exist</a></h3>

Take a look at [title section](#registry-detection-methods) to get the list of used functions.

<hr class="space">

<b>Code sample</b>
<p></p>

{% highlight c %}

/* sample of usage: see detection of VirtualBox in the table below to check registry path */
int vbox_reg_key7() {
    return pafish_exists_regkey(HKEY_LOCAL_MACHINE, "HARDWARE\\ACPI\\FADT\\VBOX__");
}

/* code is taken from "pafish" project, see references on the parent page */
int pafish_exists_regkey(HKEY hKey, char * regkey_s) {
    HKEY regkey;
    LONG ret;

    /* regkey_s == "HARDWARE\\ACPI\\FADT\\VBOX__"; */
    if (pafish_iswow64()) {
        ret = RegOpenKeyEx(hKey, regkey_s, 0, KEY_READ | KEY_WOW64_64KEY, &regkey);
    }
    else {
        ret = RegOpenKeyEx(hKey, regkey_s, 0, KEY_READ, &regkey);
    }

    if (ret == ERROR_SUCCESS) {
        RegCloseKey(regkey);
        return TRUE;
    }
    else
        return FALSE;
}

{% endhighlight %}

<i>Credits for this code sample: <a href="https://github.com/a0rtega/pafish">pafish project</a> </i>

<hr class="space">

<b>Signature recommendations</b>
<p></p>
If the following function contains 2nd argument from the table column <font face="Courier New">`Registry path`</font>:
<p></p>
<ul>
<li><tt>NtOpenKey(..., registry_path, ...)</tt></li> 
</ul>
then it's an indication of application trying to use the evasion technique.

<hr class="space">

<b>Detections table</b>

<table style="width:100%">
  <tr>
  	<td colspan="3">Check if the following registry paths exist:</td>
  </tr>
  <tr>
  	<th style="text-align:center">Detect</th>
  	<th style="text-align:center">Registry path</th>
  	<th style="text-align:center">Details (if any)</th>
  </tr>
  <tr>
  	<th>[general]</th>
  	<td>HKLM\Software\Classes\Folder\shell\sandbox</td>
  	<td />
  </tr>
  <tr>
  	<th rowspan="7">Hyper-V</th>
  	<td>HKLM\SOFTWARE\Microsoft\Hyper-V</td>
  	<td />
  </tr>
  <tr>
  	<td>HKLM\SOFTWARE\Microsoft\VirtualMachine</td>
  	<td />
  </tr>
  <tr>
  	<td>HKLM\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters</td>
  	<td>Usually "HostName" and "VirtualMachineName" values are read under this path</td>
  </tr>
  <tr>
  	<td>HKLM\SYSTEM\ControlSet001\Services\vmicheartbeat</td>
  	<td />
  </tr>
  <tr>
  	<td>HKLM\SYSTEM\ControlSet001\Services\vmicvss</td>
  	<td />
  </tr>
  <tr>
  	<td>HKLM\SYSTEM\ControlSet001\Services\vmicshutdown</td>
  	<td />
  </tr>
  <tr>
  	<td>HKLM\SYSTEM\ControlSet001\Services\vmicexchange</td>
  	<td />
  </tr>
  <tr>
  	<th rowspan="1">Parallels</th>
  	<td>HKLM\SYSTEM\CurrentControlSet\Enum\PCI\VEN_1AB8*</td>
  	<td>Subkey has the following structure: VEN_XXXX&DEV_YYYY&SUBSYS_ZZZZ&REV_WW</td>
  </tr>
  <tr>
  	<th rowspan="2">Sandboxie</th>
  	<td>HKLM\SYSTEM\CurrentControlSet\Services\SbieDrv</td>
  	<td />
  </tr>
  <tr>
  	<td>HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Sandboxie</td>
  	<td />
  </tr>
  <tr>
  	<th rowspan="10">VirtualBox</th>
  	<td>HKLM\SYSTEM\CurrentControlSet\Enum\PCI\VEN_80EE*</td>
  	<td>Subkey has the following structure: VEN_XXXX&DEV_YYYY&SUBSYS_ZZZZ&REV_WW</td>
  </tr>
  <tr>
  	<td>HKLM\HARDWARE\ACPI\DSDT\VBOX__</td>
  	<td />
  </tr>
  <tr>
  	<td>HKLM\HARDWARE\ACPI\FADT\VBOX__</td>
  	<td />
  </tr>
  <tr>
  	<td>HKLM\HARDWARE\ACPI\RSDT\VBOX__</td>
  	<td />
  </tr>
  <tr>
  	<td>HKLM\SOFTWARE\Oracle\VirtualBox Guest Additions</td>
  	<td />
  </tr>
  <tr>
  	<td>HKLM\SYSTEM\ControlSet001\Services\VBoxGuest</td>
  	<td />
  </tr>
  <tr>
  	<td>HKLM\SYSTEM\ControlSet001\Services\VBoxMouse</td>
  	<td />
  </tr>
  <tr>
  	<td>HKLM\SYSTEM\ControlSet001\Services\VBoxService</td>
  	<td />
  </tr>
  <tr>
  	<td>HKLM\SYSTEM\ControlSet001\Services\VBoxSF</td>
  	<td />
  </tr>
  <tr>
  	<td>HKLM\SYSTEM\ControlSet001\Services\VBoxVideo</td>
  	<td />
  </tr>
  <tr>
  	<th rowspan="5">VirtualPC</th>
  	<td>HKLM\SYSTEM\CurrentControlSet\Enum\PCI\VEN_5333*</td>
  	<td>Subkey has the following structure: VEN_XXXX&DEV_YYYY&SUBSYS_ZZZZ&REV_WW</td>
  </tr>
  <tr>
  	<td>HKLM\SYSTEM\ControlSet001\Services\vpcbus</td>
  	<td />
  </tr>
  <tr>
  	<td>HKLM\SYSTEM\ControlSet001\Services\vpc-s3</td>
  	<td />
  </tr>
  <tr>
  	<td>HKLM\SYSTEM\ControlSet001\Services\vpcuhub</td>
  	<td />
  </tr>
  <tr>
  	<td>HKLM\SYSTEM\ControlSet001\Services\msvmmouf</td>
  	<td></td>
  </tr>
  <tr>
  	<th rowspan="14">VMware</th>
  	<td>HKLM\SYSTEM\CurrentControlSet\Enum\PCI\VEN_15AD*</td>
  	<td>Subkey has the following structure: VEN_XXXX&DEV_YYYY&SUBSYS_ZZZZ&REV_WW</td>
  </tr>
  <tr>
  	<td>HKCU\SOFTWARE\VMware, Inc.\VMware Tools</td>
  	<td></td>
  </tr>
  <tr>
  	<td>HKLM\SOFTWARE\VMware, Inc.\VMware Tools</td>
  	<td></td>
  </tr>
  <tr>
  	<td>HKLM\SYSTEM\ControlSet001\Services\vmdebug</td>
  	<td></td>
  </tr>
  <tr>
  	<td>HKLM\SYSTEM\ControlSet001\Services\vmmouse</td>
  	<td></td>
  </tr>
  <tr>
  	<td>HKLM\SYSTEM\ControlSet001\Services\VMTools</td>
  	<td></td>
  </tr>
  <tr>
  	<td>HKLM\SYSTEM\ControlSet001\Services\VMMEMCTL</td>
  	<td></td>
  </tr>
  <tr>
  	<td>HKLM\SYSTEM\ControlSet001\Services\vmware</td>
  	<td></td>
  </tr>
  <tr>
  	<td>HKLM\SYSTEM\ControlSet001\Services\vmci</td>
  	<td></td>
  </tr>
  <tr>
  	<td>HKLM\SYSTEM\ControlSet001\Services\vmx86</td>
  	<td></td>
  </tr>
  <tr>
  	<td>HKLM\SYSTEM\CurrentControlSet\Enum\IDE\CdRomNECVMWar_VMware_IDE_CD*</td>
  	<td></td>
  </tr>
  <tr>
  	<td>HKLM\SYSTEM\CurrentControlSet\Enum\IDE\CdRomNECVMWar_VMware_SATA_CD*</td>
  	<td></td>
  </tr>
  <tr>
  	<td>HKLM\SYSTEM\CurrentControlSet\Enum\IDE\DiskVMware_Virtual_IDE_Hard_Drive*</td>
  	<td></td>
  </tr>
  <tr>
  	<td>HKLM\SYSTEM\CurrentControlSet\Enum\IDE\DiskVMware_Virtual_SATA_Hard_Drive*</td>
  	<td></td>
  </tr>
  <tr>
  	<th rowspan="2">Wine</th>
  	<td>HKCU\SOFTWARE\Wine</td>
  	<td></td>
  </tr>
  <tr>
  	<td>HKLM\SOFTWARE\Wine</td>
  	<td></td>
  </tr>
  <tr>
  	<th rowspan="8">Xen</th>
  	<td>HKLM\HARDWARE\ACPI\DSDT\xen</td>
  	<td></td>
  </tr>
  <tr>
  	<td>HKLM\HARDWARE\ACPI\FADT\xen</td>
  	<td></td>
  </tr>
  <tr>
  	<td>HKLM\HARDWARE\ACPI\RSDT\xen</td>
  	<td></td>
  </tr>
  <tr>
  	<td>HKLM\SYSTEM\ControlSet001\Services\xenevtchn</td>
  	<td></td>
  </tr>
  <tr>
  	<td>HKLM\SYSTEM\ControlSet001\Services\xennet</td>
  	<td></td>
  </tr>
  <tr>
  	<td>HKLM\SYSTEM\ControlSet001\Services\xennet6</td>
  	<td></td>
  </tr>
  <tr>
  	<td>HKLM\SYSTEM\ControlSet001\Services\xensvc</td>
  	<td></td>
  </tr>
  <tr>
  	<td>HKLM\SYSTEM\ControlSet001\Services\xenvdb</td>
  	<td></td>
  </tr>
</table>

<br />
In particular cases malware may enumerate sub-keys and check if a name of the sub-key contain some string instead of checking if the specified key exists.

<p></p>
For example: enumerate sub-keys of <font face="Courier New">"HKLM\SYSTEM\ControlSet001\Services\"</font> and search for <font face="Courier New">"VBox"</font> string.

<br />
<h3><a class="a-dummy" name="check-if-keys-contain-strings">2. Check if particular registry keys contain specified strings</a></h3>

Take a look at [title section](#registry-detection-methods) to get the list of used functions. Please note that case is irrelevant for these checks: it may be either upper or lower.

<hr class="space">

<b>Code sample</b>
<p></p>

{% highlight c %}
/* sample of usage: see detection of VirtualBox in the table below to check registry path and key values */
int vbox_reg_key2() {
    return pafish_exists_regkey_value_str(HKEY_LOCAL_MACHINE, "HARDWARE\\Description\\System", "SystemBiosVersion", "VBOX");
}

/* code is taken from "pafish" project, see references on the parent page */
int pafish_exists_regkey_value_str(HKEY hKey, char * regkey_s, char * value_s, char * lookup) {
    /*
        regkey_s == "HARDWARE\\Description\\System";
        value_s == "SystemBiosVersion";
        lookup == "VBOX";
    */

    HKEY regkey;
    LONG ret;
    DWORD size;
    char value[1024], * lookup_str;
    size_t lookup_size;

    lookup_size = strlen(lookup);
    lookup_str = malloc(lookup_size+sizeof(char));
    strncpy(lookup_str, lookup, lookup_size+sizeof(char));
    size = sizeof(value);

    /* regkey_s == "HARDWARE\\Description\\System"; */
    if (pafish_iswow64()) {
        ret = RegOpenKeyEx(hKey, regkey_s, 0, KEY_READ | KEY_WOW64_64KEY, &regkey);
    }
    else {
        ret = RegOpenKeyEx(hKey, regkey_s, 0, KEY_READ, &regkey);
    }

    if (ret == ERROR_SUCCESS) {
        /* value_s == "SystemBiosVersion"; */
        ret = RegQueryValueEx(regkey, value_s, NULL, NULL, (BYTE*)value, &size);
        RegCloseKey(regkey);

        if (ret == ERROR_SUCCESS) {
            size_t i;
            for (i = 0; i < strlen(value); i++) { /* case-insensitive */
                value[i] = toupper(value[i]);
            }
            for (i = 0; i < lookup_size; i++) { /* case-insensitive */
                lookup_str[i] = toupper(lookup_str[i]);
            }
            if (strstr(value, lookup_str) != NULL) {
                free(lookup_str);
                return TRUE;
            }
        }
    }

    free(lookup_str);
    return FALSE;
}
{% endhighlight %}

<i>Credits for this code sample: <a href="https://github.com/a0rtega/pafish">pafish project</a> </i>

<hr class="space">

<b>Signature recommendations</b>
<p></p>
If the following function contains 2nd argument from the table column <font face="Courier New">`Registry path`</font>:
<p></p>
<ul>
<li><tt>NtOpenKey(..., registry_path, ...)</tt></li> 
</ul>
and is followed by the call to the following function with 2nd argument from the table column <font face="Courier New">`Registry key`</font>:
<ul>
<li><tt>NtQueryValueKey(..., registry_item, ...)</tt></li> 
</ul>
then it's an indication of application trying to use the evasion technique.

<hr class="space">

<b>Detections table</b>

<table style="width:100%">
  <tr>
  	<td colspan="4">Check if the following registry values contain the following strings (case insensitive):</td>
  </tr>
  <tr>
  	<th style="text-align:center">Detect</th>
  	<th style="text-align:center">Registry path</th>
  	<th style="text-align:center">Registry key</th>
  	<th style="text-align:center">String</th>
  </tr>
  <tr>
  	<th rowspan="2">[general]</th>
  	<td>HKLM\HARDWARE\Description\System</td>
  	<td>SystemBiosDate</td>
  	<td>06/23/99</td>
  </tr>
  <tr>
  	<td>HKLM\HARDWARE\Description\System\BIOS</td>
  	<td>SystemProductName</td>
  	<td>A M I</td>
  </tr>
  <tr>
  	<th rowspan="2">BOCHS</th>
  	<td>HKLM\HARDWARE\Description\System</td>
  	<td>SystemBiosVersion</td>
  	<td>BOCHS</td>
  </tr>
  <tr>
  	<td>HKLM\HARDWARE\Description\System</td>
  	<td>VideoBiosVersion</td>
  	<td>BOCHS</td>
  </tr>
  <tr>
  	<th rowspan="2">Anubis</th>
  	<td>HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion</td>
  	<td>ProductID</td>
  	<td>76487-337-8429955-22614</td>
  </tr>
  <tr>
  	<td>HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion</td>
  	<td>ProductID</td>
  	<td>76487-337-8429955-22614</td>
  </tr>
  <tr>
  	<th rowspan="2">CwSandbox</th>
  	<td>HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion</td>
  	<td>ProductID</td>
  	<td>76487-644-3177037-23510</td>
  </tr>
  <tr>
  	<td>HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion</td>
  	<td>ProductID</td>
  	<td>76487-644-3177037-23510</td>
  </tr>
  <tr>
  	<th rowspan="2">JoeBox</th>
  	<td>HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion</td>
  	<td>ProductID</td>
  	<td>55274-640-2673064-23950</td>
  </tr>
  <tr>
  	<td>HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion</td>
  	<td>ProductID</td>
  	<td>55274-640-2673064-23950</td>
  </tr>
  <tr>
  	<th rowspan="2">Parallels</th>
  	<td>HKLM\HARDWARE\Description\System</td>
  	<td>SystemBiosVersion</td>
  	<td>PARALLELS</td>
  </tr>
  <tr>
  	<td>HKLM\HARDWARE\Description\System</td>
  	<td>VideoBiosVersion</td>
  	<td>PARALLELS</td>
  </tr>
  <tr>
  	<th rowspan="4">QEMU</th>
  	<td>HKLM\HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\Scsi Bus 0\Target Id 0\Logical Unit Id 0</td>
  	<td>Identifier</td>
  	<td>QEMU</td>
  </tr>
  <tr>
  	<td>HKLM\HARDWARE\Description\System</td>
  	<td>SystemBiosVersion</td>
  	<td>QEMU</td>
  </tr>
  <tr>
  	<td>HKLM\HARDWARE\Description\System</td>
  	<td>VideoBiosVersion</td>
  	<td>QEMU</td>
  </tr>
  <tr>
  	<td>HKLM\HARDWARE\Description\System\BIOS</td>
  	<td>SystemManufacturer</td>
  	<td>QEMU</td>
  </tr>
  <tr>
  	<th rowspan="14">VirtualBox</th>
  	<td>HKLM\HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\Scsi Bus 0\Target Id 0\Logical Unit Id 0</td>
  	<td>Identifier</td>
  	<td>VBOX</td>
  </tr>
  <tr>
  	<td>HKLM\HARDWARE\DEVICEMAP\Scsi\Scsi Port 1\Scsi Bus 0\Target Id 0\Logical Unit Id 0</td>
  	<td>Identifier</td>
  	<td>VBOX</td>
  </tr>
  <tr>
  	<td>HKLM\HARDWARE\DEVICEMAP\Scsi\Scsi Port 2\Scsi Bus 0\Target Id 0\Logical Unit Id 0</td>
  	<td>Identifier</td>
  	<td>VBOX</td>
  </tr>
  <tr>
  	<td>HKLM\HARDWARE\Description\System</td>
  	<td>SystemBiosVersion</td>
  	<td>VBOX</td>
  </tr>
  <tr>
  	<td>HKLM\HARDWARE\Description\System</td>
  	<td>VideoBiosVersion</td>
  	<td>VIRTUALBOX</td>
  </tr>
  <tr>
  	<td>HKLM\HARDWARE\Description\System\BIOS</td>
  	<td>SystemProductName</td>
  	<td>VIRTUAL</td>
  </tr>
  <tr>
  	<td>HKLM\SYSTEM\ControlSet001\Services\Disk\Enum</td>
  	<td>DeviceDesc</td>
  	<td>VBOX</td>
  </tr>
  <tr>
  	<td>HKLM\SYSTEM\ControlSet001\Services\Disk\Enum</td>
  	<td>FriendlyName</td>
  	<td>VBOX</td>
  </tr>
  <tr>
  	<td>HKLM\SYSTEM\ControlSet002\Services\Disk\Enum</td>
  	<td>DeviceDesc</td>
  	<td>VBOX</td>
  </tr>
  <tr>
  	<td>HKLM\SYSTEM\ControlSet002\Services\Disk\Enum</td>
  	<td>FriendlyName</td>
  	<td>VBOX</td>
  </tr>
  <tr>
  	<td>HKLM\SYSTEM\ControlSet003\Services\Disk\Enum</td>
  	<td>DeviceDesc</td>
  	<td>VBOX</td>
  </tr>
  <tr>
  	<td>HKLM\SYSTEM\ControlSet003\Services\Disk\Enum</td>
  	<td>FriendlyName</td>
  	<td>VBOX</td>
  </tr>
  <tr>
  	<td>HKLM\SYSTEM\CurrentControlSet\Control\SystemInformation</td>
  	<td>SystemProductName</td>
  	<td>VIRTUAL</td>
  </tr>
  <tr>
  	<td>HKLM\SYSTEM\CurrentControlSet\Control\SystemInformation</td>
  	<td>SystemProductName</td>
  	<td>VIRTUALBOX</td>
  </tr>
  <tr>
  	<th rowspan="27">VMware</th>
  	<td>HKLM\HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\Scsi Bus 0\Target Id 0\Logical Unit Id 0</td>
  	<td>Identifier</td>
  	<td>VMWARE</td>
  </tr>
  <tr>
  	<td>HKLM\HARDWARE\DEVICEMAP\Scsi\Scsi Port 1\Scsi Bus 0\Target Id 0\Logical Unit Id 0</td>
  	<td>Identifier</td>
  	<td>VMWARE</td>
  </tr>
  <tr>
  	<td>HKLM\HARDWARE\DEVICEMAP\Scsi\Scsi Port 2\Scsi Bus 0\Target Id 0\Logical Unit Id 0</td>
  	<td>Identifier</td>
  	<td>VMWARE</td>
  </tr>
  <tr>
  	<td>HKLM\HARDWARE\Description\System</td>
  	<td>SystemBiosVersion</td>
  	<td>VMWARE</td>
  </tr>
  <tr>
  	<td>HKLM\HARDWARE\Description\System</td>
  	<td>SystemBiosVersion</td>
  	<td>INTEL - 6040000</td>
  </tr>
  <tr>
  	<td>HKLM\HARDWARE\Description\System</td>
  	<td>VideoBiosVersion</td>
  	<td>VMWARE</td>
  </tr>
  <tr>
  	<td>HKLM\HARDWARE\Description\System\BIOS</td>
  	<td>SystemProductName</td>
  	<td>VMware</td>
  </tr>
  <tr>
  	<td>HKLM\SYSTEM\ControlSet001\Services\Disk\Enum</td>
  	<td>0</td>
  	<td>VMware</td>
  </tr>
  <tr>
  	<td>HKLM\SYSTEM\ControlSet001\Services\Disk\Enum</td>
  	<td>1</td>
  	<td>VMware</td>
  </tr>
  <tr>
  	<td>HKLM\SYSTEM\ControlSet001\Services\Disk\Enum</td>
  	<td>DeviceDesc</td>
  	<td>VMware</td>
  </tr>
  <tr>
  	<td>HKLM\SYSTEM\ControlSet001\Services\Disk\Enum</td>
  	<td>FriendlyName</td>
  	<td>VMware</td>
  </tr>
  <tr>
  	<td>HKLM\SYSTEM\ControlSet002\Services\Disk\Enum</td>
  	<td>DeviceDesc</td>
  	<td>VMware</td>
  </tr>
  <tr>
  	<td>HKLM\SYSTEM\ControlSet002\Services\Disk\Enum</td>
  	<td>FriendlyName</td>
  	<td>VMware</td>
  </tr>
  <tr>
  	<td>HKLM\SYSTEM\ControlSet003\Services\Disk\Enum</td>
  	<td>DeviceDesc</td>
  	<td>VMware</td>
  </tr>
  <tr>
  	<td>HKLM\SYSTEM\ControlSet003\Services\Disk\Enum</td>
  	<td>FriendlyName</td>
  	<td>VMware</td>
  </tr>
  <tr>
  	<td>HKCR\Installer\Products</td>
  	<td>ProductName</td>
  	<td>vmware tools</td>
  </tr>
  <tr>
  	<td>HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall</td>
  	<td>DisplayName</td>
  	<td>vmware tools</td>
  </tr>
  <tr>
  	<td>HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall</td>
  	<td>DisplayName</td>
  	<td>vmware tools</td>
  </tr>
  <tr>
  	<td>HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall</td>
  	<td>DisplayName</td>
  	<td>vmware tools</td>
  </tr>
  <tr>
  	<td>HKLM\SYSTEM\ControlSet001\Control\Class\{4D36E968-E325-11CE-BFC1-08002BE10318}\0000</td>
  	<td>CoInstallers32</td>
  	<td>*vmx*</td>
  </tr>
  <tr>
  	<td>HKLM\SYSTEM\ControlSet001\Control\Class\{4D36E968-E325-11CE-BFC1-08002BE10318}\0000</td>
  	<td>DriverDesc</td>
  	<td>VMware*</td>
  </tr>
  <tr>
  	<td>HKLM\SYSTEM\ControlSet001\Control\Class\{4D36E968-E325-11CE-BFC1-08002BE10318}\0000</td>
  	<td>InfSection</td>
  	<td>vmx*</td>
  </tr>
  <tr>
  	<td>HKLM\SYSTEM\ControlSet001\Control\Class\{4D36E968-E325-11CE-BFC1-08002BE10318}\0000</td>
  	<td>ProviderName</td>
  	<td>VMware*</td>
  </tr>
  <tr>
  	<td>HKLM\SYSTEM\CurrentControlSet\Control\SystemInformation</td>
  	<td>SystemProductName</td>
  	<td>VMWARE</td>
  </tr>
  <tr>
  	<td>HKLM\SYSTEM\CurrentControlSet\Control\Video\{GUID}\Video</td>
  	<td>Service</td>
  	<td>vm3dmp</td>
  </tr>
  <tr>
  	<td>HKLM\SYSTEM\CurrentControlSet\Control\Video\{GUID}\Video</td>
  	<td>Service</td>
  	<td>vmx_svga</td>
  </tr>
  <tr>
  	<td>HKLM\SYSTEM\CurrentControlSet\Control\Video\{GUID}\0000</td>
  	<td>Device Description</td>
  	<td>VMware SVGA*</td>
  </tr>
  <tr>
  	<th rowspan="1">Xen</th>
  	<td>HKLM\HARDWARE\Description\System\BIOS</td>
  	<td>SystemProductName</td>
  	<td>Xen</td>
  </tr>
</table>


<br />
<h3><a class="a-dummy" name="countermeasures">Countermeasures</a></h3>

Hook target functions and return appropriate results if indicators (registry strings from tables) are checked.

<br />
<h3><a class="a-dummy" name="credits">Credits</a></h3>

Credits go to open-source project from where code samples were taken: 
<ul>
<li>pafish project on <a href="https://github.com/a0rtega/pafish">github</a></li>
</ul>

Though Check Point tool InviZzzible has them all implemented, due to modular structure of the code it would require more space to show a code sample from this tool for the same purposes. That's why we've decided to use other great open-source projects for examples throughout the encyclopedia.

