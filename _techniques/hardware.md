---
layout: post
title:  "Evasions: Hardware"
title-image: "/assets/icons/hardware.svg"
categories: evasions 
tags: hardware
---

<h1>Contents</h1>

[Hardware info detection methods](#hardware-detection-methods)
<br />
  [1. Check if HDD has specific name](#check-if-hdd-has-specific-name)
<br />
  [2. Check if HDD Vendor ID has specific value](#check-if-hdd-vendor-id-has-specific-value)
<br />
  [3. Check if audio device is absent](#check-if-audio-device-is-absent)
<br />
  [4. Check if CPU temperature information if available](#check-if-cpu-temperature-information-is-available)
<br />
  [5. Check physical display adapter for IDirect3D9 interface](#check-directx-adapter)
<br />
  [Signature recommendations](#signature-recommendations)
<br />
  [Countermeasures](#countermeasures-sandboxie)
<br />
<br />

<hr class="space">

<h2><a class="a-dummy" name="hardware-detection-methods">Hardware info detection methods</a></h2>
Virtual environments emulate hardware devices and leave specific traces in their descriptions - which may be queried and the conclusion about non-host OS made.

<br />
<h3><a class="a-dummy" name="check-if-hdd-has-specific-name">1. Check if HDD has specific name</a></h3>

Functions used:
<ul>
  <li><tt>SetupDiGetClassDevs</tt></li> 
  <li><tt>SetupDiEnumDeviceInfo</tt></li> 
  <li><tt>SetupDiGetDeviceRegistryProperty</tt></li> 
</ul>

<hr class="space">

<b>Code sample</b>
<p></p>

{% highlight c %}

hDevs = SetupDiGetClassDevs(
    &guid,  // GUID_DEVCLASS(DEVINTERFACE)_DISKDRIVE
    NULL,
    NULL,
    DIGCF_PRESENT);

SetupDiEnumDeviceInfo(
    hDevsInfo,
    0,
    &devinfo);  // PSP_DEVINFO_DATA

SetupDiGetDeviceRegistryProperty(
    hDevs,
    &devinfo,
    SPDRP_FRIENDLYNAME,
    &dword_1,
    szFriendlyName,  // HDD name will be here
    dFriendlyNameSize,
    &dword_2);

{% endhighlight %}

<hr class="space">

<b>Detections table</b>

<table style="width:60%">
  <tr>
    <td colspan="2">Check if hard disk drive has one of the following names:</td>
  </tr>
  <tr>
    <th style="text-align:center">Detect</th>
    <th style="text-align:center">Name</th>
  </tr>
  <tr>
    <th>QEMU</th>
    <td>QEMU</td>
  </tr>
  <tr>
    <th>VirtualBox</th>
    <td>VBOX</td>
  </tr>
  <tr>
    <th>VirtualPC</th>
    <td>VIRTUAL HD</td>
  </tr>
  <tr>
    <th>VMware</th>
    <td>VMware</td>
  </tr>
</table>

<br />
<h3><a class="a-dummy" name="check-if-hdd-vendor-id-has-specific-value">2. Check if HDD Vendor ID has specific value</a></h3>

The following function is used:
<ul>
  <li><tt>DeviceIoControl(..., IOCTL_STORAGE_QUERY_PROPERTY, ...)</tt></li> 
</ul>

<hr class="space">

<b>Code sample</b>
<p></p>

{% highlight c %}

bool GetHDDVendorId(std::string& outVendorId) {
    HANDLE hDevice = CreateFileA(_T("\\\\.\\PhysicalDrive0"), 
                                 0, 
                                 FILE_SHARE_READ | FILE_SHARE_WRITE, 
                                 0, 
                                 OPEN_EXISTING, 
                                 0, 
                                 0);
    if (hDevice == INVALID_HANDLE_VALUE)
        return false;
    
    STORAGE_PROPERTY_QUERY storage_property_query = {};
    storage_property_query.PropertyId = StorageDeviceProperty;
    storage_property_query.QueryType = PropertyStandardQuery;
    STORAGE_DESCRIPTOR_HEADER storage_descriptor_header = {};
    DWORD BytesReturned = 0;
  
    if (!DeviceIoControl(hDevice, IOCTL_STORAGE_QUERY_PROPERTY, 
                         &storage_property_query, sizeof(storage_property_query), 
                         &storage_descriptor_header, sizeof(storage_descriptor_header), 
                         &BytesReturned, )) {
        printf("DeviceIoControl() for size query failed\n");
        CloseHandle(hDevice);
        return false;
    }
    if (!BytesReturned) {
        CloseHandle(hDevice);
        return false;
    }
  
    std::vector<char> buff(storage_descriptor_header.Size); //_STORAGE_DEVICE_DESCRIPTOR
    if (!DeviceIoControl(hDevice, IOCTL_STORAGE_QUERY_PROPERTY, 
                         &storage_property_query, sizeof(storage_property_query), 
                         buff.data(), buff.size(), 0)) {
        CloseHandle(hDevice);
        return false;
    }
  
    CloseHandle(hDevice);
  
    if (BytesReturned) {
        STORAGE_DEVICE_DESCRIPTOR* device_descriptor = (STORAGE_DEVICE_DESCRIPTOR*)buff.data();
        if (device_descriptor->VendorIdOffset)
            outVendorId = &buff[device_descriptor->VendorIdOffset];
  
        return true;
    }
    
    return false;
}
{% endhighlight %}

<hr class="space">

<b>Detections table</b>

<table style="width:60%">
  <tr>
    <td colspan="2">Check if HDD Vendor ID is one of the following:</td>
  </tr>
  <tr>
    <th style="text-align:center">Detect</th>
    <th style="text-align:center">Name</th>
  </tr>
  <tr>
    <th>VirtualBox</th>
    <td>VBOX</td>
  </tr>
  <tr>
    <th>VMware</th>
    <td>vmware</td>
  </tr>
</table>

<br />
<h3><a class="a-dummy" name="check-if-audio-device-is-absent">3. Check if audio device is absent</a></h3>

This technique was extracted from TeslaCrypt malware sample and was described <a href="https://www.joesecurity.org/blog/6933341622592617830">in this Joe Security blog post</a>.

<hr class="space">

<b>Code sample</b>
<p></p>

{% highlight c %}

void AudioEvasion() {
  PCWSTR wszfilterName = L"audio_device_random_name";

  if (FAILED(CoInitialize(NULL)))
    return;

  IGraphBuilder *pGraph = nullptr;
  if (FAILED(CoCreateInstance(CLSID_FilterGraph, NULL, CLSCTX_INPROC_SERVER, IID_IGraphBuilder, (void**)&pGraph)))
    return;

  if (E_POINTER != pGraph->AddFilter(NULL, wszfilterName))
    ExitProcess(-1);

  IBaseFilter *pBaseFilter = nullptr;
  CoCreateInstance(CLSID_AudioRender, NULL, CLSCTX_INPROC_SERVER, IID_IBaseFilter, (void**)&pBaseFilter);
  
  pGraph->AddFilter(pBaseFilter, wszfilterName);

  IBaseFilter *pBaseFilter2 = nullptr;
  pGraph->FindFilterByName(wszfilterName, &pBaseFilter2);
  if (nullptr == pBaseFilter2)
    ExitProcess(1);

  FILTER_INFO info = { 0 };
  pBaseFilter2->QueryFilterInfo(&info);
  if (0 != wcscmp(info.achName, wszfilterName))
    return;

  IReferenceClock *pClock = nullptr;
  if (0 != pBaseFilter2->GetSyncSource(&pClock))
    return;
  if (0 != pClock)
    return;

  CLSID clsID = { 0 };
  pBaseFilter2->GetClassID(&clsID);
  if (clsID.Data1 == 0)
    ExitProcess(1);

  if (nullptr == pBaseFilter2)
    ExitProcess(-1);

  IEnumPins *pEnum = nullptr;
  if (0 != pBaseFilter2->EnumPins(&pEnum))
    ExitProcess(-1);

  if (0 == pBaseFilter2->AddRef())
    ExitProcess(-1);
}

{% endhighlight %}

<br />
<h3><a class="a-dummy" name="check-if-cpu-temperature-information-is-available">4. Check if CPU temperature information is available</a></h3>

This technique was extracted from GravityRAT malware and is described <a href="https://blog.talosintelligence.com/2018/04/gravityrat-two-year-evolution-of-apt.html">by this link</a>.

<hr class="space">

<b>Code sample (Windows cmd command)</b>
<p></p>

{% highlight cm %}

wmic /namespace:\\root\WMI path MSAcpi_ThermalZoneTemperature get CurrentTemperature

{% endhighlight %}

<br />
<h3><a class="a-dummy" name="check-directx-adapter">5. Check physical display adapter for IDirect3D9 interface</a></h3>

This method checks physical display adapters present in the system when the IDirect3D9 interface was instantiated. It works on all Windows versions starting from Windows XP.

Functions used:
<ul>
<li><tt>Direct3DCreate9</tt> - called from <font face="Courier New">`d3d9.dll`</font> library</li>
<li><tt>GetAdapterIdentifier</tt> - called via <font face="Courier New">IDirect3D9</font> interface</li> 
</ul>

<hr class="space">

<b>Code sample</b>
<p></p>

{% highlight c %}

#include <d3d9.h>

// https://github.com/qt/qtbase/blob/dev/src/plugins/platforms/windows/qwindowsopengltester.cpp#L124

void detect() {
    typedef IDirect3D9* (WINAPI* PtrDirect3DCreate9)(UINT);

    HMODULE d3d9lib = ::LoadLibraryA("d3d9");
    if (!d3d9lib)
        return;

    PtrDirect3DCreate9 direct3DCreate9 = (PtrDirect3DCreate9)GetProcAddress(d3d9lib, "Direct3DCreate9");
    if (!direct3DCreate9)
        return;

    IDirect3D9* direct3D9 = direct3DCreate9(D3D_SDK_VERSION);
    if (!direct3D9)
        return;

    D3DADAPTER_IDENTIFIER9 adapterIdentifier;
    const HRESULT hr = direct3D9->GetAdapterIdentifier(0, 0, &adapterIdentifier);
    direct3D9->Release();

    if (SUCCEEDED(hr)) {
        printf("VendorId:    0x%x\n", adapterIdentifier.VendorId);
        printf("DeviceId:    0x%x\n", adapterIdentifier.DeviceId);
        printf("Driver:      %s\n", adapterIdentifier.Driver);
        printf("Description: %s\n", adapterIdentifier.Description);
    }
}

{% endhighlight %}

<i>Credits for this code sample go to <a href="https://gist.github.com/elsamuko/d3049d52ca235112c99ac3ee30282846">elsamuko</a> who pointed it out</i>.

<hr class="space">

Example of output on a usual host machine is provided below:

{% highlight cm %}

VendorId:    0x10de
DeviceId:    0x103c
Driver:      nvldumdx.dll
Description: NVIDIA Quadro K5200

{% endhighlight %}

And here is an example of output on a virtual machine (VMware):

{% highlight cm %}

VendorId:    0x15ad
DeviceId:    0x405
Driver:      vm3dum64_loader.dll
Description: VMware SVGA 3D

{% endhighlight %}

Examined fields are named after the corresponding fields of <font face="Courier New">D3DADAPTER_IDENTIFIER9</font> structure. Malware can compare values in these fields to the ones which are known to be present inside the virtual machine and if match is found, then it draws the conclusion that it’s run under virtual machine.

<b>Detections table</b>

<table style="width:100%">
  <tr>
  	<td colspan="4">Check if the following values are present in the fields of D3DADAPTER_IDENTIFIER9 structure:</td>
  </tr>
  <tr>
  	<th style="text-align:center">Detect</th>
  	<th style="text-align:center">Structure field</th>
    <th style="text-align:center">Value</th>
    <th style="text-align:center">Comment</th>
  </tr>
  <tr>
  	<th rowspan="5">VMware</th>
  	<td>VendorId</td>
    <td>0x15AD</td>
    <td></td>
  </tr>
  <tr>
  	<td>DeviceId</td>
    <td>0x405</td>
    <td>Only when used in combination with VendorId related to VMware (0x15AD)</td>
  </tr>
  <tr>
  	<td>Driver</td>
    <td>vm3dum.dll</td>
    <td></td>
  </tr>
  <tr>
    <td>Driver</td>
  	<td>vm3dum64_loader.dll</td>
    <td></td>
  </tr>
  <tr>
    <td>Description</td>
  	<td>VMware SVGA 3D</td>
    <td></td>
  </tr>
</table>

<br />
<h3><a class="a-dummy" name="signature-recommendations">Signature recommendations</a></h3>

<i>Signature recommendations are general for each technique: hook the function used and track if it is called. It's pretty hard to tell why application wants to get HDD name, for example. It doesn't necessarily mean applying evasion technique. So the best what can be done in this situation is intercepting target functions and tracking their calls.</i>

<br />
<h3><a class="a-dummy" name="countermeasures-sandboxie">Countermeasures</a></h3>

<ul>
<li><tt>versus HDD checks:</tt> rename HDD so that it's not detected by specific strings;</li> 
<li><tt>versus audio device check:</tt> add audio device;</li> 
<li><tt>versus CPU temperature check:</tt> add stub to hypervisor to output some meaningful information;</li>
<li><tt>versus physical display adapter check:</tt> set up hook on a function <font face="Courier New">GetAdapterIdentifier</font> from <font face="Courier New">d3d9.dll</font>, check if the queried adapter is related to DirectX and replace return values.</li> 
</ul>

