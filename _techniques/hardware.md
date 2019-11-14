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
    <th>VMWare</th>
    <td>VMWare</td>
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
    <th>VMWare</th>
    <td>vmware</td>
  </tr>
</table>

<br />
<h3><a class="a-dummy" name="check-if-audio-device-is-absent">3. Check if audio device is absent</a></h3>

This technique was extracted from TeslaCrypt malware sample and is described <a href="https://github.com/a0rtega/pafish/issues/51">by this link</a>.

<hr class="space">

<b>Code sample</b>
<p></p>

{% highlight c %}

const wchar_t *filterName = L"random_name";

HRESULT hr = CoInitialize(NULL);
if (FAILED(hr))
    return;

IGraphBuilder *pGraph;
hr = CoCreateInstance(CLSID_FilterGraph, NULL, CLSCTX_INPROC_SERVER, IID_IGraphBuilder, (void**)& pGraph);
if (FAILED(hr))
    return;

if (E_POINTER != pGraph->AddFilter(NULL, filterName))
    ExitProcess(-1);

IBaseFilter *pBaseFilter;
hr = CoCreateInstance(CLSID_AudioRender, NULL, CLSCTX_INPROC_SERVER, IID_IBaseFilter, (void**)& pBaseFilter);
if (FAILED(hr))
    return;

pGraph->AddFilter(pBaseFilter, filterName);

IBaseFilter *pBaseFilter2;
pGraph->FindFilterByName(filterName, &pBaseFilter2);
if (NULL == pBaseFilter2)
    ExitProcess(-1);

FILTER_INFO info = { 0 };
pBaseFilter2->QueryFilterInfo(&info);
if (0 != wcscmp(info.achName, filterName))
    return;

IReferenceClock *pClock;
if (0 != pBaseFilter2->GetSyncSource(&pClock))
    return;

if (0 != pClock)
    return;

CLSID clsID;
pBaseFilter2->GetClassID(&clsID);
if (clsID.Data1 == 0)
    ExitProcess(1);

if (NULL == pBaseFilter2)
    ExitProcess(-1);

IEnumPins *pEnum = NULL;
if (0 != pBaseFilter2->EnumPins(&pEnum))
    ExitProcess(-1);

if (0 == pBaseFilter2->AddRef())
    ExitProcess(-1);

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
<h3><a class="a-dummy" name="signature-recommendations">Signature recommendations</a></h3>

<i>Signature recommendations are general for each technique: hook the function used and track if it is called. It's pretty hard to tell why application wants to get HDD name, for example. It doesn't necessarily mean applying evasion technique. So the best what can be done in this situation is intercepting target functions and tracking their calls.</i>

<br />
<h3><a class="a-dummy" name="countermeasures-sandboxie">Countermeasures</a></h3>

<ul>
<li><tt>versus HDD checks:</tt> rename HDD so that it's not detected by specific strings;</li> 
<li><tt>versus audio device check:</tt> add audio device;</li> 
<li><tt>versus CPU temperature check:</tt> add stub to hypervisor to output some meaningful information.</li> 
</ul>

