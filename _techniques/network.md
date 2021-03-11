---
layout: post
title:  "Evasions: Network"
title-image: "/assets/icons/network.svg"
categories: evasions 
tags: network
---

<h1>Contents</h1>

[Network detection methods used](#network-detection-methods)
<br />
  [1. Specific network properties](#check-specific-network-properties)
<br />
  [1.1. Check if MAC address is specific](#check-if-mac-address-is-specific)
<br />
  [1.2. Check if adapter name is specific](#check-if-adapter-name-is-specific)
<br />
  [1.3. Check if provider's name for network shares is specific](#check-if-provider-name-for-network-shares-is-specific)
<br />
  [2. Check if network belongs to security perimeter](#check-if-network-belongs-to-security-perimeter)
<br />
  [3. <tt>NetValidateName</tt> result based anti-emulation technique](#netvalidatename-result-based-anti-emulation-technique)
<br />
  [4. Cuckoo ResultServer connection based anti-emulation technique](#cuckoo-resultserver-connection-based-anti-emulation-technique)
<br />
  [Signature recommendations](#signature-recommendations)
<br />
  [Countermeasures](#countermeasures-sandboxie)
<br />
  [Credits](#credits)
<br />
<br />

<hr class="space">

<h2><a class="a-dummy" name="network-detection-methods">Network detection methods</a></h2>
Evasion techniques in this group are related to network in this or that sense. Either network-related functions are used or network parameters are checked — if they are different from that of usual host OS then virtual environment is likely detected.

<br />
<h3><a class="a-dummy" name="check-specific-network-properties">1. Specific network properties</a></h3>
Vendors of different virtual environments hard-code some values (MAC address) and names (network adapter) for their products — due to this fact such 
environments may be detected via checking properties of appropriate objects.

<br />
<h4><a class="a-dummy" name="check-if-mac-address-is-specific">1.1. Check if MAC address is specific</a></h4>

Functions used:
<ul>
  <li><tt>GetAdaptersAddresses(AF_UNSPEC, ...)</tt></li> 
  <li><tt>GetAdaptersInfo</tt></li> 
</ul>

<hr class="space">

<b>Code sample (function <tt>GetAdaptersAddresses</tt>)</b>
<p></p>

{% highlight c %}

int pafish_check_mac_vendor(char * mac_vendor) {
    unsigned long alist_size = 0, ret;
    ret = GetAdaptersAddresses(AF_UNSPEC, 0, 0, 0, &alist_size);

    if (ret == ERROR_BUFFER_OVERFLOW) {
        IP_ADAPTER_ADDRESSES* palist = (IP_ADAPTER_ADDRESSES*)LocalAlloc(LMEM_ZEROINIT,alist_size);
        void * palist_free = palist;

        if (palist) {
            GetAdaptersAddresses(AF_UNSPEC, 0, 0, palist, &alist_size);
            char mac[6]={0};
            while (palist){
                if (palist->PhysicalAddressLength == 0x6) {
                    memcpy(mac, palist->PhysicalAddress, 0x6);
                    if (!memcmp(mac_vendor, mac, 3)) {  /* First 3 bytes are the same */
                        LocalFree(palist_free);
                        return TRUE;
                    }
                }
                palist = palist->Next;
            }
            LocalFree(palist_free);
        }
    }

    return FALSE;
}

{% endhighlight %}

<i>Credits for this code sample: <a href="https://github.com/a0rtega/pafish">pafish project</a> </i>

<hr class="space">

<b>Code sample (function <tt>GetAdaptersInfo</tt>)</b>
<p></p>

{% highlight c %}

BOOL check_mac_addr(TCHAR* szMac)
{
    BOOL bResult = FALSE;
    PIP_ADAPTER_INFO pAdapterInfo;
    ULONG ulOutBufLen = sizeof (IP_ADAPTER_INFO); 
    pAdapterInfo = (PIP_ADAPTER_INFO) MALLOC(sizeof(IP_ADAPTER_INFO));

    if (pAdapterInfo == NULL)
    {
        _tprintf(_T("Error allocating memory needed to call GetAdaptersinfo.\n"));
        return -1;
    }

    // Make an initial call to GetAdaptersInfo to get the necessary size into the ulOutBufLen variable
    if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) 
    {
        FREE(pAdapterInfo);
        pAdapterInfo = (PIP_ADAPTER_INFO) MALLOC(ulOutBufLen);
        if (pAdapterInfo == NULL) {
            printf("Error allocating memory needed to call GetAdaptersinfo\n");
            return 1;
        }
    }

    // Now, we can call GetAdaptersInfo
    if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_SUCCESS)
    {
        // Convert the given mac address to an array of multibyte chars so we can compare.
        CHAR szMacMultiBytes [4];
        for (int i = 0; i < 4; i++) {
            szMacMultiBytes[i] = (CHAR)szMac[i];
        }
        while(pAdapterInfo)
        {
            if (pAdapterInfo->AddressLength == 6 && !memcmp(szMacMultiBytes, pAdapterInfo->Address, 3))
            {
                bResult = TRUE;
                break;
            }
            pAdapterInfo = pAdapterInfo->Next;
        }
    }

    return bResult;
}

{% endhighlight %}

<i>Credits for this code sample: <a href="https://github.com/LordNoteworthy/al-khaser">al-khaser project</a></i>

<hr class="space">

<b>Detections table</b>

<table style="width:60%">
  <tr>
    <td colspan="3">Check if MAC address starts from one of the following values:</td>
  </tr>
  <tr>
    <th style="text-align:center">Detect</th>
    <th style="text-align:center">MAC address starts with</th>
    <th style="text-align:center">Bytes</th>
  </tr>
  <tr>
    <th>Parallels</th>
    <td>00:1C:42</td>
    <td>\x00\x1C\x42</td>
  </tr>
  <tr>
    <th>VirtualBox</th>
    <td>08:00:27</td>
    <td>\x08\x00\x27</td>
  </tr>
  <tr>
    <th rowspan="4">VMware</th>
    <td>00:05:69</td>
    <td>\x00\x05\x69</td>
  </tr>
  <tr>
    <td>00:0C:29</td>
    <td>\x00\x0C\x29</td>
  </tr>
  <tr>
    <td>00:1C:14</td>
    <td>\x00\x1C\x14</td>
  </tr>
  <tr>
    <td>00:50:56</td>
    <td>\x00\x50\x56</td>
  </tr>
  <tr>
    <th>Xen</th>
    <td>00:16:E3</td>
    <td>\x00\x16\xE3</td>
  </tr>
</table>

<br />
<h4><a class="a-dummy" name="check-if-adapter-name-is-specific">1.2. Check if adapter name is specific</a></h4>

Functions used:
<ul>
  <li><tt>GetAdaptersAddresses(AF_UNSPEC, ...)</tt></li> 
  <li><tt>GetAdaptersInfo</tt></li> 
</ul>

<hr class="space">

<b>Code sample (function <tt>GetAdaptersAddresses</tt>)</b>
<p></p>

{% highlight c %}

int pafish_check_adapter_name(char * name) {
    unsigned long alist_size = 0, ret;
    wchar_t aux[1024];

    mbstowcs(aux, name, sizeof(aux)-sizeof(aux[0]));
    ret = GetAdaptersAddresses(AF_UNSPEC, 0, 0, 0, &alist_size);

    if (ret == ERROR_BUFFER_OVERFLOW) {
        IP_ADAPTER_ADDRESSES *palist = (IP_ADAPTER_ADDRESSES *)LocalAlloc(LMEM_ZEROINIT, alist_size);
        void * palist_free = palist;
        if (palist) {
            if (GetAdaptersAddresses(AF_UNSPEC, 0, 0, palist, &alist_size) == ERROR_SUCCESS) {
                while (palist) {
                    if (wcsstr(palist->Description, aux)) {
                        LocalFree(palist_free);
                        return TRUE;
                    }
                    palist = palist->Next;
                }
            }
            LocalFree(palist_free);
        }
    }

    return FALSE;
}

{% endhighlight %}

<i>Credits for this code sample: <a href="https://github.com/a0rtega/pafish">pafish project</a> </i>

<hr class="space">

<b>Code sample (function <tt>GetAdaptersInfo</tt>)</b>
<p></p>

{% highlight c %}

BOOL check_adapter_name(TCHAR* szName)
{
    BOOL bResult = FALSE;
    PIP_ADAPTER_INFO pAdapterInfo;
    ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);
    pAdapterInfo = (PIP_ADAPTER_INFO)MALLOC(sizeof(IP_ADAPTER_INFO));

    if (pAdapterInfo == NULL)
    {
        _tprintf(_T("Error allocating memory needed to call GetAdaptersinfo.\n"));
        return -1;
    }

    // Make an initial call to GetAdaptersInfo to get the necessary size into the ulOutBufLen variable
    if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW)
    {
        FREE(pAdapterInfo);
        pAdapterInfo = (PIP_ADAPTER_INFO)MALLOC(ulOutBufLen);
        if (pAdapterInfo == NULL) {
            printf("Error allocating memory needed to call GetAdaptersinfo\n");
            return 1;
        }
    }

    if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_SUCCESS)
    {
        while (pAdapterInfo)
        {
            if (StrCmpI(ascii_to_wide_str(pAdapterInfo->Description), szName) == 0)
            {
                bResult = TRUE;
                break;
            }
            pAdapterInfo = pAdapterInfo->Next;
        }
    }

    return bResult;
}

{% endhighlight %}

<i>Credits for this code sample: <a href="https://github.com/LordNoteworthy/al-khaser">al-khaser project</a></i>

<hr class="space">

<b>Detections table</b>

<table style="width:60%">
  <tr>
    <td colspan="2">Check adapter name to be the following:</td>
  </tr>
  <tr>
    <th style="text-align:center">Detect</th>
    <th style="text-align:center">Name</th>
  </tr>
  <tr>
    <th>VMware</th>
    <td>Vmware</td>
  </tr>
</table>

<br />
<h4><a class="a-dummy" name="check-if-provider-name-for-network-shares-is-specific">1.3. Check if provider's name for network shares is specific</a></h4>

Functions used (see note about native functions):
<ul>
  <li><tt>WNetGetProviderName(WNNC_NET_RDR2SAMPLE, ...)</tt></li> 
</ul>

<hr class="space">

<b>Code sample</b>
<p></p>

{% highlight c %}

int vbox_network_share() {
    unsigned long pnsize = 0x1000;
    char provider[pnsize];

    int retv = WNetGetProviderName(WNNC_NET_RDR2SAMPLE, provider, &pnsize);
    if (retv == NO_ERROR) {
        if (lstrcmpi(provider, "VirtualBox Shared Folders") == 0)
            return TRUE;
        else
            return FALSE;
    }

    return FALSE;
}

{% endhighlight %}

<i>Credits for this code sample: <a href="https://github.com/a0rtega/pafish">pafish project</a> </i>

<hr class="space">

<b>Detections table</b>

<table style="width:60%">
  <tr>
    <td colspan="2">Check provider's name for network shares to be the following:</td>
  </tr>
  <tr>
    <th style="text-align:center">Detect</th>
    <th style="text-align:center">Name</th>
  </tr>
  <tr>
    <th>VirtualBox</th>
    <td>VirtualBox Shared Folders</td>
  </tr>
</table>

<br />
<h3><a class="a-dummy" name="check-if-network-belongs-to-security-perimeter">2. Check if network belongs to security perimeter</a></h3>

Malware makes a request to <ins><tt>https[:]//www.maxmind.com/geoip/v2.1/city/me</tt></ins> which normally requires some kind of authentication or API key. To get around this requirement, the malware makes the request look as if it’s coming from the site itself by setting the HTTP Referrer to <ins><tt>https[:]//www.maxmind.com/en/locate-my-ip-address</tt></ins> and User-Agent to <em><tt>Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)</tt></em>. This trick allows the sample to retrieve the information about IP address of the machine it's running on.
<br />
<br />
The response is returned in JSON format and contains information about the country, city, and, most importantly, the organization associated with the IP address. If some "bad" strings are found in the response, malware knows that it's launched inside some kind of a security perimeter/organization.

<br />

<b>Examples</b>
<ul>
  <li><a href="https://www.sentinelone.com/blog/anti-vm-tricks/">anti VM tricks</a></li> 
  <li>malicious macros add sandbox evasion techniques to distribute <a href="https://www.proofpoint.com/us/threat-insight/post/malicious-macros-add-to-sandbox-evasion-techniques-to-distribute-new-dridex">new Dridex</a></li> 
  <li>malicious <a href="https://www.zscaler.com/blogs/research/malicious-documents-leveraging-new-anti-vm-anti-sandbox-techniques">documents with macros</a> evading automated analysis systems</li> 
</ul>

<hr class="space">

<b>"Bad strings" from malware sample (fixed capitalization):</b>
<p></p>

{% highlight c %}
Amazon
anonymous
BitDefender
BlackOakComputers
Blue Coat
BlueCoat
Cisco
cloud
Data Center
DataCenter
DataCentre
dedicated
ESET, Spol
FireEye
ForcePoint
Fortinet
Hetzner
hispeed.ch
hosted
Hosting
Iron Port
IronPort
LeaseWeb
MessageLabs
Microsoft
MimeCast
NForce
Ovh Sas
Palo Alto
ProofPoint
Rackspace
security
Server
Strong Technologies
Trend Micro
TrendMicro
TrustWave
VMVault
Zscaler
{% endhighlight %}

<br />
<h3><a class="a-dummy" name="netvalidatename-result-based-anti-emulation-technique">3. <tt>NetValidateName</tt> result based anti-emulation technique</a></h3>

<i>Initially this technique was designed for bypassing AV detection. It's not an evasion technique itself — instead it abuses interesting side-effects after the function is called.</i>
<br />
<br />
The main idea is to use the determined result of <tt>NetValidateName</tt> API function call with invalid argument as Server name (for example "123") for calculating jump address dynamically. This jump usually points into the middle of some instruction to bypass heuristic analysis of AV software. But this technique also has (at least) one side-effect.
<br />
<br />
If default NetBIOS settings are set in the operating system (NetBIOS over TCP/IP is enabled) the return code is always equal to <tt>ERROR_BAD_NETPATH (0x35)</tt>.
<br />
If NetBIOS over TCP/IP is switched off then return code is <tt>ERROR_NETWORK_UNREACHABLE (0x4CF)</tt>.
<br />
<br />
Thus jump address will be calculated incorrectly and it will lead the sample to crash. Therefore, this technique can be used to break emulation in sandboxes where NetBIOS over TCP/IP is switched off for preventing junk traffic generation by the OS.
<br />
<br />
<i>Note: NetBIOS over TCP/IP is switched off not to generate additional network requests when resolving server IP via DNS. Switching this option off cancels 
lookup requests in local network.</i>

<hr class="space">

<b>Code sample (function <tt>GetAdaptersAddresses</tt>)</b>
<p></p>

{% highlight c %}

void EntryPoint(void)
{
    HANDLE NetApi32 = LoadLibraryW(L"netapi32.dll");
    TD_NetValidateName NetValidateName = (TD_NetValidateName)GetProcAddress(NetApi32, "NetValidateName");
    DWORD Result = NetValidateName(L"123", L"", L"", L"", 1);

    __asm
    {
        call dword ptr ds:[GetLastError]
        add eax, offset TrueEntryPoint
        sub eax, 0xCB  // ERROR_ENVVAR_NOT_FOUND
        call eax
    }
}

{% endhighlight %}

<br />
<h3><a class="a-dummy" name="cuckoo-resultserver-connection-based-anti-emulation-technique">4. Cuckoo ResultServer connection based anti-emulation technique</a></h3>

This technique can be used for detecting Cuckoo Sandbox virtual environment. Malware enumerates all established outgoing TCP connections and checks 
if there is a connection to a specific TCP port (2042) that is used by the Cuckoo ResultServer.

<br />
<h3><a class="a-dummy" name="signature-recommendations">Signature recommendations</a></h3>

<i>Signature recommendations are general for each technique: hook the function used and track if it is called. It's pretty hard to tell why application wants to get adapter name, for example. It doesn't necessarily mean applying evasion technique. So the best what can be done in this situation is intercepting target functions and tracking their calls.
</i>

<br />
<h3><a class="a-dummy" name="countermeasures-sandboxie">Countermeasures</a></h3>

<ul>
<li><tt>versus checking network parameters:</tt> change them for virtual environment;</li> 
<li><tt>versus checking security perimeter:</tt> emulate network responses in an appropriate manner;</li> 
<li><tt>versus NetValidateName result based technique:</tt> turn on NetBIOS over TCP/IP;</li> 
<li><tt>versus Cuckoo ResultServer connection based technique:</tt> change ResultServer port in the Cuckoo configuration.</li> 
</ul>

<br />
<h3><a class="a-dummy" name="credits">Credits</a></h3>

Credits go to open-source project from where code samples were taken: 
<ul>
<li>pafish project on <a href="https://github.com/a0rtega/pafish">github</a></li>
<li>al-khaser project on <a href="https://github.com/LordNoteworthy/al-khaser">github</a></li>
</ul>

Though Check Point tool InviZzzible has them all implemented, due to modular structure of the code it would require more space to show a code sample from this tool for the same purposes. That's why we've decided to use other great open-source projects for examples throughout the encyclopedia.

