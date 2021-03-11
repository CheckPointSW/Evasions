---
layout: post
title:  "Evasions: CPU"
title-image: "/assets/icons/cpu.svg"
categories: evasions 
tags: cpu
---

<h1>Contents</h1>

[CPU detection methods used](#cpu-detection-methods)
<br />
  [1. Check vendor ID string via CPUID instruction](#check-vendor-id-via-cpuid)
<br />
  [2. Check if being run in Hypervisor via CPUID instruction](#check-if-being-run-in-Hypervisor-via-cpuid)
<br />
  [3. Check for global tables location: IDT/GDT/LDT](#check-for-global-tables-location)
<br />
  [4. Using exotic instructions to fool virtual emulators](#using-exotic-instructions-to-fool-virtual-emulators)
<br />
  [5. Detecting environment via execution of illegal instructions (VirtualPC only)](#detecting-environment-via-illegal-instructions-virtualpc)
<br />
  [6. Detecting environment via IN instruction - backdoor port (VMware only)](#detecting-environment-via-in-backdoor-port-vmware)
<br />
  [Signature recommendations](#signature-recommendations)
<br />
  [Countermeasures](#countermeasures-sandboxie)
<br />
  [Credits](#credits)
<br />
<br />

<hr class="space">

<h2><a class="a-dummy" name="cpu-detection-methods">CPU detection methods used</a></h2>
Techniques in this group use specific processor instructions to either get particular information about CPU — or execute predefined instruction sequence which behaves differently in usual host OS and in virtual environment.

<br />
<h3><a class="a-dummy" name="check-vendor-id-via-cpuid">1. Check vendor ID string via CPUID instruction</a></h3>
The <a href="https://x86.renejeschke.de/html/file_module_x86_id_45.html">CPUID</a> instruction is an instruction that returns processor identification and feature information to <tt>EBX, ECX, EDX</tt>. The information received to these registers can be used to identify a vendor.

<hr class="space">

<b>Code sample</b>
<p></p>

{% highlight c %}

__declspec(naked) void get_cpuid_vendor(char *vendor_id) {
  __asm {        
    ; save non-volatile register
    push ebx
    
    ; nullify output registers
    xor ebx, ebx
    xor ecx, ecx
    xor edx, edx
    
    ; call cpuid with argument in EAX
    mov eax, 0x40000000
    cpuid
    
    ; store vendor_id ptr to destination
    mov edi, vendor_id
    
    ; move string parts to destination
    mov eax, ebx  ; part 1 of 3 from EBX
    stosd
    mov eax, ecx  ; part 2 of 3 from ECX
    stosd
    mov eax, edx  ; part 3 of 3 from EDX
    stosd
    
    ; restore saved non-volatile register
    pop ebx 
    
    ; return from function
    retn
  }
}

{% endhighlight %}

<hr class="space">

<b>Detections table</b>

<table style="width:70%">
  <tr>
    <td colspan="3">Check vendor ID string via CPUID instruction - returned in parts in EBX, ECX, EDX:</td>
  </tr>
  <tr>
    <th style="text-align:center">Detect</th>
    <th style="text-align:center">EAX as argument to CPUID</th>
    <th style="text-align:center">String</th>
  </tr>
  <tr>
    <th>FreeBSD HV</th>
    <td>0x40000000</td>
    <td>bhyve bhyve</td>
  </tr>
  <tr>
    <th>Hyper-V</th>
    <td>0x40000000</td>
    <td>Microsoft Hv</td>
  </tr>
  <tr>
    <th>KVM</th>
    <td>0x40000000</td>
    <td>KVMKVMKVM</td>
  </tr>
  <tr>
    <th>Parallels</th>
    <td>0x40000000</td>
    <td>prl hyperv</td>
  </tr>
  <tr>
    <th>VirtualBox</th>
    <td>0x40000000</td>
    <td>VBoxVBoxVBox</td>
  </tr>
  <tr>
    <th>VirtualPC</th>
    <td>0x40000000</td>
    <td>Microsoft Hv</td>
  </tr>
  <tr>
    <th>VMware</th>
    <td>0x40000000</td>
    <td>VMwareVMware</td>
  </tr>
  <tr>
    <th>Xen</th>
    <td>0x40000000</td>
    <td>XenVMMXenVMM</td>
  </tr>
</table>

<br />
<h3><a class="a-dummy" name="check-if-being-run-in-Hypervisor-via-cpuid">2. Check if being run in Hypervisor via CPUID instruction</a></h3>

An other way to detect if the program is being run in hypervisor is using the <tt>CPUID</tt> instruction in an other way.
<br />
<br />
Instead of setting <tt>EAX</tt> (the argument to <tt>CPUID</tt>) to be <tt>0x40000000</tt>, <tt>EAX</tt> is set to 1. 
<br />
<br />
When <tt>EAX</tt> is set to 1, the 31st bit in <tt>ECX</tt> (<tt>CPUID</tt>'s returned value) is set, it indicates that the program is being run in Hypervisor.

<hr class="space">

<b>Code sample (function <tt>GetAdaptersAddresses</tt>)</b>
<p></p>

{% highlight c %}

__declspec(naked) bool is_run_in_hypervisor() {
  __asm {
    ; nullify output register
    xor ecx, ecx
    
    ; call cpuid with argument in EAX
    mov eax, 1
    cpuid
    
    ; set CF equal to 31st bit in ECX
    bt ecx, 31
    
    ; set AL to the value of CF
    setc al
    
    ; return from function
    retn
  }
}

{% endhighlight %}

<hr class="space">

<b>Detections table</b>

<table style="width:70%">
  <tr>
    <td colspan="3">Check if being run in Hypervisor (via CPUID)</td>
  </tr>
  <tr>
    <th style="text-align:center">Detect</th>
    <th style="text-align:center">EAX as argument to CPUID</th>
    <th style="text-align:center">Check of return value</th>
  </tr>
  <tr>
    <th>Hypervisor</th>
    <td>1</td>
    <td>31st bit in ECX - set if run in Hypervisor</td>
  </tr>
</table>

<br />
<h3><a class="a-dummy" name="check-for-global-tables-location">3. Check for global tables location: IDT/GDT/LDT</a></h3>

<i>
This technique doesn't work on latest VMware releases (all Windows releases affected). However, it is described here for the sake of completeness.
</i>
<br />
<br />

This trick involves looking at  the pointers to critical operating system tables that are typically relocated on a virtual machine. It's what called "Red Pill" and was <a href="http://web.archive.org/web/20070325211649/http://www.invisiblethings.org/papers/redpill.html">first introduced</a> by Joanna Rutkowska.
<br />
<br />
There is one Local Descriptor Table Register (LDTR), one Global Descriptor Table Register (GDTR), and one Interrupt Descriptor Table Register (IDTR) per CPU. They have to be moved to a different location when a guest operating system is running to avoid conflicts with the host.
<br />
<br />
On real machines the IDT, for example, is located lower in memory than it is on guest (i.e., virtual) machines.
<br />

<hr class="space">

<b>Code sample</b>
<p></p>

{% highlight c %}

idt_vm_detect = ((get_idt_base() >> 24) == 0xff);
ldt_vm_detect = (get_ldt_base() == 0xdead0000);
gdt_vm_detect = ((get_gdt_base >> 24) == 0xff);

// sidt instruction stores the contents of the IDT Register 
// (the IDTR which points to the IDT) in a processor register.
ULONG get_idt_base() {    
    UCHAR idtr[6];
#if defined (ENV32BIT)
    _asm sidt idtr
#endif
    return *((unsigned long *)&idtr[2]);
}

// sldt instruction stores the contents of the LDT Register 
// (the LDTR which points to the LDT) in a processor register.
ULONG get_ldt_base() {
    UCHAR ldtr[5] = "\xef\xbe\xad\xde";
#if defined (ENV32BIT)
    _asm sldt ldtr
#endif
    return *((unsigned long *)&ldtr[0]);
}

// sgdt instruction stores the contents of the GDT Register 
// (the GDTR which points to the GDT) in a processor register.
ULONG get_gdt_base() {
    UCHAR gdtr[6];
#if defined (ENV32BIT)
    _asm sgdt gdtr
#endif
    return gdt = *((unsigned long *)&gdtr[2]);
}

{% endhighlight %}

<i>Credits for this code sample: <a href="https://github.com/LordNoteworthy/al-khaser">al-khaser project</a></i>

<br />
<h3><a class="a-dummy" name="using-exotic-instructions-to-fool-virtual-emulators">4. Using exotic instructions to fool virtual emulators</a></h3>

This technique is described <a href="https://www.slideshare.net/Cyphort/mmw-antisandbox-techniques">by this link</a> (slide #37).
<br />
<br />
MMX instructions may be used as random instructions by malware. Sometimes such subsets of CPU instruction are not supported by emulators and thus exception is thrown instead of performing analysis.

<hr class="space">

<b>Example:</b>
<p></p>

<div style="text-align: center">
  <img src="{{site.baseurl}}/assets/images/mmx_anti_sb.png">
</div>

<br />
<h3><a class="a-dummy" name="detecting-environment-via-illegal-instructions-virtualpc">5. Detecting environment via execution of illegal instructions (VirtualPC only)</a></h3>

The malware executes illegal instructions, which should generate exception on the real CPU but are executed normally - or in some different way - in virtual environment.
<br />
<br />
Information about CPU exceptions is provided <a href="https://wiki.osdev.org/Exceptions#Invalid_Opcode">by this link</a>.

<hr class="space">

<b>Code sample (variant 1, generating #ud exception)</b>
<p></p>

{% highlight asm %}

push ebx
xor ebx, ebx
mov eax, 1
; the following 4 bytes below generate #ud exception
db 0x0F
db 0x3F
db 0x0D
db 0x00
test ebx, ebx
setz al
pop ebx

{% endhighlight %}

<hr class="space">

It should be emphasized that there are more than 1,000 combinations of 
{% highlight asm %}

0x0F
0x3F
0xXX
0xYY

{% endhighlight %}

bytes that may be used by malware in order to detect VirtualPC enviroment.

<hr class="space">

<b>Code sample (variant 2, executing illegal STI instruction)</b>
<p></p>

{% highlight c %}

// Taken here: https://pastebin.com/Nsv5B1yk
// http://waleedassar.blogspot.com
// http://www.twitter.com/waleedassar
// Use this code to detect if Windows XP is running inside Virtual PC 2007
#include "stdafx.h"
#include "windows.h"
#include "stdio.h"
 
#define CONTEXT_ALL 0x1003F
 
int dummy(int);
unsigned long gf=0;

int __cdecl Handler(EXCEPTION_RECORD* pRec,void* est,unsigned char* pContext,void* disp)
{
    if(pRec->ExceptionCode==0xC0000096)  //Privileged instruction
    {
        //---------------------Installing the trick--------------------------------------
        *(unsigned long*)(pContext)=CONTEXT_ALL;/*CONTEXT_DEBUG_REGISTERS|CONTEXT_FULL*/
        *(unsigned long*)(pContext+0x4)=(unsigned long)(&dummy);
        *(unsigned long*)(pContext+0x8)=(unsigned long)(&dummy);
        *(unsigned long*)(pContext+0xC)=(unsigned long)(&dummy);
        *(unsigned long*)(pContext+0x10)=(unsigned long)(&dummy);
        *(unsigned long*)(pContext+0x14)=0;
        *(unsigned long*)(pContext+0x18)=0x155; //Enable the four DRx On-Execute
        //---------------------------------------------------------------------------------
        (*(unsigned long*)(pContext+0xB8))++;
        return ExceptionContinueExecution;
    }
    else if(pRec->ExceptionCode==EXCEPTION_SINGLE_STEP)
    {
        if(gf==1)
        {
            MessageBox(0,"Expected behavior (XP)","waliedassar",0);
            ExitProcess(0);
        }
        gf++;
        (*(unsigned long*)(pContext+0xC0))|=0x00010000; //Set the RF (Resume Flag)
        return ExceptionContinueExecution;
    }
    return ExceptionContinueSearch;
}
 
int dummy(int x)
{
    x+=0x100;
    return x;
}
 
int main(int shitArg)
{
    unsigned long ver_=GetVersion();
    unsigned long major=ver_&0xFF;
    unsigned long minor=(ver_>>0x8)&0xFF;
    if(major==0x05 & minor==0x01) //Windows XP
    {
        unsigned long x=0;
        __asm
        {
            push offset Handler
            push dword ptr fs:[0x0]
            mov dword ptr fs:[0x0],esp
            STI; Triggers an exception(privileged instruction)
        }
        dummy(0xFF);
        __asm
        {
            pop dword ptr fs:[0x0]
            pop ebx
        }
        MessageBox(0,"Virtual PC 2007 detected (XP)","waliedassar",0);
    }
    return 0;
}


{% endhighlight %}

<hr class="space">

<b>Code sample (variant 3, resetting VirtualPC)</b>
<p></p>

{% highlight c %}

// Taken here: https://pastebin.com/exAK5XQx
// http://waleedassar.blogspot.com (@waleedassar)
// Executing "\x0F\xC7\xC8\x05\x00" in VirtualPC 2007 triggers a reset error.
#include "stdafx.h"
#include "windows.h"
#include "stdio.h"
 
bool flag=false;
 
int __cdecl Handler(EXCEPTION_RECORD* pRec,void* est,unsigned char* pContext,void* disp)
{
    if(pRec->ExceptionCode==0xC000001D  || pRec->ExceptionCode==0xC000001E || pRec->ExceptionCode==0xC0000005)
    {
        flag=true;
        (*(unsigned long*)(pContext+0xB8))+=5;
        return ExceptionContinueExecution;
    }
    return ExceptionContinueSearch;
}
 
int main(int argc, char* argv[])
{
    __asm
    {
        push offset Handler
        push dword ptr fs:[0x0]
        mov dword ptr fs:[0x0],esp
    }
    flag=false;
    __asm
    {
        __emit 0x0F
        __emit 0xC7
        __emit 0xC8
        __emit 0x05
        __emit 0x00
    }
    if(flag==false)
    {
        MessageBox(0,"VirtualPC detected","waliedassar",0);
    }
    __asm
    {
        pop dword ptr fs:[0x0]
        pop eax
    }
    return 0;
}

{% endhighlight %}

<br />
<h3><a class="a-dummy" name="detecting-environment-via-in-backdoor-port-vmware">6. Detecting environment via IN instruction - backdoor port (VMware only)</a></h3>

<a href="https://sites.google.com/site/chitchatvmback/backdoor">This article</a> explains why backdoor port communication is used in VMware in the first place.

<hr class="space">

<b>Code sample (variant 1)</b>
<p></p>

{% highlight c %}

bool VMWare::CheckHypervisorPort() const {
    bool is_vm = false;
    __try {
        __asm {
            push edx
            push ecx
            push ebx
            mov eax, 'VMXh'
            mov ebx, 0
            mov ecx, 10
            mov edx, 'VX'
            in eax, dx      // <- key point is here
            cmp ebx, 'VMXh'
            setz[is_vm]
            pop ebx
            pop ecx
            pop edx
        }
    } 
    __except (EXCEPTION_EXECUTE_HANDLER) {
        is_vm = false;
    }
    return is_vm;
}

{% endhighlight %}

<hr class="space">

<b>Code sample (variant 2)</b>
<p></p>

{% highlight c %}

bool VMWare::CheckHypervisorPortEnum() const {
    bool is_vm = false;
    short ioports[] = { 'VX' , 'VY' };
    short ioport;
    for (short i = 0; i < _countof(ioports); ++i) {
        ioport = ioports[i];
        for (unsigned char cmd = 0; cmd < 0x2c; ++cmd) {
            __try {
                __asm {
                    push eax
                    push ebx
                    push ecx
                    push edx
                    mov eax, 'VMXh'
                    movzx ecx, cmd
                    mov dx, ioport
                    in eax, dx      // <- key point is here
                    pop edx
                    pop ecx
                    pop ebx
                    pop eax
                }
                is_vm = true;
                break;
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {}
        }
        if (is_vm)
            break;
    }
    return is_vm;
}

{% endhighlight %}

<hr class="space">

<br />
<h3><a class="a-dummy" name="signature-recommendations">Signature recommendations</a></h3>

<i>No signature recommendations are provided for this evasion group as it's hard to track such a code being executed.</i>

<br />
<h3><a class="a-dummy" name="countermeasures-sandboxie">Countermeasures</a></h3>

Patch hypervisor. If it proves impossible — due to license issues or something else — patch VM config. Usually undocumented options help.

<ul>
<li>vs <tt>CPUID</tt> instruction: refer to <a href="http://vknowledge.net/2014/04/17/how-to-fake-a-vms-guest-os-cpuid/">this article</a> for the example of such a patch</li> 
<li>vs <tt>IN</tt> instruction (VMware backdoor): take a look at these <a href="https://wasm.in/threads/izmenenie-raboty-backdoor-interfejsa-v-vmware.24564/#post-291532">config changes</a></li> 
</ul>

<br />
<h3><a class="a-dummy" name="credits">Credits</a></h3>

Credits go to open-source project from where code samples were taken and to independent researcher who shared his findings:
<ul>
<li>al-khaser project on <a href="https://github.com/LordNoteworthy/al-khaser">github</a></li>
<li><a href="https://twitter.com/waleedassar">@waleedassar</a></li>
</ul>

Though Check Point tool InviZzzible has them all implemented, due to modular structure of the code it would require more space to show a code sample from this tool for the same purposes. That's why we've decided to use other great open-source projects for examples throughout the encyclopedia.
