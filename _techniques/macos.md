---
layout: post
title:  "Evasions: macOS"
title-image: "/assets/icons/macos.svg"
categories: evasions 
tags: macos
---

<h1>Contents</h1>

[macOS sandbox detection methods](#macos-sandbox-methods)
<br />
  [1. Hardware model detection method](#hardware-model)
<br />
  [2. Check if hyperthreading is enabled](#hyperthreading-enabled)
<br />
  [3. Memory size detection method](#memory-size)
<br />
  [4. I/O Kit Registry detection method](#iokit-registry)
<br />
  [5. Boot ROM Version detection method](#boot-rom)
<br />
  [6. Check if System Integrity Protection is enabled](#sip)
<br />
  [Signature recommendations](#signature-recommendations)
<br />
  [Countermeasures](#countermeasures)
<br />
<br />

<hr class="space">

<h2><a class="a-dummy" name="macos-sandbox-methods">macOS sandbox detection methods</a></h2>
Most macOS-specific methods for sandbox and virtual environment detection are based on using shell commands such as 
"sysctl" and "ioreg".
Instead of providing code sample blocks, we show the commands and their arguments.
Unfortunately, we can't collect command outputs for various hypervisors due to Apple software licensing policy.
Therefore, we compare the command outputs for physical and virtual machines when possible.

<br />
<h3><a class="a-dummy" name="hardware-model">1. Hardware model detection method</a></h3>
The command used:
<br />
{% highlight shell %}
sysctl -n hw.model
{% endhighlight %}
If running on native Apple hardware, the returned value contains the model name of the hardware:
{% highlight shell %}
$ sysctl -n hw.model
Macmini8,1
{% endhighlight %}
On virtualized hardware, the value may contain the hypervisor name:
{% highlight shell %}
$ sysctl -n hw.model
VMware7,0
{% endhighlight %}
<p>This technique was seen in the <a href="https://macos.checkpoint.com/families/MacRansom/">MacRansom</a> malware.
If the command output doesn't contain the "Mac" substring, the malware considers that it is running in 
a virtual machine.</p>
<br />

<h3><a class="a-dummy" name="hyperthreading-enabled">2. Check if hyperthreading is enabled</a></h3>
Most Apple hardware (MacBook, Mac mini) released before 2018 came with hyperthreading enabled. 
This means that the number of physical cores is equal to half the of logical cores.
However, some hypervisors don't provide an ability to change the number of logical cores, which is always
equal to the number of physical cores.
<p>The command used:</p>
{% highlight shell %}
echo $((`sysctl -n hw.logicalcpu`/`sysctl -n hw.physicalcpu`))
{% endhighlight %}
<p>On physical hardware, the output value of the command must be equal to "2".
This techinique was seen in the <a href="https://macos.checkpoint.com/families/MacRansom/">MacRansom</a> malware.</p>
<p>We should note that new hardware comes with hyperthreading disabled, for example, Mac mini with 6‑core Intel 
Core i7 CPU. Therefore, this method should be considered outdated.</p>
<br />


<h3><a class="a-dummy" name="memory-size">3. Memory size detection method</a></h3>
This method is similar to the <a href="/techniques/generic-os-queries.html#check-if-total-ram-is-low">
memory size detection method used for PC</a>. 
When running several virtual machines, each VM is allocated a small amount of RAM,
whereas Apple physical hardware usually have more than 4 Gb RAM.
<p>The command used:</p>
{% highlight shell %}
sysctl -n hw.memsize
{% endhighlight %}
The command returns the RAM size in bytes, for example: 17179869184.
<br />


<h3><a class="a-dummy" name="iokit-registry">4. I/O Kit Registry detection method</a></h3>
<p>There are several ways in which virtual machine can be detected using the I/O Kit Registry.</p>
<br/>

<h4>Checking the <tt>"IOPlatformExpertDevice"</tt> registry class</h4>
<p>The command used:</p>
{% highlight shell %}
ioreg -rd1 -c IOPlatformExpertDevice
{% endhighlight %}
The following fields of the IOPlatformExpertDevice class can be checked in order to detect a virtual machine:
<br />

<table style="width:100%">
  <tr>
  	<th style="text-align:center">Field</th>
  	<th style="text-align:center">Physical hardware example value&nbsp;</th>
  	<th style="text-align:center">Virtual machine example value&nbsp;</th>
  	<th style="text-align:center">VM detection rule&nbsp;</th>
  </tr>
  <tr>
  	<th style="text-align:center">IOPlatformSerialNumber</th>
  	<th style="text-align:center">"C07T40BYG1J2"</th>
  	<th style="text-align:center">"0"</th>
  	<th style="text-align:center">Equal to "0"</th>
  </tr>
  <tr>
  	<th style="text-align:center">board-id</th>
  	<th style="text-align:center">&lt;"Mac-87C4F04823D6BACF"&gt;</th>
  	<th style="text-align:center">&lt;"VirtualBox"&gt;</th>
  	<th style="text-align:center">Contains "VirtualBox", "VMware", etc.</th>
  </tr>
  <tr>
  	<th style="text-align:center">manufacturer</th>
  	<th style="text-align:center">&lt;"Apple Inc."&gt;</th>
  	<th style="text-align:center">&lt;"innotek GmbH"&gt;</th>
  	<th style="text-align:center">Doesn't contain "Apple"</th>
  </tr>
</table>
<br />

<h4><b>Checking USB device vendor names</b></h4>
<p>The commands used:</p>
{% highlight shell %}
ioreg -rd1 -c IOUSBHostDevice | grep "USB Vendor Name"
{% endhighlight %}
Sample output on native Apple hardware:
{% highlight shell %}
$ ioreg -rd1 -c IOUSBHostDevice | grep "USB Vendor Name"
    "USB Vendor Name" = "Apple Inc."
    "USB Vendor Name" = "Apple Inc."
    "USB Vendor Name" = "Apple, Inc."
{% endhighlight %}
On virtualized hardware, the value may contain the hypervisor name:
{% highlight shell %}
$ ioreg -rd1 -c IOUSBHostDevice | grep "USB Vendor Name"
    "USB Vendor Name" = "VirtualBox"
    "USB Vendor Name" = "VirtualBox"
{% endhighlight %}
<p>A virtual machine can be detected by checking if the command output contains a hypervisor name, for example "VirtualBox",
"VMware", etc.</p>
<br />
Another option is to call the <tt>ioreg</tt> command with the "<tt>-l</tt>" option which makes it show properties for all objects.
The output should be checked against known hypervisor names, for example:
{% highlight shell %}
ioreg -l | grep -i -c -e "virtualbox" -e "oracle" -e "vmware"
{% endhighlight %}
The above command counts the number of occurrences of various hypervisor names in the <tt>ioreg</tt> output.
If the number of occurrences is greater than 0, the system is likely virtualized.

<br />
<h3><a class="a-dummy" name="boot-rom">5. Boot ROM Version detection method</a></h3>
The command used:
{% highlight shell %}
system_profiler SPHardwareDataType | grep "Boot ROM Version"
{% endhighlight %}
If running on native Apple hardware, the returned value contains the letter code for the corresponding Apple product,
for example, "MM" for Mac mini, "MBP" for MacBook Pro, "MBA" for MacBook Air: 
{% highlight shell %}
$ system_profiler SPHardwareDataType | grep "Boot ROM Version"
        Boot ROM Version: MM71.0232.B00
{% endhighlight %}
If running on a virtual machine, the returned value may contain the hypervisor name:
{% highlight shell %}
$ system_profiler SPHardwareDataType | grep "Boot ROM Version"
        Boot ROM Version: VirtualBox
{% endhighlight %}

This method is implemented in <a href="https://macos.checkpoint.com/families/OceanLotus/">OceanLotus</a> malware, as shown below: 
{% highlight shell %}
system_profiler SPHardwareDataType 2>/dev/null | awk '/Boot ROM Version/ {split($0, line, ":");printf("%s", line[2]);}' 2>/dev/null
{% endhighlight %}
<br />

<h3><a class="a-dummy" name="sip">6. Check if System Integrity Protection is enabled</a></h3>
<p>The latest versions of macOS have the <a href="https://en.wikipedia.org/wiki/System_Integrity_Protection">System Integrity Protection</a> feature (SIP).
If a sandbox uses a non-signed kernel extension for monitoring purposes the, SIP feature must be disabled to load this kind of kernel extension.
Malware may check if the SIP is enabled.</p>
The command used:
{% highlight shell %}
csrutil status
{% endhighlight %}
The command returns the SIP status, for example: "<tt>System Integrity Protection status: enabled.</tt>"
<br />

<h3><a class="a-dummy" name="signature-recommendations">Signature recommendations</a></h3>
There is a kind of trade-off between the number of detected evasion techniques and the false-positive rate.
If we want to detect as many as possible attempts to use the evasion techniques, we should use signatures with a broad scope.
If a process is created with one of the following command lines, this indicates an application is trying to use an evasion technique:
{% highlight shell %}
sysctl -n hw.model
sysctl -n hw.logicalcpu
sysctl -n hw.physicalcpu
sysctl -n hw.memsize
ioreg -rd1 -c IOPlatformExpertDevice
ioreg -rd1 -c IOUSBHostDevice
ioreg -l
system_profiler SPHardwareDataType
csrutil status
{% endhighlight %}
However, the commands mentioned above can be used both to perform evasion techniques and for system information gathering.
To reduce the rate of false-positive detections, malware-specific signatures can be used, for example:
{% highlight shell %}
echo $((`sysctl -n hw.logicalcpu`/`sysctl -n hw.physicalcpu`))
{% endhighlight %}
<br />

<h3><a class="a-dummy" name="countermeasures">Countermeasures</a></h3>
Apple software licensing policy doesn't allow emulating macOS on hardware other than the original Apple hardware. 
It is also doesn't not allow more than 2 virtual machines to run on one host machine.
Therefore, we suggest using solutions such as DeepFreeze instead of virtualization. In addition, signed kernel extensions should be used.