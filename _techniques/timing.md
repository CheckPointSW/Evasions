---
layout: post
title:  "Evasions: Timing"
title-image: "/assets/icons/timing.svg"
categories: evasions 
tags: timing
---

<h1>Contents</h1>

[Time-based sandbox evasion techniques](#time-based-sandbox-evasion-techniques)
<br />
  [1. Delayed execution](#delayed-execution)
<br />
  [1.1. Simple delaying operation](#simple-delaying-operation)
<br />
  [1.2. Deferred execution using Task Scheduler](#deferred-execution-using-task-scheduler)
<br />
  [1.3. No suspicious actions until reboot](#no-suspicious-actions-until-reboot)
<br />
  [1.4. Running only on certain dates](#running-only-on-certain-dates)
<br />
  [2. Sleep skipping detection](#sleep-skipping-detection)
<br />
  [2.1. Parallel delays using different methods](#parallel-delays)
<br />
  [2.2. Measure time intervals using different methods](#measure-time-intervals)
<br />
  [2.3. Get system time using different methods](#get-system-time)
<br />
  [2.4. Check if the delay value changes after calling a delay function](#delay-value-changed)
<br />
  [2.5. Use absolute timeout](#absolute-timeout)
<br />
  [2.6. Get time from another process](#get-time-another-process)
<br />
  [3. Get the current date and time from an external source (NTP, HTTP)](#get-time-ntp)
<br />
  [4. Difference in time measurement in VM and hosts](#difference-vm-hosts)
<br />
  [4.1. RDTSC (with CPUID to force a VM Exit)](#rdtsc)
<br />
  [4.2. RDTSC (Locky version with GetProcessHeap and CloseHandle)](#rdtsc-locky)
<br />
  [5. Check the system last boot time using different methods](#check-system-boot-time)
<br />
  [Countermeasures](#countermeasures)
<br />
[Credits](#credits)
<br />
<br />

<hr class="space">

<h2><a class="a-dummy" name="time-based-sandbox-evasion-techniques">Time-based sandbox evasion techniques</a></h2>
Sandbox emulation usually lasts a short time because sandboxes are heavy loaded with thousands of samples. Emulation
time rarely exceeds 3-5 minutes. Therefore, malware can use this fact to avoid detection: it may perform
long delays before starting any malicious activity.<br />
To counteract this, sandboxes may implement features which manipulate time and execution delays. For example, the Cuckoo 
sandbox has a sleep skipping feature that replaces delays with a very short value. This should force the malware to start 
its malicious activity before an analysis timeout.

<div style="text-align: center">
  <img src="/assets/images/sleep_skipping.png" />
</div>
<br />
However, this can also be used to detect a sandbox.<br />
There are also some differences in the time of execution of some instructions and API functions that
can be used to detect a virtual environment.
<p>
<i>Signature recommendations are not provided for this class of techniques as executing functions described in this 
chapter does not imply their usage for evasion purposes. It is hard to differentiate between the code which aims to 
perform an evasion code and the one which uses the same functions with non-evasion intentions. </i>
</p>

<br />
<h3><a class="a-dummy" name="delayed-execution">1. Delayed execution</a></h3>
Execution delays are used to avoid detection of malicious activity during the emulation time.
<br />
<h4><a class="a-dummy" name="simple-delaying-operation">1.1. Simple delaying operation</a></h4>
<p>Functions used:</p>
<ul>
<li><tt>Sleep, SleepEx, NtDelayExecution</tt></li>
<li><tt>WaitForSingleObject, WaitForSingleObjectEx, NtWaitForSingleObject</tt></li>
<li><tt>WaitForMultipleObjects, WaitForMultipleObjectsEx, NtWaitForMultipleObjects</tt></li>
<li><tt>SetTimer, SetWaitableTimer, CreateTimerQueueTimer</tt></li>
<li><tt>timeSetEvent</tt> (multimedia timers)</li>
<li><tt>IcmpSendEcho</tt></li>
<li><tt>select</tt> (Windows sockets)</li>
</ul>
While the use of most of these functions is obvious, we show examples of using the <tt>timeSetEvent</tt> function
from Multimedia API and the <tt>select</tt> function from the Windows sockets API.<br />
<br />
<b>Code sample (delay using the "select" function)</b>
{% highlight c %}
int iResult;
DWORD timeout = delay; // delay in milliseconds
DWORD OK = TRUE;

SOCKADDR_IN sa = { 0 };
SOCKET sock = INVALID_SOCKET;

// this code snippet should take around Timeout milliseconds
do {
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = inet_addr("8.8.8.8");    // we should have a route to this IP address
    sa.sin_port = htons(80); // we should not be able to connect to this port

    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        OK = FALSE;
        break;
    }

    // setting socket timeout
    unsigned long iMode = 1;
    iResult = ioctlsocket(sock, FIONBIO, &iMode);

    iResult = connect(sock, (SOCKADDR*)&sa, sizeof(sa));
    if (iResult == false) {
        OK = FALSE;
        break;
    }

    iMode = 0;
    iResult = ioctlsocket(sock, FIONBIO, &iMode);
    if (iResult != NO_ERROR) {
        OK = FALSE;
        break;
    }

    // fd set data
    fd_set Write, Err;
    FD_ZERO(&Write);
    FD_ZERO(&Err);
    FD_SET(sock, &Write);
    FD_SET(sock, &Err);
    timeval tv = { 0 };
    tv.tv_usec = timeout * 1000;

    // check if the socket is ready, this call should take Timeout milliseconds
    select(0, NULL, &Write, &Err, &tv);
    
    if (FD_ISSET(sock, &Err)) {
        OK = FALSE;
        break;
    }

} while (false);

if (sock != INVALID_SOCKET)
    closesocket(sock);
{% endhighlight %}
<br />
<b>Code sample (delay using the "timeSetEvent" function)</b>
{% highlight c %}
VOID CALLBACK TimerFunction(UINT uTimerID, UINT uMsg, DWORD_PTR dwUser, DWORD_PTR dw1, DWORD_PTR dw2)
{
    bProcessed = TRUE;
}

VOID timing_timeSetEvent(UINT delayInSeconds)
{
    // Some vars
    UINT uResolution;
    TIMECAPS tc;
    MMRESULT idEvent;

    // We can obtain this minimum value by calling
    timeGetDevCaps(&tc, sizeof(TIMECAPS));
    uResolution = min(max(tc.wPeriodMin, 0), tc.wPeriodMax);

    // Create the timer
    idEvent = timeSetEvent(
        delayInSeconds,
        uResolution,
        TimerFunction,
        0,
        TIME_ONESHOT);

    while (!bProcessed){
        // wait until our function finishes
        Sleep(0);
    }

    // destroy the timer
    timeKillEvent(idEvent);

    // reset the timer
    timeEndPeriod(uResolution);
}
{% endhighlight %}
<p><i>Credits for this code sample: <a href="https://github.com/LordNoteworthy/al-khaser">al-khaser project</a></i></p>
<br />
<h4><a class="a-dummy" name="deferred-execution-using-task-scheduler">1.2. Deferred execution using Task Scheduler</a></h4>
This method can be used both for delaying execution and evading sandbox tracking.
<br /><br />
<b>Code sample (PowerShell)</b>
{% highlight powershell %}
    $tm = (get-date).AddMinutes(10).ToString("HH:mm")
    $action = New-ScheduledTaskAction -Execute "some_malicious_app.exe"
    $trigger = New-ScheduledTaskTrigger -Once -At $tm
    Register-ScheduledTask TaskName -Action $action -Trigger $trigger
{% endhighlight %}
<br />
<h4><a class="a-dummy" name="no-suspicious-actions-until-reboot">1.3. No suspicious actions until reboot</a></h4>
The idea behind this technique is that a sandbox doesn't reboot a virtual machine during the emulation of a
malicious sample. The malware may just set up persistence using any of available methods and silently exit.
Malicious actions are performed only after the system is rebooted.

<h4><a class="a-dummy" name="running-only-on-certain-dates">1.4. Running only on certain dates</a></h4>
Malware samples may check the current date and perform malicious actions only on certain dates. For example,
this technique was used in the <a href="https://www.cyphort.com/sazoora-dissecting-bundle-evasion-stealth/">Sazoora malware</a>, 
which checks the current date and verifies if the day is either the 16th, 17th or 18th 
of a given month.
<p><b>Example:</b></p>
<div style="text-align: center">
  <img src="/assets/images/date_anti_sb.png" />
</div>
<br/>

<b>Countermeasures</b>
<p></p>
Countermeasures for this class of evasion techniques should be comprehensive and include all described attack vectors.
The implementation cannot be simple and its description deserves a separate article. Therefore, we only provide general
recommendations here:
<ul>
<li>Implement sleep skipping.</li>
<li>System-wide dynamic time flow speed manipulation.</li>
<li>Run emulation multiple times on different dates.</li>
</ul>
Although sleep skipping is already implemented in the Cuckoo sandbox, it is very easy to deceive it. 
Sleep skipping is disabled after a new thread or process is created to avoid sleep skipping detection.
However, it can still be easily detected as shown below.

<br />
<h3><a class="a-dummy" name="sleep-skipping-detection">2. Sleep skipping detection</a></h3>
Techniques of this type are generally aimed at the Cuckoo monitor sleep skipping feature and other time-manipulation
techniques that can be used in sandboxes to skip long delays performed by the malware.
<h4><a class="a-dummy" name="parallel-delays">2.1. Parallel delays using different methods</a></h4>
The idea behind the techniques is to perform different types of delays in parallel and to measure the elapsed time.
<br /><br />
<b>Code sample</b>
{% highlight c %}
DWORD StartingTick, TimeElapsedMs;
LARGE_INTEGER DueTime;
HANDLE hTimer = NULL;
TIMER_BASIC_INFORMATION TimerInformation;
ULONG ReturnLength;

hTimer = CreateWaitableTimer(NULL, TRUE, NULL);
DueTime.QuadPart = Timeout * (-10000LL);

StartingTick = GetTickCount();
SetWaitableTimer(hTimer, &DueTime, 0, NULL, NULL, 0);
do
{
    Sleep(Timeout/10);
    NtQueryTimer(hTimer, TimerBasicInformation, &TimerInformation, sizeof(TIMER_BASIC_INFORMATION), &ReturnLength);
} while (!TimerInformation.TimerState);

CloseHandle(hTimer);

TimeElapsedMs = GetTickCount() - StartingTick;
printf("Requested delay: %d, elapsed time: %d\n", Timeout, TimeElapsedMs);

if (abs((LONG)(TimeElapsedMs - Timeout)) > Timeout / 2)
    printf("Sleep-skipping DETECTED!\n");
{% endhighlight %}
<br />
In the code sample above, the delay timeout is set using the <tt>SetWaitableTimer()</tt> timer function. 
The <tt>Sleep()</tt> function is called in a loop until the timer timeout. In the Cuckoo sandbox, delays that are performed 
by the <tt>Sleep()</tt> function are skipped (replaced with a very short timeout) and the virtually elapsed 
time will be much higher than the requested timeout:
{% highlight plaintex %}
    Requested delay: 60000, elapsed time: 1906975
    Sleep-skipping DETECTED!
{% endhighlight %}
<br />
<h4><a class="a-dummy" name="measure-time-intervals">2.2. Measure time intervals using different methods</a></h4>
We need to perform a delay that will be skipped in a sandbox and to measure elapsed time using different methods.
While the Cuckoo monitor hooks the <tt>GetTickCount()</tt>, <tt>GetLocalTime()</tt>, <tt>GetSystemTime()</tt> and
makes them return the skipped time, we still can find methods to measure time that are not handled by the Cuckoo 
monitor.

<p>Functions used:</p>
<ul>
  <li><tt>GetTickCount64</tt></li>
  <li><tt>QueryPerformanceFrequency, QueryPerformanceCounter</tt></li> 
  <li><tt>NtQuerySystemInformation</tt></li>
</ul>

<br /><br />
<b>Code sample (using "QueryPerformanceCounter" to measure elapsed time)</b>
{% highlight c %}
LARGE_INTEGER StartingTime, EndingTime;
LARGE_INTEGER Frequency;
DWORD TimeElapsedMs;

QueryPerformanceFrequency(&Frequency);
QueryPerformanceCounter(&StartingTime);

Sleep(Timeout);

QueryPerformanceCounter(&EndingTime);
TimeElapsedMs = (DWORD)(1000ll * (EndingTime.QuadPart - StartingTime.QuadPart) / Frequency.QuadPart);

printf("Requested delay: %d, elapsed time: %d\n", Timeout, TimeElapsedMs);

if (abs((LONG)(TimeElapsedMs - Timeout)) > Timeout / 2)
    printf("Sleep-skipping DETECTED!\n");
{% endhighlight %}

<br /><br />
<b>Code sample (using "GetTickCount64" to measure elapsed time)</b>
{% highlight c %}
ULONGLONG tick;
DWORD TimeElapsedMs;

tick = GetTickCount64();
Sleep(Timeout);
TimeElapsedMs = GetTickCount64() - tick;

printf("Requested delay: %d, elapsed time: %d\n", Timeout, TimeElapsedMs);

if (abs((LONG)(TimeElapsedMs - Timeout)) > Timeout / 2)
    printf("Sleep-skipping DETECTED!\n");
{% endhighlight %}

We can also use our own implementation of <tt>GetTickCount</tt> to detect sleep skipping.
In the next code sample, we acquire the tick count directly from the <tt>KUSER_SHARED_DATA</tt> structure. 
This way we can get the original tick count value even if the <tt>GetTickCount()</tt> function was hooked.
<br /><br />
<b>Code sample (getting the tick count from the KUSER_SHARED_DATA structure)</b>
{% highlight c %}
#define KI_USER_SHARED_DATA         0x7FFE0000
#define SharedUserData  ((KUSER_SHARED_DATA * const) KI_USER_SHARED_DATA)
#define MyGetTickCount() ((DWORD)((SharedUserData->TickCountMultiplier * (ULONGLONG)SharedUserData->TickCount.LowPart) >> 24))

// ...
StartingTick = MyGetTickCount();
Sleep(Timeout);
TimeElapsedMs = MyGetTickCount() - StartingTick;

printf("Requested delay: %d, elapsed time: %d\n", Timeout, TimeElapsedMs);

if (abs((LONG)(TimeElapsedMs - Timeout)) > Timeout / 2)
    printf("Sleep-skipping DETECTED!\n");
{% endhighlight %}
<br />

<h4><a class="a-dummy" name="get-system-time">2.3. Get system time using different methods</a></h4>
This method is similar to the previous one. Instead of measuring intervals we try to obtain the current system
time using different methods.
<br /><br />
<b>Code sample</b>
{% highlight c %}
SYSTEM_TIME_OF_DAY_INFORMATION  SysTimeInfo;
ULONGLONG time;
LONGLONG diff;

Sleep(60000); // should trigger sleep skipping
GetSystemTimeAsFileTime((LPFILETIME)&time);

NtQuerySystemInformation(SystemTimeOfDayInformation, &SysTimeInfo, sizeof(SysTimeInfo), 0);
diff = time - SysTimeInfo.CurrentTime.QuadPart;
if (abs(diff) > 10000000) // differ in more than 1 second
    printf("Sleep-skipping DETECTED!\n);
{% endhighlight %}
<br />
<h4><a class="a-dummy" name="delay-value-changed">2.4. Check if the delay value changes after calling a delay function</a></h4>
Sleep-skipping is usually implemented as a replacement of the delay value with a smaller interval. 
Let's look at the <tt>NtDelayExecution</tt> function. The delay value is passed to this function using a pointer:
<br />
{% highlight c %}
NTSYSAPI NTSTATUS NTAPI
NtDelayExecution(
    IN BOOLEAN              Alertable,
    IN PLARGE_INTEGER       DelayInterval );
{% endhighlight %}
<br />
Therefore, we can check if the value of <tt>DelayInterval</tt> changes after the function execution.
If the value differs from the initial value, the delay was skipped.
<br/><br/>
<b>Code sample</b>
{% highlight c %}
LONGLONG SavedTimeout = Timeout * (-10000LL);
DelayInterval->QuadPart = SavedTimeout;
status = NtDelayExecution(TRUE, DelayInterval);
if (DelayInterval->QuadPart != SavedTimeout)
    printf("Sleep-skipping DETECTED!\n");
{% endhighlight %}
<br />

<h4><a class="a-dummy" name="absolute-timeout">2.5. Use absolute timeout</a></h4>
For Nt-functions that perform delays we can use either a relative delay interval or an absolute time for timeout.
A negative value for the delay interval means a relative timeout, and a positive value means an absolute timeout.
High-level API functions such as <tt>WaitForSingleObject()</tt> or <tt>Sleep()</tt> operate with relative intervals.
Therefore sandbox developers may not care about absolute timeouts and handle them incorrectly.
In the Cuckoo sandbox such delays are skipped, but skipped time and ticks are counted incorrectly. This can be used
to detect sleep skipping.
<br/><br/>
<b>Code sample</b>
{% highlight c %}
void SleepAbs(DWORD ms)
{
    LARGE_INTEGER SleepUntil;

    GetSystemTimeAsFileTime((LPFILETIME)&SleepUntil);
    SleepTo.QuadPart += (ms * 10000);
    NtDelayExecution(TRUE, &SleepTo);
}
{% endhighlight %}

<br />
<h4><a class="a-dummy" name="get-time-another-process">2.6. Get time from another process</a></h4>
Sleep skipping in the Cuckoo sandbox is not system-wide. Therefore, if there are performing delays, time moves
with different speeds in the different processes. After a delay we should synchronize the processes and compare 
the current time in the two processes. A big difference in measured time values indicates sleep skipping was performed.

<div style="text-align: center">
  <img src="/assets/images/sleep_skipping_detection.png" />
</div>

The current version of the Cuckoo monitor disables sleep skipping after creating new threads or processes.
Therefore, we should use a process creation method that is not tracked by the Cuckoo monitor, for example,
using a scheduled task.

<br/>
<h3><a class="a-dummy" name="get-time-ntp">3. Get the current date and time from an external source (NTP, HTTP)</a></h3>
A sandbox may set different dates to check how the behavior of analyzed samples is changed depending on the date.
The malware can use an external date and time source to prevent time manipulation attempts inside the VM.
This method can also be used to measure time intervals, perform delays, and detect sleep skipping attempts.
NTP servers, and the HTTP header "Date" can be used as an external source for the date and time.
For example, the malware may connect to <tt>google.com</tt> to check the current date and use it as a DGA seed.

<b>Countermeasures</b>
<p></p>

Implement fake web infrastructure or spoof NTP data and HTTP headers returned by real servers. 
The returned/spoofed date and time should be synchronized with the date and time in a virtual machine.

<br />
<h3><a class="a-dummy" name="difference-vm-hosts">4. Difference in time measurement in VM and hosts</a></h3>
The execution of some API functions and instructions may take different amounts of time in a VM and in the usual 
host systems. These peculiarities can be used to detect a virtual environment.

<h4><a class="a-dummy" name="rdtsc">4.1. RDTSC (with CPUID to force a VM Exit)</a></h4>
<b>Code sample</b>
{% highlight c %}
BOOL rdtsc_diff_vmexit()
{
    ULONGLONG tsc1 = 0;
    ULONGLONG tsc2 = 0;
    ULONGLONG avg = 0;
    INT cpuInfo[4] = {};

    // Try this 10 times in case of small fluctuations
    for (INT i = 0; i < 10; i++)
    {
        tsc1 = __rdtsc();
        __cpuid(cpuInfo, 0);
        tsc2 = __rdtsc();

        // Get the delta of the two RDTSC
        avg += (tsc2 - tsc1);
    }

    // We repeated the process 10 times so we make sure our check is as much reliable as we can
    avg = avg / 10;
    return (avg < 1000 && avg > 0) ? FALSE : TRUE;
}
{% endhighlight %}
<p><i>Credits for this code sample: <a href="https://github.com/LordNoteworthy/al-khaser">al-khaser project</a></i></p>
<br />
<h4><a class="a-dummy" name="rdtsc-locky">4.2. RDTSC (Locky version with GetProcessHeap and CloseHandle)</a></h4>
<b>Code sample</b>
{% highlight c %}
#define LODWORD(_qw)    ((DWORD)(_qw))
BOOL rdtsc_diff_locky()
{
    ULONGLONG tsc1;
    ULONGLONG tsc2;
    ULONGLONG tsc3;
    DWORD i = 0;

    // Try this 10 times in case of small fluctuations
    for (i = 0; i < 10; i++)
    {
        tsc1 = __rdtsc();

        // Waste some cycles - should be faster than CloseHandle on bare metal
        GetProcessHeap();

        tsc2 = __rdtsc();

        // Waste some cycles - slightly longer than GetProcessHeap() on bare metal
        CloseHandle(0);

        tsc3 = __rdtsc();

        // Did it take at least 10 times more CPU cycles to perform CloseHandle than it took to perform GetProcessHeap()?
        if ((LODWORD(tsc3) - LODWORD(tsc2)) / (LODWORD(tsc2) - LODWORD(tsc1)) >= 10)
            return FALSE;
    }

    // We consistently saw a small ratio of difference between GetProcessHeap and CloseHandle execution times
    // so we're probably in a VM!
    return TRUE;
}
{% endhighlight %}
<p><i>Credits for this code sample: <a href="https://github.com/LordNoteworthy/al-khaser">al-khaser project</a></i></p>
<b>Countermeasures</b>
<p></p>

Implement <tt>RDTSC</tt> instruction "hooking." It is possible to make RDTSC a privileged instruction that 
can be called in kernel-mode only. Calling the "hooked" RDTSC in user-mode leads to an execution of our handler 
that can return any desired value.

<br />
<h3><a class="a-dummy" name="check-system-boot-time">5. Check the system last boot time using different methods</a></h3>
This technique is a combination of techniques described in 
<a href="generic-os-queries.html#check-if-system-uptime">Generic OS queries: Check if the system uptime is small</a> 
and <a href="wmi.html#check-last-boot-time">WMI: Check the last boot time</a> sections. 
Depending on a method used for getting system last boot time, the measured sandbox OS uptime can be too 
small (several minutes), or conversely, too big (months or even years), because the system is usually restored 
from a snapshot after the analysis starts.
<br />
We can detect a sandbox by comparing the two values for the last boot time, acquired through WMI and through 
<tt>NtQuerySystemInformation(SystemTimeOfDayInformation)</tt>.
<br /><br />

<b>Code sample</b>
<p></p>

{% highlight c %}
bool check_last_boot_time()
{
    SYSTEM_TIME_OF_DAY_INFORMATION  SysTimeInfo;
    LARGE_INTEGER LastBootTime;
    
    NtQuerySystemInformation(SystemTimeOfDayInformation, &SysTimeInfo, sizeof(SysTimeInfo), 0);
    LastBootTime = wmi_Get_LastBootTime();
    return (wmi_LastBootTime.QuadPart - SysTimeInfo.BootTime.QuadPart) / 10000000 != 0; // 0 seconds
}
{% endhighlight %}

<b>Countermeasures</b>
<p></p>
<ul>
<li>Adjust the <tt>KeBootTime</tt> value</li>
<li>Reset the WMI repository or restart the <tt>"winmgmt"</tt> service after the <tt>KeBootTime</tt> adjustment</li>
</ul>

<br />
<h3><a class="a-dummy" name="countermeasures">Countermeasures</a></h3>

Countermeasures are present in the appropriate sub-sections above.

<br />
<h3><a class="a-dummy" name="credits">Credits</a></h3>

Credits go to open-source projects from where code samples were taken: 
<ul>
<li>al-khaser project on <a href="https://github.com/LordNoteworthy/al-khaser">GitHub</a></li>
