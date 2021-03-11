---
layout: post
title:  "Evasions: Human-like behavior"
title-image: "/assets/icons/ui-artifacts.svg"
categories: evasions 
tags: human-like-behavior
---

<h1>Contents</h1>

[Human-like behavior detection methods](#human-like-behavior-detection-methods)
<br />
  [1. General detection methods via registry](#general-detection-methods-via-registry)
<br />
  [1.1. Check the number of recently opened documents](#check-number-of-recently-opened-documents)
<br />
  [1.2. Check if the browser history contains at least 10 URLs](#check-if-browser-history-contains-at-least-10-urls)
<br />
  [1.3. Check if certain software packages were installed](#check-if-certain-software-package-were-installed)
<br />
  [1.4. Countermeasures](#general-detection-methods-via-registry-countermeasures)
<br />
  [2. Check for user presence at the moment of executing a process](#check-user-presence-at-the-moment-of-executing)
<br />
  [2.1. Check the mouse movement](#check-mouse-movement)
<br />
  [2.2. Check via a request for user interaction](#check-via-request-for-user-interaction)
<br />
  [2.3. Evasion technique for the Cuckoo human-interaction module](#evasion-technique-for-cuckoo-human-interaction-module)
<br />
  [2.4. No suspicious actions until a document is scrolled down](#no-suspicious-actions-until-a-document-is-scrolled-down)
<br />
  [2.5. Check user activity via GetLastInputInfo](#check-user-activity-via-getlastinputinfo)
<br />
  [Countermeasures](#countermeasures)
<br />
  [Signature recommendations](#signature-recommendations)
<br />
  [Credits](#credits)
<br />
<br />

<hr class="space">

<h2><a class="a-dummy" name="human-like-behavior-detection-methods">Human-like behavior detection methods</a></h2>
All the techniques described in this group make use of the fact that certain actions are performed differently by a user and by a virtual environment.

<br />
<h3><a class="a-dummy" name="general-detection-methods-via-registry">1. General detection methods via registry</a></h3>
The registry is a storage for different pieces of information. For example, recently opened URLs and documents, and software installation notes are stored here. All of these may be used to determine if the machine is operated by a human user and is not a sandbox.

<br />
<h4><a class="a-dummy" name="check-number-of-recently-opened-documents">1.1. Check the number of recently opened documents</a></h4>
It’s hard to imagine a typical host system where the user does not open any documents. Therefore, the lack of recently opened documents indicates this is likely a virtual environment.

<hr class="space">

<b>Code sample (VB)</b>
<p></p>

{% highlight vb %}

Public Function DKTxHE() As Boolean
DKTxHE = RecentFiles.Count < 3
End Function
{% endhighlight %}

<i>This code sample was taken from <a href="https://www.sentinelone.com/blog/anti-vm-tricks/">SentinelOne article</a> </i>

<br />
<h4><a class="a-dummy" name="check-if-browser-history-contains-at-least-10-urls">1.2. Check if the browser history contains at least 10 URLs</a></h4>
It’s hard to imagine a typical host system where the user does not browse the Internet. Therefore, if there are fewer than 10 URLs in the browser history, this is likely a sandbox or VM.

<hr class="space">

<b>Code sample (for Chrome)</b>
<p></p>

<!-- Firefox history: http://www.rohitab.com/discuss/topic/40903-clear-browser-history-with-c/ -->
<!-- Firefox passwords: https://github.com/wekillpeople/browser-dumpwd/blob/master/firefox.c -->

{% highlight c %}

bool chrome_history_evasion(int min_websites_visited = 10)
{
  sqlite3 *db;
  int rc;
  bool vm_found = false;

  rc = sqlite3_open("C:\\Users\\<USER_NAME>\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\History", &db);
  if (!rc)
  {
    char **results = nullptr;
    char *error = nullptr;
    int rows, columns;

    rc = sqlite3_get_table(db, "SELECT DISTINCT title FROM urls;", &results, &rows, &columns, &error);
    if (!rc)
      vm_found = rows < min_websites_visited;
    sqlite3_free_table(results);
  }

  sqlite3_close(db);
  return vm_found;
}
{% endhighlight %}

<br />
<h4><a class="a-dummy" name="check-if-certain-software-package-were-installed">1.3. Check if certain software packages were installed</a></h4>
If the system is only used for simulation purposes then it is likely to have many fewer installed software packages than a usual user’s work machine. The installed packages may be specific to emulation purposes, not the ones that are usually used by human operators. Therefore, the list of installed packages may be compared to the list of commonly used applications to determine if it’s a sandbox.

<hr class="space">

<b>Code sample (PowerShell)</b>
<p></p>

{% highlight batch %}

Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Format-Table -AutoSize | Measure-Object -Line

{% endhighlight %}

<br />
<h4><a class="a-dummy" name="general-detection-methods-via-registry-countermeasures">1.4. Countermeasures</a></h4>
Countermeasures are simple:
<ul>
<li>open few documents to update the recent history</li>
<li>open few internet URLs to create a browsing history</li>
<li>install some lightweight software (like Notepad++)</li>
</ul>

<br />
<h3><a class="a-dummy" name="check-user-presence-at-the-moment-of-executing">2. Check for user presence at the moment of executing a process</a></h3>
The following sub-group leverages the differences between a user’s interaction with the machine and the actions of a virtual environment.

<br />
<h4><a class="a-dummy" name="check-mouse-movement">2.1. Check the mouse movement</a></h4>
This method relies on the fact that a user frequently moves the mouse during actual work. 

<hr class="space">

Some sandboxes and antivirus virtual machines have a static cursor position because they do not emulate any user activity while automatically running the files.

<hr class="space">

<b>Code sample</b>
<p></p>

{% highlight c %}

int gensandbox_mouse_act() {
    POINT position1, position2;

    GetCursorPos(&position1);
    Sleep(2000);
    GetCursorPos(&position2);

    if ((position1.x == position2.x) && (position1.y == position2.y))
        // No mouse activity during the sleep.
        return TRUE;
    else
        return FALSE;
}
{% endhighlight %}

<i>This code sample was taken from <a href="https://github.com/a0rtega/pafish">pafish project</a> </i>

Such a short delay of only 2 seconds implies that the user should be active at the moment of infection.

<hr class="space">

<b>Countermeasures</b>
<p></p>

Implement the module for mouse movement during a sample emulation.

<br />
<h4><a class="a-dummy" name="check-via-request-for-user-interaction">2.2. Check via a request for user interaction</a></h4>
Some malware samples contain a GUI installer which requires user interaction. For example, the user must click the “Install” or “Next” buttons. Therefore, the malware may take no action unless the button is clicked. Standard sandboxes like Cuckoo have a module which simulates user activity. It searches for and clicks buttons with the captions mentioned above.

<hr class="space">

To prevent auto-clicking, a malware sample may create buttons with a class name that differs from “Button” or with a different caption (not “Install” or “Next”). This way the sandbox can’t detect and click the button.

<hr class="space">

<b>Code sample</b>
<p></p>

{% highlight c %}

   // we use extended style flags to make a static look like a button
   HWND hButton = CreateWindowExW(
       WS_EX_DLGMODALFRAME | WS_EX_WINDOWEDGE,  // extended style flags
       TEXT("static"),         // class "static" instead of "button"
       TEXT("Real next"),      // caption different from “Install” or “Next”
       WS_VISIBLE | WS_CHILD | WS_GROUP | SS_CENTER,  // usual style flags
       10, 10, 80, 25,         // arbitrary position and size, may be any
       hWnd,                   // parent window
       NULL,                   // no menu
       NULL,                   // a handle to the instance of the module to be associated with the window
       NULL);                  // pointer to custom value is not required
{% endhighlight %}

<hr class="space">

<b>Countermeasures</b>
<p></p>

Check for controls other than the buttons and examine their properties. For example, if the “Install” text is linked with the “static” control (not with “button”), this may indicate that the evasion technique is applied. Therefore, such a static control may be clicked.

<br />
<h4><a class="a-dummy" name="evasion-technique-for-cuckoo-human-interaction-module">2.3. Evasion technique for the Cuckoo human-interaction module</a></h4>
Suppose that the malware installer window has a button with the “Install” caption or something similar. It can be found by the human-interaction module of a sandbox but it’s invisible to an actual user (one-pixel size, hidden, etc.).

<hr class="space">

The real installation button has an empty or fake caption and the window class “Static”, so it can’t be detected by the auto-clicking module. In addition, the malware may take some mock action if the invisible button is clicked.

<hr class="space">

<b>Code sample</b>
<p></p>

{% highlight c %}

    HWND hWnd = CreateWindow(
        TEXT("Button"),         // class "button"
        TEXT("Next"),           // caption is “Install” or “Next”
        NULL,                   // style flags are not required, the control is invisible
        1, 1, 1, 1,             // the control is created of 1x1 pixel size
        hParentWnd,             // parent window
        NULL,                   // no menu
        NULL,                   // a handle to the instance of the module to be associated with the window
        NULL);                  // pointer to custom value is not required
{% endhighlight %}

<hr class="space">

<b>Countermeasures</b>
<p></p>

Check for controls other than buttons and examine their properties. If there is a button of 1x1 pixel size or the button is invisible, this may be an indication of evasion technique applied. Therefore, such a control should not be clicked.

<br />
<h4><a class="a-dummy" name="no-suspicious-actions-until-a-document-is-scrolled-down">2.4. No suspicious actions until a document is scrolled down</a></h4>
Malware payloads which reside in Office documents (namely, *.docm *.docx) don’t do anything until the document is scrolled to a certain page (second, third, etc.). A human user usually scrolls through the document while a virtual environment will likely not perform this step.

<hr class="space">

<b>Example from <a href="https://www.fireeye.com/content/dam/fireeye-www/current-threats/pdfs/pf/file/fireeye-hot-knives-through-butter.pdf">FireEye report</a> (p. 6-7):</b>
<p></p>

RTF documents consist of normal text, control words, and groups. Microsoft’s RTF specification includes a shape-drawing function, which in turn includes a series of properties using the following syntax:<br />
<tt style="color:green">{\sp{\sn propertyName}{\sv propertyValueInformation}}</tt>

In this code, <tt>\sp</tt> is the control word for the drawing property, <tt>\sn</tt> is the property name, and <tt>\sv</tt> contains information about the property value. The code snippet in the image below exploits a <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2010-3333">CVE-2010-3333 vulnerability</a> that occurs when using an invalid <tt>\sv</tt> value for the pFragments shape property:

<div style="text-align: center; margin: auto">
  <img src="{{site.baseurl}}/assets/images/rtf_exploit.png"><br />
</div>

<br />
A closer look at the exploit code, as shown in the next image, reveals a series of paragraph marks (<tt>./par</tt>) that appears before the exploit code:

<div style="text-align: center; margin: auto">
  <img src="{{site.baseurl}}/assets/images/rtf_stub.png"><br />
</div>

<br />
The repeated paragraph marks push the exploit code to the second page of the RTF document. Therefore, the malicious code does not execute unless the document scrolls down to bring the exploit code up into the active window — more likely to be a deliberate act by a human user than simulated movement in a virtual machine.<br />

When the RTF is scrolled down to the second page, only then is the exploit code triggered and the payload is downloaded.<br />

In a sandbox, where any mouse activity is random or preprogrammed, the RTF document’s second page never appears. Therefore, the malicious code never executes, and nothing seems amiss in the sandbox analysis.

<hr class="space">

<b>Countermeasures</b>
<p></p>
Find a window with the document and send the WM_VSCROLL message there. Alternatively, send the WM_MOUSEWHEEL message as <a href="https://stackoverflow.com/questions/60203135/set-delta-in-a-wm-mousewheel-message-to-send-with-postmessage">described here</a>.

<br />
<h4><a class="a-dummy" name="check-user-activity-via-getlastinputinfo">2.5. Check user activity via GetLastInputInfo</a></h4>

User activity can be checked with the call to the `GetLastInputInfo` function

Although Agent Tesla v3 performs this check, it does so incorrectly. Compare the code of Agent Tesla v3 with the correct technique implementation below.

<div style="text-align: center; margin: auto">
  <img src="{{site.baseurl}}/assets/images/agent_tesla_v3_technique.png"><br />
</div>
<div style="text-align: center; margin: auto">
  <i>Evasion technique as implemented in Agent Tesla v3. This function is called after a delay of 30 seconds.</i>
</div>

<hr class="space">

As measured time values are in milliseconds, the difference between them cannot be larger than 30000 (30 seconds). This means that with division by 1000.0, the resulting value cannot be larger than 30. In turn, this indicates that a comparison with 600 always leads to a result in which the sandbox is undetected.

The correct implementation is provided below.

<hr class="space">

<b>Code sample</b>
<p></p>

{% highlight c %}

    bool sandbox_detected = false;
    
    Sleep(30000);

    DWORD ticks = GetTickCount();

    LASTINPUTINFO li;
    li.cbSize = sizeof(LASTINPUTINFO);
    BOOL res = GetLastInputInfo(&li);

    if (ticks - li.dwTime > 6000)
    {
        sandbox_detected = true;
    }
{% endhighlight %}

<hr class="space">

<b>Countermeasures</b>
<p></p>

Implement the module for mouse movement during a sample emulation.

<br />
<h3><a class="a-dummy" name="countermeasures"> Countermeasures</a></h3>
Countermeasures for chapter 1 are given in the corresponding [section](#general-detection-methods-via-registry-countermeasures).
Countermeasures for chapter 2 are given in place in the appropriate sections.

<br />
<h3><a class="a-dummy" name="signature-recommendations">Signature recommendations</a></h3>
<i>Signature recommendations are not provided for this class of techniques as the methods described in this chapter do not imply their usage for evasion purposes. It is hard to differentiate between the code meant for evasion and code designed for non-evasion purposes.</i>

<br />
<h3><a class="a-dummy" name="credits">Credits</a></h3>

Open-source project from where code samples were taken:
<ul>
<li>pafish project on <a href="https://github.com/a0rtega/pafish">Github</a></li>
</ul>

Companies from where certain examples were taken:
<ul>
<li><a href="https://www.fireeye.com">FireEye</a></li>
<li><a href="https://www.sentinelone.com/">SentinelOne</a></li>
</ul>