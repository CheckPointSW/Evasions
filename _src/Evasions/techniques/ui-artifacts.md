---
layout: post
title:  "Evasions: UI artifacts"
title-image: "/assets/icons/ui-artifacts.svg"
categories: evasions 
tags: ui-artifacts
---

<h1>Contents</h1>

[UI artifacts detection methods](#ui-artifacts-detection-methods)
<br />
  [1. Check if windows with certain class names are present in the OS](#check-windows-with-certain-class)
<br />
  [2. Check if top level windows' number is too small](#check-number-of-top-level-windows)
<br />
  [Signature recommendations](#signature-recommendations)
<br />
  [Countermeasures](#countermeasures)
<br />
  [Credits](#credits)
<br />
<br />

<hr class="space">

<h2><a class="a-dummy" name="ui-artifacts-detection-methods">UI artifacts detection methods</a></h2>
Techniques described in this group abuse the fact that some windows' names are only present in virtual environment and not is usual host OS. Even more, host OS contains a lot of windows while VM and sandboxes prefer keeping opened windows at the minimum. Their quantity is checked and the conclusion is drawn whether it is a VM or not.

<br />
<h3><a class="a-dummy" name="check-windows-with-certain-class">1. Check if windows with certain class names are present in the OS</a></h3>

<b>Detections table</b>

<table style="width:60%">
  <tr>
    <td colspan="2">Check if windows with the following class names are present in the OS:</td>
  </tr>
  <tr>
    <th style="text-align:center">Detect</th>
    <th style="text-align:center">Class name</th>
  </tr>
  <tr>
    <th rowspan="2">VirtualBox</th>
    <th>VBoxTrayToolWndClass</th>
  </tr>
  <tr>
    <td>VBoxTrayToolWnd</td>
  </tr>
</table>

<hr class="space">

<b>Code sample</b>
<p></p>

{% highlight c %}

BOOL vbox_window_class()
{
  HWND hClass = FindWindow(_T("VBoxTrayToolWndClass"), NULL);
  HWND hWindow = FindWindow(NULL, _T("VBoxTrayToolWnd"));

  if (hClass || hWindow)
    return TRUE;
  else
    return FALSE;
}
{% endhighlight %}

<i>Credits for this code sample: <a href="https://github.com/LordNoteworthy/al-khaser">al-khaser project</a></i>

<br />
<h3><a class="a-dummy" name="check-number-of-top-level-windows">2. Check if top level windows' number is too small</a></h3>
As it was stated above, host OS contains a lot of windows while VMs and sandboxes strive to keep opened windows at possible minimum. Windows count is measured and the conclusion is drawn on whether it's a VM or not.
<br />
In case there are too few windows in the OS, it could be an indication of virtual environment. Typical hosts have a lot (>10) top level windows.

<hr class="space">

<b>Code sample</b>
<p></p>

{% highlight c %}

BOOL CALLBACK enumProc(HWND, LPARAM lParam)
{
    if (LPDWORD pCnt = reinterpret_cast<LPDWORD>(lParam))
        *pCnt++;
    return TRUE;
}

bool enumWindowsCheck(bool& detected)
{
    DWORD winCnt = 0;

    if (!EnumWindows(enumProc,LPARAM(&winCnt))) {
        std::cerr << "EnumWindows() failed\n";
        return false;
    }

    return winCnt < 10;
}
{% endhighlight %}

<br />
<h3><a class="a-dummy" name="signature-recommendations">Signature recommendations</a></h3>
<i>No signature recommendations are provided for this evasion group as it's hard to tell that code aims to perform some evasion technique and not "legal" action.</i>

<br />
<h3><a class="a-dummy" name="countermeasures">Countermeasures</a></h3>

<ul>
<li><tt>versus windows with certain class names:</tt> Exclude windows with particular names from enumeration or modify these names.</li> 
<li><tt>versus checking top level windows' number:</tt> Create fake windows in the system so that their number will not be small or equal to the predefined numbers.</li> 
</ul>

<br />
<h3><a class="a-dummy" name="credits">Credits</a></h3>

Credits go to open-source project from where code samples were taken:
<ul>
<li>al-khaser project on <a href="https://github.com/LordNoteworthy/al-khaser">github</a></li>
</ul>

Though Check Point tool InviZzzible has them all implemented, due to modular structure of the code it would require more space to show a code sample from this tool for the same purposes. That's why we've decided to use other great open-source projects for examples throughout the encyclopedia.

