---
layout: post
title:  "Evasions: Filesystem"
categories: evasions 
tags: filesystem
---

<h1>Contents</h1>

[Filesystem detection methods](#filesystem-detection-methods)
<br />
  [1. Check if specific files exist](#check-if-specific-files-exist)
<br />
  [2. Check if specific directories are present](#check-if-specific-directories-present)
<br />
  [3. Check if full path to the executable contains one of specific strings](#check-if-full-path-exec)
<br />
  [4. Check if the executable is run from specific directory](#check-if-exec-is-run)
<br />
  [5. Check if the executable files with specific names are present in physical disk drives root](#check-if-exec-files-with-specific-names)
<br />
[Countermeasures](#countermeasures)
<br />
[Credits](#credits)
<br />
<br />


<h2><a class="a-dummy" name="filesystem-detection-methods">Filesystem detection methods</a></h2>
The principle of all the filesystem detection methods is the following: there are no such files and directories in usual host; however they exist in particular virtual environments and sandboxes. Virtual environment may be detected if such an artifact is present.


<br />
<h3><a class="a-dummy" name="check-if-specific-files-exist">1. Check if specific files exist</a></h3>

This method uses the difference in files which are present in usual host system and virtual environments. There are quite a few file artifacts present in virtual environments which are specific for such kinds of systems. These files are not present on usual host systems where no virtual environment is installed.

Function used:
<ul>
<li><tt>GetFileAttributes  // if attributes are invalid then no file exists</tt></li> 
</ul>

<hr class="space">

<b>Code sample</b>
<p></p>

{% highlight c %}
BOOL is_FileExists(TCHAR* szPath)
{
    DWORD dwAttrib = GetFileAttributes(szPath);
    return (dwAttrib != INVALID_FILE_ATTRIBUTES) && !(dwAttrib & FILE_ATTRIBUTE_DIRECTORY);
}

/*
Check against some of VMware blacklisted files
*/
VOID vmware_files()
{
    /* Array of strings of blacklisted paths */
    TCHAR* szPaths[] = {
        _T("system32\\drivers\\vmmouse.sys"),
        _T("system32\\drivers\\vmhgfs.sys"),
    };
    
    /* Getting Windows Directory */
    WORD dwlength = sizeof(szPaths) / sizeof(szPaths[0]);
    TCHAR szWinDir[MAX_PATH] = _T("");
    TCHAR szPath[MAX_PATH] = _T("");
    GetWindowsDirectory(szWinDir, MAX_PATH);
    
    /* Check one by one */
    for (int i = 0; i < dwlength; i++)
    {
        PathCombine(szPath, szWinDir, szPaths[i]);
        TCHAR msg[256] = _T("");
        _stprintf_s(msg, sizeof(msg) / sizeof(TCHAR), _T("Checking file %s: "), szPath);
        if (is_FileExists(szPath))
            print_results(TRUE, msg);
        else
            print_results(FALSE, msg);
    }
}

{% endhighlight %}

<i>Credits for this code sample: <a href="https://github.com/LordNoteworthy/al-khaser">al-khaser project</a></i>

<hr class="space">

<b>Signature recommendations</b>
<p></p>
If the following function contains its only argument from the table column <font face="Courier New">`Path`</font>:
<p></p>
<ul>
<li><tt>GetFileAttributes(path)</tt></li> 
</ul>
then it's an indication of application trying to use the evasion technique.

<hr class="space">

<b>Detections table</b>

<table style="width:100%">
  <tr>
  	<td colspan="3">Check if the following files exist:</td>
  </tr>
  <tr>
  	<th style="text-align:center">Detect</th>
  	<th style="text-align:center">Path</th>
  	<th style="text-align:center">Details (if any)</th>
  </tr>
  <tr>
  	<th rowspan="11">[general]</th>
  	<td>c:\[60 random hex symbols]</td>
  	<td>file unique to the PC used for encoding</td>
  </tr>
  <tr>
  	<td>c:\take_screenshot.ps1</td>
  	<td />
  </tr>
  <tr>
  	<td>c:\loaddll.exe</td>
  	<td />
  </tr>
  <tr>
  	<td>c:\email.doc</td>
  	<td />
  </tr>
  <tr>
  	<td>c:\email.htm</td>
  	<td />
  </tr>
  <tr>
  	<td>c:\123\email.doc</td>
  	<td />
  </tr>
  <tr>
  	<td>c:\123\email.docx</td>
  	<td />
  </tr>
  <tr>
  	<td>c:\a\foobar.bmp</td>
  	<td />
  </tr>
  <tr>
  	<td>c:\a\foobar.doc</td>
  	<td />
  </tr>
  <tr>
  	<td>c:\a\foobar.gif</td>
  	<td />
  </tr>
  <tr>
  	<td>c:\symbols\aagmmc.pdb</td>
  	<td />
  </tr>
  <tr>
  	<th rowspan="7">Parallels</th>
  	<td>c:\windows\system32\drivers\prleth.sys</td>
  	<td>Network Adapter</td>
  </tr>
  <tr>
  	<td>c:\windows\system32\drivers\prlfs.sys</td>
  	<td />
  </tr>
  <tr>
  	<td>c:\windows\system32\drivers\prlmouse.sys</td>
  	<td>Mouse Synchronization Tool</td>
  </tr>
  <tr>
  	<td>c:\windows\system32\drivers\prlvideo.sys</td>
  	<td />
  </tr>
  <tr>
  	<td>c:\windows\system32\drivers\prltime.sys</td>
  	<td>Time Synchronization Driver</td>
  </tr>
  <tr>
  	<td>c:\windows\system32\drivers\prl_pv32.sys</td>
  	<td>Paravirtualization Driver</td>
  </tr>
  <tr>
  	<td>c:\windows\system32\drivers\prl_paravirt_32.sys</td>
  	<td>Paravirtualization Driver</td>
  </tr>
  <tr>
  	<th rowspan="17">VirtualBox</th>
  	<td>c:\windows\system32\drivers\VBoxMouse.sys</td>
  	<td />
  </tr>
  <tr>
  	<td>c:\windows\system32\drivers\VBoxGuest.sys</td>
  	<td />
  </tr>
  <tr>
  	<td>c:\windows\system32\drivers\VBoxSF.sys</td>
  	<td />
  </tr>
  <tr>
  	<td>c:\windows\system32\drivers\VBoxVideo.sys</td>
  	<td />
  </tr>
  <tr>
  	<td>c:\windows\system32\vboxdisp.dll</td>
  	<td />
  </tr>
  <tr>
  	<td>c:\windows\system32\vboxhook.dll</td>
  	<td />
  </tr>
  <tr>
  	<td>c:\windows\system32\vboxmrxnp.dll</td>
  	<td />
  </tr>
  <tr>
  	<td>c:\windows\system32\vboxogl.dll</td>
  	<td />
  </tr>
  <tr>
  	<td>c:\windows\system32\vboxoglarrayspu.dll</td>
  	<td />
  </tr>
  <tr>
  	<td>c:\windows\system32\vboxoglcrutil.dll</td>
  	<td />
  </tr>
  <tr>
  	<td>c:\windows\system32\vboxoglerrorspu.dll</td>
  	<td />
  </tr>
  <tr>
  	<td>c:\windows\system32\vboxoglfeedbackspu.dll</td>
  	<td />
  </tr>
  <tr>
  	<td>c:\windows\system32\vboxoglpackspu.dll</td>
  	<td />
  </tr>
  <tr>
  	<td>c:\windows\system32\vboxoglpassthroughspu.dll</td>
  	<td />
  </tr>
  <tr>
  	<td>c:\windows\system32\vboxservice.exe</td>
  	<td />
  </tr>
  <tr>
  	<td>c:\windows\system32\vboxtray.exe</td>
  	<td />
  </tr>
  <tr>
  	<td>c:\windows\system32\VBoxControl.exe</td>
  	<td />
  </tr>
  <tr>
  	<th rowspan="2">VirtualPC</th>
  	<td>c:\windows\system32\drivers\vmsrvc.sys</td>
  	<td></td>
  </tr>
  <tr>
  	<td>c:\windows\system32\drivers\vpc-s3.sys</td>
  	<td></td>
  </tr>
  <tr>
  	<th rowspan="6">VMware</th>
  	<td>c:\windows\system32\drivers\vmmouse.sys</td>
  	<td>Pointing PS/2 Device Driver</td>
  </tr>
  <tr>
  	<td>c:\windows\system32\drivers\vmnet.sys</td>
  	<td></td>
  </tr>
  <tr>
  	<td>c:\windows\system32\drivers\vmxnet.sys</td>
  	<td>PCI Ethernet Adapter</td>
  </tr>
  <tr>
  	<td>c:\windows\system32\drivers\vmhgfs.sys</td>
  	<td>HGFS Filesystem Driver</td>
  </tr>
  <tr>
  	<td>c:\windows\system32\drivers\vmx86.sys</td>
  	<td></td>
  </tr>
  <tr>
  	<td>c:\windows\system32\drivers\hgfs.sys</td>
  	<td></td>
  </tr>
</table>


<br />
<h3><a class="a-dummy" name="check-if-specific-directories-present">2. Check if specific directories are present</a></h3>

This method uses the difference in directories which are present in usual host system and virtual environments. There are quite a few directory artifacts present in virtual environments which are specific for such kinds of systems. These directories are not present on usual host systems where no virtual environment is installed.

Function used:
<ul>
<li><tt>GetFileAttributes  // if attributes are invalid then no file exists</tt></li> 
</ul>

<hr class="space">

<b>Code sample</b>
<p></p>

{% highlight c %}
BOOL is_DirectoryExists(TCHAR* szPath)
{
    DWORD dwAttrib = GetFileAttributes(szPath);
    return (dwAttrib != INVALID_FILE_ATTRIBUTES) && (dwAttrib & FILE_ATTRIBUTE_DIRECTORY);
}

/*
Check against VMware blacklisted directory
*/
BOOL vmware_dir()
{
    TCHAR szProgramFile[MAX_PATH];
    TCHAR szPath[MAX_PATH] = _T("");
    TCHAR szTarget[MAX_PATH] = _T("VMware\\");
    if (IsWoW64())
        ExpandEnvironmentStrings(_T("%ProgramW6432%"), szProgramFile, ARRAYSIZE(szProgramFile));
    else
        SHGetSpecialFolderPath(NULL, szProgramFile, CSIDL_PROGRAM_FILES, FALSE);
    PathCombine(szPath, szProgramFile, szTarget);
    return is_DirectoryExists(szPath);
}
{% endhighlight %}

<i>Credits for this code sample: <a href="https://github.com/LordNoteworthy/al-khaser">al-khaser project</a> </i>

<hr class="space">

<b>Signature recommendations</b>
<p></p>
If the following function contains its only argument from the table column <font face="Courier New">`Path`</font>:
<p></p>
<ul>
<li><tt>GetFileAttributes(path)</tt></li> 
</ul>
then it's an indication of application trying to use the evasion technique.

<hr class="space">

<b>Detections table</b>

<table style="width:62%">
  <tr>
  	<td colspan="3">Check if the following files exist:</td>
  </tr>
  <tr>
  	<th style="text-align:center">Detect</th>
  	<th style="text-align:center">Path</th>
  </tr>
  <tr>
  	<th>CWSandbox</th>
  	<td>c:\analysis</td>
  </tr>
  <tr>
  	<th>VirtualBox</th>
  	<td>%PROGRAMFILES%\oracle\virtualbox guest additions\</td>
  </tr>
  <tr>
  	<th>VMware</th>
  	<td>%PROGRAMFILES%\VMware\</td>
  </tr>
</table>


<br />
<h3><a class="a-dummy" name="check-if-full-path-exec">3. Check if full path to the executable contains one of the specific strings</a></h3>

This method relies on peculiarities of launching executables inside virtual environments. Some environments launch executables from specific paths - and malware samples check these paths.

Functions used to get executable path:
<ul>
<li><tt>GetModuleFileName</tt></li>
<li><tt>GetProcessImageFileNameA/W</tt></li>
<li><tt>QueryFullProcessImageName</tt></li>
</ul>

<hr class="space">

<b>Code sample (function GetModuleFileName)</b>
<p></p>

{% highlight c %}
int gensandbox_path() {
    char path[500];
    size_t i;
    DWORD pathsize = sizeof(path);

    GetModuleFileName(NULL, path, pathsize);

    for (i = 0; i < strlen(path); i++) { /* case-insensitive */
        path[i] = toupper(path[i]);
    }

    // some sample values from the table
    if (strstr(path, "\\SAMPLE") != NULL) {
        return TRUE;
    }
    if (strstr(path, "\\VIRUS") != NULL) {
        return TRUE;
    }
    if (strstr(path, "SANDBOX") != NULL) {
        return TRUE;
    }

    return FALSE;
}
{% endhighlight %}

<i>Credits for this code sample: <a href="https://github.com/a0rtega/pafish">pafish project</a> </i>

<hr class="space">

<b>Code sample (function QueryFullProcessImageName)</b>
<p></p>

{% highlight c %}
DWORD PID = 1337; // process ID of the target process
HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, false, PID);
DWORD value = MAX_PATH;
char buffer[MAX_PATH];
QueryFullProcessImageName(hProcess, 0, buffer, &value);
printf("EXE Path: %s\n", buffer);
{% endhighlight %}

<hr class="space">

<b>No signature recommendations</b>
<p></p>
Signature recommendations are not provided as it's hard to say why exactly application wants to get its full path. Function calls may be hooked - and that's it, just general recommendation.

<hr class="space">

<b>Detections table</b>

<table style="width:62%">
  <tr>
  	<td colspan="3">Check if full path to the executable contains one of the following strings:</td>
  </tr>
  <tr>
  	<th style="text-align:center">Detect</th>
  	<th style="text-align:center">String</th>
  </tr>
  <tr>
  	<th rowspan="3">[general]</th>
  	<td>\sample</td>
  </tr>
  <tr>
  	<td>\virus</td>
  </tr>
  <tr>
  	<td>sandbox</td>
  </tr>
</table>


<br />
<h3><a class="a-dummy" name="check-if-exec-is-run">4. Check if the executable is run from specific directory</a></h3>

This method relies on peculiarities of launching executables inside virtual environments. Some environments launch executables from specific directories - and malware samples check these directories.

It's just a particular case of checking presence of specific strings in full application path, please refer to the [section above](#check-if-full-path-exec) for code sample and signature recommendations.

As this very method is pretty old and is not commonly used, the links to external sources are provided for the reference on this method:
<ul>
<li>VB <a href="https://www.opensc.io/showthread.php?t=2343">code sample</a></li> 
<li>python <a href="https://github.com/brad-accuvant/community-modified/blob/master/modules/signatures/antisandbox_joe_anubis_files.py">code sample</a></li> 
<li>anti-emulation <a href="http://web.archive.org/web/20181222042516/www.woodmann.com/forum/showthread.php?12545-Anti-Emulation-Tricks">tricks</a></li> 
<li>stub for <a href="http://web.archive.org/web/20101026233743/http://evilcry.netsons.org/OC0/code/EmulationAwareness.c">C code</a></li> 
</ul>

<hr class="space">

<b>Detections table</b>

<table style="width:62%">
  <tr>
  	<td colspan="3">Check if the executable is run from the following directories:</td>
  </tr>
  <tr>
  	<th style="text-align:center">Detect</th>
  	<th style="text-align:center">Path</th>
  </tr>
  <tr>
  	<th>Anubis</th>
  	<td>c:\insidetm</td>
  </tr>
</table>


<br />
<h3><a class="a-dummy" name="check-if-exec-files-with-specific-names">5. Check if the executable files with specific names are present in physical disk drives' root</a></h3>

This method relies on peculiarities of virtual environments, in this case it's presence of specific files in disk root root directories.

Function used:
<ul>
<li><tt>GetFileAttributes  // if attributes are invalid then no file exists</tt></li> 
</ul>

<hr class="space">

<b>Code sample (function GetModuleFileName)<b>
<p></p>

{% highlight c %}
int pafish_exists_file(char * filename) {
    DWORD res = INVALID_FILE_ATTRIBUTES;
    if (pafish_iswow64() == TRUE) {
        void *old = NULL;
        // Disable redirection immediately prior to calling GetFileAttributes.
        if (pafish_disable_wow64_fs_redirection(&old) ) {
            res = GetFileAttributes(filename);
            // Ignoring MSDN recommendation of exiting if this call fails.
            pafish_revert_wow64_fs_redirection(old);
        }
    }
    else {
        res = GetFileAttributes(filename);
    }
    return (res != INVALID_FILE_ATTRIBUTES) ? TRUE : FALSE;
}

int gensandbox_common_names() {
    DWORD dwSize = MAX_PATH;
    char szLogicalDrives[MAX_PATH] = {0};
    DWORD dwResult = GetLogicalDriveStrings(dwSize,szLogicalDrives);
    BOOL exists;

    if (dwResult > 0 && dwResult <= MAX_PATH)
    {
        char* szSingleDrive = szLogicalDrives;
        char filename[MAX_PATH] = {0};
        while(*szSingleDrive)
        {
            if (GetDriveType(szSingleDrive) != DRIVE_REMOVABLE ) {
                snprintf(filename, MAX_PATH, "%ssample.exe",szSingleDrive);
                exists = pafish_exists_file(filename);
                if (exists) return TRUE;
                
                snprintf(filename, MAX_PATH, "%smalware.exe",szSingleDrive);
                exists = pafish_exists_file(filename);
                if (exists) return TRUE;
            }

            szSingleDrive += strlen(szSingleDrive) + 1;
        }
    }

    return FALSE;
}
{% endhighlight %}

<i>Credits for this code sample: <a href="https://github.com/a0rtega/pafish">pafish project</a></i>

<hr class="space">

<b>Signature recommendations</b>
<p></p>
If the following function contains its only argument from the table column <font face="Courier New">`Path`</font>:
<p></p>
<ul>
<li><tt>GetFileAttributes(path)</tt></li> 
</ul>
then it's an indication of application trying to use the evasion technique.

<hr class="space">

<b>Detections table</b>

<table style="width:62%">
  <tr>
  	<td colspan="2">Check if the executables with particular names are present in disk root:</td>
  </tr>
  <tr>
  	<th style="text-align:center">Detect</th>
  	<th style="text-align:center">Path</th>
  </tr>
  <tr>
  	<th rowspan="2">[general]</th>
  	<td>malware.exe</td>
  </tr>
  <tr>
  	<td>sample.exe</td>
  </tr>
</table>


<br />
<h3><a class="a-dummy" name="countermeasures">Countermeasures</a></h3>

Hook target functions and return appropriate results if indicators (files from tables) are checked.

<br />
<h3><a class="a-dummy" name="credits">Credits</a></h3>

Credits go to open-source projects from where code samples were taken:
<ul>
<li>al-khaser project on <a href="https://github.com/LordNoteworthy/al-khaser">github</a></li>
<li>pafish project on <a href="https://github.com/a0rtega/pafish">github</a></li>
</ul>

Though Check Point tool InviZzzible has them all implemented, due to modular structure of the code it would require more space to show a code sample from this tool for the same purposes. That's why we've decided to use other great open-source projects for examples throughout the encyclopedia.

[vb-code-sample]:     https://www.opensc.io/showthread.php?t=2343
[python-code-sample]: https://github.com/brad-accuvant/community-modified/blob/master/modules/signatures/antisandbox_joe_anubis_files.py
[anti-emul-tricks]:   https://web.archive.org/web/20181222042516/www.woodmann.com/forum/showthread.php?12545-Anti-Emulation-Tricks
[stub-for-c-code]:    http://web.archive.org/web/20101026233743/http://evilcry.netsons.org/OC0/code/EmulationAwareness.c
[al-khaser-github]:   https://github.com/LordNoteworthy/al-khaser
[pafish-github]:      https://github.com/a0rtega/pafish
