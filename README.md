
# Encyclopedia of Evasions

## Words of gratitude

This encyclopedia wouldn't be possible without invaluable assistance of the following Check Point researchers:
* Aliaksandr Trafimchuk ([@a14xt][a14xt])
* Bohdan Melnykov ([@\_mbv06\_][\_mbv06\_])

## Site

Compiled encyclopedia resides here: https://evasions.checkpoint.com.

## Windows Evasions repository

As malicious threats evolve, the necessity in automated solutions to analyze such threats emerges. It's a very common case when malware samples are executed in some kind of virtualized environment.

These environments differ from usual host systems by a huge amount of artifacts: non-common files, registry keys, system objects, etc. By examining such artifacts malware samples are able to say if they are run in a virtualized environment. Depending on the answer to this question, malware will continue its usual execution thus giving the researchers an opportunity to monitor its behavior - or will behave itself in an unexpected way and reveal nothing about its behavior. 

If the latter was the case, we say that malware has successfully applied evasion technique, or simply evasion.

In this encyclopedia we have attempted to gather all the known ways to detect virtualized environment grouping them into big categories. Some categories are inactive on main page: it means that content will be added later.

Within each category the reader will find the following information:
* description of the technique
* code sample showing its usage
* signature recommendations to track attempts to apply this technique
* table with breakdown of which particular environments are detected with the help of certain constants
* possible countermeasures

A lot of solutions with implemented techniques exist in open-source community. These solutions are used throughout the encyclopedia in the form of code excerpts from them. We are giving credits to open-source projects from where code sampes were taken: 
* [al-khaser project][al-khaser]
* [pafish project][pafish]
* [VMDE project][vmde]

It's important to add that Check Point researchers have produced their own tool called [InviZzzible][invizzzible].

If you want to contribute to this encyclopedia, you're more than welcome to create pull requests here.

So check out all the repositories, browse through evasions encyclopedia and enjoy the journey!

[al-khaser]: <https://github.com/LordNoteworthy/al-khaser>
[pafish]: <https://github.com/a0rtega/pafish>
[vmde]: <https://github.com/hfiref0x/VMDE>
[invizzzible]: <https://github.com/CheckPointSW/InviZzzible>


## Windows Anti-Debug repository

Debugging is the essential part of malware analysis. Every time we need to drill down into malware behavior, restore encryption methods or examine communication protocols – generally, whenever we need to examine memory at a certain moment of time – we use debuggers.

Debuggers interfere with the debugged process in a way that usually produces side-effects. These side-effects are often used by malicious programs to verify if they are executed under debugging. In turn knowledge of anti-debug techniques helps us detect when the malware tries to prevent us from debugging it and mitigate the interference.

This encyclopedia contains the description of anti-debug tricks which work on the latest Windows releases with the most popular debuggers (such as OllyDbg, WinDbg, x64dbg). Deprecated techniques (e.g. for SoftICE, etc.) are not included (despite all the love to SoftICE).

Anti-Debug tricks are grouped by the way in which they trigger side-effects (“meh, yet another classification”, you might think). Each group includes the description of corresponding tricks, their implementation in C/C++ or x86/x86-64 Assembly language, and recommendations of how to mitigate the trick for developers who want to create their own anti-anti-debug solution. In general, for bypassing anti-debug techniques we recommend using the [ScyllaHide][scylla_link] plugin which supports OllyDbg, x64dbg and IDA Pro.

All the techniques which are described in this encyclopedia are implemented in our [ShowStopper][showstopper_link] open-source project. The encyclopedia can help you to better understand how these techniques work or to assess debuggers and anti-anti-debug plugins.

### References
* [P. Ferrie. The “Ultimate”Anti-Debugging Reference][ferrie]
* [N. Falliere. Windows Anti-Debug Reference][falliere]
* [J. Jackson. An Anti-Reverse Engineering Guide][jackson]
* [Anti Debugging Protection Techniques with Examples][apriorit]
* [simpliFiRE.AntiRE][simplifire]

[ferrie]: <http://pferrie.epizy.com/papers/antidebug.pdf>
[falliere]: <https://www.symantec.com/connect/articles/windows-anti-debug-reference>
[jackson]: <https://forum.tuts4you.com/files/file/1218-anti-reverse-engineering-guide/>
[apriorit]: <https://www.apriorit.com/dev-blog/367-anti-reverse-engineering-protection-techniques-to-use-before-releasing-software>
[simplifire]: <https://bitbucket.org/fkie_cd_dare/simplifire.antire/src/master/>

[scylla_link]: <https://github.com/x64dbg/ScyllaHide>
[showstopper_link]: <https://github.com/CheckPointSW/showstopper>

## macOS Evasions repository

This repository is made in the same style and format as its Windows counterparts. However, due to the specifics of the macOS platform, only evasion techniques are present, without anti-debug tricks. Code examples are provided for each of the included groups, along with countermeasures advice.

## Android Evasions repository

This repository is made in the same style and format as its Windows couterparts. However, due to the specifics of the Android platform and low number of techniques in comparison to Windows, evasions and anti-debug are present in one repository. Where applicable, the code examples are provided.

## Authors

The author of Windows Anti-Debug repository and the corresponding "About" section:
<ul>
<li>Yaraslau Harakhavik (<i class="fa fa-twitter fa-lg" style="color:#1DA1F2"></i> <a href="https://twitter.com/slevin_by">@slevin_by</a>)</li>
</ul>

The author of macOS Evasions repository and the corresponding "About" section:
<ul>
<li>Alexey Bukhteyev</li>
</ul>

The author of other encyclopedia parts:
<ul>
<li>Raman Ladutska (<i class="fa fa-twitter fa-lg" style="color:#1DA1F2"></i> <a href="https://twitter.com/DaCuriousBro">@DaCuriousBro</a>)</li>
</ul>

[a14xt]: <https://twitter.com/a14xt>
[\_mbv06\_]: <https://twitter.com/_mbv06_>
[DaCuriousBro]: <https://twitter.com/DaCuriousBro>
