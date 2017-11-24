#Basic of Windows Kernel 
1. [Windows Kernel Internals Overview](http://www.i.u-tokyo.ac.jp/edu/training/ss/lecture/new-documents/Lectures/00-WindowsKernelOverview/WindowsKernelOverview.pdf)
2. [Windows Kernel Internals Win32k.sys](http://pasotech.altervista.org/windows_internals/Win32KSYS.pdf)
3. [Windows Kernel Internals I/O Architecture](http://i-web.i.u-tokyo.ac.jp/edu/training/ss/lecture/new-documents/Lectures/06-IOArchitecture/IOArchitecture.pdf)
4. [Windows Kernel Internals Virtual Memory Manager](http://read.pudn.com/downloads11/ebook/48602/windows%20kernel/VirtualMemory.pdf)
5. [Windows Kernel Internals Object Manager](http://slideplayer.com/slide/8014139/)
6. [Windows Kernel Internals Windows Service Processes](http://index-of.es/Windows/winKernArchi/WindowsServices.pdf)
7. [Windows Kernel Internals NT Registry Implementation](https://sww-it.ru/wp-content/uploads/2011/University%20of%20Tokyo%20Windows%20Internals%20Lectures/09-Registry/Registry.pdf)
8. [Architecture of the Windows Kernel](http://www.cs.fsu.edu/~zwang/files/cop4610/Fall2016/windows.pdf)
9. [Locks, Deadlocks, and Synchronization](https://msdn.microsoft.com/en-us/library/windows/hardware/dn613957%28v=vs.85%29.aspx?f=255&MSPPError=-2147217396)
10. [The State of Synchronization](https://www.osr.com/nt-insider/2015-issue3/the-state-of-synchronization/)
11. [DeathNote of Microsoft Windows Kernel](https://www.slideshare.net/PeterHlavaty/deathnote-of-microsoft-windows-kernel)
12. [Windows Kernel Pool](http://dokydoky.tistory.com/443)
13. [Intel CPU security features](https://github.com/huku-/research/wiki/Intel-CPU-security-features)
14. [Hardening Windows 10 with zero-day exploit mitigations](https://blogs.technet.microsoft.com/mmpc/2017/01/13/hardening-windows-10-with-zero-day-exploit-mitigations/?platform=hootsuite)
15. [Windows Operating System Archaeology](https://www.slideshare.net/enigma0x3/windows-operating-system-archaeology)



##Kernel Exploitation
###General
1. [TAKING WINDOWS 10 KERNEL EXPLOITATION TO THE NEXT LEVEL – LEVERAING WRITEWHAT-WHERE VULNERABILITIES IN CREATORS UPDATE](https://www.blackhat.com/docs/us-17/wednesday/us-17-Schenk-Taking-Windows-10-Kernel-Exploitation-To-The-Next-Level%E2%80%93Leveraging-Write-What-Where-Vulnerabilities-In-Creators-Update.pdf)
2. [Bypassing kernel ASLR Target : Windows 10](https://drive.google.com/file/d/0B3P18M-shbwrNWZTa181ZWRCclk/edit?pli=1)
3. [Analysing the NULL SecurityDescriptor kernel exploitation mitigation in the latest Windows 10 v1607 Build 14393	](https://labs.nettitude.com/blog/analysing-the-null-securitydescriptor-kernel-exploitation-mitigation-in-the-latest-windows-10-v1607-build-14393/)
4. [[KR] Windows Kernel Exploit - Uninitialized Heap Variables(Paged Pool)](http://dokydoky.tistory.com/444)
5. [Windows exploitation in 2016](https://www.welivesecurity.com/wp-content/uploads/2017/01/Windows-Exploitation-2016-A4.pdf)
6. [Abusing GDI for ring0 exploit primitives](https://www.coresecurity.com/system/files/publications/2016/10/Abusing-GDI-Reloaded-ekoparty-2016_0.pdf)
7. [巧用COM接口IARPUninstallStringLauncher绕过UAC](http://www.freebuf.com/articles/system/116611.html)
8. [Windows Kernel Address Leaks](https://github.com/sam-b/windows_kernel_address_leaks)
9. [LPE vulnerabilities exploitation on Windows 10 Anniversary Update](http://cvr-data.blogspot.kr/2016/11/lpe-vulnerabilities-exploitation-on.html)
10. [Windows Privilege Escalation](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
11. [Abusing GDI Objects for ring0 Primitives Revolution](https://sensepost.com/blog/2017/abusing-gdi-objects-for-ring0-primitives-revolution/)
12. [Direct X – Direct way to Microsoft Windows Kernel](http://2015.zeronights.org/assets/files/11-Tarakanov.pdf)
13. [ADVANCED HEAP MANIPULATION IN WINDOWS 8](https://media.blackhat.com/eu-13/briefings/Liu/bh-eu-13-liu-advanced-heap-slides.pdf)
14. [윈도우 커널 익스플로잇](https://www.slideshare.net/SSRINCLee/ss-79766206)



###1-day
1. [Windows Kernel Exploitation 101: Exploiting CVE-2014-4113](https://www.exploit-db.com/docs/39665.pdf)
2. [Root Cause Analysis of Windows Kernel UAF Vulnerability lead to CVE-2016-3310](https://blog.fortinet.com/2016/08/17/root-cause-analysis-of-windows-kernel-uaf-vulnerability-lead-to-cve-2016-3310)
3. [WoW64 and So Can You : Bypassing EMET With a Single Instruction](https://duo.com/assets/pdf/wow-64-and-so-can-you.pdf)
4. [Exploiting MS16-098 RGNOBJ Integer Overflow on Windows 8.1 x64 bit by abusing GDI objects](https://sensepost.com/blog/2017/exploiting-ms16-098-rgnobj-integer-overflow-on-windows-8.1-x64-bit-by-abusing-gdi-objects/)
5. [Detecting and mitigating elevation-of-privilege exploit for CVE-2017-0005](https://blogs.technet.microsoft.com/mmpc/2017/03/27/detecting-and-mitigating-elevation-of-privilege-exploit-for-cve-2017-0005/)
6. [kernel vulnerability](https://github.com/tinysec/vulnerability)
7. [Windows Kernel Local Denial-of-Service #1: win32k!NtUserThunkedMenuItemInfo (Windows 7-10)](http://j00ru.vexillium.org/?p=3101)
8. [Windows Kernel Local Denial-of-Service #2: win32k!NtDCompositionBeginFrame (Windows 8-10)](http://j00ru.vexillium.org/?p=3151)
9. [Windows Kernel Local Denial-of-Service #3: nt!NtDuplicateToken (Windows 7-8)](http://j00ru.vexillium.org/?p=3187)
10. [Windows Kernel Local Denial-of-Service #4: nt!NtAccessCheck and family (Windows 8-10)](http://j00ru.vexillium.org/?p=3225)
11. [Windows Kernel Local Denial-of-Service #5: win32k!NtGdiGetDIBitsInternal (Windows 7-10)](http://j00ru.vexillium.org/?p=3251)
12. [SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits) : fucking cool!!!!!
13. [windows-kernel-exploits-1](https://github.com/Fandu2014/windows-kernel-exploits-1)
14. [内核漏洞进击之旅 – Dark Composition Exploitation Case Study](http://www.shellsec.com/news/48579.html)
15. [Win32k Dark Composition](https://cansecwest.com/slides/2017/CSW2017_PengQiu-ShefangZhong_win32k_dark_composition.pdf)
16. [Kernel Driver mmap Handler Exploitation](https://labs.mwrinfosecurity.com/assets/BlogFiles/mwri-mmap-exploitation-whitepaper-2017-09-18.pdf)
17. [Exploit-CVE-2017-6008](https://github.com/cbayet/Exploit-CVE-2017-6008)
18. [[Local Exploit] Windows NDPROXY Local SYSTEM Privilege Escalation Zero-Day (CVE-2013-5065)](http://hackability.kr/entry/Local-Exploit-Windows-NDPROXY-Local-SYSTEM-Privilege-Escalation-ZeroDay-CVE20135065)



###Solutions of HEVD
1. [sizzop](https://sizzop.github.io/)
2. [First exploit in Windows Kernel (HEVD)](https://blahcat.github.io/2017/08/18/first-exploit-in-windows-kernel-hevd/)


##Kernel Fuzzing
1. [FUZZING THE WINDOWS KERNEL](https://labs.mwrinfosecurity.com/assets/BlogFiles/mwri-fuzzing-the-windows-kernel.pdf)
2. [Platform Agnostic Kernel Fuzzing](https://labs.mwrinfosecurity.com/assets/BlogFiles/mwri-Platform-Agnostic-Kernel-Fuzzing-FINAL.pdf) : cross platform fuzzer
video : https://www.youtube.com/watch?v=rv5PqCEVG_U
3. [kAFL](https://www.usenix.org/system/files/conference/usenixsecurity17/sec17-schumilo.pdf)
4. [GDI Font Fuzzing in Windows Kernel for Fun](https://media.blackhat.com/bh-eu-12/Lee/bh-eu-12-Lee-GDI_Font_Fuzzing-WP.pdf)
5. [Windows Kernel Fuzzing for Beginners](https://fuzzinginfo.files.wordpress.com/2012/11/nagy-kernel.pdf)
video : https://www.reddit.com/r/fuzzing/comments/1n3h05/windows_kernel_fuzzing_for_beginners_ben_nagy/
6. [fuzzing.info](https://fuzzing.info/papers/)
7. [IOCTL Fuzzer v1.2](https://www.darknet.org.uk/2010/12/ioctl-fuzzer-v1-2-fuzzing-tool-for-windows-kernel-drivers/)
8. [Evolutionary Kernel Fuzzing](https://moflow.org/Presentations/Evolutionary%20Kernel%20Fuzzing-BH2017-rjohnson-FINAL.pdf)



##ProjectZero(All interesting articles)
1. [Windows Kernel ATMFD.DLL unlimited out-of-bounds stack manipulation via BLEND operator](https://bugs.chromium.org/p/project-zero/issues/detail?id=180&can=1&q=CVE-2015-0093)
2. [Windows Kernel ATMFD.DLL read/write-what-where in LOAD and STORE operators](https://bugs.chromium.org/p/project-zero/issues/detail?id=177&redir=1)
3. [Windows Kernel stack memory disclosure in win32kfull!SfnINLPUAHDRAWMENUITEM](https://bugs.chromium.org/p/project-zero/issues/detail?id=1192&can=1&q&sort=-id)
4. [One font vulnerability to rule them all #1: Introducing the BLEND vulnerability](https://googleprojectzero.blogspot.kr/2015/07/one-font-vulnerability-to-rule-them-all.html)
5. [One font vulnerability to rule them all #2: Adobe Reader RCE exploitation](https://googleprojectzero.blogspot.kr/2015/08/one-font-vulnerability-to-rule-them-all.html)
6. [One font vulnerability to rule them all #3: Windows 8.1 32-bit sandbox escape exploitation](https://googleprojectzero.blogspot.kr/2015/08/one-font-vulnerability-to-rule-them-all_13.html)
7. [One font vulnerability to rule them all #4: Windows 8.1 64-bit sandbox escape exploitation](https://googleprojectzero.blogspot.kr/2015/08/one-font-vulnerability-to-rule-them-all_21.html)
8. [Windows 10 Symbolic Link Mitigations](https://googleprojectzero.blogspot.kr/2015/08/windows-10hh-symbolic-link-mitigations.html)
9. [Windows Drivers are True’ly Tricky](https://googleprojectzero.blogspot.kr/2015/10/windows-drivers-are-truely-tricky.html)
10. [Windows Sandbox Attack Surface Analysis](https://googleprojectzero.blogspot.kr/2015/11/windows-sandbox-attack-surface-analysis.html)
11. [Raising the Dead](https://googleprojectzero.blogspot.kr/2016/01/raising-dead.html)
12. [The Definitive Guide on Win32 to NT Path Conversion](https://googleprojectzero.blogspot.kr/2016/02/the-definitive-guide-on-win32-to-nt.html)
13. [Exploiting a Leaked Thread Handle](https://googleprojectzero.blogspot.kr/2016/03/exploiting-leaked-thread-handle.html)
14. [Race you to the kernel!](https://googleprojectzero.blogspot.kr/2016/03/race-you-to-kernel.html)
15. [Exploiting Recursion in the Linux Kernel](https://googleprojectzero.blogspot.kr/2016/06/exploiting-recursion-in-linux-kernel_20.html)
16. [A year of Windows kernel font fuzzing #1: the results](https://googleprojectzero.blogspot.kr/2016/06/a-year-of-windows-kernel-font-fuzzing-1_27.html)
17. [A year of Windows kernel font fuzzing #2: the techniques](https://googleprojectzero.blogspot.kr/2016/07/a-year-of-windows-kernel-font-fuzzing-2.html)
18. [Breaking the Chain](https://googleprojectzero.blogspot.kr/2016/11/breaking-chain.html)
19. [Attacking the Windows NVIDIA Driver](https://googleprojectzero.blogspot.kr/2017/02/attacking-windows-nvidia-driver.html)
20. [Notes on Windows Uniscribe Fuzzing](https://googleprojectzero.blogspot.kr/2017/04/notes-on-windows-uniscribe-fuzzing.html)
21. [Exploiting .NET Managed DCOM](https://googleprojectzero.blogspot.kr/2017/04/exploiting-net-managed-dcom.html)
22. [Windows Exploitation Tricks: Arbitrary Directory Creation to Arbitrary File Read](https://googleprojectzero.blogspot.kr/2017/08/windows-exploitation-tricks-arbitrary.html)
23. [Using Binary Diffing to Discover Windows Kernel Memory Disclosure Bugs](https://googleprojectzero.blogspot.kr/2017/10/using-binary-diffing-to-discover.html)


##Other useful links
1. [fuzzysecurity](http://www.fuzzysecurity.com/tutorials.html) : exploitation for all platform
2. [KASLRfinder](https://github.com/ufrisk/kaslrfinder)
3. [j00ru](http://j00ru.vexillium.org/)
4. [Windows X86 System Call Table](http://j00ru.vexillium.org/syscalls/nt/32/)
5. [Windows X86-64 System Call Table](http://j00ru.vexillium.org/syscalls/nt/64/)
6. [Windows WIN32K.SYS System Call Table](http://j00ru.vexillium.org/syscalls/win32k/32/)
7. [Windows x86-64 WIN32K.SYS System Call Table](http://j00ru.vexillium.org/syscalls/win32k/64/)
8. [HomePosts archiveContact GoGoGadget – kernel exploitation helper class](http://blog.rewolf.pl/blog/?p=1739)
9. [shovelMan](http://shovelman.tistory.com/) : Not ningan