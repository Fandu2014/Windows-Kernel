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

##Chinese articles (Awesome Chinese Hackers!!!)
1. [Windows内核存在漏洞，影响Windows2000到Windows10所有版本](http://www.freebuf.com/vuls/147114.html)
2. [Windows内核漏洞CVE-2016-0143分析](http://www.freebuf.com/vuls/103064.html)
3. [使用WinDbg调试Windows内核(一)](http://www.freebuf.com/articles/web/99512.html)
4. [使用WinDbg调试Windows内核(二)](http://www.freebuf.com/articles/network/99856.html)
5. [Windows内核漏洞MS15-010/CVE-2015-0057分析及利用（含EXP）](http://www.freebuf.com/vuls/90501.html)
6. [Win10Pcap-Exploit：利用Win10Pcap内核驱动程序漏洞实现本地提权](http://www.freebuf.com/news/82310.html)
7. [Win64bit提权0day漏洞（CVE-2014-4113）只是内核模式漏洞的开始](http://www.freebuf.com/vuls/48239.html)
8. [补丁上的漏洞：微软NDProxy.sys内核漏洞金山毒霸防御绕过（视频）](http://www.freebuf.com/vuls/18856.html)
9. [Windows内核EPATHOBJ 0day漏洞](http://www.freebuf.com/vuls/9766.html)
10. [Intel Sysret (CVE-2012-0217)内核提权漏洞](http://www.freebuf.com/vuls/6457.html)
11. [研究人员发现针对Win8的新型内核级漏洞](http://www.freebuf.com/news/5792.html)
12. [Edge Sandbox绕过后续及Windows 10 TH2新安全特性](http://blogs.360.cn/blog/poc_edgesandboxbypass_win10th2_new_security_features/)
13. [Hacking Team攻击代码分析Part5: Adobe Font Driver内核权限提升漏洞第二弹+Win32k KALSR绕过漏洞](http://blogs.360.cn/blog/hacking-team-part5-atmfd-0day-2/)
14. [谈谈15年5月修复的三个0day](http://blogs.360.cn/blog/fixed_three_0days_in_may/)
15. [Windows10安全增强：Build 9926引入的两个字体安全特性](http://blogs.360.cn/blog/windows10_font_security_mitigations/)
16. [NtApphelpCacheControl漏洞分析](http://blogs.360.cn/blog/ntapphelpcachecontrol_vulnerability_anaysis/)
17. [谈一个Kernel32当中的ANSI到Unicode转换的问题](http://blogs.360.cn/blog/%E8%B0%88%E4%B8%80%E4%B8%AAkernel32%E5%BD%93%E4%B8%AD%E7%9A%84ansi%E5%88%B0unicode%E8%BD%AC%E6%8D%A2%E7%9A%84%E9%97%AE%E9%A2%98/)
18. [自动化挖掘 windows 内核信息泄漏漏洞](http://www.iceswordlab.com/2017/06/14/Automatically-Discovering-Windows-Kernel-Information-Leak-Vulnerabilities_zh/)
19. [CVE-2016-3308 / ZDI-16-453 Microsoft Windows内核提权漏洞原理分析与利用](http://docs.ioin.in/writeup/lab.seclover.com/6499df39-b0a3-42de-85ce-cd5e21b075a4/index.html)
20. [【技术分享】用户模式下基于异常和内核控制的线程级钩子技术分析](http://bobao.360.cn/learning/detail/4591.html)
21. [【技术分享】利用WinDbg本地内核调试器攻陷 Windows 内核](http://bobao.360.cn/learning/detail/4477.html)
22. [技术分享】Windows内核池喷射的乐趣](http://bobao.360.cn/learning/detail/4439.html)
23. [【技术分享】瓮中之鳖：Windows内核池混合对象利用](http://bobao.360.cn/learning/detail/4434.html)
24. [【技术分享】Windows内核Pool溢出漏洞：组合对象的Spray利用](http://bobao.360.cn/learning/detail/4384.html)
25. [【技术分享】内核池溢出漏洞利用实战之Windows 10篇](http://bobao.360.cn/learning/detail/4221.html)
26. [【技术分享】内核池溢出漏洞利用实战之Windows 7篇](http://bobao.360.cn/learning/detail/4188.html)
27. [【技术分享】Windows内核池漏洞利用技术](http://bobao.360.cn/learning/detail/4066.html)
28. [【技术分享】Windows内核利用之旅：熟悉HEVD（附视频演示）](http://bobao.360.cn/learning/detail/4002.html)
29. [【技术分享】Windows内核池喷射](http://bobao.360.cn/learning/detail/3921.html)
30. [【技术分享】Windows 内核攻击：栈溢出](http://bobao.360.cn/learning/detail/3712.html)
31. [【技术分享】如何利用Windows默认内核调试配置实现代码执行并获取管理员权限](http://bobao.360.cn/learning/detail/3647.html)
32. [【技术分享】探索基于Windows 10的Windows内核Shellcode（Part 1）](http://bobao.360.cn/learning/detail/3575.html)
33. [【技术分享】探索基于Windows 10的Windows内核Shellcode（Part 2）](http://bobao.360.cn/learning/detail/3593.html)
34. [技术分享】探索基于Windows 10的Windows内核Shellcode（Part 3）](http://bobao.360.cn/learning/detail/3624.html)
35. [【技术分享】探索基于Windows 10的Windows内核Shellcode（Part 4）](http://bobao.360.cn/learning/detail/3643.html)
36. [【技术分享】HEVD内核漏洞训练之SMEP绕过](http://bobao.360.cn/learning/detail/3570.html)
37. [【技术分享】通过内核地址保护措施，回顾Windows安全加固技术](http://bobao.360.cn/learning/detail/3565.html)
38. [技术分享】HEVD内核漏洞训练——陪Windows玩儿](http://bobao.360.cn/learning/detail/3544.html)
39. [【技术分享】从MS16-098看Windows 8.1内核漏洞利用](http://bobao.360.cn/learning/detail/3384.html)
40. [【技术分享】Windows exploit开发系列教程：内核利用- >内存池溢出](http://bobao.360.cn/learning/detail/3376.html)
41. [【漏洞分析】	CVE-2016-7255：分析挖掘Windows内核提权漏洞](http://bobao.360.cn/learning/detail/3359.html)
42. [【技术分享】经典内核漏洞调试笔记之二](http://bobao.360.cn/learning/detail/3184.html)
43. [技术分享】经典内核漏洞调试笔记](http://bobao.360.cn/learning/detail/3170.html)
44. [【漏洞分析】MS16-124：微软内核整型溢出漏洞](http://bobao.360.cn/learning/detail/3153.html)
45. [Microsoft Windows内核提权漏洞原理分析与利用(CVE-2016-3308 / ZDI-16-453)](http://bobao.360.cn/learning/detail/3024.html)
46. [Windows 8.1内核利用—CVE-2014-4113漏洞分析](http://bobao.360.cn/learning/detail/2989.html)
47. [【技术分享】CVE-XX-XX：“Atom截胡”Windows内核提权漏洞分析](http://bobao.360.cn/learning/detail/3017.html)
48. [MS14-063（CVE-2014-4115）FAT32驱动内核溢出分析](http://bobao.360.cn/learning/detail/118.html)






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