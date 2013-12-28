Auto Registry Parser 
====================  

The idea started out as one to duplicate autoruns to the extent possible with offline registry analysis. Then I started adding things at random.

Thanks to:
==========

@williballenthin - http://www.williballenthin.com for writing python-registry, which is what I used.

@hiddenillusion - This got me started on the idea. https://github.com/williballenthin/python-registry/blob/master/samples/forensicating.py

HELP
=====

usage: autoreg-parse.py [-h] [-nt NTUSER] [-sys SYSTEM] [-soft SOFTWARE]

Parse the Windows registry for malware-ish related artifacts.

optional arguments:
  -h, --help            show this help message and exit
  -nt NTUSER, --ntuser NTUSER
                        Path to the NTUSER.DAT hive you want parsed
  -sys SYSTEM, --system SYSTEM
                        Path to the SYSTEM hive you want parsed
  -soft SOFTWARE, --software SOFTWARE
                        Path to the SOFTWARE hive you want parsed
                        
EXAMPLE
=======

python autoreg-parse.py -nt NTUSER.DAT -sys system -soft software 


===================================================
OS INFORMATION
===================================================
Computer Name: WINXPX86
Operating System: Microsoft Windows XP 5.1 1.511.1
Install Date: Sat Mar 09 07:50:23 2013 (UTC)

===================================================
TRADITIONAL "RUN" KEYS
===================================================
Key: BluetoothAuthenticationAgent
Value: rundll32.exe bthprops.cpl,,BluetoothAuthenticationAgent
RegPath: Microsoft\Windows\CurrentVersion\Run

Key: VMware User Process
Value: "C:\Program Files\VMware\VMware Tools\vmtoolsd.exe" -n vmusr
RegPath: Microsoft\Windows\CurrentVersion\Run

Key: LogMeIn GUI
Value: "C:\Program Files\LogMeIn\x86\LogMeInSystray.exe"
RegPath: Microsoft\Windows\CurrentVersion\Run


===================================================
AppInit_DLLs
===================================================
Key: AppInit_DLLs
Value: 
RegPath: Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs


===================================================
WINDOWS LOGON
===================================================
Key: Winlogon
Value: Explorer.exe
RegPath: Microsoft\Windows NT\CurrentVersion\Winlogon

Key: Winlogon
Value: C:\WINDOWS\system32\userinit.exe,
RegPath: Microsoft\Windows NT\CurrentVersion\Winlogon


===================================================
SESSION MANAGER INFORMATION
===================================================
Key: BootExecute
Value: autocheck autochk *

Key: PendingFileRenameOperations
Value: \??\C:\DOCUME~1\ADMINI~1\LOCALS~1\Temp\vmware-Administrator\VMwareDnD\28f163d6\SecEvent.Evt

Key: PendingFileRenameOperations
Value: \??\C:\DOCUME~1\ADMINI~1\LOCALS~1\Temp\vmware-Administrator\VMwareDnD\28f163d6\

Key: PendingFileRenameOperations
Value: \??\C:\DOCUME~1\ADMINI~1\LOCALS~1\Temp\vmware-Administrator\VMwareDnD\28f163d6\5fae5ea29967d782e39acc5a86ac270287ee3c8075ac155d650011cc2252bc9b

Key: PendingFileRenameOperations
Value: \??\C:\DOCUME~1\ADMINI~1\LOCALS~1\Temp\vmware-Administrator\VMwareDnD\28f163d6\


===================================================
BROWSER HELPER OBJECTS
===================================================

===================================================
ACTIVE SETUP - INSTALLED COMPONENTS 
===================================================
Key: >{26923b43-4d38-484f-9b9e-de460746276c}
Value: %systemroot%\system32\shmgrate.exe OCInstallUserConfigIE

Key: >{881dd1c5-3dcf-431b-b061-f3f88e8be88a}
Value: %systemroot%\system32\shmgrate.exe OCInstallUserConfigOE

Key: {2C7339CF-2B09-4501-B3F3-F3508C9228ED}
Value: %SystemRoot%\system32\regsvr32.exe /s /n /i:/UserInstall %SystemRoot%\system32\themeui.dll

Key: {44BBA840-CC51-11CF-AAFA-00AA00B6015C}
Value: "%ProgramFiles%\Outlook Express\setup50.exe" /APP:OE /CALLER:WINNT /user /install

Key: {44BBA842-CC51-11CF-AAFA-00AA00B6015B}
Value: rundll32.exe advpack.dll,LaunchINFSection C:\WINDOWS\INF\msnetmtg.inf,NetMtg.Install.PerUser.NT

Key: {4b218e3e-bc98-4770-93d3-2731b9329278}
Value: %SystemRoot%\System32\rundll32.exe setupapi,InstallHinfSection MarketplaceLinkInstall 896 %systemroot%\inf\ie.inf

Key: {5945c046-1e7d-11d1-bc44-00c04fd912be}
Value: rundll32.exe advpack.dll,LaunchINFSection C:\WINDOWS\INF\msmsgs.inf,BLC.QuietInstall.PerUser

Key: {6BF52A52-394A-11d3-B153-00C04F79FAA6}
Value: rundll32.exe advpack.dll,LaunchINFSection C:\WINDOWS\INF\wmp.inf,PerUserStub

Key: {7790769C-0471-11d2-AF11-00C04FA35D02}
Value: "%ProgramFiles%\Outlook Express\setup50.exe" /APP:WAB /CALLER:WINNT /user /install

Key: {89820200-ECBD-11cf-8B85-00AA005B4340}
Value: regsvr32.exe /s /n /i:U shell32.dll

Key: {89820200-ECBD-11cf-8B85-00AA005B4383}
Value: %SystemRoot%\system32\ie4uinit.exe


===================================================
SERVICE IMAGE PATHS NOT IN SYSTEM32 (Type 2)
===================================================
[ALERT!!] 
ServiceName: HWDeviceService.exe
ImagePath: "c:\documents and settings\all users\application data\datacardservice\hwdeviceservice.exe" -/service

[ALERT!!] 
ServiceName: LMIGuardianSvc
ImagePath: "c:\program files\logmein\x86\lmiguardiansvc.exe"

[ALERT!!] 
ServiceName: LMIInfo
ImagePath: \??\c:\program files\logmein\x86\rainfo.sys

[ALERT!!] 
ServiceName: LMIMaint
ImagePath: "c:\program files\logmein\x86\ramaint.exe"

[ALERT!!] 
ServiceName: LogMeIn
ImagePath: "c:\program files\logmein\x86\logmein.exe"

[ALERT!!] 
ServiceName: VMMEMCTL
ImagePath: \??\c:\program files\common files\vmware\drivers\memctl\vmmemctl.sys

[ALERT!!] 
ServiceName: VMTools
ImagePath: "c:\program files\vmware\vmware tools\vmtoolsd.exe"

[ALERT!!] 
ServiceName: VMware Physical Disk Helper Service
ImagePath: "c:\program files\vmware\vmware tools\vmacthlp.exe"

[ALERT!!] 
ServiceName: . etadpug
ImagePath: "c:\program files\google\desktop\install\{0f91adea-a35c-b700-d36c-83378aa58eea}\   \   \\{0f91adea-a35c-b700-d36c-83378aa58eea}\googleupdate.exe" <


===================================================
SERVICE IMAGE PATHS NOT IN SYSTEM32 (Type 0)
===================================================

===================================================
LIST OF ALL AUTOSTART SERVICES
===================================================
ServiceName: AudioSrv
ImagePath: %systemroot%\system32\svchost.exe -k netsvcs

ServiceName: Browser
ImagePath: %systemroot%\system32\svchost.exe -k netsvcs

ServiceName: BthServ
ImagePath: %systemroot%\system32\svchost.exe -k bthsvcs

ServiceName: CryptSvc
ImagePath: %systemroot%\system32\svchost.exe -k netsvcs

ServiceName: DcomLaunch
ImagePath: %systemroot%\system32\svchost -k dcomlaunch

ServiceName: Dhcp
ImagePath: %systemroot%\system32\svchost.exe -k netsvcs

ServiceName: dmserver
ImagePath: %systemroot%\system32\svchost.exe -k netsvcs

ServiceName: Dnscache
ImagePath: %systemroot%\system32\svchost.exe -k networkservice

ServiceName: ERSvc
ImagePath: %systemroot%\system32\svchost.exe -k netsvcs

ServiceName: Eventlog
ImagePath: %systemroot%\system32\services.exe

ServiceName: helpsvc
ImagePath: %systemroot%\system32\svchost.exe -k netsvcs

ServiceName: HWDeviceService.exe
ImagePath: "c:\documents and settings\all users\application data\datacardservice\hwdeviceservice.exe" -/service

ServiceName: LanmanServer
ImagePath: %systemroot%\system32\svchost.exe -k netsvcs

ServiceName: lanmanworkstation
ImagePath: %systemroot%\system32\svchost.exe -k netsvcs

ServiceName: LmHosts
ImagePath: %systemroot%\system32\svchost.exe -k localservice

ServiceName: LMIGuardianSvc
ImagePath: "c:\program files\logmein\x86\lmiguardiansvc.exe"

ServiceName: LMIInfo
ImagePath: \??\c:\program files\logmein\x86\rainfo.sys

ServiceName: LMIMaint
ImagePath: "c:\program files\logmein\x86\ramaint.exe"

ServiceName: LMIRfsDriver
ImagePath: \??\c:\windows\system32\drivers\lmirfsdriver.sys

ServiceName: LogMeIn
ImagePath: "c:\program files\logmein\x86\logmein.exe"

ServiceName: NPF
ImagePath: system32\drivers\npf.sys

ServiceName: PlugPlay
ImagePath: %systemroot%\system32\services.exe

ServiceName: ProtectedStorage
ImagePath: %systemroot%\system32\lsass.exe

ServiceName: RemoteRegistry
ImagePath: %systemroot%\system32\svchost.exe -k localservice

ServiceName: RpcSs
ImagePath: %systemroot%\system32\svchost -k rpcss

ServiceName: SamSs
ImagePath: %systemroot%\system32\lsass.exe

ServiceName: Schedule
ImagePath: %systemroot%\system32\svchost.exe -k netsvcs

ServiceName: seclogon
ImagePath: %systemroot%\system32\svchost.exe -k netsvcs

ServiceName: SENS
ImagePath: %systemroot%\system32\svchost.exe -k netsvcs

ServiceName: ShellHWDetection
ImagePath: %systemroot%\system32\svchost.exe -k netsvcs

ServiceName: Spooler
ImagePath: %systemroot%\system32\spoolsv.exe

ServiceName: srservice
ImagePath: %systemroot%\system32\svchost.exe -k netsvcs

ServiceName: Themes
ImagePath: %systemroot%\system32\svchost.exe -k netsvcs

ServiceName: TrkWks
ImagePath: %systemroot%\system32\svchost.exe -k netsvcs

ServiceName: VMMEMCTL
ImagePath: \??\c:\program files\common files\vmware\drivers\memctl\vmmemctl.sys

ServiceName: VMTools
ImagePath: "c:\program files\vmware\vmware tools\vmtoolsd.exe"

ServiceName: VMware Physical Disk Helper Service
ImagePath: "c:\program files\vmware\vmware tools\vmacthlp.exe"

ServiceName: W32Time
ImagePath: %systemroot%\system32\svchost.exe -k netsvcs

ServiceName: WebClient
ImagePath: %systemroot%\system32\svchost.exe -k localservice

ServiceName: winmgmt
ImagePath: %systemroot%\system32\svchost.exe -k netsvcs

ServiceName: wuauserv
ImagePath: %systemroot%\system32\svchost.exe -k netsvcs

ServiceName: WZCSVC
ImagePath: %systemroot%\system32\svchost.exe -k netsvcs

ServiceName: . etadpug
ImagePath: "c:\program files\google\desktop\install\{0f91adea-a35c-b700-d36c-83378aa58eea}\   \   \\{0f91adea-a35c-b700-d36c-83378aa58eea}\googleupdate.exe" <


===================================================
KNOWN DLLs
===================================================
Key: advapi32
Value: advapi32.dll

Key: comdlg32
Value: comdlg32.dll

Key: DllDirectory
Value: %SystemRoot%\system32

Key: gdi32
Value: gdi32.dll

Key: imagehlp
Value: imagehlp.dll

Key: kernel32
Value: kernel32.dll

Key: lz32
Value: lz32.dll

Key: ole32
Value: ole32.dll

Key: oleaut32
Value: oleaut32.dll

Key: olecli32
Value: olecli32.dll

Key: olecnv32
Value: olecnv32.dll

Key: olesvr32
Value: olesvr32.dll

Key: olethk32
Value: olethk32.dll

Key: rpcrt4
Value: rpcrt4.dll

Key: shell32
Value: shell32.dll

Key: url
Value: url.dll

Key: urlmon
Value: urlmon.dll

Key: user32
Value: user32.dll

Key: version
Value: version.dll

Key: wininet
Value: wininet.dll

Key: wldap32
Value: wldap32.dll


=================================================================
MOUNTPOINTS2 and NETWORK MRUs (XP) -> POSSIBLE LATERAL MOVEMENT
=================================================================
MountPoints2 Share: ##<IP_Address#<share_name>
Last Write: 2010-07-19 06:19:59.577688

MountPoints2 Share: ##<IP_Address#<share_name>
Last Write: 2013-10-23 06:00:40.593750

MountPoints2 Share: ##<IP_Address#<share_name>
Last Write: 2013-10-23 06:00:40.593750

MountPoints2 Share: ##<IP_Address#<share_name>
Last Write: 2012-05-25 06:20:35.786167

MountPoints2 Share: ##<IP_Address#<share_name>
Last Write: 2011-01-27 08:47:49.465586

Network MRU: a
Share: \\<IP_Address>\<share_name>
Last Write: 2011-01-27 08:47:48.731297

Network MRU: b
Share: \\<IP_Address>\<share_name>
Last Write: 2011-01-27 08:47:48.731297

Network MRU: c
Share: \\<IP_Address>\<share_name>
Last Write: 2011-01-27 08:47:48.731297

Network MRU: d
Share: \\<IP_Address>\<share_name>
Last Write: 2011-01-27 08:47:48.731297

===================================================
SYSINTERNAL TOOLS THAT HAVE BEEN RUN 
===================================================
Key: AutoRuns
Last Write: 2013-04-18 07:09:57.140547

Key: Diskmon
Last Write: 2013-04-18 07:29:58.570456

Key: DiskView
Last Write: 2013-04-18 07:29:23.686098

Key: Handle
Last Write: 2013-10-15 09:38:43.385448

Key: ListDLLs
Last Write: 2013-10-15 09:38:43.869789

Key: LogonSessions
Last Write: 2013-04-18 07:16:46.231375

Key: Process Monitor
Last Write: 2013-10-16 02:19:53.039183

Key: PsList
Last Write: 2013-04-21 18:06:06.553217

Key: PsLoggedon
Last Write: 2013-04-18 07:15:58.311071

Key: TCPView
Last Write: 2013-10-15 09:27:22.970438
