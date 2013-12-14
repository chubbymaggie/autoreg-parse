__author__ = 'Patrick Olsen'

'''
Author: Patrick Olsen
Email: patrickolsen@sysforensics.org
Twitter: @patrickrolsen

TODO:
X = Done, O = Partially done and implemented

[O] Add [x]install date, [x]OS version, [x]Computer name, []Shutdown time, []SIDS
[ ] Add Terminal services information: NTUSER: Software\Microsoft\Terminal Server Client\Default
[X] Run Keys
[ ] Services
[ ] WinRar - reg query HKCU\\Software\\WinRAR\\DialogEditHistory\\ArcName
[ ] 7zip - reg query "HKCU\\Software\\7-Zip"
[X] Sysinternals - reg query "HKCU\\Software\\Sysinternals
[ ] TypedURLs? - HKCU\\Software\\Microsoft\\Internet Explorer\\TypedURLs
[ ] Do something with the hashing function
[X] Add support for session manager info
[X] Added AppInit_DLLs
[X] Known DLLs
[ ] Decide which keys I want to have last write time for (besides Sysinternals)

'''

import sys
import os
import time
import platform
import hashlib
import re
from Registry import Registry

reg_nt = Registry.Registry(sys.argv[1])
reg_soft = Registry.Registry(sys.argv[2])
reg_sys = Registry.Registry(sys.argv[3])

def usage():
    return "  USAGE:\n\t%s <Windows Registry file> <Registry key path>" % sys.argv[0]

def getSysInfo():
    if len(sys.argv) != 4:
        print(usage())
        sys.exit(-3)

    os_dict = {}

    k = reg_soft.open("Microsoft\\Windows NT\\CurrentVersion")

    try:
        for v in k.values():
            if v.name() == "ProductName":
                os_dict['ProductName'] = v.value()
            if v.name() == "EditionID":
                os_dict['EditionID'] = v.value()
            if v.name() == "CurrentBuild":
                os_dict['CurrentBuild'] = v.value()
            if v.name() == "CurrentVersion":
                os_dict['CurrentVersion'] = v.value()
            if v.name() == "InstallDate":
                os_dict['InstallDate'] = time.strftime('%a %b %d %H:%M:%S %Y (UTC)', time.gmtime(v.value()))
            else:
                pass

    except Registry.RegistryKeyNotFoundException as e:
        pass


    select = reg_sys.open("Select")
    current = select.value("Current").value()
    computerName = reg_sys.open("ControlSet00%d\\Control\\ComputerName\\ComputerName" % (current))

    try:
        for v in computerName.values():
            if v.name() == "ComputerName":
                os_dict["ComputerName"] = v.value()
            else:
                pass

    except Registry.RegistryKeyNotFoundException as e:
        pass

    print ("\n" + ("=" * 51) + "\nOS INFORMATION\n" + ("=" * 51))
    print "Computer Name: " + os_dict['ComputerName']
    print "Operating System: " + os_dict['ProductName'], os_dict['CurrentVersion'], os_dict['CurrentBuild']
    print "Install Date: " + os_dict['InstallDate']

def getServices():

    if len(sys.argv) != 4:
        print(usage())
        sys.exit(-3)

    select = reg_sys.open("Select")
    current = select.value("Current").value()
    services = reg_sys.open("ControlSet00%d\\Services" % (current))

    service_list        = []

    for service in services.subkeys():
        service_list.append(service.name().lower())

    bootstart_list      = []
    kernelDriver_list   = []
    autostart_list      = []
    loadonDemand_list   = []
    disabled_list       = []


    '''
    Reference: http://support.microsoft.com/kb/103000
        Boot Loader scans the Registry for drivers with a Start value of 0 (which indicates that these drivers
        should be loaded but not initialized before the Kernel) and a Type value of 0x1 (which indicates a Kernel
        device driver such as a hard disk or other low-level hardware device driver).
    Reference: Plaso Code Base
    '''
    for service_name in service_list:
        k = reg_sys.open("ControlSet00%d\\Services\\%s" % (current, service_name))
        for v in k.values():
            if v.name() == "Start":
                start_methods = v.value()
                for service_start_code in str(start_methods):
                    # 0x0 (Boot) = Kernel Loader - Loaded by the boot loader.
                    if service_start_code == "0":
                        service_boot = k.name()
                        bootstart_list.append(service_boot)
                    # 0x1 (System) = I/O Subsystem - Driver to be loaded at Kernel initialization
                    elif service_start_code == "1":
                        service_kernelDriver = k.name()
                        kernelDriver_list.append(service_kernelDriver)
                    # 0x2 (Auto Load) = SCM - Loaded or started automatically for all start ups.
                    elif service_start_code == "2":
                        service_auto = k.name()
                        autostart_list.append(service_auto)
                    # 0x3 (Load on demand) = SCM - Not start until the user starts it.
                    elif service_start_code == "3":
                        service_loadonDemand = k.name()
                        loadonDemand_list.append(service_loadonDemand)
                    # 0x4 (Disabled) = SCM - Not to be started under any conditions.
                    else:
                        service_start_code == "4"
                        service_disabled = k.name()
                        disabled_list.append(service_disabled)

    kernelDeviceDriver_list = []
    fileSystemDriver_list   = []
    adapter_list            = []
    ownProcess_list         = []
    shareProcess_list       = []

    for service_name in service_list:
        k = reg_sys.open("ControlSet00%d\\Services\\%s" % (current, service_name))
        for v in k.values():
            if v.name() == "Type":
                service_type = v.value()
                    # 1:  Kernel Device Driver (0x1)
                if service_type == 1:
                    type_KDD = k.name()
                    kernelDeviceDriver_list.append(type_KDD)
                    # 2:  File System Driver (0x2)
                elif service_type == 2:
                    type_fileSystemDriver = k.name()
                    fileSystemDriver_list.append(type_fileSystemDriver)
                    # 4:  Adapter (0x4)
                elif service_type == 4:
                    type_Adapter = k.name()
                    adapter_list.append(type_Adapter)
                    # 16: Service - Own Process (0x10)
                elif service_type == 16:
                    type_ownProcess = k.name()
                    ownProcess_list.append(type_ownProcess)
                else:
                    # 32: Service - Share Process (0x20)
                    service_type == 32
                    type_ShareProcess = k.name()
                    shareProcess_list.append(type_ShareProcess)

    print ("\n" + ("=" * 51) + "\nSERVICE IMAGE PATHS NOT IN SYSTEM32 (Type 2)\n" + ("=" * 51))

    for name in autostart_list:
        k = reg_sys.open("ControlSet00%d\\Services\\%s" % (current, name))

        try:
            image_path = k.value("ImagePath").value().lower()

            if "system32" not in image_path.lower():
                print '[ALERT!!] \nServiceName: %s\nImagePath: %s\n' % (k.name().encode('ascii', 'ignore'), image_path.encode('ascii', 'ignore'))

        except:
            pass

    print ("\n" + ("=" * 51) + "\nSERVICE IMAGE PATHS NOT IN SYSTEM32 (Type 0)\n" + ("=" * 51))

    for name in bootstart_list:
        k = reg_sys.open("ControlSet00%d\\Services\\%s" % (current, name))

        try:
            image_path = k.value("ImagePath").value().lower()

            if "system32" not in image_path.lower():
                print '[ALERT]\nServiceName: %s\nImagePath: %s\n' % (k.name().encode('ascii', 'ignore'), image_path.encode('ascii', 'ignore'))

        except:
            pass

    # Printing all of the autostart services.
    # By that I'm talking about services with type 2 start codes.
    print ("\n" + ("=" * 51) + "\nLIST OF ALL AUTOSTART SERVICES\n" + ("=" * 51))

    for name in autostart_list:
        k = reg_sys.open("ControlSet00%d\\Services\\%s" % (current, name))

        try:
            image_path = k.value("ImagePath").value().lower()
            print 'ServiceName: %s\nImagePath: %s\n' % (k.name().encode('ascii', 'ignore'), image_path.encode('ascii', 'ignore'))

        except:
            pass

def getRunKeys():

    if len(sys.argv) != 4:
        print(usage())
        sys.exit(-3)

    print ("\n" + ("=" * 51) + "\nTRADITIONAL \"RUN\" KEYS\n" + ("=" * 51))

    #Winlogon Keys
    winlogon_list = ["Microsoft\\Windows NT\\CurrentVersion",
                     "Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify"]

    appinit_dlls =  ["Microsoft\\Windows NT\\CurrentVersion\\Windows",
                     "Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows"]

    #HKLM Keys
    hklm_run_list = ["Microsoft\\Windows\\CurrentVersion\\Run",
                     "Microsoft\\Windows\\CurrentVersion\\RunOnce",
                     "Microsoft\\Windows\\CurrentVersion\\RunOnceEx",
                     "Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
                     "Microsoft\\Active Setup\\Installed Components",
                     # "Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad",
                     # "Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers",
                     "Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
                     "Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
                     "Wow6432Node\\Microsoft\\Active Setup\\Installed Components",
                     "Microsoft\\Windows\\CurrentVersion\\Explorer\\SharedTaskScheduler",
                     "Classes\\Protocols\\Handler",
                     "Classes\\*\\ShellEx\\ContextMenuHandlers"]

    #NTUSER.DAT (HKCU) Keys
    ntuser_run_list = ["Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                       "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
                       "Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce",
                       "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows",
                       #"Software\\Wow6432Node\\Microsoft\\Active Setup\\InstalledComponents",
                       "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run"]

    try:

        for k in hklm_run_list:
            key = reg_soft.open(k)
            for v in key.values():
                if v.value_type() == Registry.RegSZ or v.value_type() == Registry.RegExpandSZ or v.value_type() == Registry.RegMultiSZ:
                    print 'Key: %s\nValue: %s\nRegPath: %s\n' % (v.name().encode('ascii', 'ignore'), v.value().encode('ascii', 'ignore'), k)

        for k in hklm_run_list:
            print k
            key = reg_sys.open(k)
            for v in key.values():
                if v.value_type() == Registry.RegSZ or v.value_type() == Registry.RegExpandSZ or v.value_type() == Registry.RegMultiSZ:
                    print 'Key: %s\nValue: %s\nRegPath: %s\n' % (v.name().encode('ascii', 'ignore'), v.value().encode('ascii', 'ignore'), k)

        for k in ntuser_run_list:
            key = reg_nt.open(k)
            for v in key.values():
                if v.value_type() == Registry.RegSZ or v.value_type() == Registry.RegExpandSZ or v.value_type() == Registry.RegMultiSZ:
                    print 'Key: %s\nValue: %s\nRegPath: %s\n' % (v.name().encode('ascii', 'ignore'), v.value().encode('ascii', 'ignore'), k)

    except Registry.RegistryKeyNotFoundException as e:
        pass

    try:
        for k in appinit_dlls:
            key = reg_soft.open(k)
            for v in key.values():
                matchObj = re.match(r"AppInit_DLLs", v.name(), re.M|re.I)
                path = k + "\\" + v.name()
                if matchObj:
                    if v.value_type() == Registry.RegSZ or v.value_type() == Registry.RegExpandSZ or v.value_type() == Registry.RegMultiSZ:
                        print 'Key: %s\nValue: %s\nRegPath: %s\n' % (v.name().encode('ascii', 'ignore'), v.value().encode('ascii', 'ignore'), path)
                else:
                    pass

    except Registry.RegistryKeyNotFoundException as e:
        pass

    try:
        for k in winlogon_list:
            key = reg_soft.open(k)
            winlogon_subkeys = key.subkeys()
            for subK in winlogon_subkeys:
                if subK.name() == "Winlogon":
                    winlogon_path = "Microsoft\\Windows NT\\CurrentVersion\Winlogon"
                    for winlogon_values in subK.values():
                        if winlogon_values.name() == "Shell":
                            print 'Key: %s\nValue: %s\nRegPath: %s\n' % (subK.name(), subK.value("Shell").value(), winlogon_path)
                        else:
                            pass
                        if winlogon_values.name() == "Userinit":
                            print 'Key: %s\nValue: %s\nRegPath: %s\n' % (subK.name(), subK.value("Userinit").value(), winlogon_path)
                        else:
                            pass
                        if winlogon_values.name() == "Taskman":
                            print 'Key: %s\nValue: %s\nRegPath: %s\n' % (winlogon_values.name() == "Taskman", winlogon_path)
                        else:
                            pass
                else:
                    pass

    except Registry.RegistryKeyNotFoundException as e:
        pass

    print ("\n" + ("=" * 51) + "\nSESSION MANAGER INFORMATION\n" + ("=" * 51))

    selectCurrent = reg_sys.open("Select")
    selectCurrentNumber = selectCurrent.value("Current").value()
    controlSetSubkeys = reg_sys.open('ControlSet00%d\\Control' % (selectCurrentNumber))

    session_manager_list = [('ControlSet00%d\\' % (selectCurrentNumber)) + controlSetSubkeys.name() + "\\Session Manager"]

    try:
        for k in session_manager_list:
            key = reg_sys.open(k)
            for v in key.values():
                if v.value_type() == Registry.RegSZ or v.value_type() == Registry.RegExpandSZ or v.value_type() == Registry.RegMultiSZ:
                    if v.name() == "PendingFileRenameOperations" or v.name() == "BootExecute":
                        for emptySpaces in v.value():
                            if emptySpaces == '':
                                pass
                            else:
                                print 'Key: %s\nValue: %s\n' % (str(v.name()).encode('ascii', 'ignore'), str(emptySpaces).encode('ascii', 'ignore'))
                    else:
                        pass

    except Registry.RegistryKeyNotFoundException as e:
        pass

def knownDLLs():

    if len(sys.argv) != 4:
        print(usage())
        sys.exit(-3)

    selectCurrent = reg_sys.open("Select")
    selectCurrentNumber = selectCurrent.value("Current").value()
    controlSetSubkeys = reg_sys.open('ControlSet00%d\\Control' % (selectCurrentNumber))

    known_DLLs_list = [('ControlSet00%d\\' % (selectCurrentNumber)) + controlSetSubkeys.name() + "\\Session Manager\\KnownDLLs"]

    print ("\n" + ("=" * 51) + "\nKNOWN DLLs\n" + ("=" * 51))

    try:
        for k in known_DLLs_list:
            key = reg_sys.open(k)
            for v in key.values():
                if v.value_type() == Registry.RegSZ or v.value_type() == Registry.RegExpandSZ or v.value_type() == Registry.RegMultiSZ:
                    print 'Key: %s\nValue: %s\n' % (str(v.name()).encode('ascii', 'ignore'), str(v.value()).encode('ascii', 'ignore'))

                else:
                    pass

    except Registry.RegistryKeyNotFoundException as e:
        pass

def getActiveSetup():

    if len(sys.argv) != 4:
        print(usage())
        sys.exit(-3)

    print ("\n" + ("=" * 51) + "\nACTIVE SETUP - INSTALLED COMPONENTS \n" + ("=" * 51))

    active_setup = ["Microsoft\\Active Setup\\Installed Components",
                    "Wow6432Node\\Microsoft\\Active Setup\\Installed Components"]

    active_setup_list = []
    try:
        for m in active_setup:
            k = reg_soft.open(m)
            for v in k.subkeys():
                active_setup_list.append(v.name())

            for keys in active_setup_list:
                k = reg_soft.open(m + "\\%s" % (keys))
                for activesets in k.values():
                    if activesets.name() == "StubPath":
                        if activesets.value() == '':
                            pass
                        else:
                            print 'Key: %s\nValue: %s\n' % (k.name().encode('ascii', 'ignore'), activesets.value().encode('ascii', 'ignore'))
                    else:
                        pass

    except Registry.RegistryKeyNotFoundException as e:
        pass

def getSysinternals():

    if len(sys.argv) != 4:
        print(usage())
        sys.exit(-3)

    print ("\n" + ("=" * 51) + "\nSYSINTERNAL TOOLS THAT HAVE BEEN RUN \n" + ("=" * 51))

    #NTUSER.DAT (HKCU) Keys
    sysinternal = ["Software\\Sysinternals"]

    try:
        for k in sysinternal:
            key = reg_nt.open(k)
            sysinternal_keys = key.subkeys()
            for sysKeys in sysinternal_keys:
                for v in sysKeys.values():
                    if "EulaAccepted" in v.name():
                        if v.value() == 1:
                            print 'Key: %s\nLast Write: %s\n' % (sysKeys.name(), sysKeys.timestamp())
                        else:
                            pass
                    else:
                        pass

    except Registry.RegistryKeyNotFoundException as e:
        pass

def getBHOs():
    if len(sys.argv) != 4:
        print(usage())
        sys.exit(-3)

    bho_keys = ["Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects",
                "Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects"]

    BHO_list = []
    BHO_names_list = []

    print ("\n" + ("=" * 51) + "\nBROWSER HELPER OBJECTS\n" + ("=" * 51))

    try:
        for b in bho_keys:
            k = reg_soft.open(b)
            for v in k.subkeys():
                BHO_list.append(v.name())

        for clsids in BHO_list:
            ke = reg_soft.open("Classes\\CLSID\\%s" % (clsids))
            BHO_names_list.append(ke.name())
            print "Key Name: %s\nPath %s\nKey Last Write: %s\n" % (ke.name(), ke.subkey("InProcServer32").value('').value(), ke.timestamp())

    except Registry.RegistryKeyNotFoundException as e:
        pass

def md5sum(filename):
    md5 = hashlib.md5()
    with open(filename,'rb') as f:
        for chunk in iter(lambda: f.read(128*md5.block_size), b''):
             md5.update(chunk)
    return md5.hexdigest()

def main():

    getSysInfo()
    getRunKeys()
    getBHOs()
    getActiveSetup()
    getServices()
    knownDLLs()
    getSysinternals()

if __name__ == "__main__":
    main()