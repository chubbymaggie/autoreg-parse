'''
Author: Patrick Olsen
Email: patrickolsen@sysforensics.org
Twitter: @patrickrolsen
'''

import time
import hashlib
import codecs
import re
import argparse
from Registry import Registry
from collections import defaultdict
from itertools import izip

parser = argparse.ArgumentParser(description='Parse the Windows registry for malware-ish related artifacts.')
parser.add_argument('-nt', '--ntuser', help='Path to the NTUSER.DAT hive you want parsed')
parser.add_argument('-sys', '--system', help='Path to the SYSTEM hive you want parsed')
parser.add_argument('-soft', '--software', help='Path to the SOFTWARE hive you want parsed')
parser.add_argument('-p', '--plugin', nargs='+', help='[lateralmovement] = MountPoints2 and Network MRUs, [urls] = TypedURLs, [mounts] = MountPoints')
args = parser.parse_args()

if args.ntuser:
    reg_nt = Registry.Registry(args.ntuser)
else:
    pass
if args.software:
    reg_soft = Registry.Registry(args.software)
else:
    pass
if args.system:
    reg_sys = Registry.Registry(args.system)
else:
    pass

def getConotrolSet(reg_sys):
    try:
        select = reg_sys.open("Select")
        current = select.value("Current").value()
        controlsetnum = "ControlSet00%d" % (current)
    
        return controlsetnum

    except Registry.RegistryKeyNotFoundException as e:
        pass

def getSysInfo(reg_soft, reg_sys):
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


    current = getConotrolSet(reg_sys)
    computerName = reg_sys.open("%s\\Control\\ComputerName\\ComputerName" % (current))

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
       
def getRunKeys(reg_soft, reg_nt, reg_sys):

    print ("\n" + ("=" * 51) + "\nTRADITIONAL \"RUN\" KEYS\n" + ("=" * 51))

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

def getAppInitDLLs(reg_soft):

    print ("\n" + ("=" * 51) + "\nAppInit_DLLs\n" + ("=" * 51))

    appinit_dlls = ["Microsoft\\Windows NT\\CurrentVersion\\Windows",
                    "Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows"]

    try:
        for k in appinit_dlls:
            key = reg_soft.open(k)
            for v in key.values():
                matchObj = re.match(r"AppInit_DLLs", v.name())
                path = k + "\\" + v.name()
                if matchObj:
                    if v.value_type() == Registry.RegSZ or v.value_type() == Registry.RegExpandSZ or v.value_type() == Registry.RegMultiSZ:
                        print 'Key: %s\nValue: %s\nRegPath: %s\n' % (v.name().encode('ascii', 'ignore'), v.value().encode('ascii', 'ignore'), path)
                else:
                    pass

    except Registry.RegistryKeyNotFoundException as e:
        pass

def getWinlogon(reg_soft):

    print ("\n" + ("=" * 51) + "\nWINDOWS LOGON\n" + ("=" * 51))

    winlogon_list = ["Microsoft\\Windows NT\\CurrentVersion",
                     "Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify"]

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
                            #print 'Key: %s\nValue: %s\nRegPath: %s\n' % (winlogon_values.name(), winlogon_path)
                        else:
                            pass
                else:
                    pass

    except Registry.RegistryKeyNotFoundException as e:
        pass

def getServices(reg_sys):
    current = getConotrolSet(reg_sys)       
    services = reg_sys.open('%s\\Services' % (current))

    service_list = []
    autostart_list = []
    autostart_dict = defaultdict(list)
    loadondemand_dict = defaultdict(list)
    
    service_baseline = []
    baseline = open("services.txt", 'r').read()
    service_baseline.append(baseline.rstrip('\n').lower())    

    for service in services.subkeys():
        service_list.append(service.name().lower())

    for service_name in service_list:
        k = reg_sys.open('%s\\Services\\%s' % (current, service_name))
    
        for v in k.values():
            if v.name() == "Start":
                start_methods = v.value()
                for service_start_code in str(start_methods):
                    # 0x2 (Auto Load) = SCM - Loaded or started automatically for all start ups.
                    if service_start_code == "2": 
                        autostart_list.append(k.name())
                        try:
                            image_path = k.value("ImagePath").value()
                        except:
                            image_path = "No Image Path Found!"
                        autostart_dict['ServiceName'].append(k.name().lower())
                        autostart_dict['ImagePath'].append(image_path.lower())
                    # 0x3 (Load on demand) = SCM - Not start until the user starts it.
                    elif service_start_code == "3": 
                        autostart_list.append(k.name())
                        try:
                            image_path = k.value("ImagePath").value()
                        except:
                            image_path = "No Image Path Found!"
                        
                        loadondemand_dict['ServiceName'].append(k.name().lower())
                        loadondemand_dict['ImagePath'].append(image_path.lower())
                        pass
                    
            else:
                pass
    
    # This doesn't take into account the Image Path as whitelisted. It's only checking the service names.
    print ("\n" + ("=" * 51) + "\nUNKNOWN/NON-BASELINED TYPE 2 SERVICES)\n" + ("=" * 51))
    
    for sname, ipath  in izip(autostart_dict['ServiceName'], autostart_dict['ImagePath']):
        for name in service_baseline: #This is a list from above.
            if sname.lower() in name.lower():
                pass
            else:
                print 'Service Name: %s\nImage Path: %s\n' % (sname, ipath.encode('ascii', 'ignore'))
      
    print ("\n" + ("=" * 51) + "\nTYPE 2 SERVICES NOT IN SYSTEM32\n" + ("=" * 51))
    
    for sname, ipath  in izip(autostart_dict['ServiceName'], autostart_dict['ImagePath']):
            #print "Service Name: %s\nImage Path: %s\n" % (sname, ipath.encode('ascii', 'ignore'))
        if "system32" not in ipath.lower():
            print "Service Name: %s\nImage Path: %s\n" % (sname, ipath.encode('ascii', 'ignore'))
        else:
            pass
def getSessionManager(reg_sys):

    print ("\n" + ("=" * 51) + "\nSESSION MANAGER INFORMATION\n" + ("=" * 51))

    current = getConotrolSet(reg_sys)       
    
    controlSetSubkeys = reg_sys.open('%s\\Control' % (current))

    session_manager_list = [('%s\\' % (current)) + controlSetSubkeys.name() + "\\Session Manager"]

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

def getKnownDLLs(reg_sys):

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

def getActiveSetup(reg_soft):

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

def getSysinternals(reg_nt):

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

def getBHOs(reg_soft):

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

def getMounted(reg_sys, reg_nt):

    print ("\n" + ("=" * 65) + "\nMOUNTPOINTS2 and NETWORK MRUs (XP) -> POSSIBLE LATERAL MOVEMENT\n" + ("=" * 65))

    mDevices = []
    mPoints2 = []

    try:
        mounteddevices = reg_sys.open("MountedDevices")
        mountpoints = reg_nt.open("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2")
        networkmru = reg_nt.open("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Map Network Drive MRU")

        for mount in mounteddevices.values():
            mDevices.append(mount.name())

        for mps in mountpoints.subkeys():
            mPoints2.append(mps.name())

            if "#" in mps.name():
                print 'MountPoints2 Share: %s\nLast Write: %s\n' % (mps.name(), mps.timestamp())
            else:
                pass

        for mrus in networkmru.values():
            if mrus.name() == "MRUList":
                pass
            else:
                print 'Network MRU: %s\nShare: %s\nLast Write: %s\n' % (mrus.name(), mrus.value(), networkmru.timestamp())

    except Registry.RegistryKeyNotFoundException as e:
        pass

        '''
        This would link back to a drive being opened by a specific user at some point in time. Maybe i'll add this later.

        for x in mPoints2:
            for y in mDevices:
                if re.search(x, y):
                    print x, y
                else:
                    pass
        '''
def getArchives(reg_nt):

    print ("\n" + ("=" * 51) + "\nARCHIVE LOCATIONS (WinZip, WinRAR, and 7zip)\n" + ("=" * 51))

    #archivedFiles = []

    try:
        print ("WINZIP: Software\\Nico Mak Computing\\WinZip\\filemenu")
        winzip = reg_nt.open("Software\\Nico Mak Computing\\WinZip")        
        for wz_archives in winzip.subkeys():
            if wz_archives.name() == 'filemenu':
                print 'LastWrite Time: %s\n' % (winzip.timestamp())
                for wz_v in wz_archives.values():
                    print '%s -> %s' % (wz_v.name(), wz_v.value())
            else:
                pass            
        
        print ("\n""WINZIP: Software\\Nico Mak Computing\\WinZip\\WIZDIR")      
        for wz_archives in winzip.subkeys():
            if wz_archives.name() == 'WIZDIR':
                print 'LastWrite Time: %s\n' % (winzip.timestamp())
                for wz_v in wz_archives.values():
                    print '%s -> %s' % (wz_v.name(), wz_v.value())        
            else:
                pass
    
    except Registry.RegistryKeyNotFoundException as e:
        pass  
def getTypedURLs(reg_nt):

    print ("\n" + ("=" * 51) + "\nTYPED URLS\n" + ("=" * 51))

    TypedURL = []

    try:
        typedURLs = reg_nt.open("Software\\Microsoft\\Internet Explorer\\TypedURLs")
        for url in typedURLs.values():
            print url.value()

    except Registry.RegistryKeyNotFoundException as e:
        pass

def getMD5sum(filename):
    md5 = hashlib.md5()
    with open(filename,'rb') as f:
        for chunk in iter(lambda: f.read(128*md5.block_size), b''):
             md5.update(chunk)
    return md5.hexdigest()

def getUserAssist(reg_nt):

    print ("\n" + ("=" * 51) + "\nUSER ASSIST\n" + ("=" * 51))

    try:
        userassist = reg_nt.open("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\UserAssist")

        for items in userassist.subkeys():
            k = reg_nt.open("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\UserAssist\\%s" % (items.name()))
            for ua_keys in k.subkeys():
                for ua_values in ua_keys.values():
                    print codecs.decode(ua_values.name(), 'rot_13')

    except Registry.RegistryKeyNotFoundException as e:
        pass


def main():
    try:
        for plug in args.plugin:
            if plug == "sysinfo": getSysInfo(reg_soft, reg_sys)
            elif plug == "runkeys": getRunKeys(reg_soft, reg_nt, reg_sys)
            elif plug == "appinit": getAppInitDLLs(reg_soft)
            elif plug == "winlogon": getWinlogon(reg_soft)
            elif plug == "sessionmgr": getSessionManager(reg_sys)
            elif plug == "bhos": getBHOs(reg_soft)
            elif plug == "activeset": getActiveSetup(reg_soft)
            elif plug == "services": getServices(reg_sys)
            elif plug == "mounts": getMounted(reg_sys, reg_nt)
            elif plug == "archives": getArchives(reg_nt)
            elif plug == "urls": getTypedURLs(reg_nt)
            elif plug == "sysinternals": getSysinternals(reg_nt)
            elif plug == "userassist": getUserAssist(reg_nt)
            elif plug == "knowndlls": getKnownDLLs(reg_sys)
            elif plug == "lateralmovement": getSysinternals(reg_nt), getMounted(reg_sys, reg_nt)
            elif plug == "all": getSysInfo(reg_soft, reg_sys), \
                                getRunKeys(reg_soft, reg_nt, reg_sys), \
                                getAppInitDLLs(reg_soft), \
                                getWinlogon(reg_soft), \
                                getSessionManager(reg_sys), \
                                getBHOs(reg_soft), \
                                getActiveSetup(reg_soft), \
                                getServices(reg_sys), \
                                getMounted(reg_sys, reg_nt), \
                                getArchives(reg_nt), \
                                getTypedURLs(reg_nt), \
                                getSysinternals(reg_nt), \
                                getUserAssist(reg_nt), \
                                getKnownDLLs(reg_sys)
        
    except TypeError as e:
        print "You need to specify a plugin. Run autoreg-parse.py -h for some examples. Review def(main) for the complete list."
        
if __name__ == "__main__":
    main()
