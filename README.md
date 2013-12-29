Auto Registry Parser 
====================  

The idea of this started out as one to duplicate Microsoft's autoruns tool to the extent possible with only offline registry hives. Then I started adding things at random. I couldn't think of a better name. 

It focuses on quickly identifying malware persistence locations, a few locations/items used by actors when moving laterally throughout a network, and then a few random/informational ones.

INSTALL
========

Download: https://github.com/williballenthin/python-registry

python setup.py build

python setup.py install

That should be all you need. It will work in Windows and Linux/OSX.

HOW-TO
=======

python autoreg-parse.py -h

                        usage: autoreg-parse.py [-h] [-nt NTUSER] [-sys SYSTEM] [-soft SOFTWARE]
                                                [-p PLUGIN [PLUGIN ...]]
                        
                        Parse the Windows registry for malware-ish related artifacts.
                        optional arguments:
                          -h, --help            show this help message and exit
                          -nt NTUSER, --ntuser NTUSER
                                                Path to the NTUSER.DAT hive you want parsed
                          -sys SYSTEM, --system SYSTEM
                                                Path to the SYSTEM hive you want parsed
                          -soft SOFTWARE, --software SOFTWARE
                                                Path to the SOFTWARE hive you want parsed
                          -p PLUGIN [PLUGIN ...], --plugin PLUGIN [PLUGIN ...]
                                                [lateralmovement] = MountPoints2 and Network MRUs,
                                                [urls] = TypedURLs
                                                [mounts] = MountPoints
                        
EXAMPLE OUTPUT
===============

See Example.txt - https://github.com/sysforensics/autoreg-parse/blob/master/Example_Output.txt

TODO
=====
X = Done, O = Partially done and implemented, [ ] Not started

No order....

[O] CLEAN UP THE CODE 

- [x] 12/29/2013 - Added getControlSet functions to reuse and reduce duplication. 
- [x] 12/29/2013 - Used a dict{} within services vs. a bunch of lists to reduce code.

[ ] Error handling

- [ ] Add some better error handling.

[O] User Assist

- [x] Parser entries
- [ ] Verify I am not missing anything.

[O] System and User Information

- [x] Install date
- [x] OS version
- [x] Computer name
- [ ] Last logged on user
- [ ] Shutdown time
- [ ] SIDS and User Profile Information

[ ] Run Keys

- [ ] Go back and check and verify i'm not missing anything. 
- [ ] Verify wow6432 entries.

[O] Services

- [x] 12/29/2013 - Added White list/Baseline feature
- [ ] Make it so services.txt is optional so it will process it without. Also, make it so you can specify the location of services.txt.
- [ ] Services - Add image path checking vs. just service name checking for the whitelist/baseline.

[O] Archive Locations

- [X] WinZip - Software\\Nico Mak Computing\\WinZip
- [ ] WinRar - Software\\WinRAR\\DialogEditHistory\\ArcName
- [ ] 7zip -   Software\\7-Zip

[ ] Hashing Function

- [X] Write hashing function
- [ ] Allow the code to run against a disk image and hash the image paths of services, etc.
- [ ] VT support with returned  hashes from hashing function

[ ] LastWrite Times

- [X] SysInternals
- [X] Mount Points
- [X] Archive Locations
- [ ] Anymore???

[ ] Modular

- [O] I have a basic "plugin" feature, but not what I want for the end result.

[ ] Program Input/Output

- [ ] Input - Process multiple NTUSER.DAT files
- [ ] Input - Allow for services.txt to be inputed on the command line (right now it's hard coded)
- [O] Input - Plugins (See modular section)
- [ ] Output - CSV
- [ ] Output - sqlite???

Big Thanks to:
==============

@williballenthin - http://www.williballenthin.com for writing python-registry, which is what I am using. It's great.

@hiddenillusion - This example got me started on the idea. https://github.com/williballenthin/python-registry/blob/master/samples/forensicating.py

Wingware for providing a great Python IDE and supporting the Open Source community. http://www.wingware.com/
