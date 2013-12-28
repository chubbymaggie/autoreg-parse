Auto Registry Parser 
====================  

The idea of this started out as one to duplicate autoruns to the extent possible with only offline registry analysis. Then I started adding things at random. I couldn't think of a better name. So this focuses on quickly identifying malware persistence locations, a few locations/items used by actors when moving laterally throughout a network, and then a few random/informatioal ones.

Big Thanks to:
==============

@williballenthin - http://www.williballenthin.com for writing python-registry, which is what I am using. It's great.

@hiddenillusion - This example got me started on the idea. https://github.com/williballenthin/python-registry/blob/master/samples/forensicating.py

HELP
=====

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

See Example.txt - https://github.com/sysforensics/autoreg-parse/blob/master/EXAMPLE.TXT

TODO
=====
X = Done, O = Partially done and implemented, [ ] Not started

No order....

                        [ ] CLEAN UP THE CODE - It is poorly written
                        [ ] Add some error handling. For example, only needing to pass in NTUSER if you only want to leverage only NTUSER hives
                        [O] User Assist - got the items parsed, just need to verify other information with the keys as well.
                        [O] Add [x]install date, [x]OS version, [x]Computer name, []Shutdown time, []SIDS
                        [O] Run Keys - Go back and check and verify they are working individually. Verify wow64 as well
                        [ ] Services - White list of some kind maybe?
                        [X] WinZip - Software\\Nico Mak Computing\\WinZip
                        [ ] WinRar - Software\\WinRAR\\DialogEditHistory\\ArcName
                        [ ] 7zip -   Software\\7-Zip
                        [O] Do something with the hashing function later if I run it against a mounted full disk image later
                        [ ] VT support with hashes from hashing function
                        [ ] Decide which keys I want to have last write time for (besides Sysinternals)
                        [O] Make it modular....(read: regripper) -> I added simple elif statements in the main() so -p can be used, but it's not the final way I want.
                        [ ] Process multiple NTUSER.DAT files (think of the output)
