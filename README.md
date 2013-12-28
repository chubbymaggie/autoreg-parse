Auto Registry Parser 
====================  

The idea started out as one to duplicate autoruns to the extent possible with offline registry analysis. Then I started adding things at random.

Thanks to:
==========

@williballenthin - http://www.williballenthin.com for writing python-registry, which is what I used.
@hiddenillusion - https://github.com/williballenthin/python-registry/blob/master/samples/forensicating.py

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
                        
