Auto Registry Parser 
====================  

The idea of this started out as one to duplicate autoruns to the extent possible with only offline registry analysis. Then I started adding things at random. I couldn't think of a better name. So this focuses on quickly identifying malware persistence locations, a few locations/items used by actors when moving laterally throughout a network, and then a few random/informatioal ones.

Big Thanks to:
==============

@williballenthin - http://www.williballenthin.com for writing python-registry, which is what I am using. It's great.

@hiddenillusion - This example got me started on the idea. https://github.com/williballenthin/python-registry/blob/master/samples/forensicating.py

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
                        
EXAMPLE OUTPUT
===============

See Example.txt - https://github.com/sysforensics/autoreg-parse/blob/master/EXAMPLE.TXT
