                  ____                      
  _ __ ___  _   _|  _ \ ___  ___ ___  _ __  
 | '_ ` _ \| | | | |_) / _ \/ __/ _ \| '_ \ 
 | | | | | | |_| |  _ <  __/ (_| (_) | | | |
 |_| |_| |_|\__, |_| \_\___|\___\___/|_| |_|
            |___/                       

 #-----------------------------------------------------------------------------------#
 # Script: myrecon.py                                                                #
 # Language: Python                                                                  #
 # Dependencies: None                                                                #
 # Original: Mike Czumak (T_v3rn1x) -- @SecuritySift                                 #
 # Modified by: forScience (james@forscience.xyz)                                    #
 #-----------------------------------------------------------------------------------#

myrecon: an automated remote enumeration tool (a modified version of reconscan.py by T_v3rn1x)

Usage: python myrecon.py

This collection of scripts has been modified from the original (originals by T_v3rn1x).
A reasonable amount of updating and a small amount of additional functionality has been added. A few (tiny!) mistakes have also been corrected.

myrecon is designed to enumerate remote target IP(s) listed in the targets.txt file (hard coded).

These scripts rely on a specific directory structure to function: /root/EXAM/targets.txt should contain an IP or list of IPs to be scanned.
The scripts create .txt reports which are located in IP titled directories that are created automatically by the script (where required).
The hard coded directories (and directory locations that are automatically created) can be modified in the scripts by searching for /root/EXAM/myrecon/results/

This collection of scripts consists of (like the original):

myrecon.py (main)
dirbust.py  
dnsrecon.py  
ftprecon.py 
smbrecon.py  
smtprecon.py  
snmprecon.py  
sshrecon.py

myrecon.py is the main script and calls all relevant scripts when run. The scripts can take a considerable amount of time to complete, depending on the accessible services of the target.

Warning: (shamelessly stolen from T_v3rn1x)
These scripts comes as-is with no promise of functionality or accuracy.  I strictly wrote them for personal use
I have no plans to maintain updates, I did not write them to be efficient and in some cases you may find the 
functions may not produce the desired results so use at your own risk/discretion. I wrote these scripts to 
target machines in a lab environment so please only use them against systems for which you have permission!!

Thanks again to Mike Czumak (T_v3rn1x) for the original. 
