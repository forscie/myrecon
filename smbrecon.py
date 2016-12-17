#!/usr/bin/python

# modified by forScience. Original by Mike Czumak (T_v3rn1x)
# paths have been customised

import sys
import subprocess
import os 

if len(sys.argv) != 2:
    print "Usage: smbrecon.py <ip address>"
    sys.exit(0)

ip = sys.argv[1]
SMB139SCAN = "./samrdump.py %s 139/SMB" %(ip)
SMB445SCAN = "./samrdump.py %s 445/SMB" %(ip)

print "[+] Performing SMB NSE script scan against " + ip
SMBSCAN = "nmap -Pn -p 139,445 --script=smb-vuln* -oN '/root/EXAM/myrecon/results/%s/SMB.%s.nmap' %s" %(ip, ip, ip)
nmapresults = subprocess.check_output(SMBSCAN, shell=True)
print "[!] SMB NSE script (" + ip + ") scan complete"

try:

    smb139results = subprocess.check_output(SMB139SCAN, shell=True, stderr=open(os.devnull, 'w'))
    smb445results = subprocess.check_output(SMB445SCAN, shell=True, stderr=open(os.devnull, 'w'))

    if ("Found user: " in smb139results):
        print "[!] SAMRDUMP User accounts/domains found on " + ip + " 139/SMB"
        lines = smb139results.split("\n")
        for line in lines:
            if ("Found" in line) or (" . " in line):
                print "   [+] " + line

    if ("Found user: " in smb445results):
        print "[!] SAMRDUMP User accounts/domains found on " + ip + " 445/SMB"
        lines = smb445results.split("\n")
        for line in lines:
            if ("Found" in line) or (" . " in line):
                print "   [+] " + line

except subprocess.CalledProcessError:
    print "[!] SAMR protocol failed on " + ip
