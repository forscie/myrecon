#!/usr/bin/python

# modified by forScience. Original by Mike Czumak (T_v3rn1x)
# paths have been customised

import socket
import sys
import subprocess

if len(sys.argv) != 2:
    print "Usage: smtprecon.py <ip address>"
    sys.exit(0)

ip_address = sys.argv[1].strip()
print "[+] Performing nmap SMTP script scan against " + ip_address
SMTPSCAN = "nmap -vv -sV -Pn -p 25,465,587 --script=smtp-vuln* -oN '/root/EXAM/myrecon/results/%s/SMTP-%s-%s.nmap' %s" %(ip_address, port, ip_address, ip_address)
results = subprocess.check_output(SMTPSCAN, shell=True)

print "[+] Trying SMTP Enum on " + ip_address
names = open('/usr/share/wfuzz/wordlist/others/names.txt', 'r')
for name in names:
    s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    connect=s.connect((ip_address,25))
    banner=s.recv(1024)
    s.send('HELO test@test.org \r\n')
    result= s.recv(1024)
    s.send('VRFY ' + name.strip() + '\r\n')
    result=s.recv(1024)
    if ("not implemented" in result) or ("disallowed" in result):
        sys.exit("[!] VRFY Command not implemented on " + ip_address) 
    if (("250" in result) or ("252" in result) and ("Cannot VRFY" not in result)):
        print "[!] SMTP VRFY Account found on " + ip_address + ": " + name.strip()	
    s.close()
