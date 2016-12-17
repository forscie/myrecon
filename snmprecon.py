#!/usr/bin/env python

# modified by forScience. Original by Mike Czumak (T_v3rn1x)
# paths have been customised

import subprocess
import sys

if len(sys.argv) != 2:
    print "Usage: snmprecon.py <ip address>"
    sys.exit(0)

snmpdetect = 0
ip_address = sys.argv[1]

ONESIXONESCAN = "onesixtyone %s" % (ip_address)
results = subprocess.check_output(ONESIXONESCAN, shell=True).strip()

if results != "":
    if "Windows" in results:
        results = results.split("Software: ")[1]
        snmpdetect = 1
    elif "Linux" in results:
        results = results.split("[public] ")[1]
        snmpdetect = 1
    if snmpdetect == 1:
        print "[+] SNMP running on " + ip_address + "; OS Detect: " + results
        SNMPWALK = "snmpwalk -c public -v 1 %s > /root/EXAM/myrecon/results/%s/snmpwalk.%s.txt" %( ip_address, ip_address, ip_address)
        print "[+] Executing snmpwalk on " + ip_address 
        results = subprocess.call(SNMPWALK, shell=True)
        print "[+] snmpwalk complete " + ip_address

NMAPSCAN = "nmap -vv -sV -sU -Pn -p 161,162 --script=snmp-netstat,snmp-processes %s" % (ip_address)
results = subprocess.check_output(NMAPSCAN, shell=True)
resultsfile = "/root/EXAM/myrecon/results/" + ip_address.rstrip() + "/snmprecon." + ip_address.rstrip() + ".nmap"
f = open(resultsfile, "w")
f.write(results)
f.close

