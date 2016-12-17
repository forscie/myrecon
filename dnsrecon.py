#!/usr/bin/env python

# modified by forScience. Original by Mike Czumak (T_v3rn1x)
# paths have been customised

import subprocess
import sys
import os

if len(sys.argv) != 2:
    print "Usage: dnsrecon.py <ip address>"
    sys.exit(0)

ip_address = sys.argv[1]
HOSTNAME = "nmblookup -A %s | grep '<00>' | grep -v '<GROUP>' | cut -d' ' -f1" % (ip_address)# grab the hostname         
host = subprocess.check_output(HOSTNAME, shell=True, stderr=open(os.devnull, 'w')).strip()
print "[+] Attempting Domain Transfer on " + host
ZT = "dig @%s.thinc.local thinc.local axfr" % (host) # PWK domain
ztresults = subprocess.check_output(ZT, shell=True, stderr=open(os.devnull, 'w'))
if "failed" in ztresults:
    print "INFO: Zone Transfer failed for " + host
else:
    print "[!] Zone Transfer successful for " + host + "(" + ip_address + ")!!! [see output file]"
    outfile = "/root/EXAM/myrecon/results/" + ip_address.rstrip() + "/zonetransfer." + ip_address.rstrip() + ".txt"
    dnsf = open(outfile, "w")
    dnsf.write(ztresults)
    dnsf.close

