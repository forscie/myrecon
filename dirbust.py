#!/usr/bin/python

# modified by forScience. Original by Mike Czumak (T_v3rn1x)
# paths have been customised

import sys
import os
import subprocess

if len(sys.argv) != 4:
    print "Usage: dirbust.py <target url> <scan name> <port>"
    sys.exit(0)

url = str(sys.argv[1])
name = str(sys.argv[2])
port = str(sys.argv[3])
folders = ["/usr/share/dirb/wordlists/exam"]
directory = "/root/EXAM/myrecon/results/" + name.rstrip() + "/dirbuster/"

# make a directory for dirbuster in this IP folder if it doesnt exist
if not os.path.exists(directory):
    os.makedirs(directory)

found = []
print "[+] Starting dirb scan for " + url
for folder in folders:
    for filename in os.listdir(folder):
        outfile = " -o " + "/root/EXAM/myrecon/results/" + name.rstrip() + "/dirbuster/dirbuster-" + port.rstrip() + "-" + name.rstrip() + "-" + filename.rstrip()
        DIRBSCAN = "dirb %s %s/%s %s -S -r" % (url, folder, filename, outfile)
    try:
        results = subprocess.check_output(DIRBSCAN, shell=True)
        resultarr = results.split("\n")
        for line in resultarr:
            if "+" in line:
                if line not in found:
                    found.append(line)
    except:
        pass

try:
    if found[0] != "":
        print "[!] Dirb found the following items..."
        for item in found:
            print "   " + item
except:
    print "[!] No items found during dirb scan of " + url
