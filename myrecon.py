#!/usr/bin/python


# A recon script for enumerating targets from a file (/root/EXAM/targets.txt)
# This script is not exhaustive, however it has been created to rapidly increase the time taken
# to enumerate targets (specifically designed for the OSCP exam).
# THIS SCIPT IS STRICTLY WRITTEN FOR PERSONAL USE. YOU ARE FREE TO MODIFY AND ADAPT IT AS YOU
# SEE FIT. THIS SCRIPT SHOULD NOT BE USED AGAINST ANY TARGETS THAT YOU DO NOT HAVE PERMISSION TO
# ENUMERATE OR ATTACK!

# DIRECTORY STRUCTURE
#/root/EXAM/targets.txt - file containing list of IPs
#/root/EXAM/myrecon/results/ - directory containing ALL scan results

import sys
import os
import time 
import subprocess
import multiprocessing
from multiprocessing import Process, Queue


print(
'''
                  ____                      
  _ __ ___  _   _|  _ \ ___  ___ ___  _ __  
 | '_ ` _ \| | | | |_) / _ \/ __/ _ \| '_ \ 
 | | | | | | |_| |  _ <  __/ (_| (_) | | | |
 |_| |_| |_|\__, |_| \_\___|\___\___/|_| |_|
            |___/                           

 [!] myrecon.py
 A recon scanning script for initial enumeration of targets
 	- A modified version of reconscan.py by Mike Czumak (T_v3rn1x) 
 	  with a twist!

 [@] forScience
_________________________________________________________________
'''
)

# multiprocessing function for sub-scripts
def multProc(dotpy, IP, port):
    jobs = []
    p = multiprocessing.Process(target=dotpy, args=(IP,port))
    jobs.append(p)
    p.start()
    return

# FIXED!
def dnsEnum(ip_address, port):
    print("[!] Detected DNS on " + ip_address + ":" + port)
    if port.strip() == "53":
       SCRIPT = "./dnsrecon.py %s" %(ip_address) # execute the python script         
       subprocess.call(SCRIPT, shell=True)
    return

# FIXED!
# nmap script selection improved
def httpEnum(ip_address, port):
    print("[!] Detected HTTP on " + ip_address + ":" + port)
    print("[+] Performing NSE script scan for HTTP on " + ip_address + ":" + port)  
    HTTPSCAN = "nmap -sV -Pn -vv -p %s --script=http-webdav-scan,http-userdir-enum,http-sql-injection,http-backup-finder,http-config-backup,http-default-accounts,http-rfi-spider,http-iis-webdav-vuln,http-methods,http-method-tamper,http-passwd,http-robots.txt,http-put -oN /root/EXAM/myrecon/results/%s/HTTP-%s-%s.nmap %s" %(port, ip_address, port, ip_address, ip_address)
    results = subprocess.check_output(HTTPSCAN, shell=True)
    DIRBUST = "./dirbust.py http://%s:%s %s %s" %(ip_address, port, ip_address, port)
    subprocess.call(DIRBUST, shell=True)
    NIKTOSCAN = "nikto -host %s -p %s > /root/EXAM/myrecon/results/%s/NIKTO-%s-%s.scan" %(ip_address, port, ip_address, port, ip_address)
    subprocess.call(NIKTOSCAN, shell=True)
    return

# FIXED!
# nmap script selection improved
def httpsEnum(ip_address, port):
    print("[!] Detected HTTPS on " + ip_address + ":" + port)
    print("[+] Performing NSE script scan for HTTP/S on " + ip_address + ":" + port) 
    HTTPSCANS = "nmap -sV -Pn -vv -p %s --script=http-webdav-scan,http-userdir-enum,http-sql-injection,http-backup-finder,http-config-backup,http-default-accounts,http-rfi-spider,http-iis-webdav-vuln,http-methods,http-method-tamper,http-passwd,http-robots.txt,http-put -oN /root/EXAM/myrecon/results/%s/HTTPS-%s-%s.nmap %s" %(port, ip_address, port, ip_address, ip_address)
    results = subprocess.check_output(HTTPSCANS, shell=True)
    DIRBUST = "./dirbust.py https://%s:%s %s %s" %(ip_address, port, ip_address, port)
    subprocess.call(DIRBUST, shell=True)
    NIKTOSCAN = "nikto -host %s -p %s > /root/EXAM/myrecon/results/%s/NIKTO-%s-%s.scan" %(ip_address, port, ip_address, port, ip_address)
    subprocess.call(NIKTOSCAN, shell=True)
    return

# FIXED!
# nmap script selection improved
def mssqlEnum(ip_address, port):
    print("[!] Detected MS-SQL on " + ip_address + ":" + port)
    print("[+] Performing NSE script scan for MS-SQL on " + ip_address + ":" + port)
    MSSQLSCAN = "nmap -vv -sV -Pn -p %s --script=ms-sql-info,ms-sql-config,ms-sql-dump-hashes,ms-sql-tables,ms-sql-empty-password, --script-args=mssql.instance-port=1433,smsql.username-sa,mssql.password-sa -oN /root/EXAM/myrecon/results/%s/MSSQL-%s-%s.nmap %s" %(port, ip_address, port, ip_address, ip_address)
    results = subprocess.check_output(MSSQLSCAN, shell=True)

# FIXED!
def sshEnum(ip_address, port):
    print("[!] Detected SSH on " + ip_address + ":" + port)
    SCRIPT = "./sshrecon.py %s %s" %(ip_address, port)
    subprocess.call(SCRIPT, shell=True)
    return

# FIXED!
def snmpEnum(ip_address, port):
    print("[!] Detected snmp on " + ip_address + ":" + port)
    SCRIPT = "./snmprecon.py %s" %(ip_address)         
    subprocess.call(SCRIPT, shell=True)
    return

# FIXED!
def smtpEnum(ip_address, port):
    print("[!] Detected smtp on " + ip_address + ":" + port)
    if port.strip() == "25":
       SCRIPT = "./smtprecon.py %s" %(ip_address)       
       subprocess.call(SCRIPT, shell=True)
    else:
       print("[!] WARNING: SMTP detected on non-standard port, smtprecon skipped (must run manually)")
    return

# FIXED!
def smbEnum(ip_address, port):
    print("[!] Detected SMB on " + ip_address + ":" + port)
    if port.strip() == "445":
       SCRIPT = "./smbrecon.py %s 2>/dev/null" %(ip_address)
       subprocess.call(SCRIPT, shell=True)
    return

# FIXED!
def ftpEnum(ip_address, port):
    print("[!] Detected ftp on " + ip_address + ":" + port)
    SCRIPT = "./ftprecon.py %s %s" %(ip_address, port)       
    subprocess.call(SCRIPT, shell=True)
    return

# quick and thorough nmap scans (based on testing)
def nmapScan(ip_address):

	# nmap one liners improved (faster)
  ip_address = ip_address.strip()
  print("[+] Running nmap TCP/UDP against " + ip_address)
  serv_dict = {}
  TCPSCAN = "nmap -sV -Pn -A -T 4 -sS -oN '/root/EXAM/myrecon/results/%s/TCP.%s.nmap' %s" %(ip_address, ip_address, ip_address)
  UDPSCAN = "nmap -sV -Pn -A -T 4 -sU --top-ports 200 -oN '/root/EXAM/myrecon/results/%s/UDP.%s.nmap' %s" %(ip_address, ip_address, ip_address)
  
  # execute nmap scans for both TCP and UDP
  tcpresult = subprocess.check_output(TCPSCAN, shell=True)
  udpresult = subprocess.check_output(UDPSCAN, shell=True)

  # enter services/ports into dictionary
  lines = tcpresult.split("\n")
  for line in lines:
    ports = []
    line = line.strip()
    if ("tcp" in line) and ("open" in line) and not ("Discovered" in line):
      while "  " in line: 
        line = line.replace("  ", " ");
      linesplit= line.split(" ")
      service = linesplit[2] # grab the service name
      port = line.split(" ")[0] # grab the port/proto
      if service in serv_dict:
        ports = serv_dict[service] # if the service is already in the dict, grab the port list

      ports.append(port)
      serv_dict[service] = ports # add service to the dictionary along with the associated port(2)

	# go through the service dictionary to call additional targeted enumeration functions 
  for serv in serv_dict:
    ports = serv_dict[serv]	
    if (serv == "http"):
      for port in ports:
        port = port.split("/")[0]
        multProc(httpEnum, ip_address, port)
    elif (serv == "ssl/http") or ("https" in serv):
      for port in ports:
        port = port.split("/")[0]
        multProc(httpsEnum, ip_address, port)
    elif "ssh" in serv:
      for port in ports:
        port = port.split("/")[0]
        multProc(sshEnum, ip_address, port)
    elif "smtp" in serv:
      for port in ports:
        port = port.split("/")[0]
        multProc(smtpEnum, ip_address, port)
    elif "snmp" in serv:
      for port in ports:
        port = port.split("/")[0]
        multProc(snmpEnum, ip_address, port)
    elif ("ftp" in serv):
      for port in ports:
        port = port.split("/")[0]
        multProc(ftpEnum, ip_address, port)
    elif "microsoft-ds" in serv:
      for port in ports:
        port = port.split("/")[0]
        multProc(smbEnum, ip_address, port)
    elif "ms-sql" in serv:
      for port in ports:
        port = port.split("/")[0]
        multProc(mssqlEnum, ip_address, port)
    elif ("domain" in serv):
      for port in ports:
        port = port.split("/")[0]
        multProc(dnsEnum, ip_address, port)

	# all done with nmap
  print("[!] TCP and UDP scans are complete for " + ip_address)
  return

# kick off
if __name__ == '__main__':
  f = open('/root/EXAM/targets.txt', 'r')
  for IP in f:
    # make a directory for this IP if it doesnt exist
    dir = '/root/EXAM/myrecon/results/' + IP.rstrip()
    if not os.path.exists(dir):
      os.makedirs(dir)

    # get multiprocessing!
    jobs = []
    p = multiprocessing.Process(target=nmapScan, args=(IP,))
    jobs.append(p)
    p.start()
  f.close()
