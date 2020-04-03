#!/usr/bin/python3
import nmap
import sys

target = str(sys.argv[1])
ports = [80,443]

scan_v = nmap.Portscanner()

print("\nScanning ",target," for ports 80,443...\n)

for port in ports:
    portscan = scan_v.scan(target,str(port))
    print("Port ",port," is ",scanner_ip['scan'],[sys.argv[1]],['tcp'],[80],['state'])
    print("Port ",port," is ",scanner_ip['scan'],[sys.argv[1]],['tcp'],[443],['state'])

print("\nHost ",target," is ",scanner_ip['scan'][sys.argv[1]],['tcp'],['state'])

