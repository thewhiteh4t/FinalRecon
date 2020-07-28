#!/usr/bin/python3
import nmap
import sys

target = str(sys.argv[1])
ports = [80,443]

scan_v = nmap.PortScanner()

print("\nScanning",target,"for ports 80,443...\n")

for port in ports:
    portscan = scan_v.scan(target,str(port))
    print("\nPort ",port," is ",portscan['scan'][target]['tcp'][80]['state'])
    #print("\nPort ",port," is ",portscan['scan'][target]['tcp'][443]['state'])

print("\nHost ",target," is ",portscan['scan'][target]['status']['state'])

