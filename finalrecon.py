#!/usr/bin/env python3

import os
import socket
import argparse
from modules.sslinfo import cert
from modules.crawler import crawler
from modules.headers import headers
from modules.whois import whois_lookup

version = '1.0.1'

R = '\033[31m' # red
G = '\033[32m' # green
C = '\033[36m' # cyan
W = '\033[0m'  # white

parser = argparse.ArgumentParser(description='FinalRecon - OSINT Tool for All-In-One Web Recon | v{}'.format(version))
parser.add_argument('url', help='Target URL')
parser.add_argument('--headers', help='Get Header Information', action='store_true')
parser.add_argument('--sslinfo', help='Get SSL Certificate Information', action='store_true')
parser.add_argument('--whois', help='Get Whois Lookup', action='store_true')
parser.add_argument('--crawl', help='Crawl Target Website', action='store_true')
parser.add_argument('--full', help='Get Full Analysis, Test All Available Options', action='store_true')
args = parser.parse_args()
target = args.url
headinfo = args.headers
sslinfo = args.sslinfo
whois = args.whois
crawl = args.crawl
full = args.full

def banner():
	os.system('clear')
	banner = r'''
 ______  __   __   __   ______   __
/\  ___\/\ \ /\ "-.\ \ /\  __ \ /\ \
\ \  __\\ \ \\ \ \-.  \\ \  __ \\ \ \____
 \ \_\   \ \_\\ \_\\"\_\\ \_\ \_\\ \_____\
  \/_/    \/_/ \/_/ \/_/ \/_/\/_/ \/_____/
 ______   ______   ______   ______   __   __
/\  == \ /\  ___\ /\  ___\ /\  __ \ /\ "-.\ \
\ \  __< \ \  __\ \ \ \____\ \ \/\ \\ \ \-.  \
 \ \_\ \_\\ \_____\\ \_____\\ \_____\\ \_\\"\_\
  \/_/ /_/ \/_____/ \/_____/ \/_____/ \/_/ \/_/'''
	print (G + banner + W + '\n')
	print (G + '[>]' + C + ' Created By : ' + W + 'thewhiteh4t')
	print (G + '[>]' + C + ' Version    : ' + W + version + '\n')

def all():
	headers(target)
	cert(hostname)
	whois_lookup(ip)
	crawler(target)

try:
	banner()

	print (G + '[+]' + C + ' Target : ' + W + target + '\n')

	if 'http' in target:
		hostname = target.split('//')
		hostname = hostname[1]
	elif 'http' not in target:
		hostname = target
		target = 'http://{}'.format(target)
	elif ':' in hostname:
		hostname = hostname.split(':')
		hostname = hostname[0]
	else:
		print (R + '[-] Error : ' + C + 'Invalid URL / IP Entered')
		exit()

	try:
		if "/" in hostname:
			hostname = hostname.split("/")[0]
		ip = socket.gethostbyname(hostname)
		print (G + '[+]' + C + ' IP Address : ' + W + str(ip))
	except Exception as e:
		print (R + '[+]' + C + ' Unable to Get IP : ' + W + str(e))
		if '[Errno -2]' in str(e):
			exit()
		else:
			pass

	if headinfo is True:
		headers(target)
	elif sslinfo is True:
		cert(hostname)
	elif whois is True:
		whois_lookup(ip)
	elif crawl is True:
		crawler(target)
	elif full == True:
		all()
	else:
		print (R + '[-] Error : ' + C + 'Atleast One Argument is Required with URL' + W)
		exit()

	print (G + '[+]' + C + ' Completed!' + W)
except KeyboardInterrupt:
	print (R + '[-]' + C + ' Keyboard Interrupt.')
	exit()
