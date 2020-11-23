#!/usr/bin/env python3

import os
import sys
import atexit
import importlib.util

R = '\033[31m' # red
G = '\033[32m' # green
C = '\033[36m' # cyan
W = '\033[0m'  # white

home = os.getenv('HOME')
pid_path = home + '/.local/share/finalrecon/finalrecon.pid'
usr_data = home + '/.local/share/finalrecon/dumps/'
conf_path = home + '/.config/finalrecon'
path_to_script = os.path.dirname(os.path.realpath(__file__))
src_conf_path = path_to_script + '/conf/'
fail = False

if os.path.isfile(pid_path):
	print(R + '[-]' + C + ' One instance of FinalRecon is already running!' + W)
	with open(pid_path, 'r') as pidfile:
		pid = pidfile.read()
	print(G + '[+]' + C + ' PID : ' + W + str(pid))
	print(G + '[>]' + C + ' If FinalRecon crashed, execute : ' + W + 'rm {}'.format(pid_path))
	sys.exit()
else:
	os.makedirs(os.path.dirname(pid_path), exist_ok=True)
	with open(pid_path, 'w') as pidfile:
		pidfile.write(str(os.getpid()))

if os.path.exists(conf_path):
	pass
else:
	import shutil
	shutil.copytree(src_conf_path, conf_path, dirs_exist_ok=True)

with open(path_to_script + '/requirements.txt', 'r') as rqr:
	pkg_list = rqr.read().strip().split('\n')

print('\n' + G + '[+]' + C + ' Checking Dependencies...' + W + '\n')

for pkg in pkg_list:
	spec = importlib.util.find_spec(pkg)
	if spec is None:
		print(R + '[-]' + W + ' {}'.format(pkg) + C + ' is not Installed!' + W)
		fail = True
	else:
		pass
if fail == True:
	print('\n' + R + '[-]' + C + ' Please Execute ' + W + 'pip3 install -r requirements.txt' + C + ' to Install Missing Packages' + W + '\n')
	os.remove(pid_path)
	sys.exit()

import argparse

version = '1.1.2'
gh_version = ''
twitter_url = ''
discord_url = ''

parser = argparse.ArgumentParser(description='FinalRecon - The Last Web Recon Tool You Will Need | v{}'.format(version))
parser.add_argument('url', help='Target URL')
parser.add_argument('--headers', help='Header Information', action='store_true')
parser.add_argument('--sslinfo', help='SSL Certificate Information', action='store_true')
parser.add_argument('--whois', help='Whois Lookup', action='store_true')
parser.add_argument('--crawl', help='Crawl Target', action='store_true')
parser.add_argument('--dns', help='DNS Enumeration', action='store_true')
parser.add_argument('--sub', help='Sub-Domain Enumeration', action='store_true')
parser.add_argument('--trace', help='Traceroute', action='store_true')
parser.add_argument('--dir', help='Directory Search', action='store_true')
parser.add_argument('--ps', help='Fast Port Scan', action='store_true')
parser.add_argument('--full', help='Full Recon', action='store_true')

ext_help = parser.add_argument_group('Extra Options')
ext_help.add_argument('-t', type=int, help='Number of Threads [ Default : 30 ]')
ext_help.add_argument('-T', type=float, help='Request Timeout [ Default : 30.0 ]')
ext_help.add_argument('-w', help='Path to Wordlist [ Default : wordlists/dirb_common.txt ]')
ext_help.add_argument('-r', action='store_true', help='Allow Redirect [ Default : False ]')
ext_help.add_argument('-s', action='store_false', help='Toggle SSL Verification [ Default : True ]')
ext_help.add_argument('-sp', type=int, help='Specify SSL Port [ Default : 443 ]')
ext_help.add_argument('-d', help='Custom DNS Servers [ Default : 1.1.1.1 ]')
ext_help.add_argument('-e', help='File Extensions [ Example : txt, xml, php ]')
ext_help.add_argument('-m', help='Traceroute Mode [ Default : UDP ] [ Available : TCP, ICMP ]')
ext_help.add_argument('-p', type=int, help='Port for Traceroute [ Default : 80 / 33434 ]')
ext_help.add_argument('-tt', type=float, help='Traceroute Timeout [ Default : 1.0 ]')
ext_help.add_argument('-o', help='Export Output [ Default : txt ] [ Available : xml, csv ]')
ext_help.set_defaults(
	t = 30,
	T = 30.0,
	w = path_to_script + '/wordlists/dirb_common.txt',
	r = False,
	s = True,
	sp = 443,
	d = '1.1.1.1',
	e = '',
	m = 'UDP',
	p = 33434,
	tt = 1.0,
	o = 'txt')

try:
	args = parser.parse_args()
except SystemExit:
	os.remove(pid_path)
	sys.exit()

target = args.url
headinfo = args.headers
sslinfo = args.sslinfo
whois = args.whois
crawl = args.crawl
dns = args.dns
trace = args.trace
dirrec = args.dir
pscan = args.ps
full = args.full
threads = args.t
tout = args.T
wdlist = args.w
redir = args.r
sslv = args.s
sslp = args.sp
dserv = args.d
filext = args.e
subd = args.sub
mode = args.m
port = args.p
tr_tout = args.tt
output = args.o

import json
import socket
import requests
import datetime
import ipaddress
import tldextract

type_ip = False
data = {}
meta = {}

def fetch_meta():
	global gh_version, twitter_url, discord_url
	try:
		rqst = requests.get('https://raw.githubusercontent.com/thewhiteh4t/finalrecon/master/metadata.json', timeout=5)
		sc = rqst.status_code
		if sc == 200:
			metadata = rqst.text
			json_data = json.loads(metadata)
			gh_version = json_data['metadata']['version']
			twitter_url = json_data['metadata']['twitter']
			discord_url = json_data['metadata']['discord']
		else:
			with open('metadata.json', 'r') as metadata:
				json_data = json.loads(metadata.read())
				gh_version = json_data['metadata']['version']
				twitter_url = json_data['metadata']['twitter']
				discord_url = json_data['metadata']['discord']
	except Exception as exc:
		print('\n' + R + '[-]' + C + ' Exception : ' + W + str(exc))
		with open('metadata.json', 'r') as metadata:
			json_data = json.loads(metadata.read())
			gh_version = json_data['metadata']['version']
			twitter_url = json_data['metadata']['twitter']
			discord_url = json_data['metadata']['discord']

def banner():
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
	print(G + banner + W + '\n')
	print(G + '[>]' + C + ' Created By : ' + W + 'thewhiteh4t')
	print(G + ' |---> ' + C + 'Twitter : ' + W + twitter_url)
	print(G + ' |---> ' + C + 'Discord : ' + W + discord_url)
	print(G + '[>]' + C + ' Version    : ' + W + version + '\n')

def ver_check():
	print(G + '[+]' + C + ' Checking for Updates...', end='')
	if version == gh_version:
		print(C + '[' + G + ' Up-To-Date ' + C +']' + '\n')
	else:
		print(C + '[' + G + ' Available : {} '.format(gh_version) + C + ']' + '\n')

def full_recon():
	from modules.sslinfo import cert
	from modules.crawler import crawler
	from modules.headers import headers
	from modules.dns import dnsrec
	from modules.traceroute import troute
	from modules.whois import whois_lookup
	from modules.dirrec import hammer
	from modules.portscan import ps
	from modules.subdom import subdomains
	headers(target, output, data)
	cert(hostname, sslp, output, data)
	whois_lookup(ip, output, data)
	dnsrec(domain, output, data)
	if type_ip == False:
		subdomains(domain, tout, output, data, conf_path)
	else:
		pass
	troute(ip, mode, port, tr_tout, output, data)
	ps(ip, output, data)
	crawler(target, output, data)
	hammer(target, threads, tout, wdlist, redir, sslv, dserv, output, data, filext)

try:
	fetch_meta()
	banner()
	ver_check()

	if target.startswith(('http', 'https')) == False:
		print(R + '[-]' + C + ' Protocol Missing, Include ' + W + 'http://' + C + ' or ' + W + 'https://' + '\n')
		os.remove(pid_path)
		sys.exit()
	else:
		pass

	if target.endswith('/') == True:
		target = target[:-1]
	else:
		pass

	print (G + '[+]' + C + ' Target : ' + W + target)
	ext = tldextract.extract(target)
	domain = ext.registered_domain
	hostname = '.'.join(part for part in ext if part)

	try:
		ipaddress.ip_address(hostname)
		type_ip = True
		ip = hostname
	except:
		try:
			ip = socket.gethostbyname(hostname)
			print ('\n' + G + '[+]' + C + ' IP Address : ' + W + str(ip))
		except Exception as e:
			print ('\n' + R + '[-]' + C + ' Unable to Get IP : ' + W + str(e))
			os.remove(pid_path)
			sys.exit()

	start_time = datetime.datetime.now()

	meta.update({'Version': str(version)})
	meta.update({'Date': str(datetime.date.today())})
	meta.update({'Target': str(target)})
	meta.update({'IP Address': str(ip)})
	meta.update({'Start Time': str(start_time.strftime('%I:%M:%S %p'))})
	data['module-FinalRecon'] = meta

	if output != 'None':
		fpath = usr_data
		fname = fpath + hostname + '.' + output
		if not os.path.exists(fpath):
				os.makedirs(fpath)
		output = {
			'format': output,
			'file': fname,
			'export': False
			}

	from modules.export import export

	if full == True:
		full_recon()

	if headinfo == True:
		from modules.headers import headers
		headers(target, output, data)

	if sslinfo == True:
		from modules.sslinfo import cert
		cert(hostname, sslp, output, data)

	if whois == True:
		from modules.whois import whois_lookup
		whois_lookup(ip, output, data)

	if crawl == True:
		from modules.crawler import crawler
		crawler(target, output, data)

	if dns == True:
		from modules.dns import dnsrec
		dnsrec(domain, output, data)

	if subd == True and type_ip == False:
		from modules.subdom import subdomains
		subdomains(domain, tout, output, data, conf_path)
	elif subd == True and type_ip == True:
		print(R + '[-]' + C + ' Sub-Domain Enumeration is Not Supported for IP Addresses' + W + '\n')
		os.remove(pid_path)
		sys.exit()
	else:
		pass

	if trace == True:
		from modules.traceroute import troute
		if mode == 'TCP' and port == 33434:
			port = 80
			troute(ip, mode, port, tr_tout, output, data)
		else:
			troute(ip, mode, port, tr_tout, output, data)

	if pscan == True:
		from modules.portscan import ps
		ps(ip, output, data)

	if dirrec == True:
		from modules.dirrec import hammer
		hammer(target, threads, tout, wdlist, redir, sslv, dserv, output, data, filext)

	if any([full, headinfo, sslinfo, whois, crawl, dns, subd, trace, pscan, dirrec]) != True:
		print ('\n' + R + '[-] Error : ' + C + 'At least One Argument is Required with URL' + W)
		output = 'None'
		os.remove(pid_path)
		sys.exit()

	end_time = datetime.datetime.now() - start_time
	print ('\n' + G + '[+]' + C + ' Completed in ' + W + str(end_time) + '\n')

	@atexit.register
	def call_export():
		meta.update({'End Time': str(datetime.datetime.now().strftime('%I:%M:%S %p'))})
		meta.update({'Completion Time': str(end_time)})
		if output != 'None':
			output['export'] = True
			export(output, data)

	os.remove(pid_path)
	sys.exit()
except KeyboardInterrupt:
	print (R + '[-]' + C + ' Keyboard Interrupt.' + W + '\n')
	os.remove(pid_path)
	sys.exit()
