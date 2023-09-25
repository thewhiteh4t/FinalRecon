#!/usr/bin/env python3

import os
import sys

R = '\033[31m'  # red
G = '\033[32m'  # green
C = '\033[36m'  # cyan
W = '\033[0m'   # white

from modules.write_log import log_writer
log_writer('Importing config...')
import settings as config

home = config.home
usr_data = config.usr_data
conf_path = config.conf_path
path_to_script = config.path_to_script
src_conf_path = config.src_conf_path
meta_file_path = config.meta_file_path

log_writer(
	f'PATHS = HOME:{home}, SCRIPT_LOC:{path_to_script},\
	METADATA:{meta_file_path}, KEYS:{config.keys_file_path},\
	CONFIG:{config.conf_file_path}, LOG:{config.log_file_path}'
)

import argparse

VERSION = '1.1.5'
log_writer(f'FinalRecon v{VERSION}')

parser = argparse.ArgumentParser(description=f'FinalRecon - The Last Web Recon Tool You Will Need | v{VERSION}')
parser.add_argument('url', help='Target URL')
parser.add_argument('--headers', help='Header Information', action='store_true')
parser.add_argument('--sslinfo', help='SSL Certificate Information', action='store_true')
parser.add_argument('--whois', help='Whois Lookup', action='store_true')
parser.add_argument('--crawl', help='Crawl Target', action='store_true')
parser.add_argument('--dns', help='DNS Enumeration', action='store_true')
parser.add_argument('--sub', help='Sub-Domain Enumeration', action='store_true')
parser.add_argument('--dir', help='Directory Search', action='store_true')
parser.add_argument('--wayback', help='Wayback URLs', action='store_true')
parser.add_argument('--ps', help='Fast Port Scan', action='store_true')
parser.add_argument('--full', help='Full Recon', action='store_true')

ext_help = parser.add_argument_group('Extra Options')
ext_help.add_argument('-dt', type=int, help='Number of threads for directory enum [ Default : 30 ]')
ext_help.add_argument('-pt', type=int, help='Number of threads for port scan [ Default : 50 ]')
ext_help.add_argument('-T', type=float, help='Request Timeout [ Default : 30.0 ]')
ext_help.add_argument('-w', help='Path to Wordlist [ Default : wordlists/dirb_common.txt ]')
ext_help.add_argument('-r', action='store_true', help='Allow Redirect [ Default : False ]')
ext_help.add_argument('-s', action='store_false', help='Toggle SSL Verification [ Default : True ]')
ext_help.add_argument('-sp', type=int, help='Specify SSL Port [ Default : 443 ]')
ext_help.add_argument('-d', help='Custom DNS Servers [ Default : 1.1.1.1 ]')
ext_help.add_argument('-e', help='File Extensions [ Example : txt, xml, php ]')
ext_help.add_argument('-o', help='Export Format [ Default : txt ]')
ext_help.set_defaults(
	dt=config.dir_enum_th,
	pt=config.port_scan_th,
	T=config.timeout,
	w=config.dir_enum_wlist,
	r=config.dir_enum_redirect,
	s=config.dir_enum_sslv,
	sp=config.ssl_port,
	d=config.dir_enum_dns,
	e=config.dir_enum_ext,
	o=config.export_fmt
)

try:
	args = parser.parse_args()
except SystemExit:
	log_writer('[finalrecon] Help menu accessed')
	log_writer(f'{"-" * 30}')
	sys.exit()

target = args.url
headinfo = args.headers
sslinfo = args.sslinfo
whois = args.whois
crawl = args.crawl
dns = args.dns
dirrec = args.dir
wback = args.wayback
pscan = args.ps
full = args.full
threads = args.dt
pscan_threads = args.pt
tout = args.T
wdlist = args.w
redir = args.r
sslv = args.s
sslp = args.sp
dserv = args.d
filext = args.e
subd = args.sub
output = args.o

import socket
import datetime
import ipaddress
import tldextract
from json import loads

type_ip = False
data = {}


def banner():
	with open(meta_file_path, 'r') as metadata:
		json_data = loads(metadata.read())
		twitter_url = json_data['twitter']
		comms_url = json_data['comms']

	art = r'''
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
	print(f'{G}{art}{W}\n')
	print(f'{G}[>]{C} Created By   :{W} thewhiteh4t')
	print(f'{G} |--->{C} Twitter   :{W} {twitter_url}')
	print(f'{G} |--->{C} Community :{W} {comms_url}')
	print(f'{G}[>]{C} Version      :{W} {VERSION}\n')


try:
	banner()

	if not target.startswith(('http', 'https')):
		print(f'{R}[-] {C}Protocol Missing, Include {W}http:// {C}or{W} https:// \n')
		log_writer(f'Protocol missing in {target}, exiting')
		sys.exit(1)

	if target.endswith('/'):
		target = target[:-1]

	print(f'{G}[+] {C}Target : {W}{target}')
	ext = tldextract.extract(target)
	domain = ext.registered_domain
	hostname = '.'.join(part for part in ext if part)

	try:
		ipaddress.ip_address(hostname)
		type_ip = True
		ip = hostname
	except Exception:
		try:
			ip = socket.gethostbyname(hostname)
			print(f'\n{G}[+] {C}IP Address : {W}{str(ip)}')
		except Exception as e:
			print(f'\n{R}[-] {C}Unable to Get IP : {W}{str(e)}')
			sys.exit(1)

	start_time = datetime.datetime.now()

	if output != 'None':
		fpath = usr_data
		dt_now = str(datetime.datetime.now().strftime('%d-%m-%Y_%H:%M:%S'))
		fname = f'{fpath}fr_{hostname}_{dt_now}.{output}'
		respath = f'{fpath}fr_{hostname}_{dt_now}'
		if not os.path.exists(respath):
			os.makedirs(respath)
		out_settings = {
			'format': output,
			'directory': respath,
			'file': fname
		}
		log_writer(f'OUTPUT = FORMAT: {output}, DIR: {respath}, FILENAME: {fname}')

	if full:
		log_writer('Starting full recon...')

		from modules.dns import dnsrec
		from modules.sslinfo import cert
		from modules.portscan import scan
		from modules.dirrec import hammer
		from modules.crawler import crawler
		from modules.headers import headers
		from modules.subdom import subdomains
		from modules.wayback import timetravel
		from modules.whois import whois_lookup

		headers(target, out_settings, data)
		cert(hostname, sslp, out_settings, data)
		whois_lookup(ip, out_settings, data)
		dnsrec(domain, out_settings, data)
		if not type_ip:
			subdomains(domain, tout, out_settings, data, conf_path)
		scan(ip, out_settings, data, pscan_threads)
		crawler(target, out_settings, data)
		hammer(target, threads, tout, wdlist, redir, sslv, dserv, out_settings, data, filext)
		timetravel(target, data, out_settings)

	if headinfo:
		from modules.headers import headers
		log_writer('Starting header enum...')
		headers(target, out_settings, data)

	if sslinfo:
		from modules.sslinfo import cert
		log_writer('Starting SSL enum...')
		cert(hostname, sslp, out_settings, data)

	if whois:
		from modules.whois import whois_lookup
		log_writer('Starting whois enum...')
		whois_lookup(ip, out_settings, data)

	if crawl:
		from modules.crawler import crawler
		log_writer('Starting crawler...')
		crawler(target, out_settings, data)

	if dns:
		from modules.dns import dnsrec
		log_writer('Starting DNS enum...')
		dnsrec(domain, out_settings, data)

	if subd and not type_ip:
		from modules.subdom import subdomains
		log_writer('Starting subdomain enum...')
		subdomains(domain, tout, out_settings, data, conf_path)

	elif subd and type_ip:
		print(f'{R}[-] {C}Sub-Domain Enumeration is Not Supported for IP Addresses{W}\n')
		log_writer('Sub-Domain Enumeration is Not Supported for IP Addresses, exiting')
		sys.exit(1)

	if wback:
		from modules.wayback import timetravel
		log_writer('Starting wayback enum...')
		timetravel(hostname, data, out_settings)

	if pscan:
		from modules.portscan import scan
		log_writer('Starting port scan...')
		scan(ip, out_settings, data, threads)

	if dirrec:
		from modules.dirrec import hammer
		log_writer('Starting dir enum...')
		hammer(target, threads, tout, wdlist, redir, sslv, dserv, out_settings, data, filext)

	if not any([full, headinfo, sslinfo, whois, crawl, dns, subd, wback, pscan, dirrec]):
		print(f'\n{R}[-] Error : {C}At least One Argument is Required with URL{W}')
		log_writer('At least One Argument is Required with URL, exiting')
		output = 'None'
		sys.exit(1)

	end_time = datetime.datetime.now() - start_time
	print(f'\n{G}[+] {C}Completed in {W}{str(end_time)}\n')
	log_writer(f'Completed in {end_time}')
	print(f'{G}[+] {C}Exported : {W}{respath}')
	log_writer(f'Exported to {respath}')
	log_writer(f'{"-" * 30}')
	sys.exit()
except KeyboardInterrupt:
	print(f'{R}[-] {C}Keyboard Interrupt.{W}\n')
	log_writer('Keyboard interrupt, exiting')
	log_writer(f'{"-" * 30}')
	sys.exit(130)
