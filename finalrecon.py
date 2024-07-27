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
keys_file_path = config.keys_file_path

log_writer(
	f'PATHS = HOME:{home}, SCRIPT_LOC:{path_to_script},\
	METADATA:{meta_file_path}, KEYS:{config.keys_file_path},\
	CONFIG:{config.conf_file_path}, LOG:{config.log_file_path}'
)

import argparse

VERSION = '1.1.7'
log_writer(f'FinalRecon v{VERSION}')

parser = argparse.ArgumentParser(description=f'FinalRecon - All in One Web Recon | v{VERSION}')
parser.add_argument('--url', help='Target URL')
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
ext_help.add_argument('-nb', action='store_false', help='Hide Banner')
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
ext_help.add_argument('-cd', help='Change export directory [ Default : ~/.local/share/finalrecon ]')
ext_help.add_argument('-of', help='Change export folder name [ Default :<path>fr_<hostname>_<date> ]')
ext_help.add_argument('-k', help='Add API key [ Example : shodan@key ]')
ext_help.set_defaults(
	dt=config.dir_enum_th,
	pt=config.port_scan_th,
	T=config.timeout,
	w=config.dir_enum_wlist,
	r=config.dir_enum_redirect,
	s=config.dir_enum_sslv,
	sp=config.ssl_port,
	d=config.custom_dns,
	e=config.dir_enum_ext,
	o=config.export_fmt,
	cd=config.usr_data,
	of = None,
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
show_banner = args.nb
add_key = args.k
output_dir = args.cd
folder_name = args.of

import socket
import datetime
import ipaddress
import tldextract
from json import loads, dumps
from urllib import parse

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


def save_key(key_string):
	valid_keys = ['bevigil', 'binedge', 'facebook', 'netlas', 'shodan', 'virustotal', 'zoomeye', 'hunter']
	key_parts = key_string.split('@', 1)
	key_name = key_parts[0]
	key_str = key_parts[1]
	if key_name not in valid_keys:
		print(f'{R}[-] {C}Invalid key name!{W}')
		log_writer('Invalid key name, exiting')
		sys.exit(1)
	with open(keys_file_path, 'r') as keyfile:
		keys_json = loads(keyfile.read())
	keys_json[key_name] = key_str
	with open(keys_file_path, 'w') as key_update:
		key_update.write(dumps(keys_json))
	print(f'{G}[+] {W}{key_name} {C}Key Added!{W}')
	sys.exit(1)


try:
	if show_banner:
		banner()

	if add_key:
		save_key(add_key)

	if not target:
		print(f'{R}[-] {C}No Target Specified!{W}')
		sys.exit(1)

	if not target.startswith(('http', 'https')):
		print(f'{R}[-] {C}Protocol Missing, Include {W}http:// {C}or{W} https:// \n')
		log_writer(f'Protocol missing in {target}, exiting')
		sys.exit(1)

	if target.endswith('/'):
		target = target[:-1]

	print(f'{G}[+] {C}Target : {W}{target}')

	split_url = parse.urlsplit(target)
	extractor = tldextract.TLDExtract()
	parsed_url = extractor.extract_urllib(split_url)
	protocol = split_url.scheme

	if split_url.port:
		if not parsed_url.subdomain:
			netloc = parsed_url.domain                              # localhost:8000
			domain = netloc.split(':')[0]
			domain_suffix = ''
			hostname = domain
		else:
			netloc = f'{parsed_url.subdomain}.{parsed_url.domain}'  # abc.com:8000
			domain = parsed_url.subdomain
			domain_suffix = parsed_url.domain.split(':')[0]
			hostname = f'{domain}.{domain_suffix}'
	else:
		if len(parsed_url.registered_domain) == 0:
			netloc = parsed_url.domain                              # 8.8.8.8
			domain = ''
			domain_suffix = ''
		else:
			netloc = parsed_url.registered_domain                   # abc.com
			domain = parsed_url.domain
			domain_suffix = parsed_url.suffix
		hostname = netloc

	try:
		ipaddress.ip_address(hostname)
		type_ip = True
		ip = hostname
		private_ip = ipaddress.ip_address(ip).is_private
	except Exception:
		try:
			ip = socket.gethostbyname(hostname)
			print(f'\n{G}[+] {C}IP Address : {W}{str(ip)}')
			private_ip = ipaddress.ip_address(ip).is_private
		except Exception as e:
			print(f'\n{R}[-] {C}Unable to Get IP : {W}{str(e)}')
			sys.exit(1)

	start_time = datetime.datetime.now()

	if output != 'None':
		fpath = output_dir
		if not folder_name:
			dt_now = str(datetime.datetime.now().strftime('%d-%m-%Y_%H:%M:%S'))
			fname = f'{fpath}fr_{hostname}_{dt_now}.{output}'
			respath = f'{fpath}fr_{hostname}_{dt_now}'
		else:
			fname = f'{fpath}{folder_name}.{output}'
			respath = f'{fpath}{folder_name}'
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
		whois_lookup(domain, domain_suffix, path_to_script, out_settings, data)
		dnsrec(hostname, dserv, out_settings, data)
		if not type_ip and not private_ip:
			subdomains(hostname, tout, out_settings, data, conf_path)
		scan(ip, out_settings, data, pscan_threads)
		crawler(target, protocol, netloc, out_settings, data)
		hammer(target, threads, tout, wdlist, redir, sslv, out_settings, data, filext)
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
		whois_lookup(domain, domain_suffix, path_to_script, out_settings, data)

	if crawl:
		from modules.crawler import crawler
		log_writer('Starting crawler...')
		crawler(target, protocol, netloc, out_settings, data)

	if dns:
		from modules.dns import dnsrec
		log_writer('Starting DNS enum...')
		dnsrec(hostname, dserv, out_settings, data)

	if subd and not type_ip and not private_ip:
		from modules.subdom import subdomains
		log_writer('Starting subdomain enum...')
		subdomains(hostname, tout, out_settings, data, conf_path)

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
		hammer(target, threads, tout, wdlist, redir, sslv, out_settings, data, filext)

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
