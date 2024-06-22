#!/usr/bin/env python3

from json import loads
import modules.subdom as parent
from modules.write_log import log_writer

R = '\033[31m'  # red
G = '\033[32m'  # green
C = '\033[36m'  # cyan
W = '\033[0m'   # white
Y = '\033[33m'  # yellow


async def crtsh(hostname, session):
	print(f'{Y}[!] {C}Requesting {G}crt.sh{W}')
	url = f'https://crt.sh/?dNSName=%25.{hostname}&output=json'

	try:
		async with session.get(url) as resp:
			status = resp.status
			if status == 200:
				data = await resp.text()
				data_json = loads(data)
				tmp_list = []
				for entry in data_json:
					subdomain = entry['name_value']
					tmp_list.append(subdomain)
				print(f'{G}[+] {Y}crt.sh {W}found {C}{len(tmp_list)} {W}subdomains!')
				parent.found.extend(tmp_list)
			else:
				print(f'{R}[-] {C}HackerTarget Status : {W}{status}')
				log_writer(f'[htarget_subs] Status = {status}, expected 200')
	except Exception as exc:
		print(f'{R}[-] {C}crtsh Exception : {W}{exc}')
		log_writer(f'[crtsh_subs] Exception = {exc}')
	log_writer('[crtsh_subs] Completed')
