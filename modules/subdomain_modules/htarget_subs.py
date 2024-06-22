#!/usr/bin/env python3

import modules.subdom as parent
from modules.write_log import log_writer

R = '\033[31m'  # red
G = '\033[32m'  # green
C = '\033[36m'  # cyan
W = '\033[0m'   # white
Y = '\033[33m'  # yellow


async def hackertgt(hostname, session):
	print(f'{Y}[!] {C}Requesting {G}HackerTarget{W}')
	url = f'https://api.hackertarget.com/hostsearch/?q={hostname}'
	try:
		async with session.get(url) as resp:
			status = resp.status
			if status == 200:
				data = await resp.text()
				data_list = data.split('\n')
				tmp_list = []
				for line in data_list:
					subdomain = line.split(',')[0]
					tmp_list.append(subdomain)
				print(f'{G}[+] {Y}HackerTarget {W}found {C}{len(tmp_list)} {W}subdomains!')
				parent.found.extend(tmp_list)
			else:
				print(f'{R}[-] {C}HackerTarget Status : {W}{status}')
				log_writer(f'[htarget_subs] Status = {status}, expected 200')
	except Exception as exc:
		print(f'{R}[-] {C}HackerTarget Exception : {W}{exc}')
		log_writer(f'[htarget_subs] Exception = {exc}')
	log_writer('[htarget_subs] Completed')
