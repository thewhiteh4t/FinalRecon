#!/usr/bin/env python3

from json import loads
import modules.subdom as parent
from modules.write_log import log_writer

R = '\033[31m'  # red
G = '\033[32m'  # green
C = '\033[36m'  # cyan
W = '\033[0m'   # white
Y = '\033[33m'  # yellow


async def sonar(hostname, session):
	print(f'{Y}[!] {C}Requesting {G}Sonar{W}')
	url = f'https://sonar.omnisint.io/subdomains/{hostname}'
	try:
		async with session.get(url) as resp:
			status = resp.status
			if status == 200:
				json_data = await resp.text()
				json_read = loads(json_data)
				print(f'{G}[+] {Y}Sonar {W}found {C}{len(json_read)} {W}subdomains!')
				parent.found.extend(json_read)
			else:
				print(f'{R}[-] {C}Sonar Status : {W}{status}')
				log_writer(f'[sonar_subs] Status = {status}, expected 200')
	except Exception as exc:
		print(f'{R}[-] {C}Sonar Exception : {W}{exc}')
		log_writer(f'[sonar_subs] Exception = {exc}')
	log_writer('[sonar_subs] Completed')
