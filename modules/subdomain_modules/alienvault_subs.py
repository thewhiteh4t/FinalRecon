#!/usr/bin/env python3

from json import loads
import modules.subdom as parent
from modules.write_log import log_writer

R = '\033[31m'  # red
G = '\033[32m'  # green
C = '\033[36m'  # cyan
W = '\033[0m'   # white
Y = '\033[33m'  # yellow


async def alienvault(hostname, session):
	print(f'{Y}[!] {C}Requesting {G}AlienVault{W}')
	url = f'https://otx.alienvault.com/api/v1/indicators/domain/{hostname}/passive_dns'
	try:
		async with session.get(url) as resp:
			status = resp.status
			if status == 200:
				output = await resp.text()
				json_data = loads(output)['passive_dns']
				subdomains = []
				for entry in json_data:
					subdomains.append(entry['hostname'])
				parent.found.extend(subdomains)
				print(f'{G}[+] {Y}AlienVault {W}found {C}{len(subdomains)} {W}subdomains!')
			else:
				print(await resp.text())
				print(f'{R}[-] {C}AlienVault Status : {W}{status}')
				log_writer(f'[alienvault_subs] Status = {status}, expected 200')
	except Exception as exc:
		print(f'{R}[-] {C}AlienVault Exception : {W}{exc}')
	log_writer('[alienvault_subs] Completed')
