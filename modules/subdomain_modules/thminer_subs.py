#!/usr/bin/env python3

from json import loads
import modules.subdom as parent
from modules.write_log import log_writer

R = '\033[31m'  # red
G = '\033[32m'  # green
C = '\033[36m'  # cyan
W = '\033[0m'   # white
Y = '\033[33m'  # yellow


async def thminer(hostname, session):
	print(f'{Y}[!] {C}Requesting {G}ThreatMiner{W}')
	url = 'https://api.threatminer.org/v2/domain.php'
	thm_params = {
		'q': hostname,
		'rt': '5'
	}
	try:
		async with session.get(url, params=thm_params) as resp:
			status = resp.status
			if status == 200:
				output = await resp.text()
				json_out = loads(output)
				subd = json_out['results']
				print(f'{G}[+] {Y}ThreatMiner {W}found {C}{len(subd)} {W}subdomains!')
				parent.found.extend(subd)
			else:
				print(f'{R}[-] {C}ThreatMiner Status : {W}{status}')
				log_writer(f'[thminer_subs] Status = {status}, expected 200')
	except Exception as exc:
		print(f'{R}[-] {C}ThreatMiner Exception : {W}{exc}')
		log_writer(f'[thminer_subs] Exception = {exc}')
	log_writer('[thminer_subs] Completed')
