#!/usr/bin/env python3

R = '\033[31m'  # red
G = '\033[32m'  # green
C = '\033[36m'  # cyan
W = '\033[0m'   # white
Y = '\033[33m'  # yellow

from json import loads
import modules.subdom as parent


async def thminer(hostname, session):
	print(f'{Y}[!] {C}Requesting {G}ThreatMiner{W}')
	url = 'https://api.threatminer.org/v2/domain.php'
	thm_params = {
		'q': hostname,
		'rt': '5'
	}
	try:
		async with session.get(url, params=thm_params) as resp:
			sc = resp.status
			if sc == 200:
				output = await resp.text()
				json_out = loads(output)
				subd = json_out['results']
				print(f'{G}[+] {Y}ThreatMiner {W}found {C}{len(subd)} {W}subdomains!')
				parent.found.extend(subd)
			else:
				print(f'{R}[-] {C}ThreatMiner Status : {W}{sc}')
	except Exception as e:
		print(f'{R}[-] {C}ThreatMiner Exception : {W}{e}')
