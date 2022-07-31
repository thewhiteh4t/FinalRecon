#!/usr/bin/env python3

R = '\033[31m'  # red
G = '\033[32m'  # green
C = '\033[36m'  # cyan
W = '\033[0m'   # white
Y = '\033[33m'  # yellow

from json import loads
import modules.subdom as parent


async def thcrowd(hostname, session):
	print(f'{Y}[!] {C}Requesting {G}ThreatCrowd{W}')
	url = 'https://www.threatcrowd.org/searchApi/v2/domain/report/'
	thc_params = {
		'domain': hostname
	}
	try:
		async with session.get(url, params=thc_params) as resp:
			sc = resp.status
			if sc == 200:
				output = await resp.text()
				json_out = loads(output)
				if json_out['response_code'] == '0':
					pass
				else:
					subd = json_out['subdomains']
					print(f'{G}[+] {Y}ThreatCrowd {W}found {C}{len(subd)} {W}subdomains!')
					parent.found.extend(subd)
			else:
				print(f'{R}[-] {C}ThreatCrowd Status : {W}{sc}')
	except Exception as e:
		print(f'{R}[-] {C}ThreatCrowd Exception : {W}{e}')
