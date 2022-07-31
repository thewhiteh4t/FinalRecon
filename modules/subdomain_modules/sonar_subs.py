#!/usr/bin/env python3

R = '\033[31m'  # red
G = '\033[32m'  # green
C = '\033[36m'  # cyan
W = '\033[0m'   # white
Y = '\033[33m'  # yellow

from json import loads
import modules.subdom as parent


async def sonar(hostname, session):
	print(f'{Y}[!] {C}Requesting {G}Sonar{W}')
	url = f'https://sonar.omnisint.io/subdomains/{hostname}'
	try:
		async with session.get(url) as resp:
			sc = resp.status
			if sc == 200:
				json_data = await resp.text()
				json_read = loads(json_data)
				print(f'{G}[+] {Y}Sonar {W}found {C}{len(json_read)} {W}subdomains!')
				parent.found.extend(json_read)
			else:
				print(f'{R}[-] {C}Sonar Status : {W}{sc}')
	except Exception as e:
		print(f'{R}[-] {C}Sonar Exception : {W}{e}')
