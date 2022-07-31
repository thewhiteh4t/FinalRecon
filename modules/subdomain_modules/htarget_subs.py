#!/usr/bin/env python3

R = '\033[31m'  # red
G = '\033[32m'  # green
C = '\033[36m'  # cyan
W = '\033[0m'   # white
Y = '\033[33m'  # yellow

import modules.subdom as parent


async def hackertgt(hostname, session):
	print(f'{Y}[!] {C}Requesting {G}HackerTarget{W}')
	url = f'https://api.hackertarget.com/hostsearch/?q={hostname}'
	try:
		async with session.get(url) as resp:
			sc = resp.status
			if sc == 200:
				data = await resp.text()
				data_list = data.split('\n')
				tmp_list = []
				for line in data_list:
					subdomain = line.split(',')[0]
					tmp_list.append(subdomain)
				print(f'{G}[+] {Y}HackerTarget {W}found {C}{len(tmp_list)} {W}subdomains!')
				parent.found.extend(tmp_list)
			else:
				print(f'{R}[-] {C}HackerTarget Status : {W}{sc}')
	except Exception as e:
		print(f'{R}[-] {C}HackerTarget Exception : {W}{e}')
