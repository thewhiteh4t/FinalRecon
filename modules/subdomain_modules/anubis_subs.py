#!/usr/bin/env python3

from json import loads
import modules.subdom as parent
from modules.write_log import log_writer

R = '\033[31m'  # red
G = '\033[32m'  # green
C = '\033[36m'  # cyan
W = '\033[0m'   # white
Y = '\033[33m'  # yellow


async def anubisdb(hostname, session):
	print(f'{Y}[!] {C}Requesting {G}AnubisDB{W}')
	url = f'https://jldc.me/anubis/subdomains/{hostname}'
	try:
		async with session.get(url) as resp:
			status = resp.status
			if status == 200:
				output = await resp.text()
				json_out = loads(output)
				parent.found.extend(json_out)
				print(f'{G}[+] {Y}AnubisDB {W}found {C}{len(json_out)} {W}subdomains!')
			elif status == 300:
				print(f'{G}[+] {Y}AnubisDB {W}found {C}0 {W}subdomains!')
				log_writer(f'[anubis_subs] Status = {status}, no subdomains found')
			else:
				print(await resp.text())
				print(f'{R}[-] {C}AnubisDB Status : {W}{status}')
				log_writer(f'[anubis_subs] Status = {status}, expected 200')
	except Exception as exc:
		print(f'{R}[-] {C}AnubisDB Exception : {W}{exc}')
	log_writer('[anubis_subs] Completed')
