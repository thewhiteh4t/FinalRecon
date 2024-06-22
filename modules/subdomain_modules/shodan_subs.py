#!/usr/bin/env python3

from os import environ
from json import loads, dumps
import modules.subdom as parent
from modules.write_log import log_writer

R = '\033[31m'  # red
G = '\033[32m'  # green
C = '\033[36m'  # cyan
W = '\033[0m'   # white
Y = '\033[33m'  # yellow


async def shodan(hostname, conf_path, session):
	sho_key = environ.get('FR_SHODAN_KEY')

	if not sho_key:
		log_writer('[shodan_subs] key missing in env')
		with open(f'{conf_path}/keys.json', 'r') as keyfile:
			json_read = keyfile.read()

		json_load = loads(json_read)
		try:
			sho_key = json_load['shodan']
		except KeyError:
			log_writer('[shodan_subs] key missing in keys.json')
			with open(f'{conf_path}/keys.json', 'w') as outfile:
				json_load['shodan'] = None
				sho_key = None
				outfile.write(
					dumps(json_load, sort_keys=True, indent=4)
				)

	if sho_key is not None:
		print(f'{Y}[!] {C}Requesting {G}Shodan{W}')
		url = f'https://api.shodan.io/dns/domain/{hostname}?key={sho_key}'

		try:
			async with session.get(url) as resp:
				status = resp.status
				if status == 200:
					json_data = await resp.text()
					json_read = loads(json_data)
					domains = json_read['subdomains']
					tmp_list = []
					for i in range(0, len(domains)):
						tmp_list.append(f'{domains[i]}.{hostname}')
					print(f'{G}[+] {Y}Shodan {W}found {C}{len(tmp_list)} {W}subdomains!')
					parent.found.extend(tmp_list)
				else:
					print(f'{R}[-] {C}Shodan Status : {W}{status}')
					log_writer(f'[shodan_subs] Status = {status}, expected 200')
		except Exception as exc:
			print(f'{R}[-] {C}Shodan Exception : {W}{exc}')
			log_writer(f'[shodan_subs] Exception = {exc}')
	else:
		print(f'{Y}[!] Skipping Shodan : {W}API key not found!')
		log_writer('[shodan_subs] API key not found')
	log_writer('[shodan_subs] Completed')
