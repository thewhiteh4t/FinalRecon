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


async def virust(hostname, conf_path, session):
	vt_key = environ.get('FR_VT_KEY')

	if not vt_key:
		log_writer('[virustotal_subs] key missing in env')
		with open(f'{conf_path}/keys.json', 'r') as keyfile:
			json_read = keyfile.read()

		json_load = loads(json_read)
		try:
			vt_key = json_load['virustotal']
		except KeyError:
			log_writer('[virustotal_subs] key missing in keys.json')
			with open(f'{conf_path}/keys.json', 'w') as outfile:
				json_load['virustotal'] = None
				vt_key = None
				outfile.write(
					dumps(json_load, sort_keys=True, indent=4)
				)

	if vt_key is not None:
		print(f'{Y}[!] {C}Requesting {G}VirusTotal{W}')
		url = f'https://www.virustotal.com/api/v3/domains/{hostname}/subdomains'
		vt_headers = {
			'x-apikey': vt_key
		}
		try:
			async with session.get(url, headers=vt_headers) as resp:
				status = resp.status
				if status == 200:
					json_data = await resp.text()
					json_read = loads(json_data)
					domains = json_read['data']
					tmp_list = []
					for i in range(0, len(domains)):
						tmp_list.append(domains[i]['id'])
					print(f'{G}[+] {Y}VirusTotal {W}found {C}{len(tmp_list)} {W}subdomains!')
					parent.found.extend(tmp_list)
				else:
					print(f'{R}[-] {C}VirusTotal Status : {W}{status}')
					log_writer(f'[virustotal_subs] Status = {status}')
		except Exception as exc:
			print(f'{R}[-] {C}VirusTotal Exception : {W}{exc}')
			log_writer(f'[virustotal_subs] Exception = {exc}')
	else:
		print(f'{Y}[!] Skipping VirusTotal : {W}API key not found!')
		log_writer('[virustotal_subs] API key not found')
	log_writer('[virustotal_subs] Completed')
