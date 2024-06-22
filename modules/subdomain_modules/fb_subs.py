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


async def fb_cert(hostname, conf_path, session):
	fb_key = environ.get('FR_FB_KEY')

	if not fb_key:
		log_writer('[fb_subs] key missing in env')
		with open(f'{conf_path}/keys.json', 'r') as keyfile:
			json_read = keyfile.read()

		json_load = loads(json_read)
		try:
			fb_key = json_load['facebook']
		except KeyError:
			log_writer('[fb_subs] key missing in keys.json')
			with open(f'{conf_path}/keys.json', 'w') as outfile:
				json_load['facebook'] = None
				fb_key = None
				outfile.write(
					dumps(json_load, sort_keys=True, indent=4)
				)

	if fb_key is not None:
		print(f'{Y}[!] {C}Requesting {G}Facebook{W}')
		url = 'https://graph.facebook.com/certificates'
		fb_params = {
			'query': hostname,
			'fields': 'domains',
			'access_token': fb_key
		}
		try:
			async with session.get(url, params=fb_params) as resp:
				status = resp.status
				if status == 200:
					json_data = await resp.text()
					json_read = loads(json_data)
					domains = json_read['data']
					print(f'{G}[+] {Y}Facebook {W}found {C}{len(domains)} {W}subdomains!')
					for i in range(0, len(domains)):
						parent.found.extend(json_read['data'][i]['domains'])
				else:
					print(f'{R}[-] {C}Facebook Status : {W}{status}')
					log_writer(f'[fb_subs] Status = {status}, expected 200')
		except Exception as exc:
			print(f'{R}[-] {C}Facebook Exception : {W}{exc}')
			log_writer(f'[fb_subs] Exception = {exc}')
	else:
		print(f'{Y}[!] Skipping Facebook : {W}API key not found!')
		log_writer('[fb_subs] API key not found')
	log_writer('[fb_subs] Completed')
