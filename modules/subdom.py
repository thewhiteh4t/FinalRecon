#!/usr/bin/env python3

import json
import aiohttp
import asyncio
import psycopg2
from modules.export import export

R = '\033[31m'  # red
G = '\033[32m'  # green
C = '\033[36m'  # cyan
W = '\033[0m'   # white
Y = '\033[33m'  # yellow

found = []


async def crtsh(hostname):
	global found
	print(f'{Y}[!] {C}Requesting {G}crt.sh{W}')
	try:
		conn = psycopg2.connect(
			host="crt.sh",
			database="certwatch",
			user="guest",
			port="5432"
		)
		conn.autocommit = True
		cur = conn.cursor()
		query = f"SELECT ci.NAME_VALUE NAME_VALUE FROM certificate_identity ci WHERE ci.NAME_TYPE = 'dNSName' AND reverse(lower(ci.NAME_VALUE)) LIKE reverse(lower('%.{hostname}'))"
		cur.execute(query)
		result = cur.fetchall()
		cur.close()
		conn.close()
		for url in result:
			found.append(url[0])
	except Exception as e:
		print(f'{R}[-] {C}crtsh Exception : {W}{e}')


async def thcrowd(hostname, session):
	global found
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
				json_out = json.loads(output)
				if json_out['response_code'] == '0':
					pass
				else:
					subd = json_out['subdomains']
					found.extend(subd)
			else:
				print(f'{R}[-] {C}ThreatCrowd Status : {W}{sc}')
	except Exception as e:
		print(f'{R}[-] {C}ThreatCrowd Exception : {W}{e}')


async def anubisdb(hostname, session):
	global found
	print(f'{Y}[!] {C}Requesting {G}AnubisDB{W}')
	url = 'https://jldc.me/anubis/subdomains/{}'.format(hostname)
	try:
		async with session.get(url) as resp:
			sc = resp.status
			if sc == 200:
				output = await resp.text()
				json_out = json.loads(output)
				found.extend(json_out)
			elif sc == 300:
				pass
			else:
				print(f'{R}[-] {C}AnubisDB Status : {W}{sc}')
	except Exception as e:
		print(f'{R}[-] {C}AnubisDB Exception : {W}{e}')


async def thminer(hostname, session):
	global found
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
				json_out = json.loads(output)
				subd = json_out['results']
				found.extend(subd)
			else:
				print(f'{R}[-] {C}ThreatMiner Status : {W}{sc}')
	except Exception as e:
		print(f'{R}[-] {C}ThreatMiner Exception : {W}{e}')


async def fb_cert(hostname, conf_path, session):
	global found
	with open(f'{conf_path}/keys.json', 'r') as keyfile:
		json_read = keyfile.read()

	json_load = json.loads(json_read)
	fb_key = json_load['facebook']

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
				sc = resp.status
				if sc == 200:
					json_data = await resp.text()
					json_read = json.loads(json_data)
					domains = json_read['data']
					for i in range(0, len(domains)):
						found.extend(json_read['data'][i]['domains'])
				else:
					print(f'{R}[-] {C}Facebook Status : {W}{sc}')
		except Exception as e:
			print(f'{R}[-] {C}Facebook Exception : {W}{e}')
	else:
		pass


async def virust(hostname, conf_path, session):
	global found
	with open(f'{conf_path}/keys.json', 'r') as keyfile:
		json_read = keyfile.read()

	json_load = json.loads(json_read)
	vt_key = json_load['virustotal']

	if vt_key is not None:
		print(f'{Y}[!] {C}Requesting {G}VirusTotal{W}')
		url = f'https://www.virustotal.com/api/v3/domains/{hostname}/subdomains'
		vt_headers = {
			'x-apikey': vt_key
		}
		try:
			async with session.get(url, headers=vt_headers) as resp:
				sc = resp.status
				if sc == 200:
					json_data = await resp.text()
					json_read = json.loads(json_data)
					domains = json_read['data']
					tmp_list = []
					for i in range(0, len(domains)):
						tmp_list.append(domains[i]['id'])
					found.extend(tmp_list)
				else:
					print(f'{R}[-] {C}VirusTotal Status : {W}{sc}')
		except Exception as e:
			print(f'{R}[-] {C}VirusTotal Exception : {W}{e}')
	else:
		pass


async def certspot(hostname, session):
	global found

	print(f'{Y}[!] {C}Requesting {G}CertSpotter{W}')
	url = 'https://api.certspotter.com/v1/issuances'
	cs_params = {
		'domain': hostname,
		'expand': 'dns_names',
		'include_subdomains': 'true'
	}

	try:
		async with session.get(url, params=cs_params) as resp:
			sc = resp.status
			if sc == 200:
				json_data = await resp.text()
				json_read = json.loads(json_data)
				for i in range(0, len(json_read)):
					domains = json_read[i]['dns_names']
					found.extend(domains)
			else:
				print(f'{R}[-] {C}CertSpotter Status : {W}{sc}')
	except Exception as e:
		print(f'{R}[-] {C}CertSpotter Exception : {W}{e}')


async def shodan(hostname, conf_path, session):
	with open(f'{conf_path}/keys.json', 'r') as keyfile:
		json_read = keyfile.read()

	json_load = json.loads(json_read)
	sho_key = json_load['shodan']

	if sho_key is not None:
		print(f'{Y}[!] {C}Requesting {G}Shodan{W}')
		url = f'https://api.shodan.io/dns/domain/{hostname}?key={sho_key}'

		try:
			async with session.get(url) as resp:
				sc = resp.status
				if sc == 200:
					json_data = await resp.text()
					json_read = json.loads(json_data)
					domains = json_read['subdomains']
					tmp_list = []
					for i in range(0, len(domains)):
						tmp_list.append(f'{domains[i]}.{hostname}')
					found.extend(tmp_list)
				else:
					print(f'{R}[-] {C}Shodan Status : {W}{sc}')
		except Exception as e:
			print(f'{R}[-] {C}Shodan Exception : {W}{e}')
	else:
		pass


async def query(hostname, tout, conf_path):
	timeout = aiohttp.ClientTimeout(total=tout)
	async with aiohttp.ClientSession(timeout=timeout) as session:
		await asyncio.gather(
			thcrowd(hostname, session),
			anubisdb(hostname, session),
			thminer(hostname, session),
			fb_cert(hostname, conf_path, session),
			virust(hostname, conf_path, session),
			shodan(hostname, conf_path, session),
			certspot(hostname, session),
			crtsh(hostname)
		)
	await session.close()


def subdomains(hostname, tout, output, data, conf_path):
	global found
	result = {}

	print(f'\n{Y}[!] Starting Sub-Domain Enumeration...{W}\n')

	loop = asyncio.new_event_loop()
	asyncio.set_event_loop(loop)
	loop.run_until_complete(query(hostname, tout, conf_path))
	loop.close()

	found = [item for item in found if item.endswith(hostname)]
	valid = r"^[A-Za-z0-9._~()'!*:@,;+?-]*$"
	from re import match
	found = [item for item in found if match(valid, item)]
	found = set(found)
	total = len(found)

	if len(found) != 0:
		print(f'\n{G}[+] {C}Results : {W}\n')
		for url in found:
			print(url)

	print(f'\n{G}[+] {C}Total Unique Sub Domains Found : {W}{total}')

	if output != 'None':
		result['Links'] = list(found)
		result.update({'exported': False})
		data['module-Subdomain Enumeration'] = result
		fname = f'{output["directory"]}/subdomains.{output["format"]}'
		output['file'] = fname
		export(output, data)
