#!/usr/bin/env python3

import json
import aiohttp
import asyncio
import psycopg2

R = '\033[31m' # red
G = '\033[32m' # green
C = '\033[36m' # cyan
W = '\033[0m'  # white
Y = '\033[33m' # yellow

found = []

async def buffover(hostname, session):
	global found
	print(Y + '[!]' + C + ' Requesting ' + G + 'BuffOver' + W)
	url = 'https://dns.bufferover.run/dns'
	bo_params = {
		'q': '.{}'.format(hostname)
	}
	try:
		async with session.get(url, params=bo_params) as resp:
			sc = resp.status
			if sc == 200:
				output = await resp.text()
				json_out = json.loads(output)
				subds = json_out['FDNS_A']
				if subds == None:
					pass
				else:
					for subd in subds:
						subd = subd.split(',')
						for sub in subd:
							found.append(sub)
			else:
				print(R + '[-]' + C + ' BuffOver Status : ' + W + str(sc))
	except Exception as e:
		print(R + '[-]' + C + ' BuffOver Exception : ' + W + str(e))

async def crtsh(hostname):
	global found
	print(Y + '[!]' + C + ' Requesting ' + G + 'crt.sh' + W)
	try:
		conn = psycopg2.connect(host="crt.sh",database="certwatch", user="guest", port="5432")
		conn.autocommit = True
		cur = conn.cursor()
		query = "SELECT ci.NAME_VALUE NAME_VALUE FROM certificate_identity ci WHERE ci.NAME_TYPE = 'dNSName' AND reverse(lower(ci.NAME_VALUE)) LIKE reverse(lower('%.{}'))".format(hostname)
		cur.execute(query)
		result = cur.fetchall()
		cur.close()
		conn.close()
		for url in result:
			found.append(url[0])
	except Exception as e:
		print(R + '[-]' + C + ' crtsh Exception : ' + W + str(e))

async def thcrowd(hostname, session):
	global found
	print(Y + '[!]' + C + ' Requesting ' + G + 'ThreatCrowd' + W)
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
				print(R + '[-]' + C + ' ThreatCrowd Status : ' + W + str(sc))
	except Exception as e:
		print(R + '[-]' + C + ' ThreatCrowd Exception : ' + W + str(e))

async def anubisdb(hostname, session):
	global found
	print(Y + '[!]' + C + ' Requesting ' + G + 'AnubisDB' + W)
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
				print(R + '[-]' + C + ' AnubisDB Status : ' + W + str(sc))
	except Exception as e:
		print(R + '[-]' + C + 'AnubisDB Exception : ' + W + str(e))

async def thminer(hostname, session):
	global found
	print(Y + '[!]' + C + ' Requesting ' + G + 'ThreatMiner' + W)
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
				print(R + '[-]' + C + ' ThreatMiner Status : ' + W + str(sc))
	except Exception as e:
		print(R + '[-]' + C + ' ThreatMiner Exception : ' + W + str(e))

async def fb_cert(hostname, conf_path, session):
	global found
	with open('{}/keys.json'.format(conf_path), 'r') as keyfile:
		json_read = keyfile.read()

	json_load = json.loads(json_read)
	fb_key = json_load['facebook']

	if fb_key != None:
		print(Y + '[!]' + C + ' Requesting ' + G + 'Facebook' + W)
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
					for i in range (0, len(domains)):
						found.extend(json_read['data'][i]['domains'])
				else:
					print(R + '[-]' + C + ' Facebook Status : ' + W + str(sc))
		except Exception as e:
			print(R + '[-]' + C + ' Facebook Exception : ' + W + str(e))
	else:
		pass

async def virust(hostname, conf_path, session):
	global found
	with open('{}/keys.json'.format(conf_path), 'r') as keyfile:
		json_read = keyfile.read()

	json_load = json.loads(json_read)
	vt_key = json_load['virustotal']

	if vt_key != None:
		print(Y + '[!]' + C + ' Requesting ' + G + 'VirusTotal' + W)
		url = 'https://www.virustotal.com/api/v3/domains/{}/subdomains'.format(hostname)
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
					for i in range (0, len(domains)):
						tmp_list.append(domains[i]['id'])
					found.extend(tmp_list)
				else:
					print(R + '[-]' + C + ' VirusTotal Status : ' + W + str(sc))
		except Exception as e:
			print(R + '[-]' + C + ' VirusTotal Exception : ' + W + str(e))
	else:
		pass

async def certspot(hostname, session):
	global found

	print(Y + '[!]' + C + ' Requesting ' + G + 'CertSpotter' + W)
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
				for i in range (0, len(json_read)):
					domains = json_read[i]['dns_names']
					found.extend(domains)
			else:
				print(R + '[-]' + C + ' CertSpotter Status : ' + W + str(sc))
	except Exception as e:
		print(R + '[-]' + C + ' CertSpotter Exception : ' + W + str(e))

async def query(hostname, tout, conf_path):
	timeout = aiohttp.ClientTimeout(total=tout)
	async with aiohttp.ClientSession(timeout=timeout) as session:
		await asyncio.gather(
			buffover(hostname, session),
			thcrowd(hostname, session),
			anubisdb(hostname, session),
			thminer(hostname, session),
			fb_cert(hostname, conf_path, session),
			virust(hostname, conf_path, session),
			certspot(hostname, session),
			crtsh(hostname)
		)
	await session.close()

def subdomains(hostname, tout, output, data, conf_path):
	global found
	result = {}

	print('\n' + Y + '[!]' + Y + ' Starting Sub-Domain Enumeration...' + W + '\n')

	loop = asyncio.new_event_loop()
	asyncio.set_event_loop(loop)
	loop.run_until_complete(query(hostname, tout, conf_path))
	loop.close()

	from urllib.parse import urlparse
	found = [item for item in found if item.endswith(hostname)]
	valid = r"^[A-Za-z0-9._~()'!*:@,;+?-]*$"
	import re
	found = [item for item in found if re.match(valid, item)]
	found = set(found)
	total = len(found)

	if len(found) != 0:
		print('\n' + G + '[+]' + C + ' Results : ' + W + '\n')
		for url in found:
			print(G + '[+] ' + C + url)

	print('\n' + G + '[+]' + C + ' Total Unique Sub Domains Found : ' + W + str(total))

	if output != 'None':
		result['Links'] = list(found)
		subd_output(output, data, result, total)

def subd_output(output, data, result, total):
	data['module-Subdomain Enumeration'] = result
	data['module-Subdomain Enumeration'].update({'Total Unique Sub Domains Found': str(total)})