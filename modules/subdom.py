#!/usr/bin/env python3

import json
import asyncio
import requests
import psycopg2

R = '\033[31m' # red
G = '\033[32m' # green
C = '\033[36m' # cyan
W = '\033[0m'  # white
Y = '\033[33m' # yellow

found = []

async def buffover(hostname, tout):
	global found
	print(Y + '[!]' + C + ' Requesting ' + G + 'BuffOver' + W)
	url = 'https://dns.bufferover.run/dns'
	data = {
	'q': '.{}'.format(hostname)
	}
	try:
		r = requests.get(url, params=data, timeout=tout)
		sc = r.status_code
		if sc == 200:
			output = r.content.decode()
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

async def thcrowd(hostname, tout):
	global found
	print(Y + '[!]' + C + ' Requesting ' + G + 'ThreadCrowd' + W)
	url = 'https://www.threatcrowd.org/searchApi/v2/domain/report/'
	data = {
	'domain': hostname
	}
	try:
		r = requests.get(url, params=data, timeout=tout)
		sc = r.status_code
		if sc == 200:
			output = r.content.decode()
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

async def anubisdb(hostname, tout):
	global found
	print(Y + '[!]' + C + ' Requesting ' + G + 'AnubisDB' + W)
	url = 'https://jldc.me/anubis/subdomains/{}'.format(hostname)
	try:
		r = requests.get(url, timeout=tout)
		sc = r.status_code
		if sc == 200:
			output = r.content.decode()
			json_out = json.loads(output)
			found.extend(json_out)
		elif sc == 300:
			pass
		else:
			print(R + '[-]' + C + ' AnubisDB Status : ' + W + str(sc))
	except Exception as e:
		print(R + '[-]' + C + 'AnubisDB Exception : ' + W + str(e))

async def thminer(hostname, tout):
	global found
	print(Y + '[!]' + C + ' Requesting ' + G + 'ThreatMiner' + W)
	url = 'https://api.threatminer.org/v2/domain.php?q=instagram.com&rt=5'
	data = {
	'q': hostname,
	'rt': '5'
	}
	try:
		r = requests.get(url, params=data, timeout=tout)
		sc = r.status_code
		if sc == 200:
			output = r.content.decode()
			json_out = json.loads(output)
			subd = json_out['results']
			found.extend(subd)
		else:
			print(R + '[-]' + C + ' ThreatMiner Status : ' + W + str(sc))
	except Exception as e:
		print(R + '[-]' + C + ' ThreatMiner Exception : ' + W + str(e))

async def fb_cert(hostname, tout):
	global found
	with open('conf/keys.json', 'r') as keyfile:
		json_read = keyfile.read()
	
	json_load = json.loads(json_read)
	fb_key = json_load['api_keys'][0]['facebook']
	
	if fb_key != None:
		print(Y + '[!]' + C + ' Requesting ' + G + 'Facebook' + W)
		url = 'https://graph.facebook.com/certificates'
		data = {
			'query': hostname,
    		'fields': 'domains',
    		'access_token': fb_key
		}

		r = requests.get(url, params=data)
		json_data = r.text
		json_read = json.loads(json_data)
		domains = json_read['data']

		for i in range (0, len(domains)):
			found.extend(json_read['data'][i]['domains'])
	else:
		pass

async def query(hostname, tout):
	await asyncio.gather(
		buffover(hostname, tout),
		thcrowd(hostname, tout),
		crtsh(hostname),
		anubisdb(hostname, tout),
		thminer(hostname, tout),
		fb_cert(hostname, tout)
		)

def subdomains(hostname, tout, output, data):
	global found
	result = {}

	print('\n' + Y + '[!]' + Y + ' Starting Sub-Domain Enumeration...' + W + '\n')

	loop = asyncio.new_event_loop()
	asyncio.set_event_loop(loop)
	loop.run_until_complete(query(hostname, tout))
	loop.close()

	found = set(found)
	total = len(found)

	if len(found) != 0:
		print('\n' + G + '[+]' + C + ' Results : ' + W + '\n')
		for url in found:
			print(G + '[+] ' + C + url)

	print('\n' + G + '[+]' + C + ' Total Found : ' + W + str(total))

	if output != 'None':
		result['Links'] = list(found)
		subd_output(output, data, result, total)

def subd_output(output, data, result, total):
	data['module-Subdomain Enumeration'] = result
	data['module-Subdomain Enumeration'].update({'Total Found': str(total)})