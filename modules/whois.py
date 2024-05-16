#!/usr/bin/env python3

import asyncio
from json import load
from modules.export import export
from modules.write_log import log_writer

R = '\033[31m'  # red
G = '\033[32m'  # green
C = '\033[36m'  # cyan
W = '\033[0m'   # white
Y = '\033[33m'  # yellow


async def get_whois(domain, server):
	whois_result = {}
	reader, writer = await asyncio.open_connection(server, 43)
	writer.write((domain + '\r\n').encode())

	raw_resp = b''
	while True:
		chunk = await reader.read(4096)
		if not chunk:
			break
		raw_resp += chunk

	writer.close()
	await writer.wait_closed()
	raw_result = raw_resp.decode()

	if 'No match for' in raw_result:
		whois_result = None

	res_parts = raw_result.split('>>>', 1)
	whois_result['whois'] = res_parts[0]
	return whois_result


def whois_lookup(domain, tld, script_path, output, data):
	result = {}
	db_path = f'{script_path}/whois_servers.json'
	with open(db_path, 'r') as db_file:
		db_json = load(db_file)
	print(f'\n{Y}[!] Whois Lookup : {W}\n')

	try:
		whois_sv = db_json[tld]
		whois_info = asyncio.run(get_whois(f'{domain}.{tld}', whois_sv))
		print(whois_info['whois'])
		result.update(whois_info)
	except KeyError:
		print(f'{R}[-] Error : {C}This domain suffix is not supported.{W}')
		result.update({'Error': 'This domain suffix is not supported.'})
		log_writer('[whois] Exception = This domain suffix is not supported.')
	except Exception as exc:
		print(f'{R}[-] Error : {C}{exc}{W}')
		result.update({'Error': str(exc)})
		log_writer(f'[whois] Exception = {exc}')

	result.update({'exported': False})

	if output != 'None':
		fname = f'{output["directory"]}/whois.{output["format"]}'
		output['file'] = fname
		data['module-whois'] = result
		export(output, data)
	log_writer('[whois] Completed')
