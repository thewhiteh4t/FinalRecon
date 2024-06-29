#!/usr/bin/env python3

import asyncio
import aiohttp
from re import match
from modules.export import export
from modules.write_log import log_writer
from modules.subdomain_modules.bevigil_subs import bevigil
from modules.subdomain_modules.anubis_subs import anubisdb
from modules.subdomain_modules.thminer_subs import thminer
from modules.subdomain_modules.fb_subs import fb_cert
from modules.subdomain_modules.virustotal_subs import virust
from modules.subdomain_modules.shodan_subs import shodan
from modules.subdomain_modules.certspot_subs import certspot
# from modules.subdomain_modules.wayback_subs import machine
from modules.subdomain_modules.crtsh_subs import crtsh
from modules.subdomain_modules.htarget_subs import hackertgt
from modules.subdomain_modules.binedge_subs import binedge
from modules.subdomain_modules.zoomeye_subs import zoomeye
from modules.subdomain_modules.netlas_subs import netlas
from modules.subdomain_modules.hunter_subs import hunter
from modules.subdomain_modules.urlscan_subs import urlscan
from modules.subdomain_modules.alienvault_subs import alienvault

R = '\033[31m'  # red
G = '\033[32m'  # green
C = '\033[36m'  # cyan
W = '\033[0m'   # white
Y = '\033[33m'  # yellow

found = []


async def query(hostname, tout, conf_path):
	timeout = aiohttp.ClientTimeout(total=tout)
	async with aiohttp.ClientSession(timeout=timeout) as session:
		await asyncio.gather(
			bevigil(hostname, conf_path, session),
			anubisdb(hostname, session),
			thminer(hostname, session),
			fb_cert(hostname, conf_path, session),
			virust(hostname, conf_path, session),
			shodan(hostname, conf_path, session),
			certspot(hostname, session),
			# machine(hostname, session),
			hackertgt(hostname, session),
			crtsh(hostname, session),
			binedge(hostname, conf_path, session),
			zoomeye(hostname, conf_path, session),
			netlas(hostname, conf_path, session),
			hunter(hostname, conf_path, session),
			urlscan(hostname, session),
			alienvault(hostname, session)
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
	found = [item for item in found if match(valid, item)]
	found = set(found)
	total = len(found)

	if found:
		print(f'\n{G}[+] {C}Results : {W}\n')
		for url in enumerate(list(found)[:20]):
			print(url[1])

		if len(found) > 20:
			print(f'\n{G}[+]{C} Results truncated...{W}')

	print(f'\n{G}[+] {C}Total Unique Sub Domains Found : {W}{total}')

	if output != 'None':
		result['Links'] = list(found)
		result.update({'exported': False})
		data['module-Subdomain Enumeration'] = result
		fname = f'{output["directory"]}/subdomains.{output["format"]}'
		output['file'] = fname
		export(output, data)
	log_writer('[subdom] Completed')
