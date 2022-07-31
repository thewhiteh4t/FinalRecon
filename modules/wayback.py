#!/usr/bin/env python3

R = '\033[31m'  # red
G = '\033[32m'  # green
C = '\033[36m'  # cyan
W = '\033[0m'   # white
Y = '\033[33m'  # yellow

import json
import requests
from datetime import date
from modules.export import export


def timetravel(target, data, output):
	wayback_total = []
	result = {}
	is_avail = False
	domain_query = f'{target}/*'

	curr_yr = date.today().year
	last_yr = curr_yr - 5

	print(f'\n{Y}[!] Starting WayBack Machine...{W}\n')
	print(f'{Y}[!] {C}Checking Availability on Wayback Machine{W}', end='', flush=True)
	wm_avail = 'http://archive.org/wayback/available'
	avail_data = {'url': target}

	try:
		check_rqst = requests.get(wm_avail, params=avail_data, timeout=10)
		check_sc = check_rqst.status_code
		if check_sc == 200:
			check_data = check_rqst.text
			json_chk_data = json.loads(check_data)
			avail_data = json_chk_data['archived_snapshots']
			if len(avail_data) != 0:
				is_avail = True
				print(G + '['.rjust(5, '.') + ' Available ]')
			else:
				print(R + '['.rjust(5, '.') + ' N/A ]')
		else:
			print(f'\n{R}[-] Status : {C}{check_sc}{W}')
	except Exception as e:
		print(f'\n{R}[-] Exception : {C}{e}{W}')

	if is_avail is True:
		print(f'{Y}[!] {C}Fetching URLs{W}', end='', flush=True)
		wm_url = 'http://web.archive.org/cdx/search/cdx'

		payload = {
			'url': domain_query,
			'fl': 'original',
			'fastLatest': 'true',
			'from': str(last_yr),
			'to': str(curr_yr)
		}

		try:
			r = requests.get(wm_url, params=payload)
			r_sc = r.status_code
			if r_sc == 200:
				r_data = r.text
				if len(r_data) != 0:
					r_data = r_data.split('\n')
					r_data = set(r_data)
					print(G + '['.rjust(5, '.') + ' {} ]'.format(str(len(r_data))))
					wayback_total.extend(r_data)

					if output != 'None':
						result.update({'links': list(r_data)})
						result.update({'exported': False})
						data['module-wayback_urls'] = result
						fname = f'{output["directory"]}/wayback_urls.{output["format"]}'
						output['file'] = fname
						export(output, data)
				else:
					print(R + '['.rjust(5, '.') + ' Not Found ]' + W)
			else:
				print(R + '['.rjust(5, '.') + ' {} ]'.format(r_sc) + W)
		except Exception as e:
			print(f'\n{R}[-] Exception : {C}{e}{W}')
