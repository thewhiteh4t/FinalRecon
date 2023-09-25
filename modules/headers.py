#!/usr/bin/env python3

import requests
from modules.export import export
from modules.write_log import log_writer
requests.packages.urllib3.disable_warnings()

R = '\033[31m'  # red
G = '\033[32m'  # green
C = '\033[36m'  # cyan
W = '\033[0m'   # white
Y = '\033[33m'  # yellow


def headers(target, output, data):
	result = {}
	print(f'\n{Y}[!] Headers :{W}\n')
	try:
		rqst = requests.get(target, verify=False, timeout=10)
		for key, val in rqst.headers.items():
			print(f'{C}{key} : {W}{val}')
			if output != 'None':
				result.update({key: val})
	except Exception as exc:
		print(f'\n{R}[-] {C}Exception : {W}{exc}\n')
		if output != 'None':
			result.update({'Exception': str(exc)})
		log_writer(f'[headers] Exception = {exc}')
	result.update({'exported': False})

	if output != 'None':
		fname = f'{output["directory"]}/headers.{output["format"]}'
		output['file'] = fname
		data['module-headers'] = result
		export(output, data)
	log_writer('[headers] Completed')
