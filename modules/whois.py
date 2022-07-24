#!/usr/bin/env python3

import ipwhois
from modules.export import export

R = '\033[31m'  # red
G = '\033[32m'  # green
C = '\033[36m'  # cyan
W = '\033[0m'   # white
Y = '\033[33m'  # yellow


def whois_lookup(ip_addr, output, data):
	result = {}
	print(f'\n{Y}[!] Whois Lookup : {W}\n')
	try:
		lookup = ipwhois.IPWhois(ip_addr)
		results = lookup.lookup_whois()

		for key, val in results.items():
			if val is not None:
				if isinstance(val, list):
					for item in val:
						for key, value in item.items():
							if value is not None:
								if not isinstance(value, list):
									temp_val = value.replace(',', ' ').replace('\r', ' ').replace('\n', ' ')
									print(f'{G}[+] {C}{key}: {W}{temp_val}')
									if output != 'None':
										result.update({str(key): str(temp_val)})
								else:
									temp_val = ', '.join(value)
									print(f'{G}[+] {C}{key}: {W}{temp_val}')
									if output != 'None':
										result.update({str(key): str(temp_val)})
							else:
								pass
				else:
					temp_val = val.replace(',', ' ').replace('\r', ' ').replace('\n', ' ')
					print(f'{G}[+] {C}{key}: {W}{temp_val}')
					if output != 'None':
						result.update({str(key): str(temp_val)})
			else:
				pass
	except Exception as e:
		print(f'{R}[-] Error : {C}{e}{W}')
		if output != 'None':
			result.update({'Error': str(e)})

	result.update({'exported': False})

	if output != 'None':
		fname = f'{output["directory"]}/whois.{output["format"]}'
		output['file'] = fname
		data['module-whois'] = result
		export(output, data)
