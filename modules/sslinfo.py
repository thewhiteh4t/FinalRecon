#!/usr/bin/env python3

import os
import ssl
import socket
from modules.export import export
from modules.write_log import log_writer

R = '\033[31m'  # red
G = '\033[32m'  # green
C = '\033[36m'  # cyan
W = '\033[0m'   # white
Y = '\033[33m'  # yellow


def cert(hostname, sslp, output, data):
	result = {}
	pair = {}
	print(f'\n{Y}[!] SSL Certificate Information : {W}\n')

	port_test = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	port_test.settimeout(5)
	try:
		port_test.connect((hostname, sslp))
		port_test.close()

		ctx = ssl.create_default_context()
		sock = socket.socket()
		sock.settimeout(5)
		ssl_conn = ctx.wrap_socket(sock, server_hostname=hostname)

		try:
			ssl_conn.connect((hostname, sslp))
			info = ssl_conn.getpeercert()
		except Exception:
			info = ssl.get_server_certificate((hostname, sslp))
			with open(f'{hostname}.pem', 'w') as outfile:
				outfile.write(info)
			cert_dict = ssl._ssl._test_decode_cert(f'{hostname}.pem')
			info = cert_dict
			os.remove(f'{hostname}.pem')

		def unpack(val, pair):
			convert = False
			for item in val:
				if isinstance(item, tuple):
					for subitem in item:
						if isinstance(subitem, tuple):
							for elem in subitem:
								if isinstance(elem, tuple):
									unpack(elem)
								else:
									convert = True
							if convert is True:
								pair.update(dict([subitem]))
						else:
							pass
				else:
					print(f'{G}[+] {C}{key}: {W}{item}')
					if output != 'None':
						result.update({key: val})

		for key, val in info.items():
			if isinstance(val, tuple):
				unpack(val, pair)
				for key, val in pair.items():
					print(f'{G}[+] {C}{key}: {W}{val}')
					if output != 'None':
						result.update({key: val})
				pair.clear()
			else:
				print(f'{G}[+] {C}{key}: {W}{val}')
			if output != 'None':
				result.update({key: val})

	except Exception:
		port_test.close()
		print(f'{R}[-] {C}SSL is not Present on Target URL...Skipping...{W}')
		if output != 'None':
			result.update({'Error': 'SSL is not Present on Target URL'})
		log_writer('[sslinfo] SSL is not Present on Target URL...Skipping...')
	result.update({'exported': False})
	if output != 'None':
		fname = f'{output["directory"]}/ssl.{output["format"]}'
		output['file'] = fname
		data['module-SSL Certificate Information'] = result
		export(output, data)
	log_writer('[sslinfo] Completed')