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
	print(f'\n{Y}[!] SSL Certificate Information : {W}\n')

	port_test = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	port_test.settimeout(5)
	try:
		port_test.connect((hostname, sslp))
		port_test.close()
	except Exception:
		port_test.close()
		print(f'{R}[-] {C}SSL is not Present on Target URL...Skipping...{W}')
		result.update({'Error': 'SSL is not Present on Target URL'})
		log_writer('[sslinfo] SSL is not Present on Target URL...Skipping...')

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

	def unpack(nested_tuple, pair):
		for item in nested_tuple:
			if isinstance(item, tuple):
				if len(item) == 2:
					pair[item[0]] = item[1]
				else:
					unpack(item, pair)
			else:
				pair[nested_tuple.index(item)] = item

	pair = {}
	for key, val in info.items():
		if isinstance(val, tuple):
			print(f'{G}[+] {C}{key}{W}')
			unpack(val, pair)
			for sub_key, sub_val in pair.items():
				print(f'\t{G}└╴{C}{sub_key}: {W}{sub_val}')
				result.update({f'{key}-{sub_key}': sub_val})
			pair.clear()
		else:
			print(f'{G}[+] {C}{key} : {W}{val}')
			result.update({key: val})

	result.update({'exported': False})

	if output:
		fname = f'{output["directory"]}/ssl.{output["format"]}'
		output['file'] = fname
		data['module-SSL Certificate Information'] = result
		export(output, data)
	log_writer('[sslinfo] Completed')
