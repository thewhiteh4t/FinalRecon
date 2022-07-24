#!/usr/bin/env python3

import os
import ssl
import socket
from modules.export import export

R = '\033[31m'  # red
G = '\033[32m'  # green
C = '\033[36m'  # cyan
W = '\033[0m'   # white
Y = '\033[33m'  # yellow


def cert(hostname, sslp, output, data):
	result = {}
	pair = {}
	print(f'\n{Y}[!] SSL Certificate Information : {W}\n')

	pt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	pt.settimeout(5)
	try:
		pt.connect((hostname, sslp))
		pt.close()

		ctx = ssl.create_default_context()
		sock = socket.socket()
		sock.settimeout(5)
		s = ctx.wrap_socket(sock, server_hostname=hostname)

		try:
			s.connect((hostname, sslp))
			info = s.getpeercert()
		except Exception:
			info = ssl.get_server_certificate((hostname, sslp))
			f = open(f'{hostname}.pem', 'w')
			f.write(info)
			f.close()
			cert_dict = ssl._ssl._test_decode_cert(f'{hostname}.pem')
			info = cert_dict
			os.remove(f'{hostname}.pem')

		def unpack(v, pair):
			convert = False
			for item in v:
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
					print(f'{G}[+] {C}{k}: {W}{item}')
					if output != 'None':
						result.update({k: v})

		for k, v in info.items():
			if isinstance(v, tuple):
				unpack(v, pair)
				for k, v in pair.items():
					print(f'{G}[+] {C}{k}: {W}{v}')
					if output != 'None':
						result.update({k: v})
				pair.clear()
			else:
				print(f'{G}[+] {C}{k}: {W}{v}')
			if output != 'None':
				result.update({k: v})

	except Exception:
		pt.close()
		print(f'{R}[-] {C}SSL is not Present on Target URL...Skipping...{W}')
		if output != 'None':
			result.update({'Error': 'SSL is not Present on Target URL'})
	result.update({'exported': False})
	if output != 'None':
		fname = f'{output["directory"]}/ssl.{output["format"]}'
		output['file'] = fname
		data['module-SSL Certificate Information'] = result
		export(output, data)
