#!/usr/bin/env python3

import os
import ssl
import socket

R = '\033[31m' # red
G = '\033[32m' # green
C = '\033[36m' # cyan
W = '\033[0m'  # white
Y = '\033[33m' # yellow

def cert(hostname, sslp, output, data):
	result = {}
	pair = {}
	print ('\n' + Y + '[!]' + Y + ' SSL Certificate Information : ' + W + '\n')

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
		except:
			info = ssl.get_server_certificate((hostname, sslp))
			f = open('{}.pem'.format(hostname), 'w')
			f.write(info)
			f.close()
			cert_dict = ssl._ssl._test_decode_cert('{}.pem'.format(hostname))
			info = cert_dict
			os.remove('{}.pem'.format(hostname))

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
									pass
							if convert == True:
								pair.update(dict([subitem]))
						else:
							pass
				else:
					print(G + '[+]' + C + ' {} : '.format(str(k)) + W + str(item))
					if output != 'None':
						result.update({k:v})

		for k, v in info.items():
			if isinstance(v, tuple):
				unpack(v, pair)
				for k,v in pair.items():
					print(G + '[+]' + C + ' {} : '.format(str(k)) + W + str(v))
					if output != 'None':
						result.update({k:v})
				pair.clear()
			else:
				print(G + '[+]' + C + ' {} : '.format(str(k)) + W + str(v))
			if output != 'None':
				result.update({k:v})

	except:
		pt.close()
		print (R + '[-]' + C + ' SSL is not Present on Target URL...Skipping...' + W)
		if output != 'None':
			result.update({'Error':'SSL is not Present on Target URL'})

	if output != 'None':
		cert_output(output, data, result)

def cert_output(output, data, result):
	data['module-SSL Certificate Information'] = result
