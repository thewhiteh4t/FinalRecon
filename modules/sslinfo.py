#!/usr/bin/env python3

import os
import ssl
import socket

R = '\033[31m' # red
G = '\033[32m' # green
C = '\033[36m' # cyan
W = '\033[0m'  # white

def cert(hostname):
	print ('\n' + G + '[+]' + C + ' SSL Certificate Information : ' + W + '\n')

	ctx = ssl.create_default_context()
	s = ctx.wrap_socket(socket.socket(), server_hostname=hostname)
	try:
		try:
			s.connect((hostname, 443))
			info = s.getpeercert()
			subject = dict(x[0] for x in info['subject'])
			issuer = dict(y[0] for y in info['issuer'])
		except:
			ctx = ssl._create_unverified_context()
			s = ctx.wrap_socket(socket.socket(), server_hostname=hostname)
			s.connect((hostname, 443))
			info = s.getpeercert(True)
			info = ssl.get_server_certificate((hostname, 443))
			f = open('{}.pem'.format(hostname), 'w')
			f.write(info)
			f.close()
			cert_dict = ssl._ssl._test_decode_cert('{}.pem'.format(hostname))
			subject = dict(x[0] for x in cert_dict['subject'])
			issuer = dict(y[0] for y in cert_dict['issuer'])
			info = cert_dict
			os.remove('{}.pem'.format(hostname))
		try:
			for k, v in subject.items():
				print(G + '[+]' + C + ' {} : '.format(str(k)) + W + str(v))
			for k, v in issuer.items():
				print(G + '[+]' + C + ' {} : '.format(str(k)) + W + str(v))
			print(G + '[+]' + C + ' Version : ' + W + str(info['version']))
			print(G + '[+]' + C + ' Serial Number : ' + W + str(info['serialNumber']))
			print(G + '[+]' + C + ' Not Before : ' + W + str(info['notBefore']))
			print(G + '[+]' + C + ' Not After : ' + W + str(info['notAfter']))
			print(G + '[+]' + C + ' OCSP : ' + W + str(info['OCSP']))
			print(G + '[+]' + C + ' subject Alt Name : ' + W + str(info['subjectAltName']))
			print(G + '[+]' + C + ' CA Issuers : ' + W + str(info['caIssuers']))
			print(G + '[+]' + C + ' CRL Distribution Points : ' + W + str(info['crlDistributionPoints']))
		except KeyError:
			pass

	except:
		print (R + '[-]' + C + ' SSL is not Present on Target URL...Skipping...' + W)
