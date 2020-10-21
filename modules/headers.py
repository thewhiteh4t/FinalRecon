#!/usr/bin/env python3

import requests
requests.packages.urllib3.disable_warnings()

R = '\033[31m' # red
G = '\033[32m' # green
C = '\033[36m' # cyan
W = '\033[0m'  # white
Y = '\033[33m' # yellow

def headers(target, output, data):
	result = {}
	print ('\n' + Y + '[!] Headers :' + W + '\n')
	try:
		rqst = requests.get(target, verify=False, timeout=10)
		for k, v in rqst.headers.items():
			print (G + '[+]' + C + ' {} : '.format(k) + W + v)
			if output != 'None':
				result.update({k:v})
	except Exception as e:
		print('\n' + R + '[-]' + C + ' Exception : ' + W + str(e) + '\n')
		if output != 'None':
			result.update({'Exception':str(e)})

	if output != 'None':
		header_output(output, data, result)

def header_output(output, data, result):
	data['module-Headers'] = result