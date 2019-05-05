#!/usr/bin/env python3

import requests
requests.packages.urllib3.disable_warnings()

R = '\033[31m' # red
G = '\033[32m' # green
C = '\033[36m' # cyan
W = '\033[0m'  # white

def headers(target):
	print ('\n' + G + '[+]' + C + ' Headers :' + W + '\n')
	rqst = requests.get(target, verify=False, timeout=10)
	for k, v in rqst.headers.items():
		print (G + '[+]' + C + ' {} : '.format(k) + W + v)
