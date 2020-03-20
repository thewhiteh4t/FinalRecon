#!/usr/bin/env python3

import ipwhois

R = '\033[31m' # red
G = '\033[32m' # green
C = '\033[36m' # cyan
W = '\033[0m'  # white
Y = '\033[33m' # yellow

def whois_lookup(ip, output, data):
	collect = {}
	print ('\n' + Y + '[!]' + Y + ' Whois Lookup : ' + W + '\n')
	try:
		lookup = ipwhois.IPWhois(ip)
		results = lookup.lookup_whois()

		for k,v in results.items():
			if v != None:
				if isinstance(v, list):
					for item in v:
						for k, v in item.items():
							if v != None:
								print (G + '[+]' + C + ' {} : '.format(str(k)) + W + str(v).replace(',', ' ').replace('\r', ' ').replace('\n', ' '))
								if output != 'None':
									collect.update({str(k):str(v).replace(',', ' ').replace('\r', ' ').replace('\n', ' ')})
							else:
								pass
				else:
					print (G + '[+]' + C + ' {} : '.format(str(k)) + W + str(v).replace(',', ' ').replace('\r', ' ').replace('\n', ' '))
					if output != 'None':
						collect.update({str(k):str(v).replace(',', ' ').replace('\r', ' ').replace('\n', ' ')})
			else:
				pass
	
	except Exception as e:
		print (R + '[-] Error : ' + C + str(e) + W)
		if output != 'None':
			collect.update({'Error':str(e)})
		pass
	
	if output != 'None':
		whois_output(output, data, collect)

def whois_output(output, data, collect):
	data['module-Whois Lookup'] = collect