#!/usr/bin/env python3

import ipwhois

R = '\033[31m' # red
G = '\033[32m' # green
C = '\033[36m' # cyan
W = '\033[0m'  # white

def whois_lookup(ip):
	print ('\n' + G + '[+]' + C + ' Whois Lookup : ' + W + '\n')
	try:
		lookup = ipwhois.IPWhois(ip)
		results = lookup.lookup_whois()
		print (G + '[+]' + C + ' NIR : ' + W + str(results['nir']))
		print (G + '[+]' + C + ' ASN Registry : ' + W + str(results['asn_registry']))
		print (G + '[+]' + C + ' ASN : ' + W + str(results['asn']))
		print (G + '[+]' + C + ' ASN CIDR : ' + W + str(results['asn_cidr']))
		print (G + '[+]' + C + ' ASN Country Code : ' + W + str(str(results['asn_country_code'])))
		print (G + '[+]' + C + ' ASN Date : ' + W + str(results['asn_date']))
		print (G + '[+]' + C + ' ASN Description : ' + W + str(results['asn_description']))
		for k, v in results['nets'][0].items():
			print (G + '[+]' + C + ' {} : '.format(str(k)) + W + str(v))
	except Exception as e:
		print (R + '[-] Error : ' + C + str(e) + W)
		pass
