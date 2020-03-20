#!/usr/bin/env python3

import os
import dnslib

R = '\033[31m' # red
G = '\033[32m' # green
C = '\033[36m' # cyan
W = '\033[0m'  # white
Y = '\033[33m' # yellow

def dnsrec(domain, output, data):
	result = {}
	print('\n' + Y + '[!]' + Y + ' Starting DNS Enumeration...' + W + '\n')
	types = ['A', 'AAAA', 'ANY', 'CAA', 'CNAME', 'MX', 'NS', 'TXT']
	full_ans = []
	for Type in types:
		q = dnslib.DNSRecord.question(domain, Type)
		pkt = q.send('8.8.8.8', 53, tcp='UDP')
		ans = dnslib.DNSRecord.parse(pkt)
		ans = str(ans)
		ans = ans.split('\n')
		full_ans.extend(ans)
	full_ans = set(full_ans)
	dns_found = []

	for entry in full_ans:
		if entry.startswith(';') == False:
			dns_found.append(entry)
		else:
			pass
	
	if len(dns_found) != 0:
		for entry in dns_found:
			print(G + '[+]' + C + ' {}'.format(entry) + W)
			if output != 'None':
				result.setdefault('dns', []).append(entry)
	else:
		print(R + '[-]' + C + ' DNS Records Not Found!' + W)
		if output != 'None':
			result.setdefault('dns', ['DNS Records Not Found'])
	
	dmarc_target = '_dmarc.' + domain
	q = dnslib.DNSRecord.question(dmarc_target, 'TXT')
	pkt = q.send('8.8.8.8', 53, tcp='UDP')
	dmarc_ans = dnslib.DNSRecord.parse(pkt)
	dmarc_ans = str(dmarc_ans)
	dmarc_ans = dmarc_ans.split('\n')
	dmarc_found = []

	for entry in dmarc_ans:
		if entry.startswith('_dmarc') == True:
			dmarc_found.append(entry)
		else:
			pass
	if len(dmarc_found) != 0:
		for entry in dmarc_found:
			print(G + '[+]' + C + ' {}'.format(entry) + W)
			if output != 'None':
				result.setdefault('dmarc', []).append(entry)
	else:
		print('\n' + R + '[-]' + C + ' DMARC Record Not Found!' + W)
		if output != 'None':
			result.setdefault('dmarc', ['DMARC Record Not Found!'])

	if output != 'None':
		dns_export(output, data, result)

def dns_export(output, data, result):
	data['module-DNS Enumeration'] = result