#!/usr/bin/env python3

import asyncio
import dns.asyncresolver
from modules.export import export
from modules.write_log import log_writer

R = '\033[31m'  # red
G = '\033[32m'  # green
C = '\033[36m'  # cyan
W = '\033[0m'   # white
Y = '\033[33m'  # yellow


def dnsrec(domain, dns_servers, output, data):
	result = {}
	print(f'\n{Y}[!] Starting DNS Enumeration...{W}\n')
	dns_records = ['A', 'AAAA', 'AFSDB', 'APL', 'CAA', 'CDNSKEY', 'CDS', 'CERT',
                'CNAME', 'CSYNC', 'DHCID', 'DLV', 'DNAME', 'DNSKEY', 'DS', 'EUI48',
                'EUI64', 'HINFO', 'HIP', 'HTTPS', 'IPSECKEY', 'KEY', 'KX', 'LOC',
                'MX', 'NAPTR', 'NS', 'NSEC', 'NSEC3', 'NSEC3PARAM', 'OPENPGPKEY', 'PTR',
                'RP', 'RRSIG', 'SIG', 'SMIMEA', 'SOA', 'SRV', 'SSHFP', 'SVCB',
                'TA', 'TKEY', 'TLSA', 'TSIG', 'TXT', 'URI', 'ZONEMD']
	full_ans = []

	res = dns.asyncresolver.Resolver(configure=False)
	res.nameservers = dns_servers


	async def fetch_records(res, domain, record):
		answer = await res.resolve(domain, record)
		return answer


	for dns_record in dns_records:
		try:
			ans = asyncio.run(fetch_records(res, domain, dns_record))
			for record_data in ans:
				full_ans.append(f'{dns_record} : {record_data.to_text()}')
		except dns.resolver.NoAnswer as exc:
			log_writer(f'[dns] Exception = {exc}')
		except dns.resolver.NoMetaqueries as exc:
			log_writer(f'[dns] Exception = {exc}')
		except dns.resolver.NoNameservers as exc:
			log_writer(f'[dns] Exception = {exc}')
		except dns.resolver.NXDOMAIN as exc:
			log_writer(f'[dns] Exception = {exc}')
			print(f'{R}[-] {C}DNS Records Not Found!{W}')
			if output != 'None':
				result.setdefault('dns', ['DNS Records Not Found'])
			return

	for entry in full_ans:
		entry_parts = entry.split(' : ')
		print(f'{C}{entry_parts[0]} \t: {W}{entry_parts[1]}')
		if output != 'None':
			result.setdefault('dns', []).append(entry)

	dmarc_target = f'_dmarc.{domain}'
	try:
		dmarc_ans = asyncio.run(fetch_records(res, dmarc_target, 'TXT'))
		for entry in dmarc_ans:
			print(f'{C}DMARC \t: {W}{entry.to_text()}')
			if output != 'None':
				result.setdefault('dmarc', []).append(f'DMARC : {entry.to_text()}')
	except dns.resolver.NoAnswer as exc:
		log_writer(f'[dns.dmarc] Exception = {exc}')
	except dns.resolver.NoMetaqueries as exc:
		log_writer(f'[dns.dmarc] Exception = {exc}')
	except dns.resolver.NoNameservers as exc:
		log_writer(f'[dns.dmarc] Exception = {exc}')
	except dns.resolver.NXDOMAIN as exc:
		log_writer(f'[dns.dmarc] Exception = {exc}')
		print(f'\n{R}[-] {C}DMARC Record Not Found!{W}')
		if output != 'None':
			result.setdefault('dmarc', ['DMARC Record Not Found!'])

	result.update({'exported': False})

	if output != 'None':
		data['module-DNS Enumeration'] = result
		fname = f'{output["directory"]}/dns_records.{output["format"]}'
		output['file'] = fname
		export(output, data)
	log_writer('[dns] Completed')
