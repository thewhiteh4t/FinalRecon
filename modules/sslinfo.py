#!/usr/bin/env python3

import ssl
import socket
from modules.export import export
from modules.write_log import log_writer
from cryptography import x509
from cryptography.hazmat.backends import default_backend

R = '\033[31m'  # red
G = '\033[32m'  # green
C = '\033[36m'  # cyan
W = '\033[0m'   # white
Y = '\033[33m'  # yellow


def cert(hostname, sslp, output, data):
	result = {}
	presence = False
	print(f'\n{Y}[!] SSL Certificate Information : {W}\n')

	port_test = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	port_test.settimeout(5)
	try:
		port_test.connect((hostname, sslp))
		port_test.close()
		presence = True
	except Exception:
		port_test.close()
		print(f'{R}[-] {C}SSL is not Present on Target URL...Skipping...{W}')
		result.update({'Error': 'SSL is not Present on Target URL'})
		log_writer('[sslinfo] SSL is not Present on Target URL...Skipping...')

	def unpack(nested_tuple, pair):
		for item in nested_tuple:
			if isinstance(item, tuple):
				if len(item) == 2:
					pair[item[0]] = item[1]
				else:
					unpack(item, pair)
			else:
				pair[nested_tuple.index(item)] = item

	def process_cert(info):
		pair = {}
		for key, val in info.items():
			if isinstance(val, tuple):
				print(f'{G}[+] {C}{key}{W}')
				unpack(val, pair)
				for sub_key, sub_val in pair.items():
					print(f'\t{G}└╴{C}{sub_key}: {W}{sub_val}')
					result.update({f'{key}-{sub_key}': sub_val})
				pair.clear()
			elif isinstance(val, dict):
				print(f'{G}[+] {C}{key}{W}')
				for sub_key, sub_val in val.items():
					print(f'\t{G}└╴{C}{sub_key}: {W}{sub_val}')
					result.update({f'{key}-{sub_key}': sub_val})
			elif isinstance(val, list):
				print(f'{G}[+] {C}{key}{W}')
				for sub_val in val:
					print(f'\t{G}└╴{C}{val.index(sub_val)}: {W}{sub_val}')
					result.update({f'{key}-{val.index(sub_val)}': sub_val})
			else:
				print(f'{G}[+] {C}{key} : {W}{val}')
				result.update({key: val})

	if presence:
		ctx = ssl.create_default_context()
		ctx.check_hostname = False
		ctx.verify_mode = ssl.CERT_NONE
		sock = socket.socket()
		sock.settimeout(5)
		ssl_conn = ctx.wrap_socket(sock, server_hostname=hostname)
		ssl_conn.connect((hostname, sslp))
		x509_cert = ssl_conn.getpeercert(binary_form=True)
		decoded_cert = x509.load_der_x509_certificate(x509_cert, default_backend())

		subject_dict = {}
		issuer_dict = {}

		def name_to_dict(attribute):
			attr_name = attribute.oid._name
			attr_value = attribute.value
			return attr_name, attr_value

		for attribute in decoded_cert.subject:
			name, value = name_to_dict(attribute)
			subject_dict[name] = value

		for attribute in decoded_cert.issuer:
			name, value = name_to_dict(attribute)
			issuer_dict[name] = value

		cert_dict = {
			'protocol': ssl_conn.version(),
			'cipher': ssl_conn.cipher(),
			'subject': subject_dict,
			'issuer': issuer_dict,
			'version': decoded_cert.version,
			'serialNumber': decoded_cert.serial_number,
			'notBefore': decoded_cert.not_valid_before.strftime("%b %d %H:%M:%S %Y GMT"),
			'notAfter': decoded_cert.not_valid_after.strftime("%b %d %H:%M:%S %Y GMT"),
		}

		extensions = decoded_cert.extensions
		for ext in extensions:
			if ext.oid != x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME:
				continue
			san_entries = ext.value
			subject_alt_names = []
			for entry in san_entries:
				if isinstance(entry, x509.DNSName):
					subject_alt_names.append(entry.value)
			cert_dict['subjectAltName'] = subject_alt_names

		process_cert(cert_dict)
	result.update({'exported': False})

	if output:
		fname = f'{output["directory"]}/ssl.{output["format"]}'
		output['file'] = fname
		data['module-SSL Certificate Information'] = result
		export(output, data)
	log_writer('[sslinfo] Completed')
