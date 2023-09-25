#!/usr/bin/env python3

R = '\033[31m'  # red
G = '\033[32m'  # green
C = '\033[36m'  # cyan
W = '\033[0m'   # white
Y = '\033[33m'  # yellow

import psycopg2
import modules.subdom as parent
from modules.write_log import log_writer


async def crtsh(hostname):
	print(f'{Y}[!] {C}Requesting {G}crt.sh{W}')
	try:
		conn = psycopg2.connect(
			host="crt.sh",
			database="certwatch",
			user="guest",
			port="5432"
		)
		conn.autocommit = True
		cur = conn.cursor()
		query = f"SELECT ci.NAME_VALUE NAME_VALUE FROM certificate_identity ci WHERE ci.NAME_TYPE = 'dNSName' AND reverse(lower(ci.NAME_VALUE)) LIKE reverse(lower('%.{hostname}'))"
		cur.execute(query)
		result = cur.fetchall()
		cur.close()
		conn.close()
		tmp_list = []
		for url in result:
			tmp_list.append(url[0])
		print(f'{G}[+] {Y}CRT.sh {W}found {C}{len(tmp_list)} {W}subdomains!')
		parent.found.extend(tmp_list)
	except Exception as exc:
		print(f'{R}[-] {C}crtsh Exception : {W}{exc}')
		log_writer(f'[crtsh_subs] Exception = {exc}')
	log_writer('[crtsh_subs] Completed')
