#!/usr/bin/env python3

from os import environ
from json import loads, dumps
import modules.subdom as parent
from modules.write_log import log_writer

R = '\033[31m'  # red
G = '\033[32m'  # green
C = '\033[36m'  # cyan
W = '\033[0m'   # white
Y = '\033[33m'  # yellow


async def netlas(hostname, conf_path, session):
    netlas_key = environ.get('FR_NETLAS_KEY')

    if not netlas_key:
        log_writer('[netlas_subs] key missing in env')
        with open(f'{conf_path}/keys.json', 'r') as keyfile:
            json_read = keyfile.read()

        json_load = loads(json_read)
        try:
            netlas_key = json_load['netlas']
        except KeyError:
            log_writer('[netlas_subs] key missing in keys.json')
            with open(f'{conf_path}/keys.json', 'w') as outfile:
                json_load['netlas'] = None
                netlas_key = None
                outfile.write(
                    dumps(json_load, sort_keys=True, indent=4)
                )

    if netlas_key is not None:
        print(f'{Y}[!] {C}Requesting {G}Netlas{W}')
        url = f'https://app.netlas.io/api/domains/download/'
        header = {'X-API-Key': netlas_key}
        payload = {
            'q': f'domain: *.{hostname}',
            'fields': ['domain'],
            'source_type': 'include',
            'size': '200'
        }

        try:
            async with session.post(url, headers=header, data=payload) as resp:
                status = resp.status
                if status == 200:
                    json_data = loads(await resp.text())
                    subdomains = []
                    for entry in json_data:
                        subdomain = entry['data']['domain']
                        subdomains.append(subdomain)
                    print(f'{G}[+] {Y}netlas {W}found {C}{len(subdomains)} {W}subdomains!')
                    parent.found.extend(subdomains)
                else:
                    print(f'{R}[-] {C}netlas Status : {W}{status}')
                    log_writer(f'[netlas_subs] Status = {status}, expected 200')

        except Exception as exc:
            print(f'{R}[-] {C}netlas Exception : {W}{exc}')
            log_writer(f'[netlas_subs] Exception = {exc}')
    else:
        print(f'{Y}[!] Skipping netlas : {W}API key not found!')
        log_writer('[netlas_subs] API key not found')
    log_writer('[netlas_subs] Completed')
