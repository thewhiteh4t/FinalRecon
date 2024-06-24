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


async def binedge(hostname, conf_path, session):
    binedge_key = environ.get('FR_BINEDGE_KEY')

    if not binedge_key:
        log_writer('[binedge_subs] key missing in env')
        with open(f'{conf_path}/keys.json', 'r') as keyfile:
            json_read = keyfile.read()

        json_load = loads(json_read)
        try:
            binedge_key = json_load['binedge']
        except KeyError:
            log_writer('[binedge_subs] key missing in keys.json')
            with open(f'{conf_path}/keys.json', 'w') as outfile:
                json_load['binedge'] = None
                binedge_key = None
                outfile.write(
                    dumps(json_load, sort_keys=True, indent=4)
                )

    if binedge_key is not None:
        print(f'{Y}[!] {C}Requesting {G}BinaryEdge{W}')
        url = f'https://api.binaryedge.io/v2/query/domains/subdomain/{hostname}'
        header = {'X-key': binedge_key}

        try:
            async with session.get(url, headers=header) as resp:
                status = resp.status
                if status == 200:
                    json_data = await resp.json()
                    subdomains = json_data['events']
                    print(f'{G}[+] {Y}binedge {W}found {C}{len(subdomains)} {W}subdomains!')
                    parent.found.extend(subdomains)
                else:
                    print(f'{R}[-] {C}binedge Status : {W}{status}')
                    log_writer(f'[binedge_subs] Status = {status}, expected 200')

        except Exception as exc:
            print(f'{R}[-] {C}binedge Exception : {W}{exc}')
            log_writer(f'[binedge_subs] Exception = {exc}')
    else:
        print(f'{Y}[!] Skipping binedge : {W}API key not found!')
        log_writer('[binedge_subs] API key not found')
    log_writer('[binedge_subs] Completed')
