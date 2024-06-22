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


async def bevigil(hostname, conf_path, session):
    bevigil_key = environ.get('FR_BEVIGIL_KEY')

    if not bevigil_key:
        log_writer('[bevigil_subs] key missing in env')
        with open(f'{conf_path}/keys.json', 'r') as keyfile:
            json_read = keyfile.read()

        json_load = loads(json_read)
        try:
            bevigil_key = json_load['bevigil']
        except KeyError:
            log_writer('[bevigil_subs] key missing in keys.json')
            with open(f'{conf_path}/keys.json', 'w') as outfile:
                json_load['bevigil'] = None
                bevigil_key = None
                outfile.write(
                    dumps(json_load, sort_keys=True, indent=4)
                )

    if bevigil_key is not None:
        print(f'{Y}[!] {C}Requesting {G}BeVigil{W}')
        url = f"https://osint.bevigil.com/api/{hostname}/subdomains/"
        header = {"X-Access-Token": bevigil_key}

        try:
            async with session.get(url, headers=header) as resp:
                status = resp.status
                if status == 200:
                    json_data: list = await resp.json()
                    subdomains = json_data.get("subdomains")
                    print(f'{G}[+] {Y}BeVigil {W}found {C}{len(subdomains)} {W}subdomains!')
                    parent.found.extend(subdomains)
                else:
                    print(f'{R}[-] {C}BeVigil Status : {W}{status}')
                    log_writer(f'[bevigil_subs] Status = {status}, expected 200')

        except Exception as exc:
            print(f'{R}[-] {C}BeVigil Exception : {W}{exc}')
            log_writer(f'[bevigil_subs] Exception = {exc}')
    else:
        print(f'{Y}[!] Skipping BeVigil : {W}API key not found!')
        log_writer('[bevigil_subs] API key not found')
    log_writer('[bevigil_subs] Completed')
