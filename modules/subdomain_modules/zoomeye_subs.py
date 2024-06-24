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


async def zoomeye(hostname, conf_path, session):
    zoomeye_key = environ.get('FR_ZOOMEYE_KEY')

    if not zoomeye_key:
        log_writer('[zoomeye_subs] key missing in env')
        with open(f'{conf_path}/keys.json', 'r') as keyfile:
            json_read = keyfile.read()

        json_load = loads(json_read)
        try:
            zoomeye_key = json_load['zoomeye']
        except KeyError:
            log_writer('[zoomeye_subs] key missing in keys.json')
            with open(f'{conf_path}/keys.json', 'w') as outfile:
                json_load['zoomeye'] = None
                zoomeye_key = None
                outfile.write(
                    dumps(json_load, sort_keys=True, indent=4)
                )

    if zoomeye_key is not None:
        print(f'{Y}[!] {C}Requesting {G}ZoomEye{W}')
        url = f'https://api.zoomeye.hk/domain/search?q={hostname}&type=0'
        header = {
            'API-KEY': zoomeye_key,
            'User-Agent': 'curl'
        }

        try:
            async with session.get(url, headers=header) as resp:
                status = resp.status
                if status == 200:
                    json_data = await resp.json()
                    subdomain_list = json_data['list']
                    subdomains = [subd['name'] for subd in subdomain_list]
                    print(f'{G}[+] {Y}zoomeye {W}found {C}{len(subdomains)} {W}subdomains!')
                    parent.found.extend(subdomains)
                else:
                    print(f'{R}[-] {C}zoomeye Status : {W}{status}')
                    log_writer(f'[zoomeye_subs] Status = {status}, expected 200')

        except Exception as exc:
            print(f'{R}[-] {C}zoomeye Exception : {W}{exc}')
            log_writer(f'[zoomeye_subs] Exception = {exc}')
    else:
        print(f'{Y}[!] Skipping zoomeye : {W}API key not found!')
        log_writer('[zoomeye_subs] API key not found')
    log_writer('[zoomeye_subs] Completed')
