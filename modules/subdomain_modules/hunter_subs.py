#!/usr/bin/env python3

from os import environ
from base64 import b64encode
from json import loads, dumps
import modules.subdom as parent
from modules.write_log import log_writer
from datetime import datetime, timedelta

R = '\033[31m'  # red
G = '\033[32m'  # green
C = '\033[36m'  # cyan
W = '\033[0m'   # white
Y = '\033[33m'  # yellow


async def hunter(hostname, conf_path, session):
    hunter_key = environ.get('FR_HUNTER_KEY')

    if not hunter_key:
        log_writer('[hunter_subs] key missing in env')
        with open(f'{conf_path}/keys.json', 'r') as keyfile:
            json_read = keyfile.read()

        json_load = loads(json_read)
        try:
            hunter_key = json_load['hunter']
        except KeyError:
            log_writer('[hunter_subs] key missing in keys.json')
            with open(f'{conf_path}/keys.json', 'w') as outfile:
                json_load['hunter'] = None
                hunter_key = None
                outfile.write(
                    dumps(json_load, sort_keys=True, indent=4)
                )

    if hunter_key is not None:
        print(f'{Y}[!] {C}Requesting {G}Hunter{W}')
        url = f'https://api.hunter.how/search'
        query = f'domain.suffix=="{hostname}"'
        query64 = b64encode(query.encode()).decode()
        start_year = datetime.today().year - 1
        start_month = datetime.today().month
        start_day = datetime.today().day
        try:
            start_date = datetime.strptime(
                f'{start_year}-{start_month}-{start_day}', '%Y-%m-%d').strftime('%Y-%m-%d')
        except ValueError:
            # handle leap year
            start_date = datetime.strptime(
                f'{start_year}-{start_month}-{start_day - 1}', '%Y-%m-%d').strftime('%Y-%m-%d')
        end_date = (datetime.today() - timedelta(days=2)).strftime('%Y-%m-%d')

        payload = {
            'api-key': hunter_key,
            'query': query64,
            'page': 1,
            'page_size': 1000,
            'start_time': start_date,
            'end_time': end_date
        }
        try:
            async with session.get(url, params=payload) as resp:
                status = resp.status
                if status == 200:
                    json_data = await resp.json()
                    resp_code = json_data['code']
                    if resp_code != 200:
                        resp_msg = json_data['message']
                        print(f'{R}[-] {C}Hunter Status : {W}{resp_code}, {resp_msg}')
                        log_writer(f'[hunter_subs] Status = {resp_code}, expected 200')
                        return
                    subdomain_list = json_data['data']['list']
                    subdomains = []
                    for entry in subdomain_list:
                        subdomains.append(entry['domain'])
                    print(f'{G}[+] {Y}hunter {W}found {C}{len(subdomains)} {W}subdomains!')
                    parent.found.extend(subdomains)
                else:
                    print(f'{R}[-] {C}Hunter Status : {W}{status}')
                    log_writer(f'[hunter_subs] Status = {status}, expected 200')
        except Exception as exc:
            print(f'{R}[-] {C}Hunter Exception : {W}{exc}')
            log_writer(f'[hunter_subs] Exception = {exc}')
    else:
        print(f'{Y}[!] Skipping hunter : {W}API key not found!')
        log_writer('[hunter_subs] API key not found')
    log_writer('[hunter_subs] Completed')
