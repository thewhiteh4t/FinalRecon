#!/usr/bin/env python3

R = '\033[31m'  # red
G = '\033[32m'  # green
C = '\033[36m'  # cyan
W = '\033[0m'   # white
Y = '\033[33m'  # yellow

import modules.subdom as parent


async def machine(hostname, session):
    print(f'{Y}[!] {C}Requesting {G}Wayback{W}')
    url = f'http://web.archive.org/cdx/search/cdx?url=*.{hostname}/*&output=txt&fl=original&collapse=urlkey'
    try:
        async with session.get(url) as resp:
            sc = resp.status
            if sc == 200:
                raw_data = await resp.text()
                lines = raw_data.split('\n')
                tmp_list = []
                for line in lines:
                    subdomain = line.replace('http://', '').replace('https://', '').split('/')[0].split(':')[0]
                    if len(subdomain) > len(hostname):
                        tmp_list.append(subdomain)
                print(f'{G}[+] {Y}Wayback {W}found {C}{len(tmp_list)} {W}subdomains!')
                parent.found.extend(tmp_list)
            else:
                print(f'{R}[-] {C}Wayback Status : {W}{sc}')
    except Exception as e:
        print(f'{R}[-] {C}Wayback Exception : {W}{e}')
