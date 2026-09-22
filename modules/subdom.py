#!/usr/bin/env python3

import asyncio
from json import dump, loads
from os import environ
from re import match

import aiohttp

from modules.export import export
from modules.subdomain_modules.alienvault_subs import alienvault
from modules.subdomain_modules.anubis_subs import anubisdb
from modules.subdomain_modules.bevigil_subs import bevigil
from modules.subdomain_modules.certspot_subs import certspot
from modules.subdomain_modules.chaos_subs import chaos
from modules.subdomain_modules.github_subs import github
from modules.subdomain_modules.htarget_subs import hackertgt
from modules.subdomain_modules.hunter_subs import hunter
from modules.subdomain_modules.leakix_subs import leakix
from modules.subdomain_modules.netlas_subs import netlas
from modules.subdomain_modules.scanmalware_subs import scanmalware
from modules.subdomain_modules.shodan_subs import shodan
from modules.subdomain_modules.urlscan_subs import urlscan
from modules.subdomain_modules.virustotal_subs import virust
from modules.subdomain_modules.wayback_subs import machine
from modules.subdomain_modules.zoomeye_subs import zoomeye
from modules.write_log import log_writer

R = "\033[31m"  # red
G = "\033[32m"  # green
C = "\033[36m"  # cyan
W = "\033[0m"  # white
Y = "\033[33m"  # yellow
HEADER = "\033[1;35m"  # bold magenta

found = []


def migrate_config_file(config_path):
    current_schema = {
        "shodan": None,
        "zoomeye": None,
        "virustotal": None,
        "alienvault": None,
        "hunter": None,
        "chaos": None,
        "leakix": None,
        "netlas": None,
        "bevigil": None,
        "github": None,
    }

    try:
        with open(config_path, "r") as f:
            user_data = loads(f.read())
    except FileNotFoundError:
        user_data = {}

    missing_keys = {k: v for k, v in current_schema.items() if k not in user_data}

    if missing_keys:
        user_data.update(missing_keys)

        with open(config_path, "w") as f:
            dump(user_data, f, indent=4)
        print(
            f"[*] Migrated config: Added {len(missing_keys)} new API key slots to {config_path}"
        )

    return user_data


async def query(hostname, tout, api_keys):
    timeout = aiohttp.ClientTimeout(total=tout)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        results = await asyncio.gather(
            alienvault(hostname, api_keys["alienvault"], session),
            anubisdb(hostname, session),
            bevigil(hostname, api_keys["bevigil"], session),
            certspot(hostname, session),
            hackertgt(hostname, session),
            hunter(hostname, api_keys["hunter"], session),
            netlas(hostname, api_keys["netlas"], session),
            shodan(hostname, api_keys["shodan"], session),
            scanmalware(hostname, session),
            urlscan(hostname, session),
            virust(hostname, api_keys["virustotal"], session),
            zoomeye(hostname, api_keys["zoomeye"], session),
            chaos(hostname, api_keys["chaos"], session),
            leakix(hostname, api_keys["leakix"], session),
            github(hostname, api_keys["github"], session),
            machine(hostname, session),
        )
    await session.close()
    return results


def subdomains(hostname, tout, output, data, conf_path):
    global found
    result = {}
    api_keys = {}

    print(f"\n{HEADER}━━━ SubDomain Enum {'━' * 30}{W}\n")

    migrate_config_file(f"{conf_path}/keys.json")

    with open(f"{conf_path}/keys.json", "r") as keyfile:
        json_read = keyfile.read()

    keys_json = loads(json_read)
    api_keys["alienvault"] = environ.get("FR_ALIENVAULT_KEY") or keys_json.get(
        "alienvault"
    )
    api_keys["bevigil"] = environ.get("FR_BEVIGIL_KEY") or keys_json.get("bevigil")
    api_keys["hunter"] = environ.get("FR_HUNTER_KEY") or keys_json.get("hunter")
    api_keys["netlas"] = environ.get("FR_NETLAS_KEY") or keys_json.get("netlas")
    api_keys["shodan"] = environ.get("FR_SHODAN_KEY") or keys_json.get("shodan")
    api_keys["virustotal"] = environ.get("FR_VT_KEY") or keys_json.get("virustotal")
    api_keys["zoomeye"] = environ.get("FR_ZOOMEYE_KEY") or keys_json.get("zoomeye")
    api_keys["chaos"] = environ.get("FR_CHAOS_KEY") or keys_json.get("chaos")
    api_keys["leakix"] = environ.get("FR_LEAKIX_KEY") or keys_json.get("leakix")
    api_keys["github"] = environ.get("FR_GITHUB_KEY") or keys_json.get("github")

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    results = loop.run_until_complete(query(hostname, tout, api_keys))
    for name, subs, error in results:
        if error is None:
            found.extend(subs)
        if subs:
            print(f"{G}[+] {C}{name.ljust(15)}{W} : {len(subs)}")
        elif error is not None:
            if error.startswith("API key not configured"):
                print(f"{Y}[!] {C}{name.ljust(15)}{W} : {error}")
            else:
                print(f"{R}[-] {C}{name.ljust(15)}{W} : {error}")
    loop.close()

    found = [item for item in found if item.endswith(hostname)]
    valid = r"^[A-Za-z0-9._~()'!*:@,;+?-]*$"
    found = [item for item in found if match(valid, item)]
    found = set(found)
    total = len(found)

    if found:
        print(f"\n{G}[+]{W} {'Total Unique'.ljust(15)} : {total}\n")
        for url in enumerate(list(found)[:20]):
            print(url[1])

        if len(found) > 20:
            print(f"\n{C}[*]{W} Results truncated...")

    if output != "None":
        result["Links"] = list(found)
        result.update({"exported": False})
        data["module-Subdomain Enumeration"] = result
        fname = f"{output['directory']}/subdomains.{output['format']}"
        output["file"] = fname
        export(output, data)
    log_writer("[subdom] Completed")
