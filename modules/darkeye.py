#!/usr/bin/env python3

import asyncio
import re
import unicodedata
from json import dumps, loads
from os import environ
from urllib.parse import urlsplit

import aiohttp

from modules.export import export
from modules.write_log import log_writer

R = "\033[31m"  # red
G = "\033[32m"  # green
C = "\033[36m"  # cyan
W = "\033[0m"  # white
Y = "\033[33m"  # yellow
HEADER = "\033[1;35m"  # bold magenta

HIBR = "HaveIBeenRansom"
BH = "Breach House"
HIBR_URL = "https://haveibeenransom.com/api/metadata/domain/"
BH_URL = "https://breach.house/api/v1/search"

HIBR_CATEGORIES = {"ransomware_leak": "ransomware", "traditional_breach": "breach"}
BH_CATEGORIES = {
    "ransomware": "ransomware",
    "breaches": "breach",
    "leads": "leads",
    "stealers": "stealer",
}

MAX_PAGES = 5  # HaveIBeenRansom pages requested
BH_LIMIT = 25  # Breach House results requested per source
MAX_RECORDS = 100  # records kept per product
MAX_PRINT = 20  # records printed to the terminal
MAX_TEXT = 512


class DarkEyeError(Exception):
    pass


def clean_text(value):
    """Keep short printable text only, drop control characters"""
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        return ""
    text = unicodedata.normalize("NFKC", str(value))
    text = "".join(
        ch for ch in text if unicodedata.category(ch)[0] != "C" or ch.isspace()
    )
    return " ".join(text.split())[:MAX_TEXT]


def valid_domain(value):
    """Return a normalized plain domain name or None"""
    if not isinstance(value, str):
        return None
    try:
        value = value.strip().lower().rstrip(".").encode("idna").decode("ascii")
    except UnicodeError:
        return None
    labels = value.split(".")
    if len(value) > 253 or len(labels) < 2 or labels[-1].isdigit():
        return None
    for label in labels:
        if not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label):
            return None
    return value


def make_record(product, category, item):
    """Listing metadata only, nothing else from the response is read"""
    return {
        "product": product,
        "category": category,
        "id": clean_text(
            item.get("id_source") or item.get("victim_id") or item.get("id")
        ),
        "title": clean_text(item.get("post_title") or item.get("name")),
        "website": clean_text(item.get("website")),
        "group": clean_text(item.get("group_name")),
        "country": clean_text(item.get("country")),
        "discovered": clean_text(item.get("discovered"))[:10],
    }


def matches_domain(record, domain):
    """Breach House search is free text, keep the target and its subdomains only"""
    website = record["website"]
    if website:
        try:
            parsed = urlsplit(website if "://" in website else "//" + website)
            host = valid_domain(parsed.hostname)
        except ValueError:
            return False
        return host is not None and (host == domain or host.endswith("." + domain))
    pattern = r"(?<![\w-])" + re.escape(domain) + r"(?![\w-]|\.\w)"
    return re.search(pattern, record["title"].lower()) is not None


async def api_get(session, url, key, params=None):
    headers = {
        "Authorization": f"Bearer {key}",
        "Accept": "application/json",
    }
    try:
        # redirects are not followed so the Authorization header stays on the API host
        async with session.get(
            url, params=params, headers=headers, allow_redirects=False
        ) as resp:
            if resp.status != 200:
                raise DarkEyeError(f"Status : {resp.status}")
            data = await resp.json(content_type=None)
    except DarkEyeError:
        raise
    except asyncio.TimeoutError:
        raise DarkEyeError("Request Timeout") from None
    except ValueError:
        raise DarkEyeError("Invalid JSON response") from None
    except aiohttp.ClientError:
        raise DarkEyeError("Request failed") from None
    if not isinstance(data, dict) or data.get("success") is False or "error" in data:
        raise DarkEyeError("Invalid or unsuccessful API response")
    return data


async def hibr_lookup(session, domain, key):
    records = []
    seen = set()
    for page in range(1, MAX_PAGES + 1):
        url = HIBR_URL + domain + (f"/{page}" if page > 1 else "")
        data = await api_get(session, url, key)
        items = data.get("sources") if "sources" in data else data.get("results")
        pagination = data.get("pagination", {})
        if not isinstance(items, list) or not isinstance(pagination, dict):
            raise DarkEyeError("Invalid metadata response")
        has_next = data.get("has_next", pagination.get("has_next"))
        if not isinstance(has_next, bool) or any(
            not isinstance(item, dict) for item in items
        ):
            raise DarkEyeError("Invalid metadata pagination or records")
        for item in items:
            category = HIBR_CATEGORIES.get(clean_text(item.get("leak_type")), "leak")
            record = make_record(HIBR, category, item)
            if not any(record[field] for field in ("id", "title", "website")):
                raise DarkEyeError("Invalid metadata record")
            identity = record["id"] or dumps(record, sort_keys=True)
            if identity in seen:
                continue
            seen.add(identity)
            if len(records) == MAX_RECORDS:
                return records, True
            records.append(record)
        if not has_next:
            return records, False
        if len(records) == MAX_RECORDS:
            return records, True
    return records, True


async def bh_lookup(session, domain, key):
    data = await api_get(session, BH_URL, key, params={"q": domain, "limit": BH_LIMIT})
    records = []
    seen = set()
    truncated = False
    for source, category in BH_CATEGORIES.items():
        if source not in data:
            raise DarkEyeError("Invalid search response")
        section = data[source]
        total = None
        if isinstance(section, dict):
            total, section = section.get("total"), section.get("results")
        if not isinstance(section, list) or any(
            not isinstance(item, dict) for item in section
        ):
            raise DarkEyeError("Invalid search records")
        if total is not None and (type(total) is not int or total < len(section)):
            raise DarkEyeError("Invalid search total")
        if total is not None:
            truncated |= total > len(section)
        else:
            truncated |= len(section) >= BH_LIMIT
        for item in section:
            record = make_record(BH, category, item)
            if not matches_domain(record, domain):
                continue
            identity = (category, record["id"] or dumps(record, sort_keys=True))
            if identity in seen:
                continue
            seen.add(identity)
            if len(records) == MAX_RECORDS:
                truncated = True
            else:
                records.append(record)
    return records, truncated


async def run_product(name, lookup, domain, key, tout):
    """One session per product so keys and cookies are never shared"""
    timeout = aiohttp.ClientTimeout(total=tout)
    try:
        async with aiohttp.ClientSession(timeout=timeout) as session:
            records, truncated = await lookup(session, domain, key)
    except DarkEyeError as exc:
        log_writer(f"[darkeye] {name} error = {exc}")
        return name, [], False, str(exc)
    except Exception:
        log_writer(f"[darkeye] {name} unexpected error")
        return name, [], False, "Request failed"
    log_writer(f"[darkeye] {name} records = {len(records)}")
    return name, records, truncated, None


async def query(domain, tout, products):
    return await asyncio.gather(
        *[
            run_product(name, lookup, domain, key, tout)
            for name, lookup, key in products
        ]
    )


def load_keys(conf_path):
    try:
        with open(f"{conf_path}/keys.json", "r") as keyfile:
            keys_json = loads(keyfile.read())
    except (OSError, ValueError):
        keys_json = {}
    if not isinstance(keys_json, dict):
        keys_json = {}
    return {
        "haveibeenransom": environ.get("FR_HAVEIBEENRANSOM_KEY")
        or keys_json.get("haveibeenransom"),
        "breachhouse": environ.get("FR_BREACHHOUSE_KEY")
        or keys_json.get("breachhouse"),
    }


def usable_key(key):
    if not isinstance(key, str):
        return None
    key = key.strip()
    if not key or any(ord(ch) < 33 or ord(ch) > 126 for ch in key):
        return None
    return key


def format_record(record):
    fields = (
        "product",
        "category",
        "discovered",
        "title",
        "website",
        "group",
        "country",
        "id",
    )
    return " | ".join(record[field] or "-" for field in fields)


def darkeye_lookup(domain, tout, output, data, conf_path):
    result = {}

    print(f"\n{HEADER}━━━ DarkEye Exposure Lookup {'━' * 30}{W}\n")

    keys = load_keys(conf_path)
    products = []
    for key_name, lookup, name in (
        ("haveibeenransom", hibr_lookup, HIBR),
        ("breachhouse", bh_lookup, BH),
    ):
        raw_key = keys[key_name]
        key = usable_key(raw_key)
        if key:
            products.append((name, lookup, key))
        elif raw_key:
            print(f"{R}[-] {C}{name.ljust(15)}{W} : API key has invalid characters")
            log_writer(f"[darkeye] {name} API key has invalid characters")
        else:
            print(f"{Y}[!] {C}{name.ljust(15)}{W} : API key not configured")
            log_writer(f"[darkeye] {name} API key not configured")

    if not products:
        print(f"\n{Y}[!]{W} No DarkEye API key is available, skipping lookup")
        print(
            f"{C}[*]{W} Use -k haveibeenransom@KEY or -k breachhouse@KEY, "
            "the domain is only sent when a key is set"
        )
        log_writer("[darkeye] No API key, skipped")
        return None

    target = valid_domain(domain)
    if target is None:
        print(f"\n{Y}[!]{W} Not a plain domain name, skipping lookup")
        log_writer("[darkeye] Invalid domain, skipped")
        return None

    print(f"{C}[*]{W} Domain : {target}\n")

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        outcomes = loop.run_until_complete(query(target, tout, products))
    finally:
        loop.close()

    records = []
    answered = []
    errors = []
    truncated = False
    for name, found, trunc, error in outcomes:
        if error is None:
            answered.append(name)
            records.extend(found)
            truncated |= trunc
            print(f"{G}[+] {C}{name.ljust(15)}{W} : {len(found)}")
        else:
            errors.append(f"{name}: {error}")
            print(f"{R}[-] {C}{name.ljust(15)}{W} : {error}")

    if not answered:
        status = "failed"
    elif errors or truncated:
        status = "partial"
    else:
        status = "complete"

    if answered:
        print(f"\n{G}[+]{W} {'Total'.ljust(15)} : {len(records)}\n")
        for record in records[:MAX_PRINT]:
            print(
                f"{C}{record['product']}{W} | {record['category']} | "
                f"{record['title'] or '-'} | {record['discovered'] or '-'}"
            )
        if len(records) > MAX_PRINT:
            print(f"\n{C}[*]{W} Results truncated...")
        if truncated:
            print(f"{Y}[!]{W} Lookup limits were reached, results may be incomplete")
        print(
            f"\n{C}[*]{W} A listing needs verification and does not prove a "
            "compromise. No match does not prove the domain is unexposed."
        )
    else:
        print(f"\n{R}[-]{W} All DarkEye lookups failed, this is not a clean result")

    if output != "None":
        result["Domain"] = target
        result["Status"] = status
        result["Products"] = ", ".join(answered) if answered else "none"
        result["Count"] = len(records)
        if errors:
            result["Errors"] = "; ".join(errors)
        result["Records"] = [format_record(record) for record in records]
        result.update({"exported": False})
        data["module-DarkEye"] = result
        fname = f"{output['directory']}/darkeye.{output['format']}"
        output["file"] = fname
        export(output, data)
    log_writer("[darkeye] Completed")
    return {
        "status": status,
        "products": answered,
        "records": records,
        "errors": errors,
        "truncated": truncated,
    }
