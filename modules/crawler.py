#!/usr/bin/env python3

import asyncio
import re
from contextlib import asynccontextmanager

import aiohttp
import bs4
import tldextract

from modules.export import export
from modules.write_log import log_writer

import settings as config

R = "\033[31m"  # red
G = "\033[32m"  # green
C = "\033[36m"  # cyan
W = "\033[0m"  # white
Y = "\033[33m"  # yellow
HEADER = "\033[1;35m"  # bold magenta

user_agent = {"User-Agent": f"FinalRecon/{config.version}"}

# Bound outbound concurrency. Replaces the previous design that created/borrowed a
# fresh worker thread for *every* request via asyncio.to_thread + ThreadPoolExecutor,
# which is what made this module "async in name only" with high per-request overhead.
CONN_LIMIT = 32
_request_gate = asyncio.Semaphore(CONN_LIMIT)


async def _fetch(session, url):
    """Bounded, error-tolerant GET. Returns a ClientResponse, or None on failure."""
    async with _request_gate:
        try:
            return await session.get(url, allow_redirects=True)
        except aiohttp.ClientError as exc:
            log_writer(f"[crawler] GET failed {url} : {exc}")
            return None


@asynccontextmanager
async def _open(session, url):
    """Acquire a response and guarantee its release via `async with`."""
    resp = await _fetch(session, url)
    if resp is None:
        yield None
        return
    try:
        yield resp
    finally:
        resp.release()


async def _compute(fn, *args):
    """Run a CPU-bound parse step cooperatively without spinning up a thread."""
    fn(*args)


def crawler(target, protocol, netloc, output, data):
    r_total = []
    sm_total = []
    css_total = []
    js_total = []
    int_total = []
    ext_total = []
    img_total = []
    sm_crawl_total = []
    js_crawl_total = []
    total = []

    print(f"\n{HEADER}━━━ Crawler {'━' * 30}{W}\n")

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    soup = None
    try:
        soup = loop.run_until_complete(
            _crawl(
                target,
                protocol,
                netloc,
                output,
                data,
                r_total,
                sm_total,
                css_total,
                js_total,
                int_total,
                ext_total,
                img_total,
                sm_crawl_total,
                js_crawl_total,
            )
        )
    finally:
        loop.close()

    if soup is not None:
        stats(
            output,
            r_total,
            sm_total,
            css_total,
            js_total,
            int_total,
            ext_total,
            img_total,
            sm_crawl_total,
            js_crawl_total,
            total,
            data,
            soup,
        )
        log_writer("[crawler] Completed")


async def _crawl(
    target,
    protocol,
    netloc,
    output,
    data,
    r_total,
    sm_total,
    css_total,
    js_total,
    int_total,
    ext_total,
    img_total,
    sm_crawl_total,
    js_crawl_total,
):
    base_url = f"{protocol}://{netloc}"
    r_url = f"{base_url}/robots.txt"
    sm_url = f"{base_url}/sitemap.xml"

    timeout = aiohttp.ClientTimeout(total=10)
    connector = aiohttp.TCPConnector(
        limit=CONN_LIMIT, ssl=False, enable_cleanup_closed=True
    )
    async with aiohttp.ClientSession(
        headers=user_agent, connector=connector, timeout=timeout
    ) as session:
        try:
            async with _open(session, target) as rqst:
                if rqst is None:
                    return None
                status = rqst.status
                page = await rqst.read()
        except aiohttp.ClientError as exc:
            print(f"{R}[-]{W} Exception : {exc}")
            log_writer(f"[crawler] Exception = {exc}")
            return None

        if status != 200:
            print(f"{R}[-]{W} Status : {status}")
            log_writer(f"[crawler] Status code = {status}, expected 200")
            return None

        soup = bs4.BeautifulSoup(page, "lxml")

        # True async I/O (network) runs concurrently on the shared session; the pure
        # CPU parses are dispatched with _compute so no worker thread is created.
        await asyncio.gather(
            robots(session, r_url, r_total, sm_total, base_url, data, output),
            sitemap(session, sm_url, sm_total, data, output),
            _compute(css, target, css_total, data, soup, output),
            _compute(js_scan, target, js_total, data, soup, output),
            _compute(internal_links, target, int_total, data, soup, output),
            _compute(external_links, target, ext_total, data, soup, output),
            _compute(images, target, img_total, data, soup, output),
            sm_crawl(session, data, sm_crawl_total, sm_total, sm_url, output),
            js_crawl(session, data, js_crawl_total, js_total, output),
        )

    return soup


def url_filter(target, link):
    if all([link.startswith("/") is True, link.startswith("//") is False]):
        ret_url = target + link
        return ret_url

    if link.startswith("//") is True:
        ret_url = link.replace("//", "http://")
        return ret_url

    if all(
        [
            link.find("//") == -1,
            link.find("../") == -1,
            link.find("./") == -1,
            link.find("http://") == -1,
            link.find("https://") == -1,
        ]
    ):
        ret_url = f"{target}/{link}"
        return ret_url

    if all([link.find("http://") == -1, link.find("https://") == -1]):
        ret_url = link.replace("//", "http://")
        ret_url = link.replace("../", f"{target}/")
        ret_url = link.replace("./", f"{target}/")
        return ret_url
    return link


async def robots(session, robo_url, r_total, sm_total, base_url, data, output):
    print(f"{C}[*]{W} Looking for robots.txt", end="", flush=True)

    async with _open(session, robo_url) as r_rqst:
        if r_rqst is None:
            print(f"{R}{'['.rjust(9, '.')} Error ]{W}")
            return
        r_sc = r_rqst.status
        if r_sc == 200:
            print(f"{G}{'['.rjust(9, '.')} Found ]{W}")
            print(f"{C}[*]{W} Extracting robots Links", end="", flush=True)
            r_page = await r_rqst.text()
            r_scrape = r_page.split("\n")
            for entry in r_scrape:
                if any(
                    [
                        entry.find("Disallow") == 0,
                        entry.find("Allow") == 0,
                        entry.find("Sitemap") == 0,
                    ]
                ):
                    url = entry.split(": ", 1)[1].strip()
                    tmp_url = url_filter(base_url, url)

                    if tmp_url is not None:
                        r_total.append(url_filter(base_url, url))

                    if url.endswith("xml"):
                        sm_total.append(url)

            r_total[:] = list(set(r_total))
            print(f"{G}{'['.rjust(8, '.')} {len(r_total)} ]")
            exporter(data, output, r_total, "robots")

        elif r_sc == 404:
            print(f"{R}{'['.rjust(9, '.')} Not Found ]{W}")

        else:
            print(f"{R}{'['.rjust(9, '.')} {r_sc} ]{W}")


async def sitemap(session, target_url, sm_total, data, output):
    print(f"{C}[*]{W} Looking for sitemap.xml", end="", flush=True)
    async with _open(session, target_url) as sm_rqst:
        if sm_rqst is None:
            print(f"{R}{'['.rjust(8, '.')} Error ]{W}")
            return
        sm_sc = sm_rqst.status
        if sm_sc == 200:
            print(f"{G}{'['.rjust(8, '.')} Found ]{W}")
            print(f"{C}[*]{W} Extracting sitemap Links", end="", flush=True)
            sm_page = await sm_rqst.read()
            sm_soup = bs4.BeautifulSoup(sm_page, "xml")
            links = sm_soup.find_all("loc")
            for url in links:
                url = url.get_text()
                if url is not None:
                    sm_total.append(url)

            sm_total[:] = list(set(sm_total))
            print(f"{G}{'['.rjust(7, '.')} {len(sm_total)} ]{W}")
            exporter(data, output, sm_total, "sitemap")
        elif sm_sc == 404:
            print(f"{R}{'['.rjust(8, '.')} Not Found ]{W}")
        else:
            print(f"{R}{'['.rjust(8, '.')} Status Code : {sm_sc} ]{W}")


def css(target, css_total, data, soup, output):
    print(f"{C}[*]{W} Extracting CSS Links", end="", flush=True)
    css_links = soup.find_all("link", href=True)

    for link in css_links:
        url = link.get("href")
        if url is not None and ".css" in url:
            css_total.append(url_filter(target, url))

    css_total[:] = list(set(css_total))
    print(f"{G}{'['.rjust(11, '.')} {len(css_total)} ]{W}")
    exporter(data, output, css_total, "css")


def js_scan(target, js_total, data, soup, output):
    print(f"{C}[*]{W} Extracting Javascript Links", end="", flush=True)
    scr_tags = soup.find_all("script", src=True)

    for link in scr_tags:
        url = link.get("src")
        if url is not None and ".js" in url:
            tmp_url = url_filter(target, url)
            if tmp_url is not None:
                js_total.append(tmp_url)

    js_total[:] = list(set(js_total))
    print(f"{G}{'['.rjust(4, '.')} {len(js_total)} ]{W}")
    exporter(data, output, js_total, "javascripts")


def internal_links(target, int_total, data, soup, output):
    print(f"{C}[*]{W} Extracting Internal Links", end="", flush=True)

    ext = tldextract.extract(target)
    domain = ext.registered_domain

    links = soup.find_all("a")
    for link in links:
        url = link.get("href")
        if url is not None:
            if domain in url:
                int_total.append(url)

    int_total[:] = list(set(int_total))
    print(f"{G}{'['.rjust(6, '.')} {len(int_total)} ]{W}")
    exporter(data, output, int_total, "internal_urls")


def external_links(target, ext_total, data, soup, output):
    print(f"{C}[*]{W} Extracting External Links", end="", flush=True)

    ext = tldextract.extract(target)
    domain = ext.registered_domain

    links = soup.find_all("a")
    for link in links:
        url = link.get("href")
        if url is not None:
            if domain not in url and "http" in url:
                ext_total.append(url)

    ext_total[:] = list(set(ext_total))
    print(f"{G}{'['.rjust(6, '.')} {len(ext_total)} ]{W}")
    exporter(data, output, ext_total, "external_urls")


def images(target, img_total, data, soup, output):
    print(f"{C}[*]{W} Extracting Images", end="", flush=True)
    image_tags = soup.find_all("img")

    for link in image_tags:
        url = link.get("src")
        if url is not None and len(url) > 1:
            img_total.append(url_filter(target, url))

    img_total[:] = list(set(img_total))
    print(f"{G}{'['.rjust(14, '.')} {len(img_total)} ]{W}")
    exporter(data, output, img_total, "images")


async def sm_crawl(session, data, sm_crawl_total, sm_total, sm_url, output):
    print(f"{C}[*]{W} Crawling Sitemaps", end="", flush=True)

    urls = [
        site_url
        for site_url in sm_total
        if site_url != sm_url and site_url.endswith("xml") is True
    ]

    async def fetch(site_url):
        async with _open(session, site_url) as sm_rqst:
            if sm_rqst is None:
                return
            sm_sc = sm_rqst.status
            if sm_sc == 200:
                sm_data = await sm_rqst.text()
                sm_soup = bs4.BeautifulSoup(sm_data, "xml")
                links = sm_soup.find_all("loc")
                for url in links:
                    url = url.get_text()
                    if url is not None:
                        sm_crawl_total.append(url)
            elif sm_sc == 404:
                pass
            else:
                pass

    if urls:
        await asyncio.gather(*(fetch(site_url) for site_url in urls))

    sm_crawl_total[:] = list(set(sm_crawl_total))
    print(f"{G}{'['.rjust(14, '.')} {len(sm_crawl_total)} ]{W}")
    exporter(data, output, sm_crawl_total, "urls_inside_sitemap")


async def js_crawl(session, data, js_crawl_total, js_total, output):
    print(f"{C}[*]{W} Crawling Javascripts", end="", flush=True)

    urls = list(js_total)

    async def fetch(js_url):
        async with _open(session, js_url) as js_rqst:
            if js_rqst is None:
                return
            js_sc = js_rqst.status
            if js_sc == 200:
                js_data = await js_rqst.text()
                js_data = js_data.split(";")
                for line in js_data:
                    if any(["http://" in line, "https://" in line]):
                        found = re.findall(r"\"(http[s]?://.*?)\"", line)
                        for item in found:
                            if len(item) > 8:
                                js_crawl_total.append(item)

    if urls:
        await asyncio.gather(*(fetch(js_url) for js_url in urls))

    js_crawl_total[:] = list(set(js_crawl_total))
    print(f"{G}{'['.rjust(11, '.')} {len(js_crawl_total)} ]{W}")
    exporter(data, output, js_crawl_total, "urls_inside_js")


def exporter(data, output, list_name, file_name):
    data[f"module-crawler-{file_name}"] = {"links": list(list_name)}
    data[f"module-crawler-{file_name}"].update({"exported": False})
    fname = f"{output['directory']}/{file_name}.{output['format']}"
    output["file"] = fname
    export(output, data)


def stats(
    output,
    r_total,
    sm_total,
    css_total,
    js_total,
    int_total,
    ext_total,
    img_total,
    sm_crawl_total,
    js_crawl_total,
    total,
    data,
    soup,
):
    total.extend(r_total)
    total.extend(sm_total)
    total.extend(css_total)
    total.extend(js_total)
    total.extend(js_crawl_total)
    total.extend(sm_crawl_total)
    total.extend(int_total)
    total.extend(ext_total)
    total.extend(img_total)
    total = set(total)

    print(f"\n{G}[+]{W} Total Unique Links Extracted : {len(total)}")

    if output != "None":
        if len(total) != 0:
            data["module-crawler-stats"] = {
                "Total Unique Links Extracted": str(len(total))
            }
            try:
                target_title = soup.title.string
            except AttributeError:
                target_title = "None"
            data["module-crawler-stats"].update({"Title ": str(target_title)})

            data["module-crawler-stats"].update(
                {
                    "total_urls_robots": len(r_total),
                    "total_urls_sitemap": len(sm_total),
                    "total_urls_css": len(css_total),
                    "total_urls_js": len(js_total),
                    "total_urls_in_js": len(js_crawl_total),
                    "total_urls_in_sitemaps": len(sm_crawl_total),
                    "total_urls_internal": len(int_total),
                    "total_urls_external": len(ext_total),
                    "total_urls_images": len(img_total),
                    "total_urls": len(total),
                }
            )
            data["module-crawler-stats"].update({"exported": False})
