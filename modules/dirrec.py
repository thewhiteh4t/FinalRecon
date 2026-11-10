#!/usr/bin/env python3

import asyncio
import socket
from datetime import date
from random import choices
from string import ascii_letters, digits
from urllib.parse import urlparse

import aiohttp

import settings as config
from modules.export import export
from modules.write_log import log_writer

R = "\033[31m"  # red
G = "\033[32m"  # green
C = "\033[36m"  # cyan
W = "\033[0m"  # white
Y = "\033[33m"  # yellow
HEADER = "\033[1;35m"  # bold magenta

header = {"User-Agent": f"FinalRecon/{config.version}"}
count = 0
wm_count = 0
exc_count = 0
found = []
curr_yr = date.today().year
last_yr = curr_yr - 1
stop_event = asyncio.Event()
length_counts = {}


async def fetch(url, session, redir):
    global exc_count
    if stop_event.is_set():
        return
    try:
        async with session.get(url, headers=header, allow_redirects=redir) as response:
            cont_len = len(await response.read())
            cont_type = response.headers.get("Content-Type", "").split(";")[0].strip()
            location = response.headers.get("Location", "")
            return response.status, cont_type, cont_len, location
    except asyncio.TimeoutError:
        exc_count += 1
        log_writer(f"[dirrec.fetch] Exception : Request Timed Out [{url}]")
        return None, None, None, None
    except aiohttp.ClientConnectionError as cce_exc:
        exc_count += 1
        log_writer(f"[dirrec.fetch] Exception : {cce_exc} [{url}]")
        return None, None, None, None
    except aiohttp.ClientError as exc:
        exc_count += 1
        log_writer(f"[dirrec.fetch] Exception : {exc} [{url}]")
        return None, None, None, None
    except Exception as err:
        exc_count += 1
        log_writer(f"[dirrec.fetch] Exception : {err} [{url}]")
        return None, None, None, None


async def insert(queue, filext, target, wdlist, redir):
    if not filext:
        url = target + "/{}"
        with open(wdlist, "r", errors="replace") as wordlist:
            for word in wordlist:
                word = word.strip()
                await queue.put([url.format(word), redir, len(word)])
                await asyncio.sleep(0)
    else:
        if "," in filext:
            filext = filext.split(",")
        else:
            filext = [filext]
        with open(wdlist, "r", errors="replace") as wordlist:
            for word in wordlist:
                for ext in filext:
                    ext = ext.strip()
                    url = target + "/{}." + ext
                    word = word.strip()
                    await queue.put([url.format(word), redir, len(word)])
                    await asyncio.sleep(0)


async def consumer(
    queue,
    target,
    session,
    redir,
    total_num_words,
    use_cont_len,
    dir_in_content,
    exist_len,
    exist_location,
):
    global count
    while True:
        values = await queue.get()
        try:
            if stop_event.is_set():
                continue
            url = values[0]
            redir = values[1]
            dir_len = values[2]
            status, content_type, content_len, location = await fetch(
                url, session, redir
            )
            if status is not None:
                await filter_out(
                    target,
                    url,
                    status,
                    content_type,
                    content_len,
                    location,
                    use_cont_len,
                    dir_in_content,
                    dir_len,
                    exist_len,
                    exist_location,
                )
            count += 1

            print(
                f"\r\033[K{C}[*]{W} Requests : {count}/{total_num_words}",
                end="\r",
                flush=True,
            )
        except Exception as exc:
            exc_count += 1
            log_writer(f"[dirrec.consumer] Exception : {exc}")
        finally:
            queue.task_done()


async def run(target, threads, tout, wdlist, redir, sslv, filext, total_num_words):
    use_cont_len = False
    dir_in_content = False
    len_test_res = []
    queue = asyncio.Queue(maxsize=threads)

    conn = aiohttp.TCPConnector(
        limit=threads,
        limit_per_host=threads,
        family=socket.AF_INET,
        ssl=sslv,
        ttl_dns_cache=300,
        enable_cleanup_closed=True,
    )
    timeout = aiohttp.ClientTimeout(total=tout, sock_connect=tout, sock_read=tout)
    async with aiohttp.ClientSession(connector=conn, timeout=timeout) as session:
        print(f"{C}[*]{W} Probing for phantom URLs...")
        rand_urls = [
            "".join(choices(ascii_letters + digits, k=k)) for k in (10, 6, 8, 7, 9)
        ]
        for item in rand_urls:
            rand_url = f"{target}/{item}"
            exist_sc, con_type, exist_len, exist_location = await fetch(
                rand_url, session, True
            )
            len_test_res.append((item, exist_sc, exist_len))

        successful = [r for r in len_test_res if r[1] == 200]
        if successful:
            print(f"{Y}[!]{W} Response 200 OK for non existent URLs...")
            use_cont_len = True

            if len(successful) >= 2:
                cont_len1, dir_len1 = successful[0][2], len(successful[0][0])
                cont_len2, dir_len2 = successful[1][2], len(successful[1][0])
                if cont_len1 != cont_len2:
                    if (cont_len1 - dir_len1) == (cont_len2 - dir_len2):
                        print(f"{C}[*]{W} Content contains directory name...")
                        dir_in_content = True

            lengths = sorted(r[2] for r in successful)
            exist_len = lengths[len(lengths) // 2]
            if dir_in_content:
                exist_len -= len(successful[lengths.index(exist_len)][0])

            print(f"{C}[*]{W} Filtering content length for accuracy...")

        print()
        print(f"{Y}{'STATUS'} {'LENGTH'.ljust(10)} {'TYPE'.ljust(30)} URL{W}")

        distrib = asyncio.create_task(insert(queue, filext, target, wdlist, redir))
        workers = [
            asyncio.create_task(
                consumer(
                    queue,
                    target,
                    session,
                    redir,
                    total_num_words,
                    use_cont_len,
                    dir_in_content,
                    exist_len,
                    exist_location,
                )
            )
            for _ in range(threads)
        ]

        try:
            await asyncio.gather(distrib)
            await queue.join()
            print()
        finally:
            # Always tear down workers so the shared session/connector can close
            # cleanly instead of leaking open sockets.
            for worker in workers:
                worker.cancel()
            await asyncio.gather(*workers, return_exceptions=True)


def normalize_location(location):
    try:
        return urlparse(location).path
    except Exception as exc:
        print(exc)


async def filter_out(
    target,
    url,
    status,
    cont_type,
    length,
    location,
    use_cont_len,
    dir_in_content,
    dir_len,
    exist_len,
    exist_location,
):
    global found

    def log_and_append(status, length, url, color):
        found.append((url, status, length))
        print(
            f"{color}{str(status).ljust(6)}{W} {str(length).ljust(10)} {cont_type.ljust(30)} {url}",
        )

    if status in {301, 302, 303, 307, 308}:
        location_key = normalize_location(location)
        length_counts[location_key] = length_counts.get(location_key, 0) + 1
        if length_counts[location_key] == 10:
            print(
                f"\r\033[K{Y}[!]{W} Auto-filtering redirect to {location_key} — possible soft-404"
            )
        if length_counts[location_key] >= 10:
            return
    else:
        if length > 0:
            length_key = round(length, -1)
            length_counts[length_key] = length_counts.get(length_key, 0) + 1
            if length_counts[length_key] == 10:
                print(
                    f"\r\033[K{Y}[!]{W} Auto-filtering length ~{length_key} — possible soft-404"
                )
            if length_counts[length_key] >= 10:
                found[:] = [
                    f
                    for f in found
                    if not (round(f[2], -1) == length_key and f[1] == 200)
                ]
                return

    if status in {200}:
        compare_len = length
        if use_cont_len:
            if dir_in_content:
                compare_len = length - dir_len
            if round(compare_len, -1) != round(exist_len, -1):
                log_and_append(status, length, url, G)
        else:
            if str(url) != target + "/":
                log_and_append(status, length, url, G)
    elif status in {301, 302, 303, 307, 308}:
        if exist_location and normalize_location(location) == normalize_location(
            exist_location
        ):
            return
        log_and_append(status, length, url, Y)
    elif status in {403}:
        log_and_append(status, length, url, R)
    elif status in {429}:
        print(f"{R}[-]{W} Status 429, getting ratelimited, stopping...")
        stop_event.set()


def dir_output(output, data):
    result = {}
    status_map = {
        200: "Status 200",
        403: "Status 403",
        301: "Status 301",
        302: "Status 302",
        303: "Status 303",
        307: "Status 307",
        308: "Status 308",
    }
    for entry in found:
        if entry is None or output == "None":
            continue
        status = entry[1]
        status_str = status_map.get(status)
        if status_str:
            result.setdefault(status_str, []).append(f"{status}, {entry[0]}")

    print(f"\n{G}[+]{W} Directories Found   : {len(found)}\n")
    print(f"{C}[*]{W} Exceptions          : {exc_count}")

    if output != "None":
        result.update({"exported": False})
        data["module-Directory Search"] = result
        fname = f"{output['directory']}/directory_enum.{output['format']}"
        output["file"] = fname
        export(output, data)


def hammer(target, threads, tout, wdlist, redir, sslv, output, data, filext):
    print(f"\n{HEADER}━━━ Dir Enum {'━' * 30}{W}\n")
    print(f"{G}Threads          : {W}{threads}")
    print(f"{G}Timeout          : {W}{tout}")
    print(f"{G}Wordlist         : {W}{wdlist}")
    print(f"{G}Allow Redirects  : {W}{redir}")
    print(f"{G}SSL Verification : {W}{sslv}")
    with open(wdlist, "r", errors="replace") as wordlist:
        num_words = sum(1 for i in wordlist)
    print(f"{G}Wordlist Size    : {W}{num_words}")
    print(f"{G}File Extensions  : {W}{filext}\n")
    if len(filext) != 0:
        total_num_words = num_words * (len(filext.split(",")) + 1)
    else:
        total_num_words = num_words

    # asyncio.run() owns the event-loop lifecycle: it drives aiohttp's background
    # socket-cleanup to completion and closes the loop only afterwards, so idle/
    # keep-alive sockets are terminated instead of being leaked by an early close().
    try:
        asyncio.run(
            run(target, threads, tout, wdlist, redir, sslv, filext, total_num_words)
        )
        dir_output(output, data)
    finally:
        log_writer("[dirrec] Completed")
