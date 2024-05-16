#!/usr/bin/env python3

import re
import bs4
import lxml
import asyncio
import requests
import threading
import tldextract
from modules.export import export
from modules.write_log import log_writer
requests.packages.urllib3.disable_warnings()

R = '\033[31m'  # red
G = '\033[32m'  # green
C = '\033[36m'  # cyan
W = '\033[0m'   # white
Y = '\033[33m'  # yellow

user_agent = {'User-Agent': 'FinalRecon'}

total = []
r_total = []
sm_total = []
js_total = []
css_total = []
int_total = []
ext_total = []
img_total = []
js_crawl_total = []
sm_crawl_total = []


def crawler(target, protocol, netloc, output, data):
	global r_url, sm_url
	print(f'\n{Y}[!] Starting Crawler...{W}\n')

	try:
		rqst = requests.get(target, headers=user_agent, verify=False, timeout=10)
	except Exception as exc:
		print(f'{R}[-] Exception : {C}{exc}{W}')
		log_writer(f'[crawler] Exception = {exc}')
		return

	status = rqst.status_code
	if status == 200:
		page = rqst.content
		soup = bs4.BeautifulSoup(page, 'lxml')

		r_url = f'{protocol}://{netloc}/robots.txt'
		sm_url = f'{protocol}://{netloc}/sitemap.xml'
		base_url = f'{protocol}://{netloc}'

		loop = asyncio.new_event_loop()
		asyncio.set_event_loop(loop)
		tasks = asyncio.gather(
			robots(r_url, base_url, data, output),
			sitemap(sm_url, data, output),
			css(target, data, soup, output),
			js_scan(target, data, soup, output),
			internal_links(target, data, soup, output),
			external_links(target, data, soup, output),
			images(target, data, soup, output),
			sm_crawl(data, output),
			js_crawl(data, output))
		loop.run_until_complete(tasks)
		loop.close()
		stats(output, data, soup)
		log_writer('[crawler] Completed')
	else:
		print(f'{R}[-] {C}Status : {W}{status}')
		log_writer(f'[crawler] Status code = {status}, expected 200')


def url_filter(target, link):
	if all([link.startswith('/') is True, link.startswith('//') is False]):
		ret_url = target + link
		return ret_url

	if link.startswith('//') is True:
		ret_url = link.replace('//', 'http://')
		return ret_url

	if all([
		link.find('//') == -1,
		link.find('../') == -1,
		link.find('./') == -1,
		link.find('http://') == -1,
		link.find('https://') == -1]
	):
		ret_url = f'{target}/{link}'
		return ret_url

	if all([
		link.find('http://') == -1,
		link.find('https://') == -1]
	):
		ret_url = link.replace('//', 'http://')
		ret_url = link.replace('../', f'{target}/')
		ret_url = link.replace('./', f'{target}/')
		return ret_url
	return link


async def robots(robo_url, base_url, data, output):
	global r_total
	print(f'{G}[+] {C}Looking for robots.txt{W}', end='', flush=True)

	try:
		r_rqst = requests.get(robo_url, headers=user_agent, verify=False, timeout=10)
		r_sc = r_rqst.status_code
		if r_sc == 200:
			print(f'{G}{"[".rjust(9, ".")} Found ]{W}')
			print(f'{G}[+] {C}Extracting robots Links{W}', end='', flush=True)
			r_page = r_rqst.text
			r_scrape = r_page.split('\n')
			for entry in r_scrape:
				if any([
					entry.find('Disallow') == 0,
					entry.find('Allow') == 0,
					entry.find('Sitemap') == 0]):

					url = entry.split(': ', 1)[1].strip()
					tmp_url = url_filter(base_url, url)

					if tmp_url is not None:
						r_total.append(url_filter(base_url, url))

					if url.endswith('xml'):
						sm_total.append(url)

			r_total = set(r_total)
			print(f'{G}{"[".rjust(8, ".")} {len(r_total)} ]')
			exporter(data, output, r_total, 'robots')

		elif r_sc == 404:
			print(f'{R}{"[".rjust(9, ".")} Not Found ]{W}')

		else:
			print(f'{R}{"[".rjust(9, ".")} {r_sc} ]{W}')

	except Exception as exc:
		print(f'\n{R}[-] Exception : {C}{exc}{W}')
		log_writer(f'[crawler.robots] Exception = {exc}')


async def sitemap(target_url, data, output):
	global sm_total
	print(f'{G}[+] {C}Looking for sitemap.xml{W}', end='', flush=True)
	try:
		sm_rqst = requests.get(target_url, headers=user_agent, verify=False, timeout=10)
		sm_sc = sm_rqst.status_code
		if sm_sc == 200:
			print(f'{G}{"[".rjust(8, ".")} Found ]{W}')
			print(f'{G}[+] {C}Extracting sitemap Links{W}', end='', flush=True)
			sm_page = sm_rqst.content
			sm_soup = bs4.BeautifulSoup(sm_page, 'xml')
			links = sm_soup.find_all('loc')
			for url in links:
				url = url.get_text()
				if url is not None:
					sm_total.append(url)

			sm_total = set(sm_total)
			print(f'{G}{"[".rjust(7, ".")} {len(sm_total)} ]{W}')
			exporter(data, output, sm_total, 'sitemap')
		elif sm_sc == 404:
			print(f'{R}{"[".rjust(8, ".")} Not Found ]{W}')
		else:
			print(f'{R}{"[".rjust(8, ".")} Status Code : {sm_sc} ]{W}')
	except Exception as exc:
		print(f'\n{R}[-] Exception : {C}{exc}{W}')
		log_writer(f'[crawler.sitemap] Exception = {exc}')


async def css(target, data, soup, output):
	global css_total
	print(f'{G}[+] {C}Extracting CSS Links{W}', end='', flush=True)
	css_links = soup.find_all('link', href=True)

	for link in css_links:
		url = link.get('href')
		if url is not None and '.css' in url:
			css_total.append(url_filter(target, url))

	css_total = set(css_total)
	print(f'{G}{"[".rjust(11, ".")} {len(css_total)} ]{W}')
	exporter(data, output, css_total, 'css')


async def js_scan(target, data, soup, output):
	global js_total
	print(f'{G}[+] {C}Extracting Javascript Links{W}', end='', flush=True)
	scr_tags = soup.find_all('script', src=True)

	for link in scr_tags:
		url = link.get('src')
		if url is not None and '.js' in url:
			tmp_url = url_filter(target, url)
			if tmp_url is not None:
				js_total.append(tmp_url)

	js_total = set(js_total)
	print(f'{G}{"[".rjust(4, ".")} {len(js_total)} ]{W}')
	exporter(data, output, js_total, 'javascripts')


async def internal_links(target, data, soup, output):
	global int_total
	print(f'{G}[+] {C}Extracting Internal Links{W}', end='', flush=True)

	ext = tldextract.extract(target)
	domain = ext.registered_domain

	links = soup.find_all('a')
	for link in links:
		url = link.get('href')
		if url is not None:
			if domain in url:
				int_total.append(url)

	int_total = set(int_total)
	print(f'{G}{"[".rjust(6, ".")} {len(int_total)} ]{W}')
	exporter(data, output, int_total, 'internal_urls')


async def external_links(target, data, soup, output):
	global ext_total
	print(f'{G}[+] {C}Extracting External Links{W}', end='', flush=True)

	ext = tldextract.extract(target)
	domain = ext.registered_domain

	links = soup.find_all('a')
	for link in links:
		url = link.get('href')
		if url is not None:
			if domain not in url and 'http' in url:
				ext_total.append(url)

	ext_total = set(ext_total)
	print(f'{G}{"[".rjust(6, ".")} {len(ext_total)} ]{W}')
	exporter(data, output, ext_total, 'external_urls')


async def images(target, data, soup, output):
	global img_total
	print(f'{G}[+] {C}Extracting Images{W}', end='', flush=True)
	image_tags = soup.find_all('img')

	for link in image_tags:
		url = link.get('src')
		if url is not None and len(url) > 1:
			img_total.append(url_filter(target, url))

	img_total = set(img_total)
	print(f'{G}{"[".rjust(14, ".")} {len(img_total)} ]{W}')
	exporter(data, output, img_total, 'images')


async def sm_crawl(data, output):
	global sm_crawl_total
	print(f'{G}[+] {C}Crawling Sitemaps{W}', end='', flush=True)

	threads = []

	def fetch(site_url):
		try:
			sm_rqst = requests.get(site_url, headers=user_agent, verify=False, timeout=10)
			sm_sc = sm_rqst.status_code
			if sm_sc == 200:
				sm_data = sm_rqst.content.decode()
				sm_soup = bs4.BeautifulSoup(sm_data, 'xml')
				links = sm_soup.find_all('loc')
				for url in links:
					url = url.get_text()
					if url is not None:
						sm_crawl_total.append(url)
			elif sm_sc == 404:
				# print(R + '['.rjust(8, '.') + ' Not Found ]' + W)
				pass
			else:
				# print(R + '['.rjust(8, '.') + ' {} ]'.format(sm_sc) + W)
				pass
		except Exception as exc:
			# print(f'\n{R}[-] Exception : {C}{exc}{W}')
			log_writer(f'[crawler.sm_crawl] Exception = {exc}')

	for site_url in sm_total:
		if site_url != sm_url:
			if site_url.endswith('xml') is True:
				task = threading.Thread(target=fetch, args=[site_url])
				task.daemon = True
				threads.append(task)
				task.start()

	for thread in threads:
		thread.join()

	sm_crawl_total = set(sm_crawl_total)
	print(f'{G}{"[".rjust(14, ".")} {len(sm_crawl_total)} ]{W}')
	exporter(data, output, sm_crawl_total, 'urls_inside_sitemap')


async def js_crawl(data, output):
	global js_crawl_total
	print(f'{G}[+] {C}Crawling Javascripts{W}', end='', flush=True)

	threads = []

	def fetch(js_url):
		try:
			js_rqst = requests.get(js_url, headers=user_agent, verify=False, timeout=10)
			js_sc = js_rqst.status_code
			if js_sc == 200:
				js_data = js_rqst.content.decode()
				js_data = js_data.split(';')
				for line in js_data:
					if any(['http://' in line, 'https://' in line]):
						found = re.findall(r'\"(http[s]?://.*?)\"', line)
						for item in found:
							if len(item) > 8:
								js_crawl_total.append(item)
		except Exception as exc:
			# print(f'\n{R}[-] Exception : {C}{exc}{W}')
			log_writer(f'[crawler.js_crawl] Exception = {exc}')

	for js_url in js_total:
		task = threading.Thread(target=fetch, args=[js_url])
		task.daemon = True
		threads.append(task)
		task.start()

	for thread in threads:
		thread.join()

	js_crawl_total = set(js_crawl_total)
	print(f'{G}{"[".rjust(11, ".")} {len(js_crawl_total)} ]{W}')
	exporter(data, output, js_crawl_total, 'urls_inside_js')


def exporter(data, output, list_name, file_name):
	data[f'module-crawler-{file_name}'] = {'links': list(list_name)}
	data[f'module-crawler-{file_name}'].update({'exported': False})
	fname = f'{output["directory"]}/{file_name}.{output["format"]}'
	output['file'] = fname
	export(output, data)


def stats(output, data, soup):
	global total

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

	print(f'\n{G}[+] {C}Total Unique Links Extracted : {W}{len(total)}')

	if output != 'None':
		if len(total) != 0:
			data['module-crawler-stats'] = {'Total Unique Links Extracted': str(len(total))}
			try:
				target_title = soup.title.string
			except AttributeError:
				target_title = 'None'
			data['module-crawler-stats'].update({'Title ': str(target_title)})

			data['module-crawler-stats'].update(
				{
					'total_urls_robots': len(r_total),
					'total_urls_sitemap': len(sm_total),
					'total_urls_css': len(css_total),
					'total_urls_js': len(js_total),
					'total_urls_in_js': len(js_crawl_total),
					'total_urls_in_sitemaps': len(sm_crawl_total),
					'total_urls_internal': len(int_total),
					'total_urls_external': len(ext_total),
					'total_urls_images': len(img_total),
					'total_urls': len(total)
				})
			data['module-crawler-stats'].update({'exported': False})
