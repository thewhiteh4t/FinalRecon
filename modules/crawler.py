#!/usr/bin/env python3

import os
import re
import bs4
import lxml
import json
import asyncio
import requests
import threading
import tldextract
from datetime import date
requests.packages.urllib3.disable_warnings()

R = '\033[31m' # red
G = '\033[32m' # green
C = '\033[36m' # cyan
W = '\033[0m'  # white
Y = '\033[33m' # yellow

user_agent = {
	'User-Agent' : 'Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0'
	}

soup = ''
r_url = ''
sm_url = ''
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
wayback_total = []

def crawler(target, output, data):
	global soup, r_url, sm_url
	print('\n' + Y + '[!]' + Y + ' Starting Crawler...' + W + '\n')

	try:
		rqst = requests.get(target, headers=user_agent, verify=False, timeout=10)
	except Exception as e:
		print(R + '[-] Exception : ' + C + str(e) + W)
		return

	sc = rqst.status_code
	if sc == 200:
		page = rqst.content
		soup = bs4.BeautifulSoup(page, 'lxml')

		protocol = target.split('://')
		protocol = protocol[0]
		temp_tgt = target.split('://')[1]
		pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{2,5}'
		custom = bool(re.match(pattern, temp_tgt))
		if custom == True:
			r_url = protocol + '://' + temp_tgt + '/robots.txt'
			sm_url = protocol + '://' + temp_tgt + '/sitemap.xml'
		else:
			ext = tldextract.extract(target)
			hostname = '.'.join(part for part in ext if part)
			r_url = protocol + '://' + hostname + '/robots.txt'
			sm_url = protocol + '://' + hostname + '/sitemap.xml'

		loop = asyncio.new_event_loop()
		asyncio.set_event_loop(loop)
		tasks = asyncio.gather(
			robots(target),
			sitemap(),
			css(target),
			js(target),
			internal_links(target),
			external_links(target),
			images(target),
			sm_crawl(),
			js_crawl(),
			wayback(target))
		loop.run_until_complete(tasks)
		loop.close()

		out(target, output, data)
	else:
		print (R + '[-]' + C + ' Status : ' + W + str(sc))

def url_filter(target):
	global url

	if all([url.startswith('/') == True, url.startswith('//') == False]):
		url = target + url
	else:
		pass

	if all([url.find('http://') == -1,
		url.find('https://') == -1]):

		url = url.replace('//', 'http://')
		url = url.replace('../', target + '/')
		url = url.replace('./', target + '/')
	else:
		pass

	if all([url.find('//') == -1,
		url.find('../') == -1,
		url.find('./') == -1,
		url.find('http://') == -1,
		url.find('https://') == -1]):

		url = target + '/' + url
	else:
		pass

async def wayback(target):
	global wayback_total
	is_avail = False
	ext = tldextract.extract(target)
	domain = ext.registered_domain
	if len(domain) < 2:
		domain = ext.domain
	domain_query = domain + '/*'

	#today = date.today().strftime("%Y%m%d")
	#past = date.today() + relativedelta(months=-6)
	#past = past.strftime("%Y%m%d")

	curr_yr = date.today().year
	last_yr = curr_yr - 1

	print(Y + '[!]' + C + ' Checking Availability on Wayback Machine' + W, end = '')
	wm_avail = 'http://archive.org/wayback/available'
	avail_data = { 'url': domain }

	try:
		check_rqst = requests.get(wm_avail, params=avail_data, timeout=10)
		check_sc = check_rqst.status_code
		if check_sc == 200:
			check_data = check_rqst.text
			json_chk_data = json.loads(check_data)
			avail_data = json_chk_data['archived_snapshots']
			if len(avail_data) != 0:
				is_avail = True
				print(G + '['.rjust(5, '.') + ' Available ]')
			else:
				print(R + '['.rjust(5, '.') + ' N/A ]')
		else:
			print('\n' + R + '[-] Status : ' + C + str(check_sc) + W)
	except Exception as e:
		print('\n' + R + '[-] Exception : ' + C + str(e) + W)

	if is_avail == True:
		print(Y + '[!]' + C + ' Requesting Wayback Machine' + W, end = '')
		wm_url = 'http://web.archive.org/cdx/search/cdx'

		data = {
	    	'url': domain_query,
	    	'fl': 'original',
	    	'fastLatest': 'true',
			'from': '{}'.format(str(last_yr)),
			'to': '{}'.format(str(curr_yr)),
			'filter': 'statuscode:200'
		}

		try:
			r = requests.get(wm_url, params=data)
			r_sc = r.status_code
			if r_sc == 200:
				r_data = r.text
				if len(r_data) != 0:
					r_data = r_data.split('\n')
					r_data = set(r_data)
					print(G + '['.rjust(5, '.') + ' {} ]'.format(str(len(r_data))))
					wayback_total.extend(r_data)
				else:
					print(R + '['.rjust(5, '.') + ' Not Found ]' + W)
			else:
				print(R + '['.rjust(5, '.') + ' {} ]'.format(r_sc) + W)
		except Exception as e:
			print('\n' + R + '[-] Exception : ' + C + str(e) + W)

async def robots(target):
	global url, r_url, r_total
	print(G + '[+]' + C + ' Looking for robots.txt' + W, end = '')

	try:
		r_rqst = requests.get(r_url, headers=user_agent, verify=False, timeout=10)
		r_sc = r_rqst.status_code
		if r_sc == 200:
			print(G + '['.rjust(9, '.') + ' Found ]' + W)
			print(G + '[+]' + C + ' Extracting robots Links', end = '')
			r_page = r_rqst.text
			r_scrape = r_page.split('\n')
			for entry in r_scrape:
				if (entry.find('Disallow') == 0 or
					entry.find('Allow') == 0 or
					entry.find('Sitemap') == 0):

					url = entry.split(': ')
					try:
						url = url[1]
						url = url.strip()
						url_filter(target)
						r_total.append(url)
						if url.endswith('xml') == True:
							sm_total.append(url)
					except:
						pass

			r_total = set(r_total)

			print(G + '['.rjust(8, '.') + ' {} ]'.format(str(len(r_total))))

		elif r_sc == 404:
			print(R + '['.rjust(9, '.') + ' Not Found ]' + W)
		else:
			print(R + '['.rjust(9, '.') + ' {} ]'.format(r_sc) + W)
	except Exception as e:
		print('\n' + R + '[-] Exception : ' + C + str(e) + W)

async def sitemap():
	global url, sm_url, total, sm_total
	print(G + '[+]' + C + ' Looking for sitemap.xml' + W, end = '')
	try:
		sm_rqst = requests.get(sm_url, headers=user_agent, verify=False, timeout=10)
		sm_sc = sm_rqst.status_code
		if sm_sc == 200:
			print(G + '['.rjust(8, '.') + ' Found ]' + W)
			print(G + '[+]' + C + ' Extracting sitemap Links', end = '')
			sm_page = sm_rqst.content
			sm_soup = bs4.BeautifulSoup(sm_page, 'xml')
			links = sm_soup.find_all('loc')
			for url in links:
				url = url.get_text()
				if url != None:
					sm_total.append(url)

			sm_total = set(sm_total)

			print(G + '['.rjust(7, '.') + ' {} ]'.format(str(len(sm_total))))
		elif sm_sc == 404:
			print(R + '['.rjust(8, '.') + ' Not Found ]' + W)
		else:
			print(R + '['.rjust(8, '.') + ' {} ]'.format(sm_sc) + W)
	except Exception as e:
		print('\n' + R + '[-] Exception : ' + C + str(e))

async def css(target):
	global url, soup, total, css_total
	print(G + '[+]' + C + ' Extracting CSS Links' + W, end = '')
	css = soup.find_all('link')

	for link in css:
		url = link.get('href')
		if url != None and '.css' in url:
			url_filter(target)
			css_total.append(url)

	css_total = set(css_total)
	print(G + '['.rjust(11, '.') + ' {} ]'.format(str(len(css_total))) + W)

async def js(target):
	global url, total, js_total
	print(G + '[+]' + C + ' Extracting Javascript Links' + W, end = '')
	js = soup.find_all('script')

	for link in js:
		url = link.get('src')
		if url != None and '.js' in url:
			url_filter(target)
			js_total.append(url)

	js_total = set(js_total)
	print(G + '['.rjust(4, '.') + ' {} ]'.format(str(len(js_total))))

async def internal_links(target):
	global total, int_total
	print(G + '[+]' + C + ' Extracting Internal Links' + W, end = '')

	ext = tldextract.extract(target)
	domain = ext.registered_domain

	links = soup.find_all('a')
	for link in links:
		url = link.get('href')
		if url != None:
			if domain in url:
				int_total.append(url)

	int_total = set(int_total)
	print(G + '['.rjust(6, '.') + ' {} ]'.format(str(len(int_total))))

async def external_links(target):
	global total, ext_total
	print(G + '[+]' + C + ' Extracting External Links' + W, end = '')

	ext = tldextract.extract(target)
	domain = ext.registered_domain

	links = soup.find_all('a')
	for link in links:
		url = link.get('href')
		if url != None:
			if domain not in url and 'http' in url:
				ext_total.append(url)

	ext_total = set(ext_total)
	print(G + '['.rjust(6, '.') + ' {} ]'.format(str(len(ext_total))))

async def images(target):
	global url, total, img_total
	print(G + '[+]' + C + ' Extracting Images' + W, end = '')
	images = soup.find_all('img')

	for link in images:
		url = link.get('src')
		if url != None and len(url) > 1:
			url_filter(target)
			img_total.append(url)

	img_total = set(img_total)
	print(G + '['.rjust(14, '.') + ' {} ]'.format(str(len(img_total))))

async def sm_crawl():
	global sm_crawl_total
	print(G + '[+]' + C + ' Crawling Sitemaps' + W, end = '')

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
					if url != None:
						sm_crawl_total.append(url)
			elif sm_sc == 404:
				print(R + '['.rjust(8, '.') + ' Not Found ]' + W)
			else:
				print(R + '['.rjust(8, '.') + ' {} ]'.format(sm_sc) + W)
		except Exception as e:
			print('\n' + R + '[-] Exception : ' + C + str(e))

	for site_url in sm_total:
		if site_url != sm_url:
			if site_url.endswith('xml') == True:
				t = threading.Thread(target=fetch, args=[site_url])
				t.daemon = True
				threads.append(t)
				t.start()

	for thread in threads:
		thread.join()

	sm_crawl_total = set(sm_crawl_total)
	print(G + '['.rjust(14, '.') + ' {} ]'.format(str(len(sm_crawl_total))))

async def js_crawl():
	global js_crawl_total
	print(G + '[+]' + C + ' Crawling Javascripts' + W, end = '')

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
		except Exception as e:
			print('\n' + R + '[-] Exception : ' + C + str(e))

	for js_url in js_total:
		t = threading.Thread(target=fetch, args=[js_url])
		t.daemon = True
		threads.append(t)
		t.start()

	for thread in threads:
		thread.join()

	js_crawl_total = set(js_crawl_total)
	print(G + '['.rjust(11, '.') + ' {} ]'.format(str(len(js_crawl_total))))

def out(target, output, data):
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
	total.extend(wayback_total)
	total = set(total)

	print('\n' + G + '[+]' + C + ' Total Unique Links Extracted : ' + W + str(len(total)))

	if output != 'None':
		if len(total) != 0:
			data['module-Crawler'] = {'Total Unique Links Extracted': str(len(total))}
			try:
				target_title = soup.title.string
			except AttributeError:
				target_title = 'None'
			data['module-Crawler'].update({'Title ': str(target_title)})

			data['module-Crawler'].update(
				{
					'Count ( Robots )':      str(len(r_total)),
					'Count ( Sitemap )':     str(len(sm_total)),
					'Count ( CSS )':         str(len(css_total)),
					'Count ( JS )':          str(len(js_total)),
					'Count ( Links in JS )':       str(len(js_crawl_total)),
					'Count ( Links in Sitemaps )': str(len(sm_crawl_total)),
					'Count ( Internal )':    str(len(int_total)),
					'Count ( External )':    str(len(ext_total)),
					'Count ( Images )':      str(len(img_total)),
					'count ( Wayback Machine )': str(len(wayback_total)),
					'Count ( Total )': str(len(total))
				})
			
			if len(r_total) != 0:
				data['module-Crawler'].update({'Robots': list(r_total)})
			
			if len(sm_total) != 0:
				data['module-Crawler'].update({'Sitemaps': list(sm_total)})
			
			if len(css_total) != 0:
				data['module-Crawler'].update({'CSS': list(css_total)})
			
			if len(js_total) != 0:
				data['module-Crawler'].update({'Javascripts': list(js_total)})

			if len(js_crawl_total) != 0:
				data['module-Crawler'].update({'Links inside Javascripts': list(js_crawl_total)})
			
			if len(sm_crawl_total) != 0:
				data['module-Crawler'].update({'Links Inside Sitemaps': list(sm_crawl_total)})
			
			if len(int_total) != 0:
				data['module-Crawler'].update({'Internal Links': list(int_total)})
		
			if len(ext_total) != 0:
				data['module-Crawler'].update({'External Links': list(ext_total)})
			
			if len(img_total) != 0:
				data['module-Crawler'].update({'Images': list(img_total)})
			
			if len(wayback_total) != 0:
				data['module-Crawler'].update({'Wayback Machine': list(wayback_total)})