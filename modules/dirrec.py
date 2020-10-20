#!/usr/bin/env python3

import json
import socket
import aiohttp
import asyncio
import requests
import tldextract
from datetime import date

R = '\033[31m' # red
G = '\033[32m' # green
C = '\033[36m' # cyan
W = '\033[0m'  # white
Y = '\033[33m' # yellow

header = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:72.0) Gecko/20100101 Firefox/72.0'}
count = 0
wm_count = 0
found = []
skipped = []
responses = []
wayback_found = []
curr_yr = date.today().year
last_yr = curr_yr - 1

async def fetch(url, session, redir, sslv):
	global count
	try:
		async with session.get(url, headers=header, allow_redirects=redir) as response:
			count += 1
			print(Y + '[!]' + C + ' Requests : ' + W + str(count), end='\r')
			return response.url, response.status
	except Exception as e:
		print(R + '[-]' + C + ' Exception : ' + W + str(e).strip('\n'))

async def run(target, threads, tout, wdlist, redir, sslv, dserv, output, data, filext):
	global responses
	tasks = []
	resolver = aiohttp.AsyncResolver(nameservers=[dserv])
	conn = aiohttp.TCPConnector(limit=threads, resolver=resolver, family=socket.AF_INET, verify_ssl=sslv)
	timeout = aiohttp.ClientTimeout(total=None, sock_connect=tout, sock_read=tout)
	async with aiohttp.ClientSession(connector=conn, timeout=timeout) as session:
		if len(filext) == 0:
			url = target + '/{}'
			with open(wdlist, 'r') as wordlist:
				for word in wordlist:
					word = word.strip()
					task = asyncio.create_task(fetch(url.format(word), session, redir, sslv))
					tasks.append(task)
					await asyncio.sleep(0)
			responses = await asyncio.gather(*tasks)
		else:
			filext = ',' + filext
			filext = filext.split(',')
			with open(wdlist, 'r') as wordlist:
				for word in wordlist:
					for ext in filext:
						ext = ext.strip()
						if len(ext) == 0:
							url = target + '/{}'
						else:
							url = target + '/{}.' + ext
						word = word.strip()
						task = asyncio.create_task(fetch(url.format(word), session, redir, sslv))
						tasks.append(task)
						await asyncio.sleep(0)
			responses = await asyncio.gather(*tasks)

async def wayback(target, dserv, tout):
	global found
	is_avail = False
	ext = tldextract.extract(target)
	domain = ext.registered_domain
	if len(domain) < 2:
		domain = ext.domain

	print('\n' + Y + '[!]' + C + ' Checking Availability on Wayback Machine' + W, end = '')
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
		print('\n' + Y + '[!]' + C + ' Requesting Wayback Machine...' + W + '\n')
		tasks = []
		resolver = aiohttp.AsyncResolver(nameservers=[dserv])
		conn = aiohttp.TCPConnector(limit=10)
		timeout = aiohttp.ClientTimeout(total=None, sock_connect=tout, sock_read=tout)
		async with aiohttp.ClientSession(connector=conn, timeout=timeout) as session:
			for f_url in found:
				tasks.append(asyncio.create_task(wm_fetch(f_url, session)))
			await asyncio.gather(*tasks)

async def wm_fetch(f_url, session):
	global wayback_found, wm_count
	wm_url = 'http://web.archive.org/cdx/search/cdx'
	domain = str(f_url)
	data= {
	    'url': domain,
		'matchType': 'prefix',
	    'fl': 'original',
	    'fastLatest': 'true',
	    'filter': 'statuscode:200',
		'from': '{}'.format(str(last_yr)),
		'to': '{}'.format(str(curr_yr)),
		'output': 'json'
	}
	try:
		async with session.get(wm_url, params=data) as resp:
			wm_count += 1
			print(Y + '[!]' + C + ' Requests : ' + W + str(wm_count), end='\r')
			answer = await resp.text()
			if resp.status == 200:
				json_ans = json.loads(answer)
				if len(json_ans) != 0:
					json_ans.pop(0)
					if len(json_ans) != 0:
						for item in json_ans:
							addr = item[0]
							addr = addr.replace(':80', '')
							wayback_found.append(addr)
	except Exception as e:
		print(R + '[-]' + C + ' Exception : ' + W + str(e))

def filter_out(target):
	global responses, found, skipped, wayback_found
	for entry in responses:
		if entry != None:
			if entry[1] in {200}:
				if str(entry[0]) != target + '/':
					found.append(entry[0])
					print(G + '[+]' + G + ' {}'.format(str(entry[1]) + C + ' | ' + W + '{}'.format(entry[0])))
			elif entry[1] in {301, 302, 303, 307, 308}:
				found.append(entry[0])
				print(G + '[+]' + Y + ' {}'.format(str(entry[1]) + C + ' | ' + W + '{}'.format(entry[0])))
			elif entry[1] in {403}:
				found.append(entry[0])
				print(G + '[+]' + R + ' {}'.format(str(entry[1]) + C + ' | ' + W + '{}'.format(entry[0])))
			else:
				skipped.append(entry[0])

def wm_filter():
	global wayback_found

	for entry in wayback_found:
		if len(entry) == 0:
			wayback_found.pop(wayback_found.index(entry))
	wayback_found = list(set(wayback_found))

	count = 0
	for entry in wayback_found:
		mod_entry = entry.split('/')
		last = mod_entry[-1]
		if '.' in last and last.startswith('.') == False:
			mod_entry.pop(mod_entry.index(last))
			mod_entry = '/'.join(mod_entry)
			loc = wayback_found.index(entry)
			wayback_found.remove(entry)
			wayback_found.insert(loc, mod_entry)
			count += 1
			print(G + '[+]' + C + ' Filtering Results : ' + W + str(count), end='\r')
	wayback_found = set(wayback_found)

def dir_output(output, data):
	global responses, found, skipped, wayback_found
	result = {}

	for entry in responses:
		if entry != None:
			if entry[1] in {200}:
				if output != 'None':
					result.setdefault('Status 200', []).append(entry[0])
			elif entry[1] in {301, 302, 303, 307, 308}:
				if output != 'None':
					result.setdefault('Status {}'.format(str(entry[1])), []).append(entry[0])
			elif entry[1] in {403}:
				if output != 'None':
					result.setdefault('Status 403', []).append(entry[0])
			else:
				pass
	
	for entry in wayback_found:
		if len(entry) != 0:
			result.setdefault('Wayback Machine', []).append(entry)
	
	print(G + '[+]' + C + ' Directories Found   : ' + W + str(len(found)))
	print(G + '[+]' + C + ' Directories Skipped : ' + W + str(len(skipped)))
	print(G + '[+]' + C + ' Total Requests      : ' + W + str(len(found) + len(skipped)))
	print(G + '[+]' + C + ' Directories Found on Wayback Machine : ' + W + str(len(wayback_found)))

	if output != 'None':
		result['Directories Found'] = str(len(found))
		result['Directories Skipped'] = str(len(skipped))
		result['Total Requests'] = str(len(found) + len(skipped))
		result['Directories Found on Wayback Machine'] = str(len(wayback_found))
		data['module-Directory Search'] = result

def hammer(target, threads, tout, wdlist, redir, sslv, dserv, output, data, filext):
	print('\n' + Y + '[!]' + Y + ' Starting Directory Search...' + W + '\n')
	print(G + '[+]' + C + ' Threads          : ' + W + str(threads))
	print(G + '[+]' + C + ' Timeout          : ' + W + str(tout))
	print(G + '[+]' + C + ' Wordlist         : ' + W + wdlist)
	print(G + '[+]' + C + ' Allow Redirects  : ' + W + str(redir))
	print(G + '[+]' + C + ' SSL Verification : ' + W + str(sslv))
	print(G + '[+]' + C + ' DNS Servers      : ' + W + dserv)
	with open(wdlist, 'r') as wordlist:
		num_words = sum(1 for i in wordlist)
	print(G + '[+]' + C + ' Wordlist Size    : ' + W + str(num_words))
	print(G + '[+]' + C + ' File Extensions  : ' + W + str(filext) + '\n')
	loop = asyncio.new_event_loop()
	asyncio.set_event_loop(loop)
	loop.run_until_complete(run(target, threads, tout, wdlist, redir, sslv, dserv, output, data, filext))
	filter_out(target)
	loop.run_until_complete(wayback(target, dserv, tout))
	wm_filter()
	dir_output(output, data)
	loop.close()