#!/usr/bin/env python3

import socket
import aiohttp
import asyncio

R = '\033[31m' # red
G = '\033[32m' # green
C = '\033[36m' # cyan
W = '\033[0m'  # white
Y = '\033[93m' # yellow

header = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:72.0) Gecko/20100101 Firefox/72.0'}
count = 0

async def fetch(url, session, redir, sslv):
	global count
	try:
		async with session.get(url, headers=header, allow_redirects=redir) as response:
			count += 1
			print(Y + '[!]' + C + ' Requests : ' + W + str(count), end='\r')
			return response.url, response.status
	except Exception as e:
		print(R + '[-]' + C + ' Exception : ' + W + str(e).strip('\n'))

async def run(target, threads, tout, wdlist, redir, sslv, dserv, output, data):
	tasks = []
	url = target + '/{}'
	resolver = aiohttp.AsyncResolver(nameservers=[dserv])
	conn = aiohttp.TCPConnector(limit=threads, resolver=resolver, family=socket.AF_INET, verify_ssl=sslv)
	timeout = aiohttp.ClientTimeout(total=None, sock_connect=tout, sock_read=tout)
	async with aiohttp.ClientSession(connector=conn, timeout=timeout) as session:
		with open(wdlist) as wordlist:
			for word in wordlist:
				word = word.strip()
				task = asyncio.create_task(fetch(url.format(word), session, redir, sslv))
				tasks.append(task)
		responses = await asyncio.gather(*tasks)
		dir_output(responses, output, data)

def dir_output(responses, output, data):
	found = []
	skipped = []
	result = {}

	for entry in responses:
		if entry != None:
			if entry[1] in {200}:
				print(G + '[+]' + G + ' {}'.format(str(entry[1]) + C + ' | ' + W + '{}'.format(entry[0])))
				found.append(entry[0])
				if output != 'None':
					result.setdefault('Status 200', []).append(entry[0])
			elif entry[1] in {301, 302, 303, 307, 308}:
				print(G + '[+]' + Y + ' {}'.format(str(entry[1]) + C + ' | ' + W + '{}'.format(entry[0])))
				found.append(entry[0])
				if output != 'None':
					result.setdefault('Status {}'.format(str(entry[1])), []).append(entry[0])
			elif entry[1] in {403}:
				print(G + '[+]' + R + ' {}'.format(str(entry[1]) + C + ' | ' + W + '{}'.format(entry[0])))
				found.append(entry[0])
				if output != 'None':
					result.setdefault('Status 403', []).append(entry[0])
			else:
				skipped.append(entry[0])

	print('\n' + G + '[+]' + C + ' Directories Found   : ' + W + str(len(found)))
	print(G + '[+]' + C + ' Directories Skipped : ' + W + str(len(skipped)))
	print(G + '[+]' + C + ' Total Requests      : ' + W + str(len(found) + len(skipped)))

	if output != 'None':
		result['Directories Found'] = str(len(found))
		result['Directories Skipped'] = str(len(skipped))
		result['Total Requests'] = str(len(found) + len(skipped))
		data['module-Directory Search'] = result

def hammer(target, threads, tout, wdlist, redir, sslv, dserv, output, data):
	print('\n' + Y + '[!]' + Y + ' Starting Directory Search...' + W + '\n')
	print(G + '[+]' + C + ' Threads          : ' + W + str(threads))
	print(G + '[+]' + C + ' Timeout          : ' + W + str(tout))
	print(G + '[+]' + C + ' Wordlist         : ' + W + wdlist)
	print(G + '[+]' + C + ' Allow Redirects  : ' + W + str(redir))
	print(G + '[+]' + C + ' SSL Verification : ' + W + str(sslv))
	print(G + '[+]' + C + ' DNS Servers      : ' + W + dserv + '\n')
	loop = asyncio.new_event_loop()
	asyncio.set_event_loop(loop)
	loop.run_until_complete(run(target, threads, tout, wdlist, redir, sslv, dserv, output, data))
	loop.close()