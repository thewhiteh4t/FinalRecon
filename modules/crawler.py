#!/usr/bin/env python3

import os
import bs4
import lxml
import requests

R = '\033[31m' # red
G = '\033[32m' # green
C = '\033[36m' # cyan
W = '\033[0m'  # white
user_agent = {'User-Agent' : 'Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0'}

def crawler(target):
	total = []
	r_total = []
	sm_total = []
	js_total = []
	css_total = []
	int_total = []
	ext_total = []
	img_total = []
	print ('\n' + G + '[+]' + C + ' Crawling Target...' + W + '\n')
	try:
		rqst = requests.get(target, headers=user_agent, verify=False, timeout=10)
		sc = rqst.status_code
		if sc == 200:
			domain = target.split('//')
			domain = domain[1]
			if "/" in domain:
				domain = domain.split("/")[0]
			base_target = target.split('//')[0] + "//" + domain
			page = rqst.content
			soup = bs4.BeautifulSoup(page, 'lxml')
			file = '{}.dump'.format(domain)
			path = os.getcwd()
			r_url = 'http://{}/robots.txt'.format(domain)
			sm_url = 'http://{}/sitemap.xml'.format(domain)

			print(G + '[+]' + C + ' Looking for robots.txt' + W, end = '')
			r_rqst = requests.get(r_url, headers=user_agent, verify=False, timeout=10)
			r_sc = r_rqst.status_code

			if r_sc == 200:
				print(G + '['.rjust(9, '.') + ' Found ]' + W)
				print(G + '[+]' + C + ' Extracting robots Links', end = '')
				r_page = r_rqst.text
				r_scrape = r_page.split('\n')
				for entry in r_scrape:
					if 'Disallow' in entry:
						url = entry.split(':')
						try:
							url = url[1]
							url = url.strip()
							total.append(url)
							r_total.append(base_target + url)
						except:
							pass
					elif 'Allow' in entry:
						url = entry.split(':')
						try:
							url = url[1]
							url = url.strip()
							total.append(url)
							r_total.append(base_target + url)
						except:
							pass
				r_total = set(r_total)
				print(G + '['.rjust(8, '.') + ' {} ]'.format(str(len(r_total))))

			elif r_sc == 404:
				print(R + '['.rjust(9, '.') + ' Not Found ]' + W)
			else:
				print(R + '['.rjust(9, '.') + ' {} ]'.format(r_sc) + W)

			print(G + '[+]' + C + ' Looking for sitemap.xml' + W, end = '')
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
					if url is not None:
						total.append(url)
						sm_total.append(url)
				sm_total = set(sm_total)
				print(G + '['.rjust(7, '.') + ' {} ]'.format(str(len(sm_total))))

			elif sm_sc == 404:
				print(R + '['.rjust(8, '.') + ' Not Found ]' + W)
			else:
				print(R + '['.rjust(8, '.') + ' {} ]'.format(sm_sc) + W)

			print(G + '[+]' + C + ' Extracting CSS Links' + W, end = '')
			css = soup.find_all('link')
			for link in css:
				url = link.get('href')
				if url is not None and '.css' in url:
					total.append(url)
					css_total.append(url)
			css_total = set(css_total)
			print(G + '['.rjust(11, '.') + ' {} ]'.format(str(len(css_total))))

			print(G + '[+]' + C + ' Extracting Javascript Links' + W, end = '')
			js = soup.find_all('script')
			for link in js:
				url = link.get('src')
				if url is not None and '.js' in url:
					total.append(url)
					js_total.append(url)
			js_total = set(js_total)
			print(G + '['.rjust(4, '.') + ' {} ]'.format(str(len(js_total))))

			print(G + '[+]' + C + ' Extracting Internal Links' + W, end = '')
			links = soup.find_all('a')
			for link in links:
				url = link.get('href')
				if url is not None:
					if domain in url:
						total.append(url)
						int_total.append(url)
			int_total = set(int_total)
			print(G + '['.rjust(6, '.') + ' {} ]'.format(str(len(int_total))))

			print(G + '[+]' + C + ' Extracting External Links' + W, end = '')
			for link in links:
				url = link.get('href')
				if url is not None:
					if domain not in url and 'http' in url:
						total.append(url)
						ext_total.append(url)
			ext_total = set(ext_total)
			print(G + '['.rjust(6, '.') + ' {} ]'.format(str(len(ext_total))))

			print(G + '[+]' + C + ' Extracting Images' + W, end = '')
			images = soup.find_all('img')
			for link in images:
				src = link.get('src')
				if src is not None and len(src) > 1:
					total.append(src)
					img_total.append(src)
			img_total = set(img_total)
			print(G + '['.rjust(14, '.') + ' {} ]'.format(str(len(img_total))))

			total = set(total)
			print('\n' + G + '[+]' + C + ' Total Links Extracted : ' + W + str(len(total)) + '\n')

			if len(total) is not 0:
				file = file.replace("/", ".")
				dump_path = '{}/dumps/{}'.format(path, file)
				print(G + '[+]' + C + ' Dumping Links in ' + W + dump_path)
				with open(dump_path, 'w') as dumpfile:
					dumpfile.write('URL : {}'.format(target) + '\n\n')
					try:
						dumpfile.write('Title : {}'.format(soup.title.string) + '\n')
					except AttributeError:
						dumpfile.write('Title : None' + '\n')
					dumpfile.write('\nrobots Links      : ' + str(len(r_total)))
					dumpfile.write('\nsitemap Links     : ' + str(len(sm_total)))
					dumpfile.write('\nCSS Links         : ' + str(len(css_total)))
					dumpfile.write('\nJS Links          : ' + str(len(js_total)))
					dumpfile.write('\nInternal Links    : ' + str(len(int_total)))
					dumpfile.write('\nExternal Links    : ' + str(len(ext_total)))
					dumpfile.write('\nImages Links      : ' + str(len(img_total)))
					dumpfile.write('\nTotal Links Found : ' + str(len(total)) + '\n')

					if len(r_total) is not 0:
						dumpfile.write('\nrobots :\n\n')
						for item in r_total:
							dumpfile.write(str(item) + '\n')
					if len(sm_total) is not 0:
						dumpfile.write('\nsitemap :\n\n')
						for item in sm_total:
							dumpfile.write(str(item) + '\n')
					if len(css_total) is not 0:
						dumpfile.write('\nCSS :\n\n')
						for item in css_total:
							dumpfile.write(str(item) + '\n')
					if len(js_total) is not 0:
						dumpfile.write('\nJavascript :\n\n')
						for item in js_total:
							dumpfile.write(str(item) + '\n')
					if len(int_total) is not 0:
						dumpfile.write('\nInternal Links :\n\n')
						for item in int_total:
							dumpfile.write(str(item) + '\n')
					if len(ext_total) is not 0:
						dumpfile.write('\nExternal Links :\n\n')
						for item in ext_total:
							dumpfile.write(str(item) + '\n')
					if len(img_total) is not 0:
						dumpfile.write('\nImages :\n\n')
						for item in img_total:
							dumpfile.write(str(item) + '\n')

		else:
			print (R + '[-]' + C + ' Error : ' + W + str(sc))
	except Exception as e:
		print(R + '[-] Error : ' + C + str(e))
