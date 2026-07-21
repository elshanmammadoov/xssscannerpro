#!/usr/bin/env python3
"""
xssscannerpro v3.0 — Context-Aware XSS Vulnerability Scanner
Author: Elshan Mammadov
LinkedIn: https://www.linkedin.com/in/elshanmammadoov/
GitHub:   https://github.com/elshanmammadoov
"""

import sys
import time
import re
import urllib.parse
import urllib.request
import ssl
import random
import html
from datetime import datetime
from html.parser import HTMLParser

# ─── COLORS ───────────────────────────────────────────────
class C:
    R='\033[91m'; G='\033[92m'; Y='\033[93m'; B='\033[94m'
    P='\033[95m'; C='\033[96m'; W='\033[97m'; D='\033[2m'
    BOLD='\033[1m'; RST='\033[0m'

# ─── BANNER ───────────────────────────────────────────────
BANNER = f"""{C.C}{C.BOLD}
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   ██████╗ ██╗   ██╗███████╗███████╗████████╗██████╗ ██╗   ║
║   ██╔══██╗██║   ██║██╔════╝██╔════╝╚══██╔══╝██╔══██╗██║   ║
║   ██████╔╝██║   ██║█████╗  ███████╗   ██║   ██████╔╝██║   ║
║   ██╔═══╝ ██║   ██║██╔══╝  ╚════██║   ██║   ██╔═══╝ ██║   ║
║   ██║     ╚██████╔╝███████╗███████║   ██║   ██║     ██║   ║
║   ╚═╝      ╚═════╝ ╚══════╝╚══════╝   ╚═╝   ╚═╝     ╚═╝   ║
║                                                              ║
║   ██████╗ ██████╗ ███████╗██████╗ ██████╗ ███████╗██████╗   ║
║   ██╔══██╗██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗  ║
║   ██████╔╝██████╔╝█████╗  ██████╔╝██████╔╝█████╗  ██████╔╝  ║
║   ██╔═══╝ ██╔═══╝ ██╔══╝  ██╔═══╝ ██╔═══╝ ██╔══╝  ██╔═══╝   ║
║   ██║     ██║     ███████╗██║     ██║     ███████╗██║       ║
║   ╚═╝     ╚═╝     ╚══════╝╚═╝     ╚═╝     ╚══════╝╚═╝       ║
║                                                              ║
║   {C.G}P R O  v3.0{C.C}  ─  {C.W}Context-Aware XSS Scanner{C.C}             ║
║                                                              ║
║   {C.D}Author : Elshan Mammadov{C.C}                               ║
║   {C.D}In     : https://www.linkedin.com/in/elshanmammadoov/{C.C}  ║
║   {C.D}GitHub : https://github.com/elshanmammadoov{C.C}           ║
╚══════════════════════════════════════════════════════════════╝{C.RST}
"""

# ─── XSS PAYLOADS ─────────────────────────────────────────
PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<script>alert(1)</script>",
    "<script>alert(document.cookie)</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>",
    "<svg onload=alert(1)>",
    "<body onload=alert('XSS')>",
    "<input onfocus=alert('XSS') autofocus>",
    "<select onfocus=alert('XSS') autofocus>",
    "<textarea onfocus=alert('XSS') autofocus>",
    "<marquee onstart=alert('XSS')>",
    "<details open ontoggle=alert(1)>",
    "<video onerror=alert(1)><source>",
    "<audio onerror=alert(1)><source>",
    "<embed src=x onerror=alert(1)>",
    "<object data=x onerror=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    "<form onsubmit=alert(1)><input type=submit>",
    "javascript:alert(1)",
    "javascript:alert(document.domain)",
    "data:text/html,<script>alert(1)</script>",
    "\" onmouseover=alert(1) x=\"",
    "' onmouseover=alert(1) x='",
    "\" autofocus onfocus=alert(1) x=\"",
    "' autofocus onfocus=alert(1) x='",
    "<svg/onload='alert(1)'>",
    "<script>a='al'+'ert';a(1)</script>",
    "<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>",
    "<ScRiPt>alert(1)</sCrIpT>",
    "<SCRIPT>alert(1)</SCRIPT>",
]

# ─── CONTEXT-AWARE XSS DETECTOR ───────────────────────────
class XSSContextAnalyzer:
    """
    Analyzes WHERE the payload appears in the response.
    This is what separates real detection from garbage.
    """
    
    @staticmethod
    def find_reflection_context(response_text, payload):
        """
        Find all occurrences of payload in response.
        Returns list of (position, context_type, exploitability).
        """
        findings = []
        search_text = response_text
        
        # Try multiple encodings of the payload
        variants = [
            ('raw', payload),
            ('url_encoded', urllib.parse.quote(payload)),
            ('html_encoded', html.escape(payload)),
            ('double_encoded', urllib.parse.quote(urllib.parse.quote(payload))),
        ]
        
        for variant_name, variant_payload in variants:
            idx = search_text.find(variant_payload)
            if idx == -1:
                continue
            
            # Get surrounding context (50 chars before and after)
            start = max(0, idx - 50)
            end = min(len(search_text), idx + len(variant_payload) + 50)
            context = search_text[start:end]
            
            # Analyze the context
            context_type, exploitability = XSSContextAnalyzer.analyze_context(
                search_text, idx, len(variant_payload), context
            )
            
            findings.append({
                'variant': variant_name,
                'payload': variant_payload,
                'position': idx,
                'context': context_type,
                'exploitability': exploitability,
                'context_snippet': context
            })
        
        return findings
    
    @staticmethod
    def analyze_context(full_text, pos, payload_len, snippet):
        """
        Determine the HTML context where payload appears.
        Returns (context_type, exploitability_score).
        """
        before = full_text[max(0, pos-100):pos]
        after = full_text[pos+payload_len:min(len(full_text), pos+payload_len+100)]
        
        # 1. Inside HTML comment → NOT EXPLOITABLE
        if re.search(r'<!--.*?' + re.escape(snippet[:30]), full_text, re.DOTALL):
            return ('HTML Comment', 0)
        
        # 2. Inside a <script> tag → HIGHLY EXPLOITABLE
        script_pattern = r'<script[^>]*>(.*?)</script>'
        for match in re.finditer(script_pattern, full_text, re.DOTALL | re.IGNORECASE):
            if match.start() <= pos <= match.end():
                return ('JavaScript Context (Script Tag)', 9)
        
        # 3. Inside an event handler attribute → HIGHLY EXPLOITABLE
        event_handlers = [
            'onclick', 'onmouseover', 'onmouseout', 'onmousedown', 'onmouseup',
            'onkeydown', 'onkeyup', 'onkeypress', 'onfocus', 'onblur',
            'onchange', 'onsubmit', 'onload', 'onerror', 'onresize',
            'onscroll', 'oncontextmenu', 'ondrag', 'onpaste'
        ]
        for handler in event_handlers:
            # Check if payload appears right after an event handler
            pattern = handler + r'\s*=\s*["\']?' + re.escape(snippet[:20])
            if re.search(pattern, before, re.IGNORECASE):
                return (f'Event Handler Attribute ({handler})', 9)
        
        # 4. Inside a regular HTML attribute → MODERATELY EXPLOITABLE
        attr_pattern = r'<[^>]+\s+\w+\s*=\s*["\'][^"\']*'
        if re.search(attr_pattern, before):
            return ('HTML Attribute Value', 7)
        
        # 5. Inside JavaScript inline (onclick="...") → HIGHLY EXPLOITABLE
        js_inline = re.findall(r'on\w+\s*=\s*["\']([^"\']+)["\']', full_text)
        for js_code in js_inline:
            if snippet[:30] in js_code:
                return ('Inline JavaScript', 9)
        
        # 6. Inside <style> tag → LOW EXPLOITABILITY (CSS injection)
        style_pattern = r'<style[^>]*>(.*?)</style>'
        for match in re.finditer(style_pattern, full_text, re.DOTALL | re.IGNORECASE):
            if match.start() <= pos <= match.end():
                return ('CSS Context', 3)
        
        # 7. Inside HTML body/text content → HIGHLY EXPLOITABLE
        body_pattern = r'<body[^>]*>(.*?)</body>'
        for match in re.finditer(body_pattern, full_text, re.DOTALL | re.IGNORECASE):
            if match.start() <= pos <= match.end():
                return ('HTML Body Content', 9)
        
        # 8. Inside a tag name or attribute name → MODERATE
        tag_pattern = r'<\w+[^>]*>'
        for match in re.finditer(tag_pattern, full_text):
            if match.start() <= pos <= match.end():
                return ('HTML Tag Structure', 6)
        
        # 9. Inside HTML entity-encoded text → NOT EXPLOITABLE
        if '&lt;' in snippet or '&gt;' in snippet or '&amp;' in snippet:
            return ('HTML Entity Encoded', 0)
        
        # 10. Default: reflected in unknown context → MODERATE
        return ('Unknown Context (Manual Review Needed)', 5)
    
    @staticmethod
    def check_waf(response_text):
        """Detect if a WAF is blocking payloads."""
        waf_signs = [
            'cloudflare', 'incapsula', 'akamai', 'imperva',
            'access denied', 'forbidden', 'blocked',
            'security violation', 'mod_security', 'web application firewall'
        ]
        text_lower = response_text.lower()
        for sign in waf_signs:
            if sign in text_lower:
                return True, sign
        return False, None


# ─── HTTP REQUEST ENGINE ───────────────────────────────────
class HTTPEngine:
    def __init__(self):
        self.ctx = ssl.create_default_context()
        self.ctx.check_hostname = False
        self.ctx.verify_mode = ssl.CERT_NONE
        self.session_cookies = {}
    
    def request(self, url, payload="", method="GET", data=None):
        """Send HTTP request with payload injection."""
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate, br',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1',
                'Cache-Control': 'no-cache',
            }
            
            test_url = url
            
            if payload and method == "GET":
                parsed = urllib.parse.urlparse(url)
                params = urllib.parse.parse_qs(parsed.query)
                if params:
                    for key in params:
                        params[key] = [payload]
                    new_query = urllib.parse.urlencode(params, doseq=True)
                    test_url = urllib.parse.urlunparse(parsed._replace(query=new_query))
                else:
                    sep = '&' if '?' in url else '?'
                    test_url = f"{url}{sep}test={urllib.parse.quote(payload)}"
            
            req = urllib.request.Request(
                test_url if method == "GET" else url,
                data=data.encode() if data else None,
                headers=headers,
                method=method
            )
            
            with urllib.request.urlopen(req, timeout=15, context=self.ctx) as resp:
                body = resp.read().decode('utf-8', errors='ignore')
                status = resp.status
                return body, status, dict(resp.headers)
                
        except urllib.error.HTTPError as e:
            body = e.read().decode('utf-8', errors='ignore') if e.fp else ""
            return body, e.code, dict(e.headers)
        except Exception as e:
            return None, None, str(e)


# ─── MAIN SCANNER ─────────────────────────────────────────
class XSSScannerPro:
    def __init__(self):
        self.http = HTTPEngine()
        self.analyzer = XSSContextAnalyzer()
        self.vulnerabilities = []
        self.total_tests = 0
        self.waf_detected = False
        self.waf_name = ""
    
    def log(self, msg, level='info'):
        symbols = {'info': '[i]', 'vuln': '[!]', 'ok': '[+]', 'warn': '[?]', 'scan': '[*]'}
        colors = {
            'info': C.B, 'vuln': C.R + C.BOLD, 'ok': C.G,
            'warn': C.Y, 'scan': C.C
        }
        clr = colors.get(level, C.W)
        sym = symbols.get(level, '[*]')
        print(f"{clr}{sym} {msg}{C.RST}")
    
    def validate_url(self, url):
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        parsed = urllib.parse.urlparse(url)
        if not parsed.netloc or '.' not in parsed.netloc:
            return None
        return url
    
    def scan_target(self, target_url):
        """Main scanning workflow."""
        print(BANNER)
        
        # Validate
        target_url = self.validate_url(target_url)
        if not target_url:
            self.log("Yanlış URL formatı! Nümunə: https://example.com", 'vuln')
            return
        
        self.log(f"Hədəf: {target_url}", 'scan')
        self.log(f"Tarix: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", 'scan')
        self.log(f"Payload sayı: {len(PAYLOADS)}", 'scan')
        print()
        
        # Phase 0: Connectivity check
        self.log("Hədəfə qoşulma yoxlanılır...", 'info')
        body, status, headers = self.http.request(target_url)
        
        if body is None:
            self.log(f"Qoşulma uğursuz! Xəta: {headers}", 'vuln')
            return
        
        self.log(f"Hədəf cavab verdi — HTTP {status}, {len(body)} bayt", 'ok')
        
        # Check for WAF
        waf_found, waf_name = self.analyzer.check_waf(body)
        if waf_found:
            self.waf_detected = True
            self.waf_name = waf_name
            self.log(f"WAF aşkar edildi: {waf_name} — bəzi payload'lar bloklanacaq", 'warn')
        
        print()
        
        # Phase 1: URL parameter scanning
        self.log("=" * 64, 'info')
        self.log("MƏRHƏLƏ 1: URL Parametrləri", 'scan')
        self.log("=" * 64, 'info')
        print()
        self.scan_url_params(target_url)
        
        # Phase 2: Form discovery and testing
        self.log("")
        self.log("=" * 64, 'info')
        self.log("MƏRHƏLƏ 2: Formlar", 'scan')
        self.log("=" * 64, 'info')
        print()
        self.scan_forms(target_url)
        
        # Phase 3: Header injection
        self.log("")
        self.log("=" * 64, 'info')
        self.log("MƏRHƏLƏ 3: HTTP Header'lər", 'scan')
        self.log("=" * 64, 'info')
        print()
        self.scan_headers(target_url)
        
        # Final report
        self.print_report(target_url)
    
    def scan_url_params(self, url):
        """Test GET parameters with context analysis."""
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        
        if not params:
            self.log("URL-də parametr yoxdur, test parametrləri əlavə edilir...", 'warn')
            params = {'q': 'test', 'search': 'test', 'id': '1', 'page': '1'}
        
        self.log(f"{len(params)} parametr tapıldı, {len(PAYLOADS)} payload test edilir...", 'info')
        print()
        
        for param_name in params:
            for i, payload in enumerate(PAYLOADS, 1):
                self.total_tests += 1
                
                # Show progress
                sys.stdout.write(
                    f"\r{C.C}Test: {param_name} → Payload {i}/{len(PAYLOADS)}{C.RST}     "
                )
                sys.stdout.flush()
                
                body, status, _ = self.http.request(url, payload, method="GET")
                
                if body:
                    findings = self.analyzer.find_reflection_context(body, payload)
                    
                    for finding in findings:
                        if finding['exploitability'] >= 7:
                            self.vulnerabilities.append({
                                'type': 'Reflected XSS (URL Param)',
                                'param': param_name,
                                'payload': finding['payload'][:80],
                                'context': finding['context'],
                                'score': finding['exploitability'],
                                'url': url
                            })
                            print()  # newline after progress
                            self.log(
                                f"VULNERABLE! Param='{param_name}' | "
                                f"Context={finding['context']} | "
                                f"Score={finding['exploitability']}/10",
                                'vuln'
                            )
                            self.log(f"Payload: {finding['payload'][:70]}", 'vuln')
                            break
                
                time.sleep(random.uniform(0.03, 0.08))
        
        print()  # newline
    
    def scan_forms(self, url):
        """Discover forms and test them."""
        self.log("Formlar aşkar edilir...", 'info')
        
        body, status, _ = self.http.request(url)
        if not body:
            self.log("Sayt yüklənmədi, form skanı keçilir.", 'warn')
            return
        
        # Simple form extraction
        forms = re.findall(
            r'<form[^>]*action=["\']?([^"\'\s>]*)["\']?[^>]*method=["\']?(\w+)["\']?[^>]*>(.*?)</form>',
            body, re.DOTALL | re.IGNORECASE
        )
        
        if not forms:
            self.log("Saytda form tapılmadı.", 'warn')
            return
        
        self.log(f"{len(forms)} form tapıldı!", 'ok')
        print()
        
        for idx, (action, method, form_body) in enumerate(forms, 1):
            self.log(f"Form #{idx} test edilir (method={method.upper()})...", 'scan')
            
            # Extract input names
            inputs = re.findall(r'<input[^>]*name=["\']?([^"\'\s>]*)', form_body, re.IGNORECASE)
            inputs += re.findall(r'<textarea[^>]*name=["\']?([^"\'\s>]*)', form_body, re.IGNORECASE)
            
            if not inputs:
                self.log("Formda input yoxdur, keçilir.", 'warn')
                continue
            
            # Test first few inputs with subset of payloads
            test_inputs = inputs[:3]
            test_payloads = random.sample(PAYLOADS, min(20, len(PAYLOADS)))
            
            for input_name in test_inputs:
                for i, payload in enumerate(test_payloads, 1):
                    self.total_tests += 1
                    
                    sys.stdout.write(
                        f"\r{C.C}Form #{idx} → {input_name} → Payload {i}/{len(test_payloads)}{C.RST}     "
                    )
                    sys.stdout.flush()
                    
                    # Build POST data
                    post_data = {inp: payload for inp in test_inputs}
                    data_encoded = urllib.parse.urlencode(post_data)
                    
                    body_resp, status, _ = self.http.request(
                        url, payload, method="POST", data=data_encoded
                    )
                    
                    if body_resp:
                        findings = self.analyzer.find_reflection_context(body_resp, payload)
                        
                        for finding in findings:
                            if finding['exploitability'] >= 7:
                                self.vulnerabilities.append({
                                    'type': f'Reflected XSS (Form {method.upper()})',
                                    'param': input_name,
                                    'payload': finding['payload'][:80],
                                    'context': finding['context'],
                                    'score': finding['exploitability'],
                                    'url': url
                                })
                                print()
                                self.log(
                                    f"VULNERABLE! Form={method.upper()} | "
                                    f"Input='{input_name}' | "
                                    f"Context={finding['context']}",
                                    'vuln'
                                )
                                break
                    
                    time.sleep(random.uniform(0.03, 0.08))
            
            print()
    
    def scan_headers(self, url):
        """Test XSS in HTTP headers."""
        self.log("HTTP Header'lərdə XSS yoxlanılır...", 'info')
        print()
        
        header_payloads = [
            ('User-Agent', '<script>alert(1)</script>'),
            ('Referer', '<script>alert(1)</script>'),
            ('X-Forwarded-For', '<img src=x onerror=alert(1)>'),
            ('X-Originating-IP', '<svg onload=alert(1)>'),
        ]
        
        for header_name, payload in header_payloads:
            self.total_tests += 1
            self.log(f"Header test: {header_name}", 'scan')
            
            try:
                headers = {
                    'User-Agent': 'Mozilla/5.0',
                    header_name: payload
                }
                req = urllib.request.Request(url, headers=headers)
                
                with urllib.request.urlopen(req, timeout=10, context=self.http.ctx) as resp:
                    body = resp.read().decode('utf-8', errors='ignore')
                    
                    if payload in body or urllib.parse.quote(payload) in body:
                        self.log(f"VULNERABLE! Header '{header_name}' reflects payload!", 'vuln')
                        self.vulnerabilities.append({
                            'type': 'Reflected XSS (HTTP Header)',
                            'param': header_name,
                            'payload': payload[:80],
                            'context': 'HTTP Header Reflection',
                            'score': 8,
                            'url': url
                        })
            except Exception as e:
                self.log(f"Header test xətası: {e}", 'warn')
            
            time.sleep(0.1)
        
        print()
    
    def print_report(self, target_url):
        """Print final scan report."""
        print()
        print(f"{C.BOLD}{'═' * 64}{C.RST}")
        print(f"{C.BOLD}  SKAN TAMAMLANDI — NƏTİCƏ{C.RST}")
        print(f"{C.BOLD}{'═' * 64}{C.RST}")
        print()
        print(f"  Hədəf URL    : {C.Y}{target_url}{C.RST}")
        print(f"  Ümumi test   : {C.W}{self.total_tests}{C.RST}")
        print(f"  Zəiflik sayı : {C.R if self.vulnerabilities else C.G}{len(self.vulnerabilities)}{C.RST}")
        print(f"  Tarix        : {C.D}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{C.RST}")
        print()
        
        if self.vulnerabilities:
            print(f"{C.R}{C.BOLD}  ⚠️  {len(self.vulnerabilities)} XSS ZƏİFLİYİ AŞKAR EDİLDİ!{C.RST}")
            print()
            
            for idx, vuln in enumerate(self.vulnerabilities, 1):
                print(f"  {C.R}┌─ Zəiflik #{idx}{C.RST}")
                print(f"  {C.R}│{C.RST} Növ        : {C.Y}{vuln['type']}{C.RST}")
                print(f"  {C.R}│{C.RST} Parametr   : {C.W}{vuln['param']}{C.RST}")
                print(f"  {C.R}│{C.RST} Kontekst   : {C.W}{vuln['context']}{C.RST}")
                print(f"  {C.R}│{C.RST} Təhlükə    : {C.R}{vuln['score']}/10{C.RST}")
                print(f"  {C.R}│{C.RST} Payload    : {C.D}{vuln['payload'][:70]}{C.RST}")
                print(f"  {C.R}└{'─' * 50}{C.RST}")
                print()
        else:
            print(f"{C.G}{C.BOLD}  ✓ XSS ZƏİFLİYİ AŞKAR EDİLMƏDİ{C.RST}")
            print()
            print(f"  {C.D}Sayt təhlükəsiz görünür. Amma bu 100% təmin etmir.")
            print(f"  Bəzi XSS flaw'ları xüsusi şərtlər və ya autentifikasiya")
            print(f"  tələb edir. Əlavə manual yoxlama tövsiyə olunur.{C.RST}")
            print()
        
        print(f"{C.BOLD}{'═' * 64}{C.RST}")
        print(f"{C.D}  xssscannerpro by Elshan Mammadov{C.RST}")
        print(f"{C.D}  LinkedIn: https://www.linkedin.com/in/elshanmammadoov/{C.RST}")
        print(f"{C.D}  GitHub  : https://github.com/elshanmammadoov{C.RST}")
        print(f"{C.BOLD}{'═' * 64}{C.RST}")
        print()


# ─── ENTRY POINT ──────────────────────────────────────────
def main():
    print(BANNER)
    
    # Get target URL
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        try:
            target = input(f"{C.G}[?] Hədəf URL daxil edin: {C.RST}").strip()
        except KeyboardInterrupt:
            print(f"\n\n{C.Y}[!] Skan ləğv edildi.{C.RST}")
            sys.exit(0)
    
    if not target:
        print(f"{C.R}[!] URL daxil edilmədi!{C.RST}")
        sys.exit(1)
    
    scanner = XSSScannerPro()
    scanner.scan_target(target)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{C.Y}[!] Skan dayandırıldı.{C.RST}")
        sys.exit(0)
