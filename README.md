# XSSScannerPro v4.0

Advanced Precision Context-Aware XSS Vulnerability Scanner designed for penetration testers and security researchers.

## Features
- **Precision Context-Aware Analysis:** Evaluates exact HTML/JS contexts (Comments, Script tags, Attributes, Event handlers) to drastically reduce false positives.
- **Multi-Vector Scanning:** 
  - URL Parameters (GET)
  - Forms (GET/POST)
  - HTTP Headers (User-Agent, Referer, X-Forwarded-For, etc.)
- **WAF Detection:** Automatically detects Web Application Firewalls.

## Installation & Setup

Run the following commands in your terminal to install and make it globally accessible:

```bash
git clone [https://github.com/elshanmammadoov/xssscannerpro.git](https://github.com/elshanmammadoov/xssscannerpro.git)
cd xssscannerpro
chmod +x xssscannerpro.py
cp xssscannerpro.py /usr/local/bin/xssscannerpro

Usage
After global installation, you can run the tool from anywhere in your terminal:

Bash
xssscannerpro
Or pass the target directly:

Bash
xssscannerpro [https://example.com](https://example.com)
Author
Elshan Mammadov

LinkedIn: elshanmammadoov

GitHub: elshanmammadoov
