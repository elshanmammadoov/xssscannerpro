# XSS Scanner PRO (v9.2)

Advanced, asynchronous, and multi-vector XSS (Cross-Site Scripting) vulnerability scanner built with Python. Designed for security professionals and penetration testers to automatically discover Reflected, Stored, and DOM-based XSS flaws while effectively filtering out false positives.

## Features

- **Asynchronous Engine**: Powered by `asyncio` and `aiohttp` for fast, concurrent scanning.
- **Smart Crawler**: Automatically discovers endpoints, parameters, and HTML forms.
- **Multi-Vector Testing**: 
  - Reflected XSS (GET parameters & body vectors)
  - Stored / Form-based XSS (POST/GET forms)
  - DOM-based XSS (URL fragment manipulation)
- **False Positive Filter**: Analyzes HTML response contexts to eliminate false positives (checks meta tags, comments, entity encoding, and active script execution contexts).
- **WAF Detection**: Automatically identifies common Web Application Firewalls (Cloudflare, AWS WAF, Akamai, etc.).
- **JSON Reporting**: Saves detailed scan results into a structured JSON file.

## Installation

```bash
# Clone the repository
git clone [https://github.com/elshanmammadoov/xssscannerpro.git](https://github.com/elshanmammadoov/xssscannerpro.git)
cd xssscannerpro

# Install dependencies
pip install aiohttp beautifulsoup4

# Make it globally accessible (optional)
sudo cp xssscannerpro /usr/local/bin/xssscannerpro
sudo chmod +x /usr/local/bin/xssscannerpro


-----------------------------------------------------------------------------------------|
Usage
Run the scanner directly against a target URL:
--
Bash
xssscannerpro [https://example.com](https://example.com)
Or save the results to a specific JSON file:
-----------------------------------------------------------------------------------------|
Bash
python3 xssscannerpro [https://example.com](https://example.com) --json report.json
-----------------------------------------------------------------------------------------|
