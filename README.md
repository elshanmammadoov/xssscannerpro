# XSSScannerPro

**Enterprise-Grade Precision XSS, SQLi & WAF-Bypass Scanner**

---

## 📦 Installation

Clone the repository and enter the project directory:

```bash
git clone https://github.com/elshanmammadoov/xssscannerpro.git
cd xssscannerpro
```

Make the scanner executable:

```bash
chmod +x scanner.py
```

Install it globally:

```bash
sudo cp scanner.py /usr/local/bin/xssscannerpro
```

Verify the installation:

```bash
xssscannerpro --help
```

---

## 🚀 Usage

### Basic Scan (GET)

```bash
xssscannerpro https://example.com/page.php?id=1
```

### Multi-threaded Scan

```bash
xssscannerpro https://example.com/page.php?id=1 -t 30
```

### POST Request

```bash
xssscannerpro https://example.com/login.php \
  --method POST \
  --data "username=test&password=test"
```

### Save Results to JSON

```bash
xssscannerpro https://example.com/login.php \
  --method POST \
  --data "username=test&password=test" \
  --output report.json
```

### Interactive Mode

```bash
xssscannerpro
```

If no URL is provided, the scanner will prompt you to enter one.

---

## ⚙️ Command-Line Options

|        Option        |              Description                         |
| :--------------------|:-------------------------------------------------|
| `url`  | Target URL. | If omitted, interactive mode is started.         |
| `-t`, `--threads`    | Number of concurrent threads (default: `15`).    |
| `--method`           | HTTP method (`GET` or `POST`). Default: `GET`.   |
| `--data`             | POST request body (e.g. `"user=admin&pass=123"`) |
| `-o`, `--output`     | Save scan results to a JSON file.                |

---

## ⚠️ Disclaimer

This tool is intended **only for authorized security testing and educational purposes**.

Do **not** use it against systems you do not own or do not have explicit permission to test.
