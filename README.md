# 🛡️ XSS Scanner Pro

> Simple, fast, and concurrent automated XSS vulnerability scanner.

---

## 🚀 Installation & Usage (Linux)

Terminalı açın və aşağıdakı blokları kopyalayıb birbaşa terminala yapışdırın:

```bash
sudo apt update && sudo apt install python3 python3-pip git -y
--------------------------------------------------------------------------------------------------------------------
git clone https://github.com/elshanmammadoov/xssscannerpro.git
--------------------------------------------------------------------------------------------------------------------
cd xssscannerpro
--------------------------------------------------------------------------------------------------------------------
chmod +x xssscannerpro && sudo cp xssscannerpro /usr/local/bin/
--------------------------------------------------------------------------------------------------------------------
(xssscannerpro https://example.com/search?q=test)



-----Options & Argument-----
+--------------------+------------------------------------+--------------------------------+
| Flag               | Description                        | Example                        |
+--------------------+------------------------------------+--------------------------------+
| -t, --threads      | Set parallel threads (Default: 15) | xssscannerpro <url> -t 30      |
| -o, --output       | Save report to a text file         | xssscannerpro <url> -o rep.txt |
+--------------------+------------------------------------+--------------------------------+
