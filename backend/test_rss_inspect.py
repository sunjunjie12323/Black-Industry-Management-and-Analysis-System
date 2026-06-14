import urllib.request
import socket
import ssl

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
socket.setdefaulttimeout(10)

for name, url in [
    ("Anquanke atom", "https://www.anquanke.com/?type=atom"),
    ("Sitemap", "https://www.anquanke.com/sitemap.xml"),
]:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
            body = resp.read().decode('utf-8', errors='replace')
            print(f"=== {name} ===")
            print(body[:1500])
            print("---")
    except Exception as e:
        print(f"ERR {name}: {e}")
