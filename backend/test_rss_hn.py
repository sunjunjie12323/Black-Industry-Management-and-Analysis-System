import urllib.request
import socket
import ssl
import re

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
socket.setdefaulttimeout(10)

for name, url in [
    ("HN top", "https://hnrss.org/frontpage"),
    ("HN best", "https://hnrss.org/best"),
    ("4hou atom", "https://www.4hou.com/atom"),
    ("Chaox content", "https://www.chaox.io/"),
    ("52pojie", "https://www.52pojie.cn/"),
    ("ai-sec", "https://www.aisec.com/"),
]:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
            body = resp.read().decode('utf-8', errors='replace')
            titles = re.findall(r'<title(?: [^>]*)?>(?:<!\[CDATA\[)?(.*?)(?:\]\]>)?</title>', body, re.DOTALL)
            print(f"=== {name} === ({len(titles)} titles)")
            for t in titles[:6]:
                clean = re.sub(r'\s+', ' ', t).strip()[:120]
                print(f"  - {clean}")
    except Exception as e:
        print(f"ERR {name}: {e}")
