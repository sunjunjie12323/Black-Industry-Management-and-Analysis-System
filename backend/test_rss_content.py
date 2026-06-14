import urllib.request
import socket
import ssl
import re

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
socket.setdefaulttimeout(10)

working_urls = [
    ("FreeBuf", "https://www.freebuf.com/feed"),
    ("XianZhi", "https://xz.aliyun.com/feed"),
    ("Sihou", "https://www.4hou.com/feed"),
    ("Aqniu", "https://www.aqniu.com/feed"),
    ("Tencent", "https://s.tencent.com/feed"),
    ("SecPulse", "https://www.secpulse.com/feed"),
]

for name, url in working_urls:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (ThreatIntelBot)"})
        with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
            body = resp.read().decode('utf-8', errors='replace')
            # Check for items
            item_count = body.count("<item>")
            title_match = re.findall(r'<title>(?:<!\[CDATA\[)?(.*?)(?:\]\]>)?</title>', body, re.DOTALL)
            print(f"OK  {name}: items={item_count} titles={len(title_match)}")
            for t in title_match[:3]:
                clean = re.sub(r'\s+', ' ', t).strip()[:80]
                print(f"     - {clean}")
    except Exception as e:
        print(f"ERR {name}: {e}")
