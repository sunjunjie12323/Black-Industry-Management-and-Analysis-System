import urllib.request
import socket
import ssl
import sys

urls = [
    ("FreeBuf", "https://www.freebuf.com/feed"),
    ("Anquanke", "https://www.anquanke.com/feed"),
    ("XianZhi", "https://xz.aliyun.com/feed"),
    ("4hou", "https://www.4hou.com/feed.php"),
    ("RSSHub Baidu", "https://rsshub.app/baidu/search/网络安全"),
    ("RSSHub NVD", "https://rsshub.app/nvd/recent"),
    ("Kanxue", "https://bbs.kanxue.com/feed"),
    ("Aqniu", "https://www.aqniu.com/feed"),
    ("Tencent", "https://s.tencent.com/feed"),
    ("Aliyun dev", "https://developer.aliyun.com/feed"),
]

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

socket.setdefaulttimeout(10)

for name, url in urls:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (ThreatIntelBot)"})
        with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
            body = resp.read()
            print(f"OK  {name}: HTTP {resp.status} {len(body)} bytes  -  {url}")
    except Exception as e:
        print(f"ERR {name}: {type(e).__name__}: {e}  -  {url}")

print("Done.")
