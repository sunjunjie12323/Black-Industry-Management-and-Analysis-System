import urllib.request
import socket
import ssl
import sys

urls = [
    ("Anquanke alt", "https://www.anquanke.com/rss.php"),
    ("Anquanke v1", "https://anquanke.com/feed"),
    ("Sihou alt1", "https://www.4hou.com/rss"),
    ("Sihou alt2", "https://4hou.com/feed.php"),
    ("Sihou alt3", "https://www.4hou.com/feed"),
    ("Kanxue alt1", "https://bbs.kanxue.com/rss.php"),
    ("Kanxue alt2", "https://bbs.kanxue.com/rss"),
    ("Kanxue feed", "https://www.kanxue.com/feed"),
    ("Freebuf rss", "https://www.freebuf.com/rss"),
    ("Freebuf backup", "https://www.freebuf.com/feed/"),
    ("Aliyun dev alt", "https://developer.aliyun.com/feed.xml"),
    ("CSDN security", "https://blog.csdn.net/security/community/community-rss"),
    ("Jiankong", "https://www.jiankong.com/feed"),
    ("SecPulse", "https://www.secpulse.com/feed"),
    ("Linuxidc", "https://www.linuxidc.com/feed"),
    ("Anquanke rss.xml", "https://www.anquanke.com/rss.xml"),
    ("Anquanke atom", "https://www.anquanke.com/atom.xml"),
    ("RSShub Bilibili security", "https://rsshub.app/bilibili/followings/dynamic/485456261"),
    ("Sohu Security", "https://www.sohu.com/feed"),
]

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

socket.setdefaulttimeout(8)

for name, url in urls:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (ThreatIntelBot)"})
        with urllib.request.urlopen(req, timeout=8, context=ctx) as resp:
            body = resp.read()
            print(f"OK  {name}: HTTP {resp.status} {len(body)} bytes  -  {url}")
    except Exception as e:
        msg = str(e)
        if len(msg) > 100:
            msg = msg[:100]
        print(f"ERR {name}: {type(e).__name__}: {msg}  -  {url}")

print("Done.")
