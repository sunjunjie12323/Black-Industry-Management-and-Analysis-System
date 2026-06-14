import urllib.request
import socket
import ssl

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
socket.setdefaulttimeout(10)

urls = [
    ("FreeBuf api", "https://www.freebuf.com/api/rss"),
    ("FreeBuf article", "https://www.freebuf.com/articles/rss"),
    ("FreeBuf new", "https://www.freebuf.com/rss.xml"),
    ("FreeBuf json", "https://www.freebuf.com/api/articles"),
    ("Anquanke search", "https://www.anquanke.com/api/articles"),
    ("Anquanke rss.php", "https://www.anquanke.com/?type=atom"),
    ("Anquanke sitemap", "https://www.anquanke.com/sitemap.xml"),
    ("xianzhi API", "https://xz.aliyun.com/api/articles"),
    ("xianzhi atom", "https://xz.aliyun.com/atom.xml"),
    ("4hou rss2", "https://www.4hou.com/feed/"),
    ("4hou atom", "https://www.4hou.com/atom"),
    ("4hou news rss", "https://www.4hou.com/feed/news"),
]

for name, url in urls:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
            body = resp.read().decode('utf-8', errors='replace')
            print(f"OK  {name}: HTTP {resp.status} {len(body)}b  -  {url}")
            if len(body) < 1500:
                print("     " + body[:300])
    except Exception as e:
        print(f"ERR {name}: {type(e).__name__}: {str(e)[:80]}")
