import urllib.request
import socket
import ssl
import re

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
socket.setdefaulttimeout(10)

urls = [
    ("cnbeta", "https://www.cnbeta.com.tw/backend.php"),
    ("donews rss", "https://www.donews.com/rss"),
    ("oschina blog", "https://my.oschina.net/rss"),
    ("oschina all", "https://www.oschina.net/news/rss?show=time"),
    ("v2ex security", "https://v2ex.com/feed/section/security.xml"),
    ("ithome sec", "https://www.ithome.com/rss/security/"),
    ("cnvd", "https://www.cnvd.org.cn/flaw/list.htm"),
    ("4hou atom", "https://www.4hou.com/atom"),
    ("Hacker News top", "https://hnrss.org/frontpage"),
    ("Hacker News best", "https://hnrss.org/best"),
    ("Reddit netsec", "https://www.reddit.com/r/netsec/.rss"),
    ("F-Droid sec", "https://f-droid.org/category/security/feed.xml"),
    ("openwall", "https://www.openwall.com/lists/oss-security/"),
    ("Linux sec", "https://lwn.net/Security/"),
    ("Sohu IT", "https://www.sohu.com/rss/it_2"),
    ("donews all", "https://www.donews.com/rss/"),
    ("RSSHub instant", "https://rsshub.app/"),
    ("Chaox", "https://www.chaox.io/"),
    ("88bug", "https://www.88bug.cn/"),
    ("buuoj", "https://buuoj.cn/"),
    ("Buuctf", "https://buuctf.cn/"),
    ("52pojie", "https://www.52pojie.cn/"),
    ("ai-sec", "https://www.aisec.com/"),
    ("Chuangxin", "https://www.chuangkit.com/feed"),
    ("csdn", "https://blog.csdn.net/rss"),
    ("huxiu", "https://www.huxiu.com/rss/0.xml"),
    ("lieyun", "https://www.lieyunwang.com/"),
]

for name, url in urls:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
            body = resp.read().decode('utf-8', errors='replace')
            items = body.count("<item>") + body.count("<entry>")
            titles = re.findall(r'<title>(?:<!\[CDATA\[)?(.*?)(?:\]\]>)?</title>', body, re.DOTALL)
            print(f"OK  {name}: HTTP {resp.status} {len(body)}b items={items} titles={len(titles)}")
            if 0 < items < 5 and titles:
                for t in titles[:3]:
                    clean = re.sub(r'\s+', ' ', t).strip()[:80]
                    print(f"     - {clean}")
    except Exception as e:
        msg = str(e)[:80]
        print(f"ERR {name}: {type(e).__name__}: {msg}")
