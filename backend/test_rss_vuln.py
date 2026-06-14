import urllib.request
import socket
import ssl
import re

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
socket.setdefaulttimeout(10)

urls = [
    ("aliyun vuln", "https://avd.aliyun.com/json/list"),
    ("aliyun api", "https://api.aliyun.com/api/cve/2024-06-25/ListCves"),
    ("cnnvd", "http://www.cnnvd.org.cn/"),
    ("CNVD", "https://www.cnvd.org.cn/"),
    ("QQ vuln", "https://vuln.qq.com/"),
    ("qihoo vuln", "https://vul.qihoo.net/"),
    ("threatbook", "https://www.threatbook.io/"),
    ("ThreatBook lab", "https://lab.threatbook.io/"),
    ("ThreatBook blog", "https://blog.threatbook.io/"),
    ("nsfocus", "https://www.nsfocus.com.cn/"),
    ("venustech", "https://www.venustech.com.cn/"),
    ("dbappsecurity", "https://www.dbappsecurity.com.cn/"),
    ("Knownsec", "https://www.knownsec.com/"),
    ("knownsec blog", "https://blog.knownsec.com/feed/"),
    ("qihoo blog", "https://blogs.360.cn/"),
    ("qihoo blog rss", "https://blogs.360.cn/feed/"),
    ("qihoo rss alt", "https://blog.360.cn/feed"),
    ("qihoo rss alt2", "https://www.360.cn/rss/"),
    ("aliyun insight", "https://xz.aliyun.com/feed"),
    ("ZhiShi", "https://www.zhishi.com/"),
    ("freebuf api", "https://www.freebuf.com/fapi/getArticleList"),
    ("kanxue feed", "https://bbs.kanxue.com/forum-72-1.html"),
    ("XCTF", "https://www.xctf.org.cn/"),
    ("sankuai", "https://sankuai.com/"),
    ("Netease cve", "https://news.163.com/special/00011K6L/rss_security.xml"),
]

for name, url in urls:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
            body = resp.read().decode('utf-8', errors='replace')
            items = body.count("<item>") + body.count("<entry>")
            print(f"OK  {name}: HTTP {resp.status} {len(body)}b items={items}  -  {url[:60]}")
    except Exception as e:
        msg = str(e)[:60]
        print(f"ERR {name}: {type(e).__name__}: {msg}")
