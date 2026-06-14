import urllib.request
import socket
import ssl
import re

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
socket.setdefaulttimeout(10)

urls = [
    ("avd feed", "https://avd.aliyun.com/feed"),
    ("avd rss", "https://avd.aliyun.com/rss"),
    ("avd news", "https://avd.aliyun.com/news/feed"),
    ("avd api", "https://avd.aliyun.com/feeds/recent"),
    ("avd atom", "https://avd.aliyun.com/atom.xml"),
    ("avd list", "https://avd.aliyun.com/highlight/list.htm"),
    ("aliyun insight api", "https://xz.aliyun.com/api/articles"),
    ("aliyun forum", "https://xz.aliyun.com/forum"),
    ("aliyun topics", "https://xz.aliyun.com/topic/feed"),
    ("aliyun vuln feed", "https://avd.aliyun.com/feed/recent"),
    ("NSFocus feed", "https://www.nsfocus.com.cn/rss"),
    ("NSFocus rss", "https://www.nsfocus.com.cn/feed"),
    ("CVE feed", "https://cve.mitre.org/data/downloads/allitems.xml"),
    ("NVD cvss", "https://nvd.nist.gov/download/nvdcve-CVE-Recent.json"),
    ("exploit-db", "https://www.exploit-db.com/rss"),
    ("packet storm", "https://rss.packetstormsecurity.com/"),
    ("VulnCheck", "https://vulncheck.com/rss"),
    ("CVE Details", "https://www.cvedetails.com/rss"),
    ("Cisco Talos", "https://talosintelligence.com/vulnerability_recently_rss"),
    ("JPCERT", "https://www.jpcert.or.jp/english/at/"),
    ("JPCERT feed", "https://www.jpcert.or.jp/rss/"),
    ("JPCERT news", "https://www.jpcert.or.jp/newsflash/"),
    ("CERT China", "http://www.cert.org.cn/publish/main/index.html"),
    ("Venustech news", "https://www.venustech.com.cn/news/"),
    ("Sangfor", "https://www.sangfor.com.cn/"),
    ("VulBox", "https://www.vulbox.com/"),
    ("SecurityWeek", "https://www.securityweek.com/rss"),
    ("DarkReading", "https://www.darkreading.com/rss.xml"),
    ("TheRecord", "https://therecord.media/feed/"),
    ("SecSrv", "https://www.securingsam.com/feed"),
    ("TheHackerNews alt", "https://thehackernews.com/feed/"),
    ("Bleeping alt", "https://www.bleepingcomputer.com/feed/"),
    ("Bleeping new", "https://www.bleepstatic.com/feed/"),
    ("Krebs new", "https://krebsonsecurity.com/feed/"),
    ("malwarebytes labs", "https://www.malwarebytes.com/blog/feed/"),
    ("Talos blog", "https://blog.talosintelligence.com/feeds/posts/default"),
    ("Trend Micro", "https://feeds.trendmicro.com/TM-SecurityNews/"),
    ("Sophos", "https://news.sophos.com/en-us/feed/"),
    ("Rapid7", "https://blog.rapid7.com/rss/"),
    ("Crowdstrike", "https://www.crowdstrike.com/blog/feed/"),
    ("Mandiant", "https://www.mandiant.com/feed/"),
    ("SANS", "https://isc.sans.edu/rssfeed_full.xml"),
    ("SANS alt", "https://www.sans.org/feeds/"),
    ("Schneier", "https://www.schneier.com/feed/"),
    ("Ars Technica", "https://feeds.arstechnica.com/arstechnica/security/"),
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
