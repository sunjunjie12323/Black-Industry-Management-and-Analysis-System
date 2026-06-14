import urllib.request
import socket
import ssl

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
socket.setdefaulttimeout(10)

urls = [
    ("v2ex", "https://www.v2ex.com/feed/security.xml"),
    ("ithome sec", "https://www.ithome.com/rss/security.xml"),
    ("oschina sec", "https://www.oschina.net/news/rss?show=time&catalog=29"),
    ("qihoo", "https://www.qihoo.com/rss"),
    ("chinaz", "https://rss.chinaz.com/"),
    ("cnbeta", "https://www.cnbeta.com.tw/backend.php"),
    ("Donews", "https://www.donews.com/feed"),
    ("Freebuf with cookies", "https://www.freebuf.com/feed"),
    ("weibo alert", "https://rsshub.app/weibo/user/6126940125"),
    ("hackernews-cn", "https://hn.algolia.com/api/v1/search_by_date?query=CVE&tags=story"),
    ("osch sec", "https://my.oschina.net/action/blog/rss?catalog=20"),
    ("Sina Security", "https://rss.sina.com.cn/roll/safety/hot.xml"),
    ("Sina Military", "https://rss.sina.com.cn/news/marquee/rolling.xml"),
    ("NetEase Security", "https://news.163.com/special/00011K6L/rss_security.xml"),
    ("QQ Security", "https://rss.qq.com/news.htm"),
    ("Yahoo Sec", "https://tw.news.yahoo.com/rss/security"),
    ("Telegram krebson", "https://t.me/s/krebsonsecurity"),
    ("SecWiki", "https://www.sec-wiki.com/rss"),
    ("SecNews", "https://www.secrss.com/feed"),
    ("CSDN security", "https://blog.csdn.net/xiaofeng_xiao/rss/list"),
    ("toutiao sec", "https://www.toutiao.com/c/user/token/MS4wLjABAAAAdR4t5rJZkF-/"),
]

for name, url in urls:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
            body = resp.read().decode('utf-8', errors='replace')
            items = body.count("<item>") + body.count("<entry>")
            print(f"OK  {name}: HTTP {resp.status} {len(body)}b items={items}")
    except Exception as e:
        msg = str(e)[:80]
        print(f"ERR {name}: {type(e).__name__}: {msg}")
