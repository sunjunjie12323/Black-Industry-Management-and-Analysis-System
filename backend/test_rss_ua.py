import urllib.request
import socket
import ssl

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
socket.setdefaulttimeout(15)

ua_options = [
    "curl/7.88.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "FeedBurner/1.0",
    "UniversalFeedParser/5.0.1 +https://github.com/kurtmckee/feedparser",
]

for ua in ua_options:
    print(f"=== User-Agent: {ua} ===")
    try:
        req = urllib.request.Request("https://www.freebuf.com/feed", headers={"User-Agent": ua})
        with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
            body = resp.read().decode('utf-8', errors='replace')
            print(f"size={len(body)}")
            print(body[:500])
    except Exception as e:
        print(f"ERR: {type(e).__name__}: {str(e)[:200]}")
    print("---")
