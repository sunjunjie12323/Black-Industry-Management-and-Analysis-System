import urllib.request
import socket
import ssl

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
socket.setdefaulttimeout(10)

for name, url in [
    ("FreeBuf", "https://www.freebuf.com/feed"),
    ("Aqniu", "https://www.aqniu.com/feed"),
    ("Tencent", "https://s.tencent.com/feed"),
    ("Jiankong", "https://www.jiankong.com/feed"),
]:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (ThreatIntelBot)"})
        with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
            body = resp.read().decode('utf-8', errors='replace')
            print(f"=== {name} (size={len(body)}) ===")
            print(body[:2000])
            print("---END SAMPLE---")
    except Exception as e:
        print(f"ERR {name}: {e}")
