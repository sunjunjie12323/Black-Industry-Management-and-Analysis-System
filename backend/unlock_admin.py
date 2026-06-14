import sqlite3
conn = sqlite3.connect(r'c:\Users\sunjunjie\Desktop\vibe coding项目\黑产系统\threat-intel-agent\backend\threat_intel.db')
c = conn.cursor()
c.execute("UPDATE users SET locked_until=NULL, login_fail_count=0 WHERE username='admin'")
conn.commit()
print('Cleared:', c.rowcount)
conn.close()
