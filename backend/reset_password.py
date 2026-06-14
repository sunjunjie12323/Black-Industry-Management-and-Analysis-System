import sqlite3
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

new_password = "admin123"
hashed = pwd_context.hash(new_password)

conn = sqlite3.connect(r'c:\Users\sunjunjie\Desktop\vibe coding项目\黑产系统\threat-intel-agent\backend\threat_intel.db')
c = conn.cursor()
c.execute("UPDATE users SET hashed_password=?, locked_until=NULL, login_fail_count=0 WHERE username='admin'", (hashed,))
conn.commit()
print(f"Password reset to '{new_password}', rows affected: {c.rowcount}")
conn.close()
