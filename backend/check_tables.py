import sqlite3
conn = sqlite3.connect('threat_intel.db')
cursor = conn.cursor()

# 列出所有表
cursor.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;")
tables = cursor.fetchall()
print("数据库表列表:")
for table in tables:
    print(f"  - {table[0]}")

conn.close()
