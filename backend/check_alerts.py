import sqlite3
conn = sqlite3.connect('threat_intel.db')
cursor = conn.cursor()

# 检查 alert_rules 表
print("=== alert_rules 表 ===")
cursor.execute('SELECT COUNT(*) FROM alert_rules')
print(f'告警规则数: {cursor.fetchone()[0]}')

# 检查 notifications 表
print("\n=== notifications 表 ===")
cursor.execute('SELECT COUNT(*) FROM notifications')
print(f'通知总数: {cursor.fetchone()[0]}')

cursor.execute('''
    SELECT type, COUNT(*) 
    FROM notifications 
    GROUP BY type
''')
print("按类型统计:")
for row in cursor.fetchall():
    print(f"  {row[0]}: {row[1]} 条")

# 检查最近的威胁告警
print("\n=== 最近的威胁告警 ===")
cursor.execute('''
    SELECT type, title, created_at 
    FROM notifications 
    WHERE type = 'threat_alert'
    ORDER BY created_at DESC
    LIMIT 5
''')
for row in cursor.fetchall():
    print(f"  [{row[2]}] {row[1]}")

conn.close()
