import sqlite3, uuid, json
from datetime import datetime, timezone, timedelta

conn = sqlite3.connect('threat_intel.db')
cursor = conn.cursor()

cursor.execute("SELECT COUNT(*) FROM audit_log")
count = cursor.fetchone()[0]
print(f"Current audit_log count: {count}")

if count < 5:
    admin_id = None
    cursor.execute("SELECT id FROM users WHERE username='admin'")
    row = cursor.fetchone()
    if row:
        admin_id = row[0]

    actions = [
        ('login', 'auth', '用户登录系统', '127.0.0.1'),
        ('query', 'intelligence', '查询情报列表，筛选条件: threat_level=critical', '127.0.0.1'),
        ('analyze', 'intelligence', '批量分析情报数据，共处理23条', '127.0.0.1'),
        ('generate', 'report', '生成威胁评估报告: 2026年5月黑产态势', '127.0.0.1'),
        ('create', 'pir', '创建优先情报需求: 暗网数据泄露追踪', '127.0.0.1'),
        ('update', 'alert_rule', '更新告警规则: 高危IOC检测阈值', '127.0.0.1'),
        ('export', 'report', '导出报告为PDF格式', '127.0.0.1'),
        ('delete', 'intelligence', '删除过期情报记录5条', '127.0.0.1'),
        ('chat', 'deepseek', 'AI对话: 分析近期钓鱼攻击趋势', '127.0.0.1'),
        ('collect', 'pipeline', '触发情报采集任务: darkweb+forum', '127.0.0.1'),
    ]

    now = datetime.now(timezone.utc)
    for i, (action, resource, detail, ip) in enumerate(actions):
        cursor.execute('''
            INSERT INTO audit_log (id, user_id, username, action, resource, detail, ip_address, user_agent, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (str(uuid.uuid4()), admin_id, 'admin', action, resource, detail, ip,
              'Mozilla/5.0 ThreatIntel/1.0',
              (now - timedelta(hours=i*2+1)).isoformat()))

    conn.commit()
    print(f"Inserted {len(actions)} audit log entries")
else:
    print("Audit log already has data, skipping")

cursor.execute("SELECT COUNT(*) FROM audit_log")
print(f"Total audit_log: {cursor.fetchone()[0]}")
conn.close()
