import sqlite3, uuid, json
from datetime import datetime, timezone

conn = sqlite3.connect('threat_intel.db')
cursor = conn.cursor()

cursor.execute("PRAGMA table_info(pir)")
cols = [c[1] for c in cursor.fetchall()]
print("pir columns:", cols)

cursor.execute("SELECT COUNT(*) FROM pir")
count = cursor.fetchone()[0]
print(f"Current PIR count: {count}")

if count == 0:
    pirs_data = [
        {
            'id': str(uuid.uuid4()),
            'title': '新型信贷欺诈手法监测',
            'description': '监测近期出现的信贷欺诈新型手法，包括套路贷、房贷背债等变种',
            'priority': 'high',
            'status': 'active',
            'keywords_json': json.dumps(['信贷', '欺诈', '套路贷', '背债'], ensure_ascii=False),
            'target_sources_json': json.dumps(['telegram', 'forum', 'wechat'], ensure_ascii=False),
            'fulfillment_score': 0.35,
            'created_at': datetime.now(timezone.utc).isoformat(),
            'updated_at': datetime.now(timezone.utc).isoformat(),
        },
        {
            'id': str(uuid.uuid4()),
            'title': '暗网数据泄露追踪',
            'description': '追踪暗网市场上出售的中国公民个人数据泄露事件',
            'priority': 'critical',
            'status': 'active',
            'keywords_json': json.dumps(['数据泄露', '脱库', '个人信息', 'fullz'], ensure_ascii=False),
            'target_sources_json': json.dumps(['darkweb', 'forum'], ensure_ascii=False),
            'fulfillment_score': 0.6,
            'created_at': datetime.now(timezone.utc).isoformat(),
            'updated_at': datetime.now(timezone.utc).isoformat(),
        },
        {
            'id': str(uuid.uuid4()),
            'title': 'AI赋能黑产趋势分析',
            'description': '分析黑产利用AI技术（换脸、语音克隆、自动化攻击）的趋势和案例',
            'priority': 'medium',
            'status': 'active',
            'keywords_json': json.dumps(['AI', '换脸', '语音克隆', '自动化'], ensure_ascii=False),
            'target_sources_json': json.dumps(['telegram', 'wechat', 'darkweb'], ensure_ascii=False),
            'fulfillment_score': 0.2,
            'created_at': datetime.now(timezone.utc).isoformat(),
            'updated_at': datetime.now(timezone.utc).isoformat(),
        },
        {
            'id': str(uuid.uuid4()),
            'title': '跨境赌博平台资金链追踪',
            'description': '追踪跨境网络赌博平台的资金流转路径和洗钱手法',
            'priority': 'high',
            'status': 'executing',
            'keywords_json': json.dumps(['赌博', '洗钱', '资金链', '跨境'], ensure_ascii=False),
            'target_sources_json': json.dumps(['darkweb', 'forum'], ensure_ascii=False),
            'fulfillment_score': 0.45,
            'created_at': datetime.now(timezone.utc).isoformat(),
            'updated_at': datetime.now(timezone.utc).isoformat(),
        },
        {
            'id': str(uuid.uuid4()),
            'title': '电信诈骗新变种预警',
            'description': '监测电信诈骗的新变种手法，包括AI语音诈骗、虚假投资平台等',
            'priority': 'critical',
            'status': 'fulfilled',
            'keywords_json': json.dumps(['电信诈骗', 'AI语音', '虚假投资', '杀猪盘'], ensure_ascii=False),
            'target_sources_json': json.dumps(['telegram', 'wechat', 'forum'], ensure_ascii=False),
            'fulfillment_score': 0.85,
            'created_at': datetime.now(timezone.utc).isoformat(),
            'updated_at': datetime.now(timezone.utc).isoformat(),
        },
    ]

    for pir in pirs_data:
        cursor.execute('''
            INSERT INTO pir (id, title, description, priority, status, keywords_json, target_sources_json, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (pir['id'], pir['title'], pir['description'], pir['priority'], pir['status'],
              pir['keywords_json'], pir['target_sources_json'],
              pir['created_at'], pir['updated_at']))

    conn.commit()
    print(f"Inserted {len(pirs_data)} PIRs")
else:
    print("PIRs already exist, skipping")

cursor.execute("SELECT COUNT(*) FROM pir")
print(f"Total PIRs: {cursor.fetchone()[0]}")
conn.close()
