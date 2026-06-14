import sys
import asyncio
sys.path.insert(0, r'c:\Users\sunjunjie\Desktop\vibe coding项目\黑产系统\threat-intel-agent\backend')

async def check():
    from app.db.database import engine
    from sqlalchemy import text

    async with engine.connect() as conn:
        # 检查各表数据量
        tables = [
            'raw_intelligence',
            'cleaned_intelligence', 
            'analyzed_intelligence',
            'api_keys',
            'audit_log'
        ]
        
        print('=== 数据库表统计 ===')
        for table in tables:
            try:
                result = await conn.execute(text(f'SELECT COUNT(*) FROM {table}'))
                count = result.scalar()
                print(f'{table}: {count} 条')
            except Exception as e:
                print(f'{table}: 错误 - {e}')
        
        # 检查JSON文件中的告警数据
        print('\n=== 告警统计 (JSON文件) ===')
        import json
        import os
        alert_path = os.path.join(os.path.dirname(__file__), 'backend', 'alert_data', 'alerts.json')
        if os.path.exists(alert_path):
            with open(alert_path) as f:
                data = json.load(f)
            print(f'活跃告警: {len(data.get("active_alerts", {}))} 条')
            print(f'告警历史: {len(data.get("alert_history", []))} 条')
            print(f'告警规则: {len(data.get("rules", {}))} 条')
        else:
            print('alerts.json 不存在')
        
        # 检查最新数据
        print('\n=== 最新情报数据 ===')# 查看最新几条情报数据
        result = await conn.execute(text('''
            SELECT id, source, content, collected_at
            FROM raw_intelligence
            ORDER BY collected_at DESC
            LIMIT 5
        '''))
        rows = result.fetchall()
        for row in rows:
            print(f'ID: {row[0][:8]}...')
            print(f'来源: {row[1]}')
            print(f'内容: {row[2][:100]}...' if len(row[2]) > 100 else f'内容: {row[2]}')
            print(f'时间: {row[3]}')
            print('---')

    await engine.dispose()

asyncio.run(check())
