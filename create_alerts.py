import sys
import asyncio
sys.path.insert(0, r'c:\Users\sunjunjie\Desktop\vibe coding项目\黑产系统\threat-intel-agent\backend')

async def create_alerts():
    from app.db.database import engine, Base
    from sqlalchemy import text

    async with engine.begin() as conn:
        print('=== CREATING ALERTS TABLE ===')
        await conn.execute(text('''
            CREATE TABLE IF NOT EXISTS alerts (
                id VARCHAR(64) PRIMARY KEY,
                tenant_id VARCHAR(64),
                analyzed_id VARCHAR(64) NOT NULL,
                alert_type VARCHAR(32) NOT NULL,
                severity VARCHAR(16) NOT NULL,
                title VARCHAR(255) NOT NULL,
                description TEXT,
                status VARCHAR(16) DEFAULT 'active',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        '''))
        print('  alerts table created')

        r = await conn.execute(text('SELECT COUNT(*) FROM alerts'))
        print('  alerts count:', r.scalar())

    await engine.dispose()

asyncio.run(create_alerts())
