import sys
import asyncio
sys.path.insert(0, r'c:\Users\sunjunjie\Desktop\vibe coding项目\黑产系统\threat-intel-agent\backend')

async def verify():
    from app.db.database import engine
    from app.core.seed_data import load_seed_data
    from sqlalchemy import text

    async with engine.connect() as conn:
        print('=== BEFORE SEED ===')
        for t in ['raw_intelligence', 'cleaned_intelligence', 'analyzed_intelligence']:
            r = await conn.execute(text('SELECT COUNT(*) FROM ' + t))
            n = r.scalar() or 0
            print('  ' + t + ': ' + str(n) + ' rows')

        print()
        print('=== RUNNING SEED ===')
        result = await load_seed_data(None)
        print('  Result:', result)

        await conn.commit()

        print()
        print('=== AFTER SEED ===')
        for t in ['raw_intelligence', 'cleaned_intelligence', 'analyzed_intelligence']:
            r = await conn.execute(text('SELECT COUNT(*) FROM ' + t))
            n = r.scalar() or 0
            print('  ' + t + ': ' + str(n) + ' rows')

        print()
        print('=== SAMPLE RAW ===')
        r = await conn.execute(text(
            "SELECT id, source_type, source_url, substr(content, 1, 120) FROM raw_intelligence LIMIT 3"
        ))
        rows = r.fetchall()
        for row in rows:
            print(' ', tuple(row))

        print()
        print('=== SOURCE BREAKDOWN ===')
        r = await conn.execute(text(
            "SELECT source_type, COUNT(*) FROM raw_intelligence GROUP BY source_type"
        ))
        rows = r.fetchall()
        for row in rows:
            print(' ', tuple(row))

    await engine.dispose()

asyncio.run(verify())
