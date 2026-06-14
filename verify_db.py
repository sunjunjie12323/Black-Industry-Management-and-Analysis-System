import sys
import asyncio
sys.path.insert(0, r'c:\Users\sunjunjie\Desktop\vibe coding项目\黑产系统\threat-intel-agent\backend')

async def verify():
    from app.db.database import engine
    from sqlalchemy import text

    async with engine.connect() as conn:
        print('=== TABLE SCHEMAS ===')
        for t in ['raw_intelligence', 'cleaned_intelligence', 'analyzed_intelligence']:
            r = await conn.execute(text('PRAGMA table_info(' + t + ')'))
            cols = r.fetchall()
            print('  ' + t + ':')
            for c in cols:
                print('    ' + str(tuple(c)))

        print()
        print('=== RAW COUNT ===')
        r = await conn.execute(text('SELECT COUNT(*) FROM raw_intelligence'))
        print('  ', r.scalar())

        print()
        print('=== SAMPLE RAW (first 3) ===')
        r = await conn.execute(text('SELECT * FROM raw_intelligence LIMIT 3'))
        cols = r.keys()
        rows = r.fetchall()
        print('  columns:', list(cols))
        for row in rows:
            d = dict(zip(cols, row))
            for k, v in d.items():
                sv = str(v)
                if len(sv) > 100:
                    sv = sv[:100] + '...'
                print('    ' + k + ': ' + sv)
            print('  ---')

        print()
        print('=== ANALYZED SAMPLE ===')
        r = await conn.execute(text('SELECT * FROM analyzed_intelligence LIMIT 2'))
        cols = r.keys()
        rows = r.fetchall()
        print('  columns:', list(cols))
        for row in rows:
            d = dict(zip(cols, row))
            for k, v in d.items():
                sv = str(v)
                if len(sv) > 100:
                    sv = sv[:100] + '...'
                print('    ' + k + ': ' + sv)
            print('  ---')

        print()
        print('=== ALERTS COUNT ===')
        try:
            r = await conn.execute(text('SELECT COUNT(*) FROM alerts'))
            print('  ', r.scalar())
        except Exception as e:
            print('  ERR:', e)

    await engine.dispose()

asyncio.run(verify())
