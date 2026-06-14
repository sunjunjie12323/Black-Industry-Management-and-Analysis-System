import asyncio
from sqlalchemy import text
from app.db.database import engine

async def check_alerts_schema():
    async with engine.connect() as conn:
        # 检查 alerts 表结构
        result = await conn.execute(text("PRAGMA table_info(alerts)"))
        print("=== alerts 表结构 ===")
        for row in result.fetchall():
            print(row)

asyncio.run(check_alerts_schema())
