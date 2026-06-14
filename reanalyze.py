import sys
import asyncio
sys.path.insert(0, r'c:\Users\sunjunjie\Desktop\vibe coding项目\黑产系统\threat-intel-agent\backend')

async def reanalyze():
    from app.db.database import engine, Base
    from app.core.rule_classifier import RuleBasedClassifier
    from app.core.rule_extractor import RuleBasedEntityExtractor
    from sqlalchemy import text
    import json
    from datetime import datetime
    import uuid

    classifier = RuleBasedClassifier()
    extractor = RuleBasedEntityExtractor()

    async with engine.begin() as conn:
        print('=== RE-ANALYZING EXISTING DATA ===')

        r = await conn.execute(text('SELECT COUNT(*) FROM cleaned_intelligence'))
        total = r.scalar()
        print(f'  Total cleaned records: {total}')

        r = await conn.execute(text('SELECT COUNT(*) FROM analyzed_intelligence WHERE confidence_score > 0'))
        valid = r.scalar()
        print(f'  Currently valid analyzed: {valid}')

        print()
        print('=== RE-RUNNING RULE CLASSIFIER ===')

        r = await conn.execute(text('SELECT id, content FROM cleaned_intelligence'))
        rows = r.fetchall()

        updated = 0
        for row in rows:
            cleaned_id = row[0]
            content = row[1] or ''

            entities = extractor.extract(content)
            classification = classifier.classify(content)

            threat_level = classification.get('severity', 'info')
            categories = classification.get('categories', [])
            confidence = classification.get('confidence', 0.0)
            matched_keywords = classification.get('matched_keywords', [])

            summary_parts = []
            if categories:
                cats = [c.get('category', '') for c in categories if c.get('confidence', 0) > 0.3]
                if cats:
                    summary_parts.append('分类: ' + ', '.join(cats))
            if threat_level != 'info':
                summary_parts.append('威胁等级: ' + threat_level)
            entity_count = sum(len(v) for v in entities.values())
            if entity_count > 0:
                summary_parts.append(f'提取实体: {entity_count}个')

            summary = '; '.join(summary_parts) if summary_parts else '规则分析完成'

            entities_json = json.dumps(entities, ensure_ascii=False)
            categories_json = json.dumps(categories, ensure_ascii=False)

            await conn.execute(text('''
                UPDATE analyzed_intelligence
                SET threat_level = :threat_level,
                    threat_categories_json = :categories_json,
                    confidence_score = :confidence,
                    analysis_summary = :summary,
                    evidence_refs_json = :entities_json,
                    updated_at = :now
                WHERE cleaned_id = :cleaned_id
            '''), {
                'threat_level': threat_level,
                'categories_json': categories_json,
                'confidence': confidence,
                'summary': summary,
                'entities_json': entities_json,
                'cleaned_id': cleaned_id,
                'now': datetime.utcnow()
            })

            if confidence > 0:
                updated += 1

        await conn.execute(text('COMMIT'))

        print(f'  Updated {updated} / {len(rows)} records')

        print()
        print('=== VERIFYING UPDATE ===')
        r = await conn.execute(text('SELECT COUNT(*) FROM analyzed_intelligence WHERE confidence_score > 0'))
        valid = r.scalar()
        print(f'  Valid analyzed records: {valid}')

        r = await conn.execute(text('''
            SELECT threat_level, COUNT(*) FROM analyzed_intelligence
            GROUP BY threat_level
        '''))
        rows = r.fetchall()
        print('  Threat level distribution:')
        for row in rows:
            print(f'    {row[0]}: {row[1]}')

        print()
        print('=== SAMPLE UPDATED ANALYZED ===')
        r = await conn.execute(text('''
            SELECT threat_level, confidence_score, analysis_summary, threat_categories_json
            FROM analyzed_intelligence
            WHERE confidence_score > 0
            LIMIT 3
        '''))
        rows = r.fetchall()
        for row in rows:
            print(f'  level={row[0]}, confidence={row[1]:.2f}')
            print(f'    summary: {row[2]}')
            print(f'    categories: {row[3][:100]}...')

    await engine.dispose()

asyncio.run(reanalyze())
