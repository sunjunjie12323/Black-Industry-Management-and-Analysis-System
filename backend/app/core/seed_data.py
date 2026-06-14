import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from loguru import logger
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.tables import RawIntelligenceTable


def _backend_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _config_dir() -> Path:
    return _backend_root() / "app" / "config"


def _data_dir() -> Path:
    return _backend_root() / "app" / "data"


def load_data_sources_config() -> Dict[str, Any]:
    config_path = _config_dir() / "data_sources.json"
    if not config_path.exists():
        logger.warning(f"data_sources.json not found at {config_path}, returning empty config")
        return {"rss_feeds": [], "api_sources": [], "seed_datasets": []}
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            config = json.load(f)
        return {
            "rss_feeds": config.get("rss_feeds", []),
            "api_sources": config.get("api_sources", []),
            "seed_datasets": config.get("seed_datasets", []),
        }
    except Exception as exc:
        logger.error(f"Failed to load data_sources.json: {exc}")
        return {"rss_feeds": [], "api_sources": [], "seed_datasets": []}


def load_known_orgs() -> set:
    config_path = _config_dir() / "known_orgs.json"
    if not config_path.exists():
        logger.warning(f"known_orgs.json not found at {config_path}")
        return set()
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        orgs: set = set()
        for key in ("apt_groups", "state_attributed", "ransomware_groups", "other_actors", "all_real_threat_actors"):
            for name in data.get(key, []):
                if isinstance(name, str) and name.strip():
                    orgs.add(name.strip())
        return orgs
    except Exception as exc:
        logger.error(f"Failed to load known_orgs.json: {exc}")
        return set()


def load_classification_rules() -> Dict[str, Any]:
    config_path = _config_dir() / "classification_rules.json"
    if not config_path.exists():
        logger.warning(f"classification_rules.json not found at {config_path}")
        return {"categories": {}, "severity_keywords": {}}
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as exc:
        logger.error(f"Failed to load classification_rules.json: {exc}")
        return {"categories": {}, "severity_keywords": {}}


def _resolve_seed_path(rel_path: str) -> Path:
    p = Path(rel_path)
    if p.is_absolute():
        return p
    return _backend_root() / p


def _parse_date(value: str) -> Optional[str]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).isoformat()
    except Exception:
        return value


def _build_seed_record(entry: Dict[str, Any], source_tag: str = "web") -> Dict[str, Any]:
    cve_id = entry.get("cveID", "")
    vendor = entry.get("vendorProject", "")
    product = entry.get("product", "")
    vuln_name = entry.get("vulnerabilityName", "")
    short_desc = entry.get("shortDescription", "")
    required_action = entry.get("requiredAction", "")
    date_added = entry.get("dateAdded", "")
    due_date = entry.get("dueDate", "")

    content_parts = []
    if vuln_name:
        content_parts.append(f"CISA KEV - {vuln_name}")
    if cve_id:
        content_parts.append(f"CVE ID: {cve_id}")
    if vendor or product:
        content_parts.append(f"Affected: {vendor} {product}".strip())
    if short_desc:
        content_parts.append(f"Description: {short_desc}")
    if required_action:
        content_parts.append(f"Required Action: {required_action}")
    if due_date:
        content_parts.append(f"Remediation Due: {due_date}")
    content = "\n".join(content_parts)

    metadata = {
        "cve_id": cve_id,
        "vendor": vendor,
        "product": product,
        "vulnerability_name": vuln_name,
        "date_added": _parse_date(date_added),
        "due_date": _parse_date(due_date),
        "required_action": required_action,
        "category": "vulnerability",
        "threat_level": "high",
        "language": "en",
        "confidence": 0.95,
        "source_name": "CISA_KEV",
    }

    return {
        "id": uuid.uuid4().hex,
        "source": "seed_cisa_kev",
        "source_url": f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog#{cve_id}",
        "content": content,
        "raw_content": json.dumps(entry, ensure_ascii=False),
        "collected_at": datetime.now(timezone.utc),
        "status": "raw",
        "metadata_json": json.dumps(metadata, ensure_ascii=False),
        "classification_level": "PUBLIC",
    }


async def load_seed_data(session: Optional[AsyncSession]) -> int:
    if session is None:
        logger.info("load_seed_data: no session provided, parsing JSON only for verification")
        return _load_seed_data_sync()

    config = load_data_sources_config()
    datasets = config.get("seed_datasets", [])
    if not datasets:
        logger.warning("No seed_datasets configured in data_sources.json")
        return 0

    total_inserted = 0
    for ds in datasets:
        file_rel = ds.get("file", "")
        source_tag = ds.get("source_tag", "web")
        name = ds.get("name", "seed")
        if not file_rel:
            continue

        seed_path = _resolve_seed_path(file_rel)
        if not seed_path.exists():
            logger.warning(f"Seed dataset '{name}' file not found: {seed_path}")
            continue

        try:
            with open(seed_path, "r", encoding="utf-8") as f:
                entries = json.load(f)
        except Exception as exc:
            logger.error(f"Failed to parse {seed_path}: {exc}")
            continue

        if not isinstance(entries, list):
            logger.warning(f"Seed dataset '{name}' is not a list, skipping")
            continue

        existing_cves: set = set()
        try:
            result = await session.execute(
                select(RawIntelligenceTable).where(RawIntelligenceTable.source == "seed_cisa_kev")
            )
            for row in result.scalars().all():
                try:
                    meta = json.loads(row.metadata_json) if row.metadata_json else {}
                    cve = meta.get("cve_id")
                    if cve:
                        existing_cves.add(cve)
                except Exception:
                    pass
        except Exception as exc:
            logger.debug(f"Could not query existing seed entries: {exc}")

        inserted_this_dataset = 0
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            cve_id = entry.get("cveID", "")
            if not cve_id:
                continue
            if cve_id in existing_cves:
                continue

            record = _build_seed_record(entry, source_tag=source_tag)
            try:
                session.add(RawIntelligenceTable(**record))
                existing_cves.add(cve_id)
                inserted_this_dataset += 1
            except Exception as exc:
                logger.warning(f"Failed to add seed record {cve_id}: {exc}")

        try:
            await session.commit()
            logger.info(f"Seed dataset '{name}': inserted {inserted_this_dataset} records from {seed_path}")
            total_inserted += inserted_this_dataset
        except Exception as exc:
            logger.error(f"Failed to commit seed dataset '{name}': {exc}")
            try:
                await session.rollback()
            except Exception:
                pass

    return total_inserted


def _load_seed_data_sync() -> int:
    config = load_data_sources_config()
    datasets = config.get("seed_datasets", [])
    total = 0
    for ds in datasets:
        file_rel = ds.get("file", "")
        if not file_rel:
            continue
        seed_path = _resolve_seed_path(file_rel)
        if not seed_path.exists():
            continue
        try:
            with open(seed_path, "r", encoding="utf-8") as f:
                entries = json.load(f)
            if isinstance(entries, list):
                total += len(entries)
                logger.info(f"Verified {len(entries)} seed entries in {seed_path}")
        except Exception as exc:
            logger.error(f"Failed to load {seed_path}: {exc}")
    return total
