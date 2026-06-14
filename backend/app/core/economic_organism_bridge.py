"""
EconomicOrganismBridge — 经济系统与情报体深度联动
将情报体的活力衰减与经济系统的市场波动关联
"""
from typing import Dict, List, Optional
from loguru import logger
from app.core.economic_engine import EconomicEngine, MARKET_SECTORS, RISK_LEVEL_MULTIPLIERS
from app.core.intelligence_organism import IntelligenceOrganismEngine


ORGANISM_SPECIES_TO_SECTOR: Dict[str, List[str]] = {
    "ip": ["ddos_service", "phishing"],
    "phone": ["fraud", "account_trading"],
    "bankcard": ["money_laundering", "fraud"],
    "domain": ["phishing", "phishing_kit", "tool_sales"],
    "ttp": ["tool_sales", "ransomware"],
    "organization": ["fraud", "money_laundering"],
    "slang": ["fraud", "gambling"],
    "campaign": ["fraud", "ransomware", "money_laundering"],
}


class EconomicOrganismBridge:
    def __init__(
        self,
        economic_engine: EconomicEngine,
        organism_engine: IntelligenceOrganismEngine,
    ):
        self.economic_engine = economic_engine
        self.organism_engine = organism_engine

    async def sync_organism_vitality_to_market(self):
        sector_vitality: Dict[str, List[float]] = {}
        for organism in self.organism_engine.organisms.values():
            if not organism.is_alive:
                continue
            sectors = ORGANISM_SPECIES_TO_SECTOR.get(organism.species, [])
            for sector in sectors:
                if sector not in sector_vitality:
                    sector_vitality[sector] = []
                sector_vitality[sector].append(organism.vitality)

        for sector, vitalities in sector_vitality.items():
            if not vitalities:
                continue
            avg_vitality = sum(vitalities) / len(vitalities)
            max_vitality = max(vitalities)
            active_count = len(vitalities)

            market_state = self.economic_engine.market_states.get(sector)
            if market_state:
                market_state.active_entities = active_count
                if avg_vitality > 0.7:
                    market_state.trend = "rising"
                elif avg_vitality < 0.3:
                    market_state.trend = "falling"
                else:
                    market_state.trend = "stable"
                market_state.risk_score = min(1.0, max_vitality * 0.8 + market_state.risk_score * 0.2)

        logger.info(f"Synced {sum(len(v) for v in sector_vitality.values())} organisms to market states")

    async def generate_economic_organism_report(self) -> Dict:
        report = {
            "total_organisms": len(self.organism_engine.organisms),
            "alive_organisms": sum(1 for o in self.organism_engine.organisms.values() if o.is_alive),
            "sector_health": {},
            "high_risk_organisms": [],
            "recommendations": [],
        }

        sector_data: Dict[str, Dict] = {}
        for organism in self.organism_engine.organisms.values():
            sectors = ORGANISM_SPECIES_TO_SECTOR.get(organism.species, [])
            for sector in sectors:
                if sector not in sector_data:
                    sector_data[sector] = {
                        "count": 0,
                        "alive": 0,
                        "avg_vitality": 0.0,
                        "max_vitality": 0.0,
                        "vitalities": [],
                    }
                sector_data[sector]["count"] += 1
                if organism.is_alive:
                    sector_data[sector]["alive"] += 1
                    sector_data[sector]["vitalities"].append(organism.vitality)

        for sector, data in sector_data.items():
            vitalities = data["vitalities"]
            avg_v = sum(vitalities) / len(vitalities) if vitalities else 0
            max_v = max(vitalities) if vitalities else 0
            market = self.economic_engine.market_states.get(sector)

            report["sector_health"][sector] = {
                "sector_name": MARKET_SECTORS.get(sector, sector),
                "organism_count": data["count"],
                "alive_count": data["alive"],
                "avg_vitality": round(avg_v, 3),
                "max_vitality": round(max_v, 3),
                "market_risk_score": market.risk_score if market else 0,
                "market_trend": market.trend if market else "unknown",
                "estimated_loss": market.market_cap_estimate * (1 - avg_v) if market else 0,
            }

        for organism in self.organism_engine.organisms.values():
            if organism.is_alive and organism.vitality > 0.8:
                report["high_risk_organisms"].append({
                    "id": organism.intelligence_id[:8],
                    "species": organism.species,
                    "vitality": round(organism.vitality, 3),
                    "generation": organism.generation,
                    "age_hours": round(organism.current_age_hours, 1),
                })

        report["high_risk_organisms"].sort(key=lambda x: x["vitality"], reverse=True)
        report["high_risk_organisms"] = report["high_risk_organisms"][:10]

        for sector, health in report["sector_health"].items():
            if health["avg_vitality"] > 0.7 and health["market_risk_score"] > 0.5:
                report["recommendations"].append(
                    f"⚠️ {health['sector_name']}板块活跃度高(vitality={health['avg_vitality']:.2f})，"
                    f"市场风险大(risk={health['market_risk_score']:.2f})，建议加强监控"
                )
            elif health["alive_count"] > 5 and health["market_trend"] == "rising":
                report["recommendations"].append(
                    f"📈 {health['sector_name']}板块有{health['alive_count']}个活跃情报体，"
                    f"市场趋势上升，预计损失约{health['estimated_loss']:.0f}元"
                )

        return report

    async def trigger_economic_decay(self):
        for organism in self.organism_engine.organisms.values():
            if not organism.is_alive:
                sectors = ORGANISM_SPECIES_TO_SECTOR.get(organism.species, [])
                for sector in sectors:
                    self.economic_engine.update_market(sector, risk_delta=-0.02)

        logger.info("Economic decay applied for dead organisms")
