"""
Economic Tables — 经济系统数据库表定义
添加到现有 tables.py 中
"""
from datetime import datetime
from sqlalchemy import Boolean, Float, Integer, String, Text, DateTime, func
from sqlalchemy.orm import Mapped, mapped_column
from app.db.database import Base


class EconomicImpactTable(Base):
    __tablename__ = "economic_impact"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    sector: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    estimated_loss: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    affected_users: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    geographic_scope: Mapped[str] = mapped_column(Text, nullable=True)
    duration_days: Mapped[int] = mapped_column(Integer, nullable=False, default=30)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.5)
    intelligence_source_ids: Mapped[str] = mapped_column(Text, nullable=True)
    threat_categories: Mapped[str] = mapped_column(Text, nullable=True)
    assessed_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=func.now(), index=True)


class MarketTransactionTable(Base):
    __tablename__ = "market_transaction"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    sector: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    tx_type: Mapped[str] = mapped_column(String(16), nullable=False)
    amount: Mapped[float] = mapped_column(Float, nullable=False)
    price: Mapped[float] = mapped_column(Float, nullable=False)
    total_value: Mapped[float] = mapped_column(Float, nullable=False)
    fee: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    from_entity: Mapped[str] = mapped_column(String(128), nullable=True)
    to_entity: Mapped[str] = mapped_column(String(128), nullable=True)
    risk_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    intelligence_ids: Mapped[str] = mapped_column(Text, nullable=True)
    description: Mapped[str] = mapped_column(Text, nullable=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=func.now(), index=True)


class MarketStateTable(Base):
    __tablename__ = "market_state"

    sector: Mapped[str] = mapped_column(String(32), primary_key=True)
    sector_name: Mapped[str] = mapped_column(String(64), nullable=False)
    price_index: Mapped[float] = mapped_column(Float, nullable=False, default=100.0)
    volume_24h: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    volatility: Mapped[float] = mapped_column(Float, nullable=False, default=0.15)
    trend: Mapped[str] = mapped_column(String(16), nullable=False, default="stable")
    risk_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    market_cap_estimate: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    active_entities: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_updated: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=func.now())


class EconomicAlertTable(Base):
    __tablename__ = "economic_alert"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    sector: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    alert_type: Mapped[str] = mapped_column(String(32), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, default="medium")
    message: Mapped[str] = mapped_column(Text, nullable=False)
    related_intelligence_ids: Mapped[str] = mapped_column(Text, nullable=True)
    economic_impact_ids: Mapped[str] = mapped_column(Text, nullable=True)
    is_resolved: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=func.now(), index=True)
