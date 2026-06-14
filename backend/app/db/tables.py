from datetime import datetime
from sqlalchemy import Boolean, CheckConstraint, DateTime, Float, ForeignKey, Index, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.database import Base


class RawIntelligenceTable(Base):
    __tablename__ = "raw_intelligence"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    source: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    source_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    raw_content: Mapped[str | None] = mapped_column(Text, nullable=True)
    collected_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=func.now(), index=True
    )
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="raw", index=True)
    metadata_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    classification_level: Mapped[str | None] = mapped_column(String(16), nullable=True, index=True)
    retention_expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, index=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=func.now(), onupdate=func.now()
    )
    cleaned: Mapped["CleanedIntelligenceTable | None"] = relationship(
        "CleanedIntelligenceTable", back_populates="raw", uselist=False, lazy="selectin"
    )


class CleanedIntelligenceTable(Base):
    __tablename__ = "cleaned_intelligence"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    raw_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("raw_intelligence.id", ondelete="CASCADE"), nullable=False, index=True
    )
    content: Mapped[str] = mapped_column(Text, nullable=False)
    decoded_content: Mapped[str | None] = mapped_column(Text, nullable=True)
    blacktalk_terms_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    entities_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    threat_level: Mapped[str] = mapped_column(String(16), nullable=False, default="info", index=True)
    cleaned_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=func.now(), index=True
    )
    raw: Mapped["RawIntelligenceTable"] = relationship(
        "RawIntelligenceTable", back_populates="cleaned", lazy="selectin"
    )
    analyzed: Mapped["AnalyzedIntelligenceTable | None"] = relationship(
        "AnalyzedIntelligenceTable", back_populates="cleaned", uselist=False, lazy="selectin"
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=func.now(), onupdate=func.now()
    )

    __table_args__ = (
        CheckConstraint(
            "threat_level IN ('critical', 'high', 'medium', 'low', 'info')",
            name='ck_cleaned_intelligence_threat_level',
        ),
    )


class AnalyzedIntelligenceTable(Base):
    __tablename__ = "analyzed_intelligence"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    cleaned_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("cleaned_intelligence.id", ondelete="CASCADE"), nullable=False, index=True
    )
    threat_level: Mapped[str] = mapped_column(String(16), nullable=False, default="info", index=True)
    threat_categories_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    attack_patterns_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    technique_chain_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    confidence_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    analysis_summary: Mapped[str] = mapped_column(Text, nullable=False, default="")
    evidence_refs_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    analyzed_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=func.now(), index=True
    )
    cleaned: Mapped["CleanedIntelligenceTable"] = relationship(
        "CleanedIntelligenceTable", back_populates="analyzed", lazy="selectin"
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=func.now(), onupdate=func.now()
    )

    __table_args__ = (
        CheckConstraint(
            "threat_level IN ('critical', 'high', 'medium', 'low', 'info')",
            name='ck_analyzed_intelligence_threat_level',
        ),
    )


class EntityTable(Base):
    __tablename__ = "entity"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    value: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    context: Mapped[str | None] = mapped_column(Text, nullable=True)
    source_ids_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.5)
    first_seen: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=func.now())
    last_seen: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=func.now())
    metadata_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=func.now(), onupdate=func.now()
    )
    source_relations: Mapped[list["RelationTable"]] = relationship(
        "RelationTable", foreign_keys="RelationTable.source_entity_id",
        back_populates="source_entity", lazy="selectin", cascade="all, delete-orphan"
    )
    target_relations: Mapped[list["RelationTable"]] = relationship(
        "RelationTable", foreign_keys="RelationTable.target_entity_id",
        back_populates="target_entity", lazy="selectin", cascade="all, delete-orphan"
    )


class RelationTable(Base):
    __tablename__ = "relation"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    source_entity_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("entity.id", ondelete="CASCADE"), nullable=False, index=True
    )
    target_entity_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("entity.id", ondelete="CASCADE"), nullable=False, index=True
    )
    type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.5)
    evidence: Mapped[str | None] = mapped_column(Text, nullable=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=func.now())
    last_seen: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=func.now(), onupdate=func.now()
    )
    source_entity: Mapped["EntityTable"] = relationship(
        "EntityTable", foreign_keys=[source_entity_id], back_populates="source_relations", lazy="selectin"
    )
    target_entity: Mapped["EntityTable"] = relationship(
        "EntityTable", foreign_keys=[target_entity_id], back_populates="target_relations", lazy="selectin"
    )


class UserTable(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    username: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    email: Mapped[str | None] = mapped_column(String(256), nullable=True, unique=True, index=True)
    hashed_password: Mapped[str] = mapped_column(String(256), nullable=False)
    role: Mapped[str] = mapped_column(String(16), nullable=False, default="viewer", index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, index=True)
    totp_secret: Mapped[str | None] = mapped_column(String(64), nullable=True)
    totp_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    login_fail_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=func.now(), index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=func.now(), onupdate=func.now())

    __table_args__ = (
        CheckConstraint(
            "role IN ('admin', 'analyst', 'viewer')",
            name='ck_users_role',
        ),
    )
    refresh_tokens: Mapped[list["RefreshTokenTable"]] = relationship(
        "RefreshTokenTable", back_populates="user", lazy="selectin", cascade="all, delete-orphan"
    )
    notifications: Mapped[list["NotificationTable"]] = relationship(
        "NotificationTable", back_populates="user", lazy="selectin", cascade="all, delete-orphan"
    )


class TokenBlacklistTable(Base):
    __tablename__ = "token_blacklist"

    jti: Mapped[str] = mapped_column(String(64), primary_key=True)
    token_hash: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    exp: Mapped[float] = mapped_column(Float, nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=func.now())


class RefreshTokenTable(Base):
    __tablename__ = "refresh_tokens"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    token_hash: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    device_info: Mapped[str | None] = mapped_column(String(256), nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    is_revoked: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=func.now(), onupdate=func.now()
    )
    user: Mapped["UserTable"] = relationship("UserTable", back_populates="refresh_tokens", lazy="selectin")

    __table_args__ = (
        Index("ix_refresh_tokens_user_id", "user_id"),
        Index("ix_refresh_tokens_expires_at", "expires_at"),
        Index("ix_refresh_tokens_is_revoked", "is_revoked"),
    )


class NotificationTable(Base):
    __tablename__ = "notifications"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    type: Mapped[str] = mapped_column(String(32), nullable=False)
    title: Mapped[str] = mapped_column(String(256), nullable=False)
    content: Mapped[str | None] = mapped_column(Text, nullable=True)
    link: Mapped[str | None] = mapped_column(String(512), nullable=True)
    is_read: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=func.now(), onupdate=func.now()
    )
    user: Mapped["UserTable"] = relationship("UserTable", back_populates="notifications", lazy="selectin")

    __table_args__ = (
        Index("ix_notifications_user_id", "user_id"),
        Index("ix_notifications_is_read", "is_read"),
        Index("ix_notifications_created_at", "created_at"),
        Index("ix_notifications_type", "type"),
    )


class AuditLogTable(Base):
    __tablename__ = "audit_log"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    username: Mapped[str | None] = mapped_column(String(64), nullable=True)
    action: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    resource: Mapped[str | None] = mapped_column(String(256), nullable=True)
    resource_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    resource_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    status: Mapped[str | None] = mapped_column(String(16), nullable=True, default="success")
    request_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(512), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=func.now(), index=True)


class PIRTable(Base):
    __tablename__ = "pir"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    title: Mapped[str] = mapped_column(String(256), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    priority: Mapped[str] = mapped_column(String(16), nullable=False, default="medium", index=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="active", index=True)
    keywords_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    target_sources_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=func.now(), index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=func.now(), onupdate=func.now())
    fulfilled_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    results_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    tasks: Mapped[list["PIRTaskTable"]] = relationship(
        "PIRTaskTable", back_populates="pir", lazy="selectin", cascade="all, delete-orphan"
    )
    reports: Mapped[list["ReportTable"]] = relationship(
        "ReportTable", back_populates="pir", lazy="selectin"
    )


class PIRTaskTable(Base):
    __tablename__ = "pir_task"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    pir_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("pir.id", ondelete="CASCADE"), nullable=False, index=True
    )
    agent_type: Mapped[str] = mapped_column(String(64), nullable=False)
    task_description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="pending", index=True)
    result_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=func.now())
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=func.now(), onupdate=func.now()
    )
    pir: Mapped["PIRTable"] = relationship("PIRTable", back_populates="tasks", lazy="selectin")


class ReportTable(Base):
    __tablename__ = "report"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    title: Mapped[str] = mapped_column(String(256), nullable=False)
    pir_id: Mapped[str | None] = mapped_column(
        String(64), ForeignKey("pir.id", ondelete="SET NULL"), nullable=True, index=True
    )
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="draft", index=True)
    summary: Mapped[str] = mapped_column(Text, nullable=False, default="")
    key_findings_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    threat_actors_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    iocs_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    attack_chains_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    recommendations_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    evidence_chain_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    confidence_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    author: Mapped[str] = mapped_column(String(128), nullable=False, default="system")
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=func.now(), index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=func.now(), onupdate=func.now())
    published_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    pir: Mapped["PIRTable | None"] = relationship("PIRTable", back_populates="reports", lazy="selectin")


class AnalysisResultTable(Base):
    __tablename__ = "analysis_result"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    analysis_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    target_id: Mapped[str] = mapped_column(String(64), nullable=False, default="", index=True)
    target_type: Mapped[str] = mapped_column(String(32), nullable=False, default="intelligence")
    result_summary: Mapped[str] = mapped_column(Text, nullable=False, default="")
    findings_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    iocs_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    recommendations_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    result_data_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    confidence_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="completed", index=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    llm_tokens_used: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    input_content: Mapped[str] = mapped_column(Text, nullable=False, default="")
    model_name: Mapped[str] = mapped_column(String(64), nullable=False, default="deepseek-chat")
    analyzed_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=func.now(), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=func.now(), index=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=func.now(), onupdate=func.now()
    )


class PromptTemplateTable(Base):
    __tablename__ = "prompt_templates"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    category: Mapped[str] = mapped_column(String(32), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="draft", index=True)
    variables_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    parent_id: Mapped[str] = mapped_column(String(64), nullable=True, default=None, index=True)
    ab_group: Mapped[str] = mapped_column(String(64), nullable=True, default=None)
    ab_ratio: Mapped[float] = mapped_column(Float, nullable=True, default=0.5)
    is_control: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    tags_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    created_by: Mapped[str] = mapped_column(String(128), nullable=False, default="system")
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=func.now(), onupdate=func.now())

    __table_args__ = (
        CheckConstraint(
            "status IN ('draft', 'active', 'archived')",
            name='ck_prompt_templates_status',
        ),
        Index("ix_prompt_templates_category", "category"),
        Index("ix_prompt_templates_is_active", "is_active"),
        Index("ix_prompt_templates_created_at", "created_at"),
        Index("ix_prompt_templates_ab_group", "ab_group"),
    )


class TenantTable(Base):
    __tablename__ = "tenants"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    plan: Mapped[str] = mapped_column(String(16), nullable=False, default="free", index=True)
    settings_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    is_deleted: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=func.now(), index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=func.now(), onupdate=func.now())

    __table_args__ = (
        CheckConstraint(
            "plan IN ('free', 'pro', 'enterprise')",
            name='ck_tenants_plan',
        ),
    )


class TenantQuotaTable(Base):
    __tablename__ = "tenant_quotas"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    intelligence_per_day: Mapped[int] = mapped_column(Integer, nullable=False, default=100)
    api_calls_per_day: Mapped[int] = mapped_column(Integer, nullable=False, default=1000)
    max_users: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=func.now(), onupdate=func.now())


class TenantUsageTable(Base):
    __tablename__ = "tenant_usage"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    date: Mapped[str] = mapped_column(String(10), nullable=False, index=True)
    intelligence_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    api_call_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=func.now(), onupdate=func.now())

    __table_args__ = (
        Index("ix_tenant_usage_tenant_date", "tenant_id", "date", unique=True),
    )


class CaseTable(Base):
    __tablename__ = "cases"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    title: Mapped[str] = mapped_column(String(256), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="open", index=True)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, default="medium", index=True)
    assignee: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=func.now(), index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=func.now(), onupdate=func.now())
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    __table_args__ = (
        CheckConstraint(
            "status IN ('open', 'investigating', 'escalated', 'resolved', 'closed')",
            name='ck_cases_status',
        ),
        CheckConstraint(
            "severity IN ('critical', 'high', 'medium', 'low', 'info')",
            name='ck_cases_severity',
        ),
    )


class CaseEventTable(Base):
    __tablename__ = "case_events"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    case_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True
    )
    event_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    operator: Mapped[str] = mapped_column(String(128), nullable=False, default="system")
    timestamp: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=func.now(), index=True)

    __table_args__ = (
        CheckConstraint(
            "event_type IN ('created', 'updated', 'intelligence_added', 'entity_linked', "
            "'comment_added', 'status_changed', 'escalated', 'resolved')",
            name='ck_case_events_event_type',
        ),
    )


class CaseIntelligenceTable(Base):
    __tablename__ = "case_intelligence"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    case_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True
    )
    intelligence_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=func.now())

    __table_args__ = (
        Index("ix_case_intelligence_unique", "case_id", "intelligence_id", unique=True),
    )


class CaseEntityTable(Base):
    __tablename__ = "case_entity"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    case_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True
    )
    entity_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=func.now())

    __table_args__ = (
        Index("ix_case_entity_unique", "case_id", "entity_id", unique=True),
    )


class ApiKeyTable(Base):
    __tablename__ = "api_keys"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    key_hash: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    key_prefix: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    tenant_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    permissions_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    rate_limit: Mapped[int] = mapped_column(Integer, nullable=False, default=60)
    daily_quota: Mapped[int] = mapped_column(Integer, nullable=False, default=1000)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=func.now(), index=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, index=True)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    __table_args__ = ()


class ApiKeyUsageTable(Base):
    __tablename__ = "api_key_usage"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    key_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("api_keys.id", ondelete="CASCADE"), nullable=False, index=True
    )
    window_start: Mapped[datetime] = mapped_column(DateTime, nullable=False, index=True)
    request_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=func.now())

    __table_args__ = (
        Index("ix_api_key_usage_key_window", "key_id", "window_start", unique=True),
    )


class SLAReportTable(Base):
    __tablename__ = "sla_reports"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    start_date: Mapped[str] = mapped_column(String(32), nullable=False)
    end_date: Mapped[str] = mapped_column(String(32), nullable=False)
    availability_pct: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    api_response_time_p95: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    search_response_time_p95: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    report_generation_time_p95: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    data_freshness_delay_minutes: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    alert_delay_seconds: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    compliance_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    violations_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=func.now(), index=True)


class BillingRecordTable(Base):
    __tablename__ = "billing_records"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    period: Mapped[str] = mapped_column(String(16), nullable=False)
    plan_name: Mapped[str] = mapped_column(String(32), nullable=False, default="free")
    base_cost: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    usage_costs_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    total_cost: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    currency: Mapped[str] = mapped_column(String(8), nullable=False, default="CNY")
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="pending", index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=func.now(), index=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=func.now(), onupdate=func.now()
    )

    __table_args__ = (
        Index("ix_billing_records_period", "period"),
    )


class UsageRecordTable(Base):
    __tablename__ = "usage_records"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    resource_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    amount: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    metadata_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=func.now(), index=True)

    __table_args__ = ()


class BackupRecordTable(Base):
    __tablename__ = "backup_records"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    backup_type: Mapped[str] = mapped_column(String(16), nullable=False, default="full", index=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="running", index=True)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    checksum: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    file_path: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    metadata_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=func.now(), index=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=func.now(), onupdate=func.now()
    )

    __table_args__ = ()


class IndustrySceneConfigTable(Base):
    __tablename__ = "industry_scene_configs"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    industry: Mapped[str] = mapped_column(String(32), nullable=False)
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    config_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=func.now())
    updated_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, onupdate=func.now())
    created_by: Mapped[str] = mapped_column(String(128), nullable=False, default="system")
    parent_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    ab_group: Mapped[str | None] = mapped_column(String(64), nullable=True)

    __table_args__ = (
        Index("ix_industry_scene_configs_industry", "industry"),
        Index("ix_industry_scene_configs_is_active", "is_active"),
        Index("ix_industry_scene_configs_created_at", "created_at"),
    )


class PreprocessTaskTable(Base):
    __tablename__ = "preprocess_tasks"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    task_type: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="pending")
    config_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    pipeline_steps_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    input_data_ref: Mapped[str | None] = mapped_column(String(512), nullable=True)
    output_data_ref: Mapped[str | None] = mapped_column(String(512), nullable=True)
    progress: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=func.now())
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_by: Mapped[str] = mapped_column(String(128), nullable=False, default="system")
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=func.now(), onupdate=func.now()
    )

    __table_args__ = (
        Index("ix_preprocess_tasks_task_type", "task_type"),
        Index("ix_preprocess_tasks_status", "status"),
        Index("ix_preprocess_tasks_created_at", "created_at"),
        Index("ix_preprocess_tasks_created_by", "created_by"),
    )


class FinetuneTaskTable(Base):
    __tablename__ = "finetune_tasks"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    method: Mapped[str] = mapped_column(String(16), nullable=False)
    base_model: Mapped[str] = mapped_column(String(256), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="pending")
    config_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    dataset_ref: Mapped[str | None] = mapped_column(String(512), nullable=True)
    checkpoint_ref: Mapped[str | None] = mapped_column(String(512), nullable=True)
    output_model_ref: Mapped[str | None] = mapped_column(String(512), nullable=True)
    metrics_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    progress: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=func.now())
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_by: Mapped[str] = mapped_column(String(128), nullable=False, default="system")
    parent_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=func.now(), onupdate=func.now()
    )

    __table_args__ = (
        Index("ix_finetune_tasks_method", "method"),
        Index("ix_finetune_tasks_status", "status"),
        Index("ix_finetune_tasks_created_at", "created_at"),
        Index("ix_finetune_tasks_created_by", "created_by"),
    )


class QAConversationTable(Base):
    __tablename__ = "qa_conversations"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    title: Mapped[str] = mapped_column(String(256), nullable=False)
    messages_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    industry: Mapped[str | None] = mapped_column(String(32), nullable=True)
    rag_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    model_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    conversation_type: Mapped[str] = mapped_column(String(32), nullable=False, default="conversation", index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=func.now(), onupdate=func.now())
    created_by: Mapped[str] = mapped_column(String(128), nullable=False, default="system")

    __table_args__ = (
        Index("ix_qa_conversations_industry", "industry"),
        Index("ix_qa_conversations_is_active", "is_active"),
        Index("ix_qa_conversations_created_at", "created_at"),
        Index("ix_qa_conversations_created_by", "created_by"),
    )


class GeneratedContentTable(Base):
    __tablename__ = "generated_contents"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    title: Mapped[str] = mapped_column(String(256), nullable=False)
    content_type: Mapped[str] = mapped_column(String(32), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="draft", index=True)
    review_status: Mapped[str] = mapped_column(String(16), nullable=False, default="pending")
    reviewer: Mapped[str | None] = mapped_column(String(128), nullable=True)
    review_comment: Mapped[str | None] = mapped_column(Text, nullable=True)
    source_refs_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    model_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    prompt_template_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    parent_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=func.now())
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=func.now(), onupdate=func.now()
    )
    created_by: Mapped[str] = mapped_column(String(128), nullable=False, default="system")

    __table_args__ = (
        Index("ix_generated_contents_content_type", "content_type"),
        Index("ix_generated_contents_review_status", "review_status"),
        Index("ix_generated_contents_created_at", "created_at"),
        Index("ix_generated_contents_created_by", "created_by"),
    )


class IndustryConfigTable(Base):
    __tablename__ = "industry_configs"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    industry: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    prompt_templates_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    rag_collections_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    model_config_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    features_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=func.now(), onupdate=func.now())


class TranslationMemoryTable(Base):
    __tablename__ = "translation_memory"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    source_text: Mapped[str] = mapped_column(Text, nullable=False)
    source_lang: Mapped[str] = mapped_column(String(8), nullable=False, index=True)
    target_text: Mapped[str] = mapped_column(Text, nullable=False)
    target_lang: Mapped[str] = mapped_column(String(8), nullable=False, index=True)
    domain: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=func.now(), onupdate=func.now()
    )


class TerminologyTable(Base):
    __tablename__ = "terminology"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    term: Mapped[str] = mapped_column(String(256), nullable=False, index=True)
    translation: Mapped[str] = mapped_column(String(256), nullable=False)
    source_lang: Mapped[str] = mapped_column(String(8), nullable=False, index=True)
    target_lang: Mapped[str] = mapped_column(String(8), nullable=False, index=True)
    domain: Mapped[str | None] = mapped_column(String(64), nullable=True)
    note: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=func.now(), onupdate=func.now()
    )


class AnalyticsResultTable(Base):
    __tablename__ = "analytics_results"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    query_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    query_text: Mapped[str] = mapped_column(Text, nullable=False, default="")
    result_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    chart_config_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    anomalies_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    prediction_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=func.now(), index=True)
    created_by: Mapped[str] = mapped_column(String(128), nullable=False, default="system")
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=func.now(), onupdate=func.now()
    )


class DashboardConfigTable(Base):
    __tablename__ = "dashboard_configs"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    layout_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    widgets_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    industry: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    refresh_interval: Mapped[int] = mapped_column(Integer, nullable=False, default=300)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=func.now(), onupdate=func.now())
    created_by: Mapped[str] = mapped_column(String(128), nullable=False, default="system")


class AnomalyRecordTable(Base):
    __tablename__ = "anomaly_records"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    metric: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    anomaly_type: Mapped[str] = mapped_column(String(32), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, default="medium", index=True)
    value: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    expected_value: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    deviation: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    context_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    detected_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=func.now(), index=True)
    acknowledged: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    acknowledged_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=func.now(), onupdate=func.now()
    )


class DeploymentRecordTable(Base):
    __tablename__ = "deployment_records"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    deploy_type: Mapped[str] = mapped_column(String(32), nullable=False, default="docker", index=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="pending", index=True)
    config_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    result_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    version: Mapped[str] = mapped_column(String(32), nullable=False, default="1.0.0", index=True)
    rollback_from: Mapped[str | None] = mapped_column(String(32), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=func.now())
    created_by: Mapped[str] = mapped_column(String(128), nullable=False, default="system")
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=func.now(), onupdate=func.now()
    )


class ServiceStatusTable(Base):
    __tablename__ = "service_status"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    service_name: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="unknown", index=True)
    health_check_url: Mapped[str | None] = mapped_column(String(512), nullable=True)
    last_check_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    response_time_ms: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    error_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    metadata_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=func.now(), onupdate=func.now())


class ABTestTable(Base):
    __tablename__ = "ab_tests"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    test_name: Mapped[str] = mapped_column(String(256), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    template_a_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    template_b_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="running", index=True)
    winner_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    metrics_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    confidence_level: Mapped[float] = mapped_column(Float, nullable=False, default=0.95)
    sample_size_a: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    sample_size_b: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    conversion_rate_a: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    conversion_rate_b: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    started_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=func.now())
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_by: Mapped[str] = mapped_column(String(128), nullable=False, default="system")
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=func.now(), onupdate=func.now()
    )


class EnvironmentConfigTable(Base):
    __tablename__ = "environment_configs"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    env_name: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    env_type: Mapped[str] = mapped_column(String(32), nullable=False, default="development")
    variables_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=func.now(), onupdate=func.now())
    created_by: Mapped[str] = mapped_column(String(128), nullable=False, default="system")


class PipelineBatchTable(Base):
    __tablename__ = "pipeline_batches"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    batch_id: Mapped[str] = mapped_column(String(32), nullable=False, unique=True, index=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="running", index=True)
    total_input: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    total_processed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    total_duplicates: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    total_high_risk: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    total_critical: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    by_source_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    by_intent_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    by_category_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    total_time_ms: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=func.now(), index=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_by: Mapped[str] = mapped_column(String(128), nullable=False, default="system")
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=func.now(), onupdate=func.now())


class PipelineItemTable(Base):
    __tablename__ = "pipeline_items"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    batch_id: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    source: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="pending", index=True)
    cleaned_content: Mapped[str] = mapped_column(Text, nullable=False, default="")
    is_duplicate: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    duplicate_of: Mapped[str] = mapped_column(String(64), nullable=True)
    threat_level: Mapped[str] = mapped_column(String(16), nullable=False, default="info", index=True)
    intent_level: Mapped[str] = mapped_column(String(16), nullable=False, default="benign", index=True)
    intent_indicators_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    cheating_scenarios_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    threat_categories_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    entities_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    risk_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0, index=True)
    quality_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    crime_patterns_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    tech_chains_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    summary: Mapped[str] = mapped_column(Text, nullable=False, default="")
    processing_time_ms: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=func.now(), index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=func.now(), onupdate=func.now())


class AlertRuleTable(Base):
    __tablename__ = "alert_rules"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    conditions_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    severity: Mapped[str] = mapped_column(String(16), nullable=False, default="high", index=True)
    is_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, index=True)
    cooldown_minutes: Mapped[int] = mapped_column(Integer, nullable=False, default=60)
    last_triggered: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_by: Mapped[str] = mapped_column(String(128), nullable=False, default="system")
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=func.now(), index=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=func.now(), onupdate=func.now()
    )

    __table_args__ = (
        CheckConstraint(
            "severity IN ('critical', 'high', 'medium', 'low', 'info')",
            name='ck_alert_rules_severity',
        ),
    )


class SourceConfigTable(Base):
    __tablename__ = "source_configs"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    source_id: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    source_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    priority: Mapped[str] = mapped_column(String(16), nullable=False, default="medium", index=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="active", index=True)
    interval_minutes: Mapped[int] = mapped_column(Integer, nullable=False, default=30)
    max_results_per_cycle: Mapped[int] = mapped_column(Integer, nullable=False, default=50)
    keywords_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    config_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    total_collected: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    total_errors: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    consecutive_errors: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_error: Mapped[str] = mapped_column(Text, nullable=False, default="")
    last_collected_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    rate_limit_until: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=func.now(), onupdate=func.now())
