"""initial schema

Revision ID: 001_initial_schema
Revises: None
Create Date: 2026-05-30 00:00:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "001_initial_schema"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "raw_intelligence",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("source", sa.String(32), nullable=False, index=True),
        sa.Column("source_url", sa.Text(), nullable=True),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("raw_content", sa.Text(), nullable=True),
        sa.Column("collected_at", sa.DateTime(), nullable=False, server_default=sa.func.now(), index=True),
        sa.Column("status", sa.String(16), nullable=False, server_default="raw", index=True),
        sa.Column("metadata_json", sa.Text(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
    )

    op.create_table(
        "cleaned_intelligence",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("raw_id", sa.String(64), sa.ForeignKey("raw_intelligence.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("decoded_content", sa.Text(), nullable=True),
        sa.Column("blacktalk_terms_json", sa.Text(), nullable=True),
        sa.Column("entities_json", sa.Text(), nullable=True),
        sa.Column("threat_level", sa.String(16), nullable=False, server_default="info", index=True),
        sa.Column("cleaned_at", sa.DateTime(), nullable=False, server_default=sa.func.now(), index=True),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("threat_level IN ('critical', 'high', 'medium', 'low', 'info')", name="ck_cleaned_intelligence_threat_level"),
    )

    op.create_table(
        "analyzed_intelligence",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("cleaned_id", sa.String(64), sa.ForeignKey("cleaned_intelligence.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("threat_level", sa.String(16), nullable=False, server_default="info", index=True),
        sa.Column("threat_categories_json", sa.Text(), nullable=True),
        sa.Column("attack_patterns_json", sa.Text(), nullable=True),
        sa.Column("technique_chain_json", sa.Text(), nullable=True),
        sa.Column("confidence_score", sa.Float(), nullable=False, server_default="0"),
        sa.Column("analysis_summary", sa.Text(), nullable=False, server_default=""),
        sa.Column("evidence_refs_json", sa.Text(), nullable=True),
        sa.Column("analyzed_at", sa.DateTime(), nullable=False, server_default=sa.func.now(), index=True),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("threat_level IN ('critical', 'high', 'medium', 'low', 'info')", name="ck_analyzed_intelligence_threat_level"),
    )

    op.create_table(
        "entity",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("type", sa.String(32), nullable=False, index=True),
        sa.Column("value", sa.String(512), nullable=False, index=True),
        sa.Column("context", sa.Text(), nullable=True),
        sa.Column("source_ids_json", sa.Text(), nullable=True),
        sa.Column("confidence", sa.Float(), nullable=False, server_default="0.5"),
        sa.Column("first_seen", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("last_seen", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("metadata_json", sa.Text(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
    )

    op.create_table(
        "relation",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("source_entity_id", sa.String(64), sa.ForeignKey("entity.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("target_entity_id", sa.String(64), sa.ForeignKey("entity.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("type", sa.String(32), nullable=False, index=True),
        sa.Column("confidence", sa.Float(), nullable=False, server_default="0.5"),
        sa.Column("evidence", sa.Text(), nullable=True),
        sa.Column("first_seen", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("last_seen", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
    )

    op.create_table(
        "users",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("username", sa.String(64), nullable=False, unique=True, index=True),
        sa.Column("email", sa.String(256), nullable=True, unique=True, index=True),
        sa.Column("hashed_password", sa.String(256), nullable=False),
        sa.Column("role", sa.String(16), nullable=False, server_default="viewer", index=True),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("1"), index=True),
        sa.Column("totp_secret", sa.String(64), nullable=True),
        sa.Column("totp_enabled", sa.Boolean(), nullable=False, server_default=sa.text("0")),
        sa.Column("last_login_at", sa.DateTime(), nullable=True),
        sa.Column("login_fail_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("locked_until", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now(), index=True),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("role IN ('admin', 'analyst', 'viewer')", name="ck_users_role"),
    )

    op.create_table(
        "token_blacklist",
        sa.Column("jti", sa.String(64), primary_key=True),
        sa.Column("token_hash", sa.String(128), nullable=False, index=True),
        sa.Column("exp", sa.Float(), nullable=False, index=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
    )

    op.create_table(
        "refresh_tokens",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("user_id", sa.String(64), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("token_hash", sa.String(128), nullable=False, index=True),
        sa.Column("device_info", sa.String(256), nullable=True),
        sa.Column("ip_address", sa.String(45), nullable=True),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("is_revoked", sa.Boolean(), nullable=False, server_default=sa.text("0")),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_refresh_tokens_user_id", "refresh_tokens", ["user_id"])
    op.create_index("ix_refresh_tokens_expires_at", "refresh_tokens", ["expires_at"])
    op.create_index("ix_refresh_tokens_is_revoked", "refresh_tokens", ["is_revoked"])

    op.create_table(
        "notifications",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("user_id", sa.String(64), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("type", sa.String(32), nullable=False),
        sa.Column("title", sa.String(256), nullable=False),
        sa.Column("content", sa.Text(), nullable=True),
        sa.Column("link", sa.String(512), nullable=True),
        sa.Column("is_read", sa.Boolean(), nullable=False, server_default=sa.text("0")),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_notifications_user_id", "notifications", ["user_id"])
    op.create_index("ix_notifications_is_read", "notifications", ["is_read"])
    op.create_index("ix_notifications_created_at", "notifications", ["created_at"])
    op.create_index("ix_notifications_type", "notifications", ["type"])

    op.create_table(
        "audit_log",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("user_id", sa.String(64), nullable=True, index=True),
        sa.Column("username", sa.String(64), nullable=True),
        sa.Column("action", sa.String(64), nullable=False, index=True),
        sa.Column("resource", sa.String(256), nullable=True),
        sa.Column("detail", sa.Text(), nullable=True),
        sa.Column("ip_address", sa.String(45), nullable=True),
        sa.Column("user_agent", sa.String(512), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now(), index=True),
    )

    op.create_table(
        "pir",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("title", sa.String(256), nullable=False),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("priority", sa.String(16), nullable=False, server_default="medium", index=True),
        sa.Column("status", sa.String(16), nullable=False, server_default="active", index=True),
        sa.Column("keywords_json", sa.Text(), nullable=True),
        sa.Column("target_sources_json", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now(), index=True),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("fulfilled_at", sa.DateTime(), nullable=True),
        sa.Column("results_summary", sa.Text(), nullable=True),
    )

    op.create_table(
        "pir_task",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("pir_id", sa.String(64), sa.ForeignKey("pir.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("agent_type", sa.String(64), nullable=False),
        sa.Column("task_description", sa.Text(), nullable=False, server_default=""),
        sa.Column("status", sa.String(16), nullable=False, server_default="pending", index=True),
        sa.Column("result_json", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
    )

    op.create_table(
        "report",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("title", sa.String(256), nullable=False),
        sa.Column("pir_id", sa.String(64), sa.ForeignKey("pir.id", ondelete="SET NULL"), nullable=True, index=True),
        sa.Column("status", sa.String(16), nullable=False, server_default="draft", index=True),
        sa.Column("summary", sa.Text(), nullable=False, server_default=""),
        sa.Column("key_findings_json", sa.Text(), nullable=True),
        sa.Column("threat_actors_json", sa.Text(), nullable=True),
        sa.Column("iocs_json", sa.Text(), nullable=True),
        sa.Column("attack_chains_json", sa.Text(), nullable=True),
        sa.Column("recommendations_json", sa.Text(), nullable=True),
        sa.Column("evidence_chain_json", sa.Text(), nullable=True),
        sa.Column("confidence_score", sa.Float(), nullable=False, server_default="0"),
        sa.Column("author", sa.String(128), nullable=False, server_default="system"),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now(), index=True),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("published_at", sa.DateTime(), nullable=True),
    )

    op.create_table(
        "analysis_result",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("analysis_type", sa.String(32), nullable=False, index=True),
        sa.Column("target_id", sa.String(64), nullable=False, server_default="", index=True),
        sa.Column("target_type", sa.String(32), nullable=False, server_default="intelligence"),
        sa.Column("result_summary", sa.Text(), nullable=False, server_default=""),
        sa.Column("findings_json", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("iocs_json", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("recommendations_json", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("result_data_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("confidence_score", sa.Float(), nullable=False, server_default="0"),
        sa.Column("status", sa.String(16), nullable=False, server_default="completed", index=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("llm_tokens_used", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("input_content", sa.Text(), nullable=False, server_default=""),
        sa.Column("model_name", sa.String(64), nullable=False, server_default="deepseek-chat"),
        sa.Column("analyzed_at", sa.DateTime(), nullable=False, server_default=sa.func.now(), index=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now(), index=True),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
    )

    op.create_table(
        "prompt_templates",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("name", sa.String(256), nullable=False),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("category", sa.String(32), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="draft", index=True),
        sa.Column("variables_json", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("1")),
        sa.Column("parent_id", sa.String(64), nullable=True, index=True),
        sa.Column("ab_group", sa.String(64), nullable=True),
        sa.Column("ab_ratio", sa.Float(), nullable=True, server_default="0.5"),
        sa.Column("is_control", sa.Boolean(), nullable=False, server_default=sa.text("0")),
        sa.Column("tags_json", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("created_by", sa.String(128), nullable=False, server_default="system"),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("status IN ('draft', 'active', 'archived')", name="ck_prompt_templates_status"),
    )
    op.create_index("ix_prompt_templates_category", "prompt_templates", ["category"])
    op.create_index("ix_prompt_templates_is_active", "prompt_templates", ["is_active"])
    op.create_index("ix_prompt_templates_created_at", "prompt_templates", ["created_at"])
    op.create_index("ix_prompt_templates_ab_group", "prompt_templates", ["ab_group"])

    op.create_table(
        "industry_scene_configs",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("industry", sa.String(32), nullable=False),
        sa.Column("name", sa.String(256), nullable=False),
        sa.Column("config_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("0")),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
        sa.Column("created_by", sa.String(128), nullable=False, server_default="system"),
        sa.Column("parent_id", sa.String(64), nullable=True),
        sa.Column("ab_group", sa.String(64), nullable=True),
    )
    op.create_index("ix_industry_scene_configs_industry", "industry_scene_configs", ["industry"])
    op.create_index("ix_industry_scene_configs_is_active", "industry_scene_configs", ["is_active"])
    op.create_index("ix_industry_scene_configs_created_at", "industry_scene_configs", ["created_at"])

    op.create_table(
        "preprocess_tasks",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("name", sa.String(256), nullable=False),
        sa.Column("task_type", sa.String(32), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="pending"),
        sa.Column("config_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("pipeline_steps_json", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("input_data_ref", sa.String(512), nullable=True),
        sa.Column("output_data_ref", sa.String(512), nullable=True),
        sa.Column("progress", sa.Float(), nullable=False, server_default="0"),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
        sa.Column("created_by", sa.String(128), nullable=False, server_default="system"),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_preprocess_tasks_task_type", "preprocess_tasks", ["task_type"])
    op.create_index("ix_preprocess_tasks_status", "preprocess_tasks", ["status"])
    op.create_index("ix_preprocess_tasks_created_at", "preprocess_tasks", ["created_at"])
    op.create_index("ix_preprocess_tasks_created_by", "preprocess_tasks", ["created_by"])

    op.create_table(
        "finetune_tasks",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("name", sa.String(256), nullable=False),
        sa.Column("method", sa.String(16), nullable=False),
        sa.Column("base_model", sa.String(256), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="pending"),
        sa.Column("config_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("dataset_ref", sa.String(512), nullable=True),
        sa.Column("checkpoint_ref", sa.String(512), nullable=True),
        sa.Column("output_model_ref", sa.String(512), nullable=True),
        sa.Column("metrics_json", sa.Text(), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("progress", sa.Float(), nullable=False, server_default="0"),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
        sa.Column("created_by", sa.String(128), nullable=False, server_default="system"),
        sa.Column("parent_id", sa.String(64), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_finetune_tasks_method", "finetune_tasks", ["method"])
    op.create_index("ix_finetune_tasks_status", "finetune_tasks", ["status"])
    op.create_index("ix_finetune_tasks_created_at", "finetune_tasks", ["created_at"])
    op.create_index("ix_finetune_tasks_created_by", "finetune_tasks", ["created_by"])

    op.create_table(
        "qa_conversations",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("title", sa.String(256), nullable=False),
        sa.Column("messages_json", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("industry", sa.String(32), nullable=True),
        sa.Column("rag_enabled", sa.Boolean(), nullable=False, server_default=sa.text("1")),
        sa.Column("model_id", sa.String(128), nullable=True),
        sa.Column("conversation_type", sa.String(32), nullable=False, server_default="conversation", index=True),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("1")),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("created_by", sa.String(128), nullable=False, server_default="system"),
    )
    op.create_index("ix_qa_conversations_industry", "qa_conversations", ["industry"])
    op.create_index("ix_qa_conversations_is_active", "qa_conversations", ["is_active"])
    op.create_index("ix_qa_conversations_created_at", "qa_conversations", ["created_at"])
    op.create_index("ix_qa_conversations_created_by", "qa_conversations", ["created_by"])

    op.create_table(
        "generated_contents",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("title", sa.String(256), nullable=False),
        sa.Column("content_type", sa.String(32), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="draft", index=True),
        sa.Column("review_status", sa.String(16), nullable=False, server_default="pending"),
        sa.Column("reviewer", sa.String(128), nullable=True),
        sa.Column("review_comment", sa.Text(), nullable=True),
        sa.Column("source_refs_json", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("model_id", sa.String(128), nullable=True),
        sa.Column("prompt_template_id", sa.String(64), nullable=True),
        sa.Column("parent_id", sa.String(64), nullable=True, index=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("reviewed_at", sa.DateTime(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("created_by", sa.String(128), nullable=False, server_default="system"),
    )
    op.create_index("ix_generated_contents_content_type", "generated_contents", ["content_type"])
    op.create_index("ix_generated_contents_review_status", "generated_contents", ["review_status"])
    op.create_index("ix_generated_contents_created_at", "generated_contents", ["created_at"])
    op.create_index("ix_generated_contents_created_by", "generated_contents", ["created_by"])

    op.create_table(
        "industry_configs",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("industry", sa.String(32), nullable=False, index=True),
        sa.Column("name", sa.String(256), nullable=False),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("prompt_templates_json", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("rag_collections_json", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("model_config_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("features_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("1"), index=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
    )

    op.create_table(
        "translation_memory",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("source_text", sa.Text(), nullable=False),
        sa.Column("source_lang", sa.String(8), nullable=False, index=True),
        sa.Column("target_text", sa.Text(), nullable=False),
        sa.Column("target_lang", sa.String(8), nullable=False, index=True),
        sa.Column("domain", sa.String(64), nullable=True, index=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
    )

    op.create_table(
        "terminology",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("term", sa.String(256), nullable=False, index=True),
        sa.Column("translation", sa.String(256), nullable=False),
        sa.Column("source_lang", sa.String(8), nullable=False, index=True),
        sa.Column("target_lang", sa.String(8), nullable=False, index=True),
        sa.Column("domain", sa.String(64), nullable=True),
        sa.Column("note", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
    )

    op.create_table(
        "analytics_results",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("query_type", sa.String(32), nullable=False, index=True),
        sa.Column("query_text", sa.Text(), nullable=False, server_default=""),
        sa.Column("result_json", sa.Text(), nullable=True),
        sa.Column("chart_config_json", sa.Text(), nullable=True),
        sa.Column("anomalies_json", sa.Text(), nullable=True),
        sa.Column("prediction_json", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now(), index=True),
        sa.Column("created_by", sa.String(128), nullable=False, server_default="system"),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
    )

    op.create_table(
        "dashboard_configs",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("name", sa.String(256), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("layout_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("widgets_json", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("industry", sa.String(32), nullable=True, index=True),
        sa.Column("refresh_interval", sa.Integer(), nullable=False, server_default="300"),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("1"), index=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("created_by", sa.String(128), nullable=False, server_default="system"),
    )

    op.create_table(
        "anomaly_records",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("metric", sa.String(64), nullable=False, index=True),
        sa.Column("anomaly_type", sa.String(32), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False, server_default="medium", index=True),
        sa.Column("value", sa.Float(), nullable=False, server_default="0"),
        sa.Column("expected_value", sa.Float(), nullable=False, server_default="0"),
        sa.Column("deviation", sa.Float(), nullable=False, server_default="0"),
        sa.Column("context_json", sa.Text(), nullable=True),
        sa.Column("detected_at", sa.DateTime(), nullable=False, server_default=sa.func.now(), index=True),
        sa.Column("acknowledged", sa.Boolean(), nullable=False, server_default=sa.text("0")),
        sa.Column("acknowledged_by", sa.String(128), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
    )

    op.create_table(
        "deployment_records",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("deploy_type", sa.String(32), nullable=False, server_default="docker", index=True),
        sa.Column("status", sa.String(16), nullable=False, server_default="pending", index=True),
        sa.Column("config_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("result_json", sa.Text(), nullable=True),
        sa.Column("version", sa.String(32), nullable=False, server_default="1.0.0", index=True),
        sa.Column("rollback_from", sa.String(32), nullable=True),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("created_by", sa.String(128), nullable=False, server_default="system"),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
    )

    op.create_table(
        "service_status",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("service_name", sa.String(64), nullable=False, index=True),
        sa.Column("status", sa.String(16), nullable=False, server_default="unknown", index=True),
        sa.Column("health_check_url", sa.String(512), nullable=True),
        sa.Column("last_check_at", sa.DateTime(), nullable=True),
        sa.Column("response_time_ms", sa.Float(), nullable=False, server_default="0"),
        sa.Column("error_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("metadata_json", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
    )

    op.create_table(
        "ab_tests",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("test_name", sa.String(256), nullable=False),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("template_a_id", sa.String(64), nullable=False, index=True),
        sa.Column("template_b_id", sa.String(64), nullable=False, index=True),
        sa.Column("status", sa.String(16), nullable=False, server_default="running", index=True),
        sa.Column("winner_id", sa.String(64), nullable=True),
        sa.Column("metrics_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("confidence_level", sa.Float(), nullable=False, server_default="0.95"),
        sa.Column("sample_size_a", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("sample_size_b", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("conversion_rate_a", sa.Float(), nullable=False, server_default="0"),
        sa.Column("conversion_rate_b", sa.Float(), nullable=False, server_default="0"),
        sa.Column("started_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
        sa.Column("created_by", sa.String(128), nullable=False, server_default="system"),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
    )

    op.create_table(
        "environment_configs",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("env_name", sa.String(64), nullable=False, unique=True, index=True),
        sa.Column("env_type", sa.String(32), nullable=False, server_default="development"),
        sa.Column("variables_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("1")),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("created_by", sa.String(128), nullable=False, server_default="system"),
    )

    op.create_table(
        "pipeline_batches",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("batch_id", sa.String(32), nullable=False, unique=True, index=True),
        sa.Column("status", sa.String(16), nullable=False, server_default="running", index=True),
        sa.Column("total_input", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("total_processed", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("total_duplicates", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("total_high_risk", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("total_critical", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("by_source_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("by_intent_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("by_category_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("total_time_ms", sa.Float(), nullable=False, server_default="0"),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("started_at", sa.DateTime(), nullable=False, server_default=sa.func.now(), index=True),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
        sa.Column("created_by", sa.String(128), nullable=False, server_default="system"),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
    )

    op.create_table(
        "pipeline_items",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("batch_id", sa.String(32), nullable=False, index=True),
        sa.Column("source", sa.String(64), nullable=False, index=True),
        sa.Column("status", sa.String(16), nullable=False, server_default="pending", index=True),
        sa.Column("cleaned_content", sa.Text(), nullable=False, server_default=""),
        sa.Column("is_duplicate", sa.Boolean(), nullable=False, server_default=sa.text("0")),
        sa.Column("duplicate_of", sa.String(64), nullable=True),
        sa.Column("threat_level", sa.String(16), nullable=False, server_default="info", index=True),
        sa.Column("intent_level", sa.String(16), nullable=False, server_default="benign", index=True),
        sa.Column("intent_indicators_json", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("cheating_scenarios_json", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("threat_categories_json", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("entities_json", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("risk_score", sa.Float(), nullable=False, server_default="0", index=True),
        sa.Column("quality_score", sa.Float(), nullable=False, server_default="0"),
        sa.Column("crime_patterns_json", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("tech_chains_json", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("summary", sa.Text(), nullable=False, server_default=""),
        sa.Column("processing_time_ms", sa.Float(), nullable=False, server_default="0"),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now(), index=True),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
    )

    op.create_table(
        "alert_rules",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("name", sa.String(256), nullable=False),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("conditions_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("severity", sa.String(16), nullable=False, server_default="high", index=True),
        sa.Column("is_enabled", sa.Boolean(), nullable=False, server_default=sa.text("1"), index=True),
        sa.Column("cooldown_minutes", sa.Integer(), nullable=False, server_default="60"),
        sa.Column("last_triggered", sa.DateTime(), nullable=True),
        sa.Column("created_by", sa.String(128), nullable=False, server_default="system"),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now(), index=True),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("severity IN ('critical', 'high', 'medium', 'low', 'info')", name="ck_alert_rules_severity"),
    )

    op.create_table(
        "source_configs",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("source_id", sa.String(64), nullable=False, unique=True, index=True),
        sa.Column("name", sa.String(256), nullable=False),
        sa.Column("source_type", sa.String(32), nullable=False, index=True),
        sa.Column("priority", sa.String(16), nullable=False, server_default="medium", index=True),
        sa.Column("status", sa.String(16), nullable=False, server_default="active", index=True),
        sa.Column("interval_minutes", sa.Integer(), nullable=False, server_default="30"),
        sa.Column("max_results_per_cycle", sa.Integer(), nullable=False, server_default="50"),
        sa.Column("keywords_json", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("config_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("total_collected", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("total_errors", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("consecutive_errors", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_error", sa.Text(), nullable=False, server_default=""),
        sa.Column("last_collected_at", sa.DateTime(), nullable=True),
        sa.Column("rate_limit_until", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
    )

    op.create_table(
        "economic_impact",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("sector", sa.String(32), nullable=False, index=True),
        sa.Column("estimated_loss", sa.Float(), nullable=False, server_default="0"),
        sa.Column("affected_users", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("geographic_scope", sa.Text(), nullable=True),
        sa.Column("duration_days", sa.Integer(), nullable=False, server_default="30"),
        sa.Column("confidence", sa.Float(), nullable=False, server_default="0.5"),
        sa.Column("intelligence_source_ids", sa.Text(), nullable=True),
        sa.Column("threat_categories", sa.Text(), nullable=True),
        sa.Column("assessed_at", sa.DateTime(), nullable=False, server_default=sa.func.now(), index=True),
    )

    op.create_table(
        "market_transaction",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("sector", sa.String(32), nullable=False, index=True),
        sa.Column("tx_type", sa.String(16), nullable=False),
        sa.Column("amount", sa.Float(), nullable=False),
        sa.Column("price", sa.Float(), nullable=False),
        sa.Column("total_value", sa.Float(), nullable=False),
        sa.Column("fee", sa.Float(), nullable=False, server_default="0"),
        sa.Column("from_entity", sa.String(128), nullable=True),
        sa.Column("to_entity", sa.String(128), nullable=True),
        sa.Column("risk_score", sa.Float(), nullable=False, server_default="0"),
        sa.Column("intelligence_ids", sa.Text(), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("timestamp", sa.DateTime(), nullable=False, server_default=sa.func.now(), index=True),
    )

    op.create_table(
        "market_state",
        sa.Column("sector", sa.String(32), primary_key=True),
        sa.Column("sector_name", sa.String(64), nullable=False),
        sa.Column("price_index", sa.Float(), nullable=False, server_default="100"),
        sa.Column("volume_24h", sa.Float(), nullable=False, server_default="0"),
        sa.Column("volatility", sa.Float(), nullable=False, server_default="0.15"),
        sa.Column("trend", sa.String(16), nullable=False, server_default="stable"),
        sa.Column("risk_score", sa.Float(), nullable=False, server_default="0"),
        sa.Column("market_cap_estimate", sa.Float(), nullable=False, server_default="0"),
        sa.Column("active_entities", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_updated", sa.DateTime(), nullable=False, server_default=sa.func.now()),
    )

    op.create_table(
        "economic_alert",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("sector", sa.String(32), nullable=False, index=True),
        sa.Column("alert_type", sa.String(32), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False, server_default="medium"),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("related_intelligence_ids", sa.Text(), nullable=True),
        sa.Column("economic_impact_ids", sa.Text(), nullable=True),
        sa.Column("is_resolved", sa.Boolean(), nullable=False, server_default=sa.text("0")),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now(), index=True),
    )


def downgrade() -> None:
    op.drop_table("economic_alert")
    op.drop_table("market_state")
    op.drop_table("market_transaction")
    op.drop_table("economic_impact")
    op.drop_table("source_configs")
    op.drop_table("alert_rules")
    op.drop_table("pipeline_items")
    op.drop_table("pipeline_batches")
    op.drop_table("environment_configs")
    op.drop_table("ab_tests")
    op.drop_table("service_status")
    op.drop_table("deployment_records")
    op.drop_table("anomaly_records")
    op.drop_table("dashboard_configs")
    op.drop_table("analytics_results")
    op.drop_table("terminology")
    op.drop_table("translation_memory")
    op.drop_table("industry_configs")
    op.drop_table("generated_contents")
    op.drop_table("qa_conversations")
    op.drop_table("finetune_tasks")
    op.drop_table("preprocess_tasks")
    op.drop_table("industry_scene_configs")
    op.drop_table("prompt_templates")
    op.drop_table("analysis_result")
    op.drop_table("report")
    op.drop_table("pir_task")
    op.drop_table("pir")
    op.drop_table("audit_log")
    op.drop_table("notifications")
    op.drop_table("refresh_tokens")
    op.drop_table("token_blacklist")
    op.drop_table("users")
    op.drop_table("relation")
    op.drop_table("entity")
    op.drop_table("analyzed_intelligence")
    op.drop_table("cleaned_intelligence")
    op.drop_table("raw_intelligence")
