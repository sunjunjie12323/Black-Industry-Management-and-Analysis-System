import json
import logging
import secrets
from pathlib import Path
from typing import ClassVar, Dict, List, Set
from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=str(Path(__file__).resolve().parent.parent / ".env"),
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    LLM_API_KEY: str = ""
    LLM_BASE_URL: str = ""
    LLM_MODEL_NAME: str = ""
    LLM_TEMPERATURE: float = 0.0
    LLM_MAX_TOKENS: int = 0
    LLM_TEMPERATURE_ANALYSIS: float = 0.1
    LLM_TEMPERATURE_CREATIVE: float = 0.3
    LLM_TEMPERATURE_NARRATIVE: float = 0.4
    LLM_TEMPERATURE_DEFAULT: float = 0.2
    LLM_MAX_TOKENS_LONG: int = 2048
    LLM_MAX_TOKENS_MEDIUM: int = 1024
    LLM_MAX_TOKENS_SHORT: int = 512
    LLM_MAX_TOKENS_BRIEF: int = 64
    LLM_MAX_TOKENS_MINIMAL: int = 20

    CONFIDENCE_HIGH: float = 0.8
    CONFIDENCE_MEDIUM: float = 0.6
    CONFIDENCE_LOW: float = 0.3
    CONFIDENCE_FALLBACK: float = 0.5

    DEEPSEEK_BASE_MODEL: str = "deepseek-ai/deepseek-llm-7b-chat"
    DEEPSEEK_R1_MODEL: str = "deepseek-ai/DeepSeek-R1-Distill-Qwen-7B"
    DEEPSEEK_CODER_MODEL: str = "deepseek-ai/deepseek-coder-6.7b-instruct"

    DATABASE_URL: str = "sqlite+aiosqlite:///./threat_intel.db"

    CHROMA_PERSIST_DIR: str = "./chroma_data"
    LOG_LEVEL: str = "INFO"
    CORS_ORIGINS: str = '["http://localhost:5173","http://localhost:8000","http://127.0.0.1:8000"]'

    SECRET_KEY: str = ""
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24
    ALGORITHM: str = "HS256"
    RATE_LIMIT_PER_MINUTE: int = 60
    MAX_CONCURRENT_TASKS: int = 3

    DEFAULT_ADMIN_USERNAME: str = "admin"
    DEFAULT_ADMIN_PASSWORD: str = ""

    TELEGRAM_BOT_TOKEN: str = ""
    ALIENVAULT_OTX_KEY: str = ""
    VIRUSTOTAL_API_KEY: str = ""
    ABUSE_CH_AUTH_KEY: str = ""
    ABUSEIPDB_API_KEY: str = ""
    THREATBOOK_API_KEY: str = ""
    QIANXIN_API_KEY: str = ""

    REDIS_URL: str = ""
    REDIS_CACHE_TTL: int = 300
    REDIS_RATE_LIMIT_PREFIX: str = "ratelimit:"
    REDIS_CACHE_PREFIX: str = "cache:"

    OTEL_EXPORTER_OTLP_ENDPOINT: str = ""
    OTEL_TRACES_SAMPLER: str = "parentbased_traceidratio"
    OTEL_TRACES_SAMPLER_ARG: float = 0.1

    ENVIRONMENT: str = "development"
    SEED_DATABASE: bool = False
    DB_POOL_SIZE: int = 20
    DB_MAX_OVERFLOW: int = 10
    DB_POOL_TIMEOUT: int = 30
    DB_POOL_RECYCLE: int = 3600
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    SESSION_EXPIRY_DAYS: int = 7
    WEBHOOK_NOTIFICATION_URLS: str = ""
    MAX_UPLOAD_SIZE_MB: int = 100
    API_VERSION: str = "v1"
    LOG_RETENTION_DAYS: int = 30

    BACKUP_INTERVAL_SECONDS: int = 21600
    BACKUP_RETENTION_COUNT: int = 7
    MAX_LOGIN_FAILS: int = 5
    LOCKOUT_MINUTES: int = 30
    PASSWORD_MIN_LENGTH: int = 8
    PASSWORD_REQUIRE_UPPER: bool = True
    PASSWORD_REQUIRE_LOWER: bool = True
    PASSWORD_REQUIRE_DIGIT: bool = True
    PASSWORD_REQUIRE_SPECIAL: bool = True
    SESSION_TIMEOUT_MINUTES: int = 120
    MAX_CONCURRENT_SESSIONS: int = 5
    CLEANUP_INTERVAL_SECONDS: int = 300
    MAX_TRACKED_IPS: int = 10000
    ATTEMPT_TTL_SECONDS: int = 3600
    IP_RATE_LIMIT: int = 20
    IP_RATE_WINDOW: int = 300
    BRUTE_FORCE_BACKOFF_JSON: str = '{"1":1,"2":5,"3":15}'
    REDOC_CDN_URL: str = "https://cdn.bootcdn.net/ajax/libs/redoc/2.1.3/redoc.standalone.min.js"
    APP_VERSION: str = "2.3.0"
    PROGRESS_MAX_AGE_SECONDS: int = 3600
    THREAT_KEYWORDS_JSON: str = ""
    RANDOM_SEED: int = 42
    RETENTION_DAYS_PUBLIC: int = 90
    RETENTION_DAYS_INTERNAL: int = 180
    RETENTION_DAYS_CONFIDENTIAL: int = 365
    RETENTION_DAYS_RESTRICTED: int = 365
    TRANSLATION_PRIORITY_MAP_JSON: str = ""
    ECONOMIC_LOSS_CRITICAL_MULTIPLIER: int = 50
    ECONOMIC_LOSS_HIGH_MULTIPLIER: int = 10
    ECONOMIC_BASE_LOSS_JSON: str = ''
    ECONOMIC_BASE_AFFECTED_USERS_JSON: str = ''
    ECONOMIC_RISK_MULTIPLIERS_JSON: str = ''
    ORGANISM_HALF_LIFE_JSON: str = ''
    ORGANISM_VITALITY_RANGE_JSON: str = ''
    ORGANISM_EXPECTED_MENTIONS_JSON: str = ''
    TEMPORAL_HALF_LIVES_JSON: str = ''
    TEMPORAL_THREAT_KEYWORDS_JSON: str = ''
    ALERT_RULES_JSON: str = ''
    MITRE_TRANSITIONS_JSON: str = ''
    MITRE_ENTITY_TACTIC_JSON: str = ''
    SOURCE_SCHEDULER_SOURCES_JSON: str = ''
    FINETUNE_MODELS_JSON: str = ''
    FINETUNE_METHODS_JSON: str = ''
    SMARTQA_INDUSTRIES_JSON: str = ''
    FORBIDDEN_PASSWORDS: str = '["password","12345678","qwerty12","abc12345","password1","iloveyou","admin123","welcome1","123456789","password123","1234567890","passw0rd","qwerty123","admin@123"]'

    # Cache TTL settings
    API_KEY_CACHE_TTL: int = 60
    DASHBOARD_CACHE_TTL: int = 30
    CSRF_TOKEN_EXPIRY_SECONDS: int = 3600

    # Alert settings
    ALERT_RULE_DEFAULT_COOLDOWN_MINUTES: int = 60
    ALERT_ACTIVE_LIMIT: int = 50
    ALERT_TREND_DEFAULT_DAYS: int = 7
    ALERT_TREND_MAX_DAYS: int = 90

    # Intelligence query settings
    INTELLIGENCE_DEFAULT_LIMIT: int = 50
    INTELLIGENCE_MAX_LIMIT: int = 200
    DASHBOARD_RECENT_LIMIT: int = 10
    TREND_DEFAULT_DAYS: int = 7
    TREND_MAX_DAYS: int = 30

    # Pipeline and timeout settings
    PIPELINE_TIMEOUT_SECONDS: float = 10.0
    SHUTDOWN_DRAIN_TIMEOUT_SECONDS: float = 30.0
    SHUTDOWN_SERVICES_TIMEOUT_SECONDS: float = 15.0
    SEED_TIMEOUT_SECONDS: float = 15.0
    SCHEDULER_STOP_TIMEOUT_SECONDS: float = 10.0
    FLUSH_WORKER_STOP_TIMEOUT_SECONDS: float = 10.0

    WEAK_PASSWORDS: ClassVar[set] = {"admin", "password", "admin123", "123456", "admin@123", "root", "test", "changeme"}

    @model_validator(mode="after")
    def validate_config(self) -> "Settings":
        logger = logging.getLogger(__name__)
        errors = []
        if not self.SECRET_KEY or len(self.SECRET_KEY) < 32:
            if self.is_production:
                errors.append("SECRET_KEY must be set and at least 32 characters in production")
            else:
                logger.warning("SECRET_KEY is not set or too short; auto-generated keys are insecure for production")
        if not self.DATABASE_URL:
            self.DATABASE_URL = "sqlite+aiosqlite:///./threat_intel.db"
        if self.is_production and self.DATABASE_URL.startswith("sqlite"):
            errors.append("SQLite is not supported in production; use PostgreSQL (DATABASE_URL=postgresql+asyncpg://...)")
        if not self.LLM_API_KEY:
            if self.is_production:
                errors.append("LLM_API_KEY is required in production")
            else:
                logger.warning("LLM_API_KEY is not set; LLM features will be unavailable")
        if not self.LLM_BASE_URL:
            if self.is_production:
                errors.append("LLM_BASE_URL is required in production")
            else:
                logger.warning("LLM_BASE_URL is not set; LLM features will be unavailable")
        if not self.DEFAULT_ADMIN_PASSWORD:
            if self.is_production:
                errors.append("DEFAULT_ADMIN_PASSWORD must be set in production")
            else:
                logger.warning("DEFAULT_ADMIN_PASSWORD is empty; set a password before deployment")
        elif self.DEFAULT_ADMIN_PASSWORD.lower() in self.WEAK_PASSWORDS:
            if self.is_production:
                errors.append("DEFAULT_ADMIN_PASSWORD is too weak for production")
            else:
                logger.warning("DEFAULT_ADMIN_PASSWORD is a common weak password; change before deployment")
        if self.is_production:
            if self.CORS_ORIGINS == '["http://localhost:5173"]':
                logger.warning("CORS_ORIGINS allows localhost in production; restrict to actual domains")
            if self.ACCESS_TOKEN_EXPIRE_MINUTES > 60 * 8:
                logger.warning("ACCESS_TOKEN_EXPIRE_MINUTES exceeds 8 hours in production")
        if errors:
            raise ValueError("Configuration errors: " + "; ".join(errors))
        return self

    @property
    def secret_key_resolved(self) -> str:
        if self.SECRET_KEY and len(self.SECRET_KEY) >= 32:
            return self.SECRET_KEY
        if self.is_production:
            raise ValueError("SECRET_KEY must be explicitly set via environment variable in production environment")
        logger = logging.getLogger(__name__)
        logger.warning("SECRET_KEY is not set or too short; auto-generated key will be used (insecure for production)")
        key_file = Path(__file__).resolve().parent.parent / ".secret_key"
        if key_file.exists():
            existing = key_file.read_text().strip()
            if len(existing) >= 32:
                return existing
        generated = secrets.token_urlsafe(48)
        key_file.write_text(generated)
        try:
            import stat
            import os
            os.chmod(str(key_file), stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass
        return generated

    @property
    def cors_origins_list(self) -> List[str]:
        try:
            parsed = json.loads(self.CORS_ORIGINS)
            if parsed == ["*"]:
                return ["*"]
            return parsed
        except (json.JSONDecodeError, TypeError):
            return ["http://localhost:5173"]

    @property
    def forbidden_passwords_set(self) -> Set[str]:
        try:
            return set(json.loads(self.FORBIDDEN_PASSWORDS))
        except (json.JSONDecodeError, TypeError):
            return set()

    @property
    def brute_force_backoff(self) -> Dict[int, int]:
        try:
            raw = json.loads(self.BRUTE_FORCE_BACKOFF_JSON)
            return {int(k): int(v) for k, v in raw.items()}
        except (json.JSONDecodeError, TypeError, ValueError):
            return {1: 1, 2: 5, 3: 15}

    @property
    def redis_enabled(self) -> bool:
        return bool(self.REDIS_URL)

    @property
    def retention_days_map(self) -> Dict[str, int]:
        return {
            "PUBLIC": self.RETENTION_DAYS_PUBLIC,
            "INTERNAL": self.RETENTION_DAYS_INTERNAL,
            "CONFIDENTIAL": self.RETENTION_DAYS_CONFIDENTIAL,
            "RESTRICTED": self.RETENTION_DAYS_RESTRICTED,
        }

    @property
    def translation_priority_map(self) -> Dict[str, str]:
        if self.TRANSLATION_PRIORITY_MAP_JSON:
            try:
                return json.loads(self.TRANSLATION_PRIORITY_MAP_JSON)
            except (json.JSONDecodeError, TypeError):
                pass
        return {}

    @property
    def is_postgresql(self) -> bool:
        return self.DATABASE_URL.startswith("postgresql")

    @property
    def is_production(self) -> bool:
        return self.ENVIRONMENT == "production"

    @property
    def is_staging(self) -> bool:
        return self.ENVIRONMENT == "staging"

    @property
    def webhook_urls_list(self) -> List[str]:
        if not self.WEBHOOK_NOTIFICATION_URLS:
            return []
        try:
            return json.loads(self.WEBHOOK_NOTIFICATION_URLS)
        except (json.JSONDecodeError, TypeError):
            return [u.strip() for u in self.WEBHOOK_NOTIFICATION_URLS.split(",") if u.strip()]


settings = Settings()
