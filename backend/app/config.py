from __future__ import annotations

from functools import lru_cache

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

INSECURE_SECRETS = {"", "change-me", "changeme", "secret", "dev-secret-change-me-please-0123456789"}
INSECURE_PASSWORDS = {"", "admin", "password", "ChangeMe-Now-123!"}


class Settings(BaseSettings):
    # Later files override earlier ones: backend/.env wins over the repo-root .env.
    model_config = SettingsConfigDict(env_file=("../.env", ".env"), extra="ignore")

    app_name: str = "SentinelX"
    environment: str = "development"  # development | production
    enable_docs: bool = True

    database_url: str = "sqlite:///./sentinelx.db"

    secret_key: str = "dev-secret-change-me-please-0123456789"
    access_token_expire_minutes: int = 480
    cors_origins: str = "http://localhost:3000"
    trust_proxy_headers: bool = False  # true only when running behind Caddy/nginx/Render

    first_admin_username: str = "admin"
    first_admin_email: str = "admin@sentinelx.local"
    first_admin_password: str = "ChangeMe-Now-123!"

    # Detection / ML
    model_dir: str = "./data/models"
    ml_enabled: bool = True
    ml_min_train_samples: int = 200
    ml_min_score: float = 0.55
    ml_retrain_hours: int = 24
    ml_train_days: int = 30
    business_tz_offset_minutes: int = 330  # Asia/Kolkata; used for time-of-day features
    alert_cooldown_seconds: int = 3600
    auto_incident_min_severity: str = "high"
    history_row_limit: int = 20000
    max_batch_size: int = 1000

    # Threat intelligence
    abuseipdb_api_key: str = ""
    abuseipdb_max_lookups_per_batch: int = 10
    reputation_ttl_hours: int = 24
    threat_feed_urls: str = ""  # comma-separated plain-text IP/CIDR lists
    threat_feed_refresh_hours: int = 6

    # Alerts / notifications
    alert_webhook_url: str = ""
    notify_min_severity: str = "high"

    # Housekeeping
    retention_days: int = 90
    enable_simulator: bool = True
    login_rate_limit_attempts: int = 10
    login_rate_limit_window_seconds: int = 300

    @field_validator("database_url")
    @classmethod
    def _normalise_database_url(cls, value: str) -> str:
        # Some hosts hand out "postgres://", which SQLAlchemy 2 no longer accepts.
        if value.startswith("postgres://"):
            return "postgresql://" + value[len("postgres://") :]
        return value

    @property
    def is_production(self) -> bool:
        return self.environment.lower() == "production"

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip().rstrip("/") for o in self.cors_origins.split(",") if o.strip()]

    @property
    def feed_urls(self) -> list[str]:
        return [u.strip() for u in self.threat_feed_urls.split(",") if u.strip()]

    @property
    def sqlite(self) -> bool:
        return self.database_url.startswith("sqlite")

    def assert_production_safe(self) -> None:
        """Refuse to boot in production with placeholder secrets."""
        problems = []
        if self.secret_key in INSECURE_SECRETS or len(self.secret_key) < 32:
            problems.append("SECRET_KEY must be a random string of at least 32 characters")
        if self.first_admin_password in INSECURE_PASSWORDS or len(self.first_admin_password) < 12:
            problems.append("FIRST_ADMIN_PASSWORD must be changed (12+ characters)")
        if self.sqlite:
            problems.append("DATABASE_URL must point to PostgreSQL in production")
        if problems:
            raise RuntimeError("Unsafe production configuration:\n - " + "\n - ".join(problems))


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
