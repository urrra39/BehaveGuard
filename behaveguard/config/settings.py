"""Configuration system for BehaveGuard.

Settings are layered with the following precedence (highest wins):

1. Explicit keyword arguments passed to :class:`Settings`.
2. Environment variables prefixed ``BEHAVEGUARD_`` (nested via ``__``), e.g.
   ``BEHAVEGUARD_API__PORT=9000`` or ``BEHAVEGUARD_WEBHOOK_URL=https://...``.
3. A user YAML file pointed to by ``BEHAVEGUARD_CONFIG``.
4. The packaged :mod:`behaveguard.config` ``defaults.yaml``.
5. Field defaults defined on the models below.

All sections are strongly typed so that the rest of the codebase can rely on
attribute access (``settings.storage.backend``) instead of dictionary lookups.
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional, Tuple, Type

import yaml
from pydantic import BaseModel, Field
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
)

# Packaged default configuration shipped alongside this module.
DEFAULTS_PATH = Path(__file__).resolve().parent / "defaults.yaml"


# --------------------------------------------------------------------------- #
# Section models
# --------------------------------------------------------------------------- #
class CollectionSettings(BaseModel):
    """eBPF ring-buffer collection tuning."""

    ring_buffer_size_mb: int = 256
    event_batch_size: int = 1000
    poll_interval_ms: int = 100


class FeatureSettings(BaseModel):
    """Sliding-window feature extraction parameters."""

    window_seconds: int = 30
    sequence_length: int = 20
    syscall_ngram_n: int = 2


class ModelSettings(BaseModel):
    """ML model architecture and training hyper-parameters."""

    hidden_dim: int = 128
    latent_dim: int = 32
    num_lstm_layers: int = 2
    epochs: int = 100
    learning_rate: float = 0.001
    batch_size: int = 32


class ScoringSettings(BaseModel):
    """Ensemble weighting and alert thresholds."""

    lstm_weight: float = 0.6
    vae_weight: float = 0.4
    alert_threshold_high: int = 70
    alert_threshold_critical: int = 90


class AlertSettings(BaseModel):
    """Alert routing, deduplication, and rate limiting."""

    dedup_window_seconds: int = 300
    max_alerts_per_minute: int = 10
    channels: List[Dict[str, Any]] = Field(
        default_factory=lambda: [
            {"type": "webhook", "url": ""},
            {"type": "syslog", "enabled": True},
        ]
    )


class ApiSettings(BaseModel):
    """FastAPI server bind settings."""

    host: str = "0.0.0.0"
    port: int = 8888


class DashboardSettings(BaseModel):
    """Dash dashboard bind and refresh settings."""

    host: str = "0.0.0.0"
    port: int = 8050
    update_interval_ms: int = 5000


class StorageSettings(BaseModel):
    """Event/alert persistence settings."""

    backend: Literal["sqlite", "influxdb"] = "sqlite"
    sqlite_path: str = "/var/lib/behaveguard/events.db"
    retention_days: int = 30


# --------------------------------------------------------------------------- #
# YAML settings source
# --------------------------------------------------------------------------- #
def _read_yaml(path: Path) -> Dict[str, Any]:
    """Load a YAML file into a dict, returning ``{}`` for missing/empty files."""
    if not path.is_file():
        return {}
    with path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle)
    return data or {}


def _deep_merge(base: Dict[str, Any], overlay: Dict[str, Any]) -> Dict[str, Any]:
    """Recursively merge ``overlay`` onto ``base`` without mutating either."""
    result = dict(base)
    for key, value in overlay.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


class YamlConfigSource(PydanticBaseSettingsSource):
    """Pydantic settings source that feeds values from the packaged defaults and an
    optional user override file (``BEHAVEGUARD_CONFIG``)."""

    def get_field_value(self, field: Any, field_name: str) -> Tuple[Any, str, bool]:
        # Whole-document source: per-field extraction is unused.
        return None, "", False

    def __call__(self) -> Dict[str, Any]:
        merged = _read_yaml(DEFAULTS_PATH)
        user_path = os.environ.get("BEHAVEGUARD_CONFIG")
        if user_path:
            merged = _deep_merge(merged, _read_yaml(Path(user_path)))
        return merged


# --------------------------------------------------------------------------- #
# Top-level settings
# --------------------------------------------------------------------------- #
class Settings(BaseSettings):
    """Root settings object for BehaveGuard."""

    model_config = SettingsConfigDict(
        env_prefix="BEHAVEGUARD_",
        env_nested_delimiter="__",
        extra="ignore",
        case_sensitive=False,
    )

    log_level: str = "INFO"
    webhook_url: Optional[str] = None

    collection: CollectionSettings = Field(default_factory=CollectionSettings)
    features: FeatureSettings = Field(default_factory=FeatureSettings)
    models: ModelSettings = Field(default_factory=ModelSettings)
    scoring: ScoringSettings = Field(default_factory=ScoringSettings)
    alerts: AlertSettings = Field(default_factory=AlertSettings)
    api: ApiSettings = Field(default_factory=ApiSettings)
    dashboard: DashboardSettings = Field(default_factory=DashboardSettings)
    storage: StorageSettings = Field(default_factory=StorageSettings)

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: Type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> Tuple[PydanticBaseSettingsSource, ...]:
        # Order = precedence (first wins): explicit kwargs > env > .env > yaml.
        return (
            init_settings,
            env_settings,
            dotenv_settings,
            YamlConfigSource(settings_cls),
            file_secret_settings,
        )

    @property
    def data_dir(self) -> Path:
        """Directory that holds the SQLite DB and other persisted state."""
        return Path(self.storage.sqlite_path).resolve().parent

    @property
    def effective_webhook_url(self) -> Optional[str]:
        """Webhook URL from the top-level env var, falling back to the channel config."""
        if self.webhook_url:
            return self.webhook_url
        for channel in self.alerts.channels:
            if channel.get("type") == "webhook" and channel.get("url"):
                return str(channel["url"])
        return None


def load_settings(config_path: Optional[str] = None) -> Settings:
    """Build a fresh :class:`Settings`, optionally from an explicit YAML path.

    Passing ``config_path`` sets ``BEHAVEGUARD_CONFIG`` for the duration of the
    load so the YAML source picks it up.
    """
    if config_path is not None:
        os.environ["BEHAVEGUARD_CONFIG"] = config_path
    return Settings()


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return a process-wide cached :class:`Settings` instance."""
    return Settings()
