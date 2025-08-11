# Copyright 2025 PromptSentinel
# Licensed under the Elastic License 2.0; you may not use this file except
# in compliance with the Elastic License 2.0. You may obtain a copy of the
# License at https://www.elastic.co/licensing/elastic-license

"""Configuration settings management for PromptSentinel.

This module provides centralized configuration management using Pydantic
Settings. All configuration values can be set via environment variables
or a .env file, with sensible defaults for development.

Configuration categories:
- API: Server host, port, environment settings
- LLM Providers: API keys, models, and parameters for each provider
- Detection: Mode, thresholds, and feature toggles
- Security: Rate limits, input validation, allowed charsets
- Redis: Cache configuration (optional)
- Logging: Log levels, formats, and monitoring
- PII: Detection and redaction settings

Environment variables override default values, and all settings
are validated at startup.
"""

from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings with environment variable support.

    Manages all configuration for the PromptSentinel service.
    Values are loaded from environment variables or .env file,
    with validation and type conversion handled by Pydantic.

    All fields can be overridden via environment variables using
    the field name in uppercase (e.g., api_host -> API_HOST).
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        env_nested_delimiter="__",
    )

    # API Configuration
    api_host: str = Field(default="0.0.0.0")  # nosec B104 - Docker needs all interfaces
    api_port: int = Field(default=8080)
    api_env: Literal["development", "staging", "production"] = Field(default="development")
    debug: bool = Field(default=False)

    # LLM Provider Configuration
    llm_provider_order: str = Field(default="anthropic,openai,gemini")

    # Anthropic Configuration
    anthropic_api_key: str | None = Field(default=None)
    anthropic_model: str = Field(default="claude-3-haiku-20240307")
    anthropic_max_tokens: int = Field(default=1000)
    anthropic_temperature: float = Field(default=0.3)

    # OpenAI Configuration
    openai_api_key: str | None = Field(default=None)
    openai_model: str = Field(default="gpt-4-turbo-preview")
    openai_max_tokens: int = Field(default=1000)
    openai_temperature: float = Field(default=0.3)

    # Gemini Configuration
    gemini_api_key: str | None = Field(default=None)
    gemini_model: str = Field(default="gemini-1.5-flash")
    gemini_max_tokens: int = Field(default=1000)
    gemini_temperature: float = Field(default=0.3)

    # Redis Cache Configuration (Optional - system works without it)
    redis_enabled: bool = Field(default=False)
    redis_host: str = Field(default="localhost")
    redis_port: int = Field(default=6379)
    redis_db: int = Field(default=0)
    redis_password: str | None = Field(default=None)
    redis_ttl: int = Field(default=3600)  # Default TTL

    # Cache TTLs for different types (seconds)
    cache_ttl_llm: int = Field(default=3600)  # 1 hour for LLM results
    cache_ttl_detection: int = Field(default=600)  # 10 min for detection
    cache_ttl_pattern: int = Field(default=1800)  # 30 min for patterns
    cache_ttl_health: int = Field(default=60)  # 1 min for health checks

    # Detection Configuration
    detection_mode: Literal["strict", "moderate", "permissive"] = Field(default="strict")
    detection_timeout: float = Field(default=10.0)
    heuristic_enabled: bool = Field(default=True)
    llm_classification_enabled: bool = Field(default=True)
    confidence_threshold: float = Field(default=0.7)

    # Authentication Configuration
    auth_mode: Literal["none", "optional", "required"] = Field(default="optional")
    auth_enforce_https: bool = Field(default=False)
    auth_bypass_networks: str = Field(default="")
    auth_bypass_headers: str = Field(default="")
    auth_allow_localhost: bool = Field(default=True)
    auth_unauthenticated_rpm: int = Field(default=10)
    auth_unauthenticated_tpm: int = Field(default=1000)
    api_key_prefix: str = Field(default="psk_")
    api_key_length: int = Field(default=32)

    # Budget Configuration
    budget_hourly_limit: float = Field(default=10.0)
    budget_daily_limit: float = Field(default=100.0)
    budget_monthly_limit: float = Field(default=1000.0)
    budget_block_on_exceeded: bool = Field(default=True)
    budget_prefer_cache: bool = Field(default=True)

    # Rate Limiting Configuration
    rate_limit_requests_per_minute: int = Field(default=60)
    rate_limit_tokens_per_minute: int = Field(default=10000)
    rate_limit_client_requests_per_minute: int = Field(default=20)

    # Security Configuration
    max_prompt_length: int = Field(default=50000)
    rate_limit_per_ip: int = Field(default=1000)
    rate_limit_per_key: int = Field(default=10000)
    allowed_charsets: str = Field(default="utf-8,ascii")

    # Logging Configuration
    log_level: str = Field(default="INFO")
    log_format: Literal["json", "text"] = Field(default="json")
    enable_metrics: bool = Field(default=True)
    enable_tracing: bool = Field(default=False)

    # Corpus Management
    corpus_auto_update: bool = Field(default=False)
    corpus_update_interval: int = Field(default=86400)
    corpus_sources: str = Field(default="")

    # PII Detection Configuration
    pii_detection_enabled: bool = Field(default=True)
    pii_redaction_mode: Literal["mask", "remove", "hash", "reject", "pass-silent", "pass-alert"] = (
        Field(default="mask")
    )
    pii_types_to_detect: str = Field(default="all")
    pii_log_detected: bool = Field(default=False)
    pii_confidence_threshold: float = Field(default=0.7)

    # Custom PII Rules Configuration
    custom_pii_rules_path: str | None = Field(default="config/custom_pii_rules.yaml")
    custom_pii_rules_enabled: bool = Field(default=True)

    @property
    def llm_providers(self) -> list[str]:
        """Get list of LLM providers from comma-separated string."""
        return [p.strip() for p in self.llm_provider_order.split(",") if p.strip()]

    @property
    def allowed_charset_list(self) -> list[str]:
        """Get list of allowed charsets from comma-separated string."""
        return [c.strip() for c in self.allowed_charsets.split(",") if c.strip()]

    @property
    def auth_bypass_networks_list(self) -> list[str]:
        """Get list of bypass networks from comma-separated string."""
        if not self.auth_bypass_networks:
            return []
        return [n.strip() for n in self.auth_bypass_networks.split(",") if n.strip()]

    @property
    def auth_bypass_headers_dict(self) -> dict:
        """Get bypass headers as dictionary from key:value,key:value format."""
        if not self.auth_bypass_headers:
            return {}
        result = {}
        for pair in self.auth_bypass_headers.split(","):
            if ":" in pair:
                key, value = pair.split(":", 1)
                result[key.strip()] = value.strip()
        return result

    @property
    def corpus_sources_list(self) -> list[str]:
        """Get list of corpus sources from comma-separated string."""
        if not self.corpus_sources:
            return []
        return [s.strip() for s in self.corpus_sources.split(",") if s.strip()]

    @property
    def pii_types_list(self) -> list[str]:
        """Get list of PII types from comma-separated string."""
        if self.pii_types_to_detect.lower() == "all":
            return ["all"]
        return [t.strip() for t in self.pii_types_to_detect.split(",") if t.strip()]

    @property
    def redis_url(self) -> str:
        """Build Redis connection URL from components.

        Returns:
            Redis URL in format redis://[password@]host:port/db
        """
        if self.redis_password:
            return f"redis://:{self.redis_password}@{self.redis_host}:{self.redis_port}/{self.redis_db}"
        return f"redis://{self.redis_host}:{self.redis_port}/{self.redis_db}"

    def get_provider_config(self, provider: str) -> dict:
        """Get configuration for a specific LLM provider.

        Args:
            provider: Provider name (anthropic, openai, or gemini)

        Returns:
            Dictionary with provider-specific configuration including
            api_key, model, max_tokens, and temperature
        """
        configs = {
            "anthropic": {
                "api_key": self.anthropic_api_key,
                "model": self.anthropic_model,
                "max_tokens": self.anthropic_max_tokens,
                "temperature": self.anthropic_temperature,
            },
            "openai": {
                "api_key": self.openai_api_key,
                "model": self.openai_model,
                "max_tokens": self.openai_max_tokens,
                "temperature": self.openai_temperature,
            },
            "gemini": {
                "api_key": self.gemini_api_key,
                "model": self.gemini_model,
                "max_tokens": self.gemini_max_tokens,
                "temperature": self.gemini_temperature,
            },
        }
        return configs.get(provider, {})


# Create global settings instance
settings = Settings()


def get_settings() -> Settings:
    """Get the global settings instance.

    This function is used for dependency injection in FastAPI
    and provides a single point of configuration access.

    Returns:
        The global Settings instance
    """
    return settings
