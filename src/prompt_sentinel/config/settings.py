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

from typing import List, Literal, Optional
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field, field_validator


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
    api_host: str = Field(default="0.0.0.0", env="API_HOST")
    api_port: int = Field(default=8080, env="API_PORT")
    api_env: Literal["development", "staging", "production"] = Field(
        default="development", env="API_ENV"
    )
    debug: bool = Field(default=False, env="DEBUG")
    
    # LLM Provider Configuration  
    llm_provider_order: str = Field(
        default="anthropic,openai,gemini"
    )
    
    # Anthropic Configuration
    anthropic_api_key: Optional[str] = Field(default=None, env="ANTHROPIC_API_KEY")
    anthropic_model: str = Field(
        default="claude-3-haiku-20240307", env="ANTHROPIC_MODEL"
    )
    anthropic_max_tokens: int = Field(default=1000, env="ANTHROPIC_MAX_TOKENS")
    anthropic_temperature: float = Field(default=0.3, env="ANTHROPIC_TEMPERATURE")
    
    # OpenAI Configuration
    openai_api_key: Optional[str] = Field(default=None, env="OPENAI_API_KEY")
    openai_model: str = Field(default="gpt-4-turbo-preview", env="OPENAI_MODEL")
    openai_max_tokens: int = Field(default=1000, env="OPENAI_MAX_TOKENS")
    openai_temperature: float = Field(default=0.3, env="OPENAI_TEMPERATURE")
    
    # Gemini Configuration
    gemini_api_key: Optional[str] = Field(default=None, env="GEMINI_API_KEY")
    gemini_model: str = Field(default="gemini-1.5-flash", env="GEMINI_MODEL")
    gemini_max_tokens: int = Field(default=1000, env="GEMINI_MAX_TOKENS")
    gemini_temperature: float = Field(default=0.3, env="GEMINI_TEMPERATURE")
    
    # Redis Configuration
    redis_enabled: bool = Field(default=False, env="REDIS_ENABLED")
    redis_host: str = Field(default="localhost", env="REDIS_HOST")
    redis_port: int = Field(default=6379, env="REDIS_PORT")
    redis_db: int = Field(default=0, env="REDIS_DB")
    redis_password: Optional[str] = Field(default=None, env="REDIS_PASSWORD")
    redis_ttl: int = Field(default=3600, env="REDIS_TTL")
    
    # Detection Configuration
    detection_mode: Literal["strict", "moderate", "permissive"] = Field(
        default="strict", env="DETECTION_MODE"
    )
    detection_timeout: float = Field(default=10.0, env="DETECTION_TIMEOUT")
    heuristic_enabled: bool = Field(default=True, env="HEURISTIC_ENABLED")
    llm_classification_enabled: bool = Field(default=True, env="LLM_CLASSIFICATION_ENABLED")
    confidence_threshold: float = Field(default=0.7, env="CONFIDENCE_THRESHOLD")
    
    # Security Configuration
    max_prompt_length: int = Field(default=50000, env="MAX_PROMPT_LENGTH")
    rate_limit_per_ip: int = Field(default=1000, env="RATE_LIMIT_PER_IP")
    rate_limit_per_key: int = Field(default=10000, env="RATE_LIMIT_PER_KEY")
    allowed_charsets: str = Field(
        default="utf-8,ascii"
    )
    
    # Logging Configuration
    log_level: str = Field(default="INFO", env="LOG_LEVEL")
    log_format: Literal["json", "text"] = Field(default="json", env="LOG_FORMAT")
    enable_metrics: bool = Field(default=True, env="ENABLE_METRICS")
    enable_tracing: bool = Field(default=False, env="ENABLE_TRACING")
    
    # Corpus Management
    corpus_auto_update: bool = Field(default=False, env="CORPUS_AUTO_UPDATE")
    corpus_update_interval: int = Field(default=86400, env="CORPUS_UPDATE_INTERVAL")
    corpus_sources: str = Field(default="")
    
    # PII Detection Configuration
    pii_detection_enabled: bool = Field(default=True, env="PII_DETECTION_ENABLED")
    pii_redaction_mode: Literal["mask", "remove", "hash", "reject", "pass-silent", "pass-alert"] = Field(
        default="mask", env="PII_REDACTION_MODE"
    )
    pii_types_to_detect: str = Field(
        default="all"
    )
    pii_log_detected: bool = Field(default=False, env="PII_LOG_DETECTED")
    pii_confidence_threshold: float = Field(default=0.7, env="PII_CONFIDENCE_THRESHOLD")
    
    @property
    def llm_providers(self) -> List[str]:
        """Get list of LLM providers from comma-separated string."""
        return [p.strip() for p in self.llm_provider_order.split(",") if p.strip()]
    
    @property
    def allowed_charset_list(self) -> List[str]:
        """Get list of allowed charsets from comma-separated string."""
        return [c.strip() for c in self.allowed_charsets.split(",") if c.strip()]
    
    @property
    def corpus_sources_list(self) -> List[str]:
        """Get list of corpus sources from comma-separated string."""
        if not self.corpus_sources:
            return []
        return [s.strip() for s in self.corpus_sources.split(",") if s.strip()]
    
    @property
    def pii_types_list(self) -> List[str]:
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