# Elastic License 2.0
#
# Copyright (c) 2024-present, PromptSentinel
#
# This source code is licensed under the Elastic License 2.0 found in the
# LICENSE file in the root directory of this source tree.

"""Threat intelligence data models."""

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, HttpUrl


class FeedType(str, Enum):
    """Types of threat intelligence feeds."""

    JSON = "json"
    CSV = "csv"
    STIX = "stix"  # Structured Threat Information Expression
    MISP = "misp"  # Malware Information Sharing Platform
    RSS = "rss"
    API = "api"
    GITHUB = "github"
    WEBHOOK = "webhook"


class ThreatSeverity(str, Enum):
    """Threat severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AttackTechnique(str, Enum):
    """Known prompt injection attack techniques."""

    JAILBREAK = "jailbreak"
    ROLE_PLAY = "role_play"
    INSTRUCTION_OVERRIDE = "instruction_override"
    CONTEXT_MANIPULATION = "context_manipulation"
    ENCODING_OBFUSCATION = "encoding_obfuscation"
    PROMPT_LEAKING = "prompt_leaking"
    INDIRECT_INJECTION = "indirect_injection"
    MULTI_STEP = "multi_step"
    ADVERSARIAL = "adversarial"
    UNKNOWN = "unknown"


class ThreatIndicator(BaseModel):
    """Individual threat indicator from a feed."""

    # Identification
    id: str = Field(..., description="Unique identifier")
    feed_id: str = Field(..., description="Source feed ID")

    # Threat details
    pattern: str = Field(..., description="Attack pattern or regex")
    technique: AttackTechnique = Field(
        default=AttackTechnique.UNKNOWN, description="Attack technique category"
    )
    severity: ThreatSeverity = Field(
        default=ThreatSeverity.MEDIUM, description="Threat severity level"
    )
    confidence: float = Field(default=0.7, ge=0.0, le=1.0, description="Confidence score")

    # Metadata
    description: str = Field(..., description="Human-readable description")
    tags: list[str] = Field(default_factory=list, description="Associated tags")
    iocs: list[str] = Field(default_factory=list, description="Indicators of compromise")
    mitre_tactics: list[str] = Field(default_factory=list, description="MITRE ATT&CK tactics")

    # Temporal data
    first_seen: datetime = Field(
        default_factory=datetime.utcnow, description="First observation time"
    )
    last_seen: datetime = Field(
        default_factory=datetime.utcnow, description="Last observation time"
    )
    expires_at: datetime | None = Field(None, description="Expiration time for this indicator")

    # Validation and testing
    test_cases: list[str] = Field(default_factory=list, description="Example attack strings")
    false_positive_rate: float | None = Field(None, description="Known false positive rate")

    # Source attribution
    source_url: HttpUrl | None = Field(None, description="Source URL")
    source_author: str | None = Field(None, description="Author/researcher")
    reference_urls: list[HttpUrl] = Field(default_factory=list, description="Reference URLs")


class ThreatFeed(BaseModel):
    """Threat intelligence feed configuration."""

    # Identification
    id: str = Field(..., description="Unique feed identifier")
    name: str = Field(..., description="Feed name")
    description: str = Field(..., description="Feed description")

    # Configuration
    type: FeedType = Field(..., description="Feed type")
    url: HttpUrl | None = Field(None, description="Feed URL")
    api_key: str | None = Field(None, description="API key if required")
    headers: dict[str, str] = Field(default_factory=dict, description="HTTP headers")

    # Processing
    enabled: bool = Field(default=True, description="Feed enabled status")
    priority: int = Field(default=5, ge=1, le=10, description="Processing priority (1=highest)")
    refresh_interval: int = Field(default=3600, description="Refresh interval in seconds")

    # Parsing configuration
    parser_config: dict[str, Any] = Field(
        default_factory=dict, description="Parser-specific configuration"
    )
    field_mappings: dict[str, str] = Field(default_factory=dict, description="Field name mappings")
    filters: dict[str, Any] = Field(default_factory=dict, description="Data filters")

    # Quality control
    auto_validate: bool = Field(default=True, description="Automatically validate patterns")
    min_confidence: float = Field(default=0.5, description="Minimum confidence threshold")
    max_age_days: int = Field(default=30, description="Maximum indicator age in days")

    # Statistics
    last_fetch: datetime | None = Field(None, description="Last successful fetch")
    last_error: str | None = Field(None, description="Last error message")
    total_indicators: int = Field(default=0, description="Total indicators from this feed")
    active_indicators: int = Field(default=0, description="Currently active indicators")

    # Metadata
    created_at: datetime = Field(default_factory=datetime.utcnow, description="Feed creation time")
    updated_at: datetime = Field(default_factory=datetime.utcnow, description="Last update time")
    tags: list[str] = Field(default_factory=list, description="Feed tags")


class FeedStatistics(BaseModel):
    """Statistics for a threat feed."""

    feed_id: str
    total_fetches: int = 0
    successful_fetches: int = 0
    failed_fetches: int = 0
    indicators_received: int = 0
    indicators_accepted: int = 0
    indicators_rejected: int = 0
    patterns_extracted: int = 0
    false_positives_reported: int = 0
    true_positives_confirmed: int = 0
    average_confidence: float = 0.0
    last_fetch_duration_ms: int | None = None
    next_fetch_at: datetime | None = None
