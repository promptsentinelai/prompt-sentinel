"""Data models for PromptSentinel SDK."""

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Role(str, Enum):
    """Message role in conversation."""

    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"


class Verdict(str, Enum):
    """Detection verdict."""

    ALLOW = "allow"
    BLOCK = "block"
    FLAG = "flag"
    STRIP = "strip"
    REDACT = "redact"


class DetectionMode(str, Enum):
    """Detection sensitivity mode."""

    STRICT = "strict"
    MODERATE = "moderate"
    PERMISSIVE = "permissive"


class Message(BaseModel):
    """Conversation message."""

    role: Role
    content: str


class DetectionReason(BaseModel):
    """Detailed reason for detection verdict."""

    category: str
    description: str
    confidence: float
    source: str
    patterns_matched: list[str] = Field(default_factory=list)


class DetectionRequest(BaseModel):
    """Request for detection endpoint."""

    messages: list[Message] | None = None
    prompt: str | None = None
    check_format: bool = True
    use_cache: bool = True
    detection_mode: DetectionMode | None = None


class DetectionResponse(BaseModel):
    """Response from detection endpoint."""

    verdict: Verdict
    confidence: float
    reasons: list[DetectionReason] = Field(default_factory=list)
    categories: list[str] = Field(default_factory=list)
    modified_prompt: str | None = None
    pii_detected: bool = False
    pii_types: list[str] = Field(default_factory=list)
    format_issues: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    processing_time_ms: float
    timestamp: datetime
    metadata: dict[str, Any] = Field(default_factory=dict)

    # V3 specific fields
    routing_metadata: dict[str, Any] | None = None


class BatchDetectionRequest(BaseModel):
    """Request for batch detection."""

    prompts: list[dict[str, str]]


class BatchDetectionResponse(BaseModel):
    """Response from batch detection."""

    results: list[dict[str, Any]]
    processed: int
    timestamp: datetime


class UsageMetrics(BaseModel):
    """API usage metrics."""

    request_count: int
    token_usage: dict[str, int]
    cost_breakdown: dict[str, float]
    provider_stats: dict[str, Any]
    time_period: str


class BudgetStatus(BaseModel):
    """Budget status information."""

    current_usage: dict[str, float]
    budget_limits: dict[str, float]
    alerts: list[dict[str, Any]]
    projections: dict[str, float]


class ComplexityAnalysis(BaseModel):
    """Prompt complexity analysis."""

    complexity_level: str
    complexity_score: float
    metrics: dict[str, float]
    risk_indicators: list[str]
    recommendations: list[str]


class HealthStatus(BaseModel):
    """Service health status."""

    status: str
    version: str
    providers: dict[str, dict[str, Any]]
    cache: dict[str, Any]
    detection_methods: list[str]


# Exceptions
class PromptSentinelError(Exception):
    """Base exception for PromptSentinel SDK."""

    pass


class AuthenticationError(PromptSentinelError):
    """Authentication failed."""

    pass


class RateLimitError(PromptSentinelError):
    """Rate limit exceeded."""

    def __init__(self, message: str, retry_after: int | None = None):
        super().__init__(message)
        self.retry_after = retry_after


class ValidationError(PromptSentinelError):
    """Request validation failed."""

    pass


class ServiceUnavailableError(PromptSentinelError):
    """Service temporarily unavailable."""

    pass
