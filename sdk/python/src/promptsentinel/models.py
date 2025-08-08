"""Data models for PromptSentinel SDK."""

from enum import Enum
from typing import List, Optional, Dict, Any
from datetime import datetime
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
    patterns_matched: List[str] = Field(default_factory=list)


class DetectionRequest(BaseModel):
    """Request for detection endpoint."""
    messages: Optional[List[Message]] = None
    prompt: Optional[str] = None
    check_format: bool = True
    use_cache: bool = True
    detection_mode: Optional[DetectionMode] = None


class DetectionResponse(BaseModel):
    """Response from detection endpoint."""
    verdict: Verdict
    confidence: float
    reasons: List[DetectionReason] = Field(default_factory=list)
    categories: List[str] = Field(default_factory=list)
    modified_prompt: Optional[str] = None
    pii_detected: bool = False
    pii_types: List[str] = Field(default_factory=list)
    format_issues: List[str] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)
    processing_time_ms: float
    timestamp: datetime
    metadata: Dict[str, Any] = Field(default_factory=dict)
    
    # V3 specific fields
    routing_metadata: Optional[Dict[str, Any]] = None


class BatchDetectionRequest(BaseModel):
    """Request for batch detection."""
    prompts: List[Dict[str, str]]


class BatchDetectionResponse(BaseModel):
    """Response from batch detection."""
    results: List[Dict[str, Any]]
    processed: int
    timestamp: datetime


class UsageMetrics(BaseModel):
    """API usage metrics."""
    request_count: int
    token_usage: Dict[str, int]
    cost_breakdown: Dict[str, float]
    provider_stats: Dict[str, Any]
    time_period: str


class BudgetStatus(BaseModel):
    """Budget status information."""
    current_usage: Dict[str, float]
    budget_limits: Dict[str, float]
    alerts: List[Dict[str, Any]]
    projections: Dict[str, float]


class ComplexityAnalysis(BaseModel):
    """Prompt complexity analysis."""
    complexity_level: str
    complexity_score: float
    metrics: Dict[str, float]
    risk_indicators: List[str]
    recommendations: List[str]


class HealthStatus(BaseModel):
    """Service health status."""
    status: str
    version: str
    providers: Dict[str, Dict[str, Any]]
    cache: Dict[str, Any]
    detection_methods: List[str]


# Exceptions
class PromptSentinelError(Exception):
    """Base exception for PromptSentinel SDK."""
    pass


class AuthenticationError(PromptSentinelError):
    """Authentication failed."""
    pass


class RateLimitError(PromptSentinelError):
    """Rate limit exceeded."""
    def __init__(self, message: str, retry_after: Optional[int] = None):
        super().__init__(message)
        self.retry_after = retry_after


class ValidationError(PromptSentinelError):
    """Request validation failed."""
    pass


class ServiceUnavailableError(PromptSentinelError):
    """Service temporarily unavailable."""
    pass