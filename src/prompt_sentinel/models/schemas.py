# Copyright 2025 PromptSentinel
# Licensed under the Elastic License 2.0; you may not use this file except
# in compliance with the Elastic License 2.0. You may obtain a copy of the
# License at https://www.elastic.co/licensing/elastic-license

"""Pydantic models for API request and response schemas.

This module defines all data models used in the PromptSentinel API,
including request bodies, response structures, and internal data types.
All models use Pydantic for automatic validation, serialization, and
documentation generation.

Key model categories:
- Enums: Role, Verdict, DetectionCategory
- Request models: SimplePromptRequest, UnifiedDetectionRequest, AnalysisRequest
- Response models: DetectionResponse, AnalysisResponse, HealthResponse
- Internal models: Message, DetectionReason, FormatRecommendation, PIIDetection

Models include validation logic to ensure data integrity and provide
clear error messages for invalid inputs.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class Role(str, Enum):
    """Message role types for conversation structure.

    Defines the sender role for each message in a conversation,
    enabling proper role separation and security boundaries.
    """

    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"
    COMBINED = "combined"


class Verdict(str, Enum):
    """Detection verdict types indicating recommended action.

    Each verdict represents a different security response:
    - ALLOW: Safe to process
    - BLOCK: Reject entirely
    - FLAG: Allow but monitor
    - STRIP: Remove malicious parts
    - REDACT: Remove PII before processing
    """

    ALLOW = "allow"
    BLOCK = "block"
    FLAG = "flag"
    STRIP = "strip"
    REDACT = "redact"  # New verdict for PII redaction


class DetectionCategory(str, Enum):
    """Categories of detected security threats.

    Classifies different types of prompt injection and
    manipulation attempts for detailed threat analysis.
    """

    DIRECT_INJECTION = "direct_injection"
    INDIRECT_INJECTION = "indirect_injection"
    JAILBREAK = "jailbreak"
    PROMPT_LEAK = "prompt_leak"
    ENCODING_ATTACK = "encoding_attack"
    CONTEXT_SWITCHING = "context_switching"
    ROLE_MANIPULATION = "role_manipulation"
    PII_DETECTED = "pii_detected"
    BENIGN = "benign"


class Message(BaseModel):
    """Structured message format with role and content.

    Represents a single message in a conversation with
    explicit role assignment for security boundaries.

    Attributes:
        role: Sender role (system/user/assistant)
        content: Message text content
    """

    role: Role
    content: str

    @field_validator("content")
    @classmethod
    def validate_content_length(cls, v: str) -> str:
        """Validate that message content is not empty.

        Args:
            v: Content value to validate

        Returns:
            Validated content

        Raises:
            ValueError: If content is empty or only whitespace
        """
        if not v or not v.strip():
            raise ValueError("Message content cannot be empty")
        return v


class SimplePromptRequest(BaseModel):
    """Simple string prompt request for v1 API.

    Basic request format accepting a plain text prompt
    with optional role specification.
    """

    prompt: str = Field(..., description="The prompt text to analyze")
    role: Role | None = Field(
        default=Role.USER, description="Role of the prompt (user, system, or combined)"
    )

    @field_validator("prompt")
    @classmethod
    def validate_prompt_length(cls, v: str) -> str:
        """Basic prompt validation."""
        if not v or not v.strip():
            raise ValueError("Prompt cannot be empty")
        return v


class StructuredPromptRequest(BaseModel):
    """Structured prompt with role separation."""

    messages: list[Message] = Field(..., description="List of messages with roles", min_length=1)

    @field_validator("messages")
    @classmethod
    def validate_message_structure(cls, v: list["Message"]) -> list["Message"]:
        """Validate message structure."""
        if not v:
            raise ValueError("Messages list cannot be empty")

        # Check for proper role separation
        any(msg.role == Role.SYSTEM for msg in v)
        any(msg.role == Role.USER for msg in v)

        # This is just a warning in the response, not an error
        # We'll include this info in the response metadata
        return v


class UnifiedDetectionRequest(BaseModel):
    """Unified request format supporting multiple input types."""

    input: str | list[dict[str, str]] = Field(..., description="Prompt as string or message array")
    role: Role | None = Field(default=None, description="Role hint for string inputs")
    config: dict | None = Field(
        default=None, description="Optional detection configuration overrides"
    )
    # User context for A/B testing experiments
    user_id: str | None = Field(
        default=None, description="User identifier for experiment assignment"
    )
    session_id: str | None = Field(
        default=None, description="Session identifier for context tracking"
    )
    user_context: dict[str, Any] | None = Field(
        default=None, description="Additional user attributes for targeting"
    )

    def to_messages(self) -> list[Message]:
        """Convert input to standardized message format."""
        if isinstance(self.input, str):
            role = self.role or Role.USER
            return [Message(role=role, content=self.input)]
        else:
            return [Message(role=Role(msg["role"]), content=msg["content"]) for msg in self.input]


class DetectionReason(BaseModel):
    """Detailed reason for detection verdict."""

    category: DetectionCategory
    description: str
    confidence: float = Field(ge=0.0, le=1.0)
    source: Literal["heuristic", "llm", "combined"]
    patterns_matched: list[str] | None = None


class FormatRecommendation(BaseModel):
    """Recommendation for improving prompt format."""

    issue: str
    recommendation: str
    severity: Literal["info", "warning", "error"]


class PIIDetection(BaseModel):
    """PII detection information."""

    pii_type: str
    masked_value: str
    confidence: float = Field(ge=0.0, le=1.0)
    location: dict[str, int]  # {"start": x, "end": y}


class DetectionResponse(BaseModel):
    """Comprehensive detection result response.

    Contains the complete analysis results including verdict,
    confidence scores, detection reasons, and recommendations.
    """

    verdict: Verdict
    confidence: float = Field(ge=0.0, le=1.0)
    modified_prompt: str | None = None
    reasons: list[DetectionReason] = Field(default_factory=list)
    format_recommendations: list[FormatRecommendation] = Field(default_factory=list)
    pii_detected: list[PIIDetection] = Field(default_factory=list)
    metadata: dict = Field(default_factory=dict)
    processing_time_ms: float
    timestamp: datetime = Field(default_factory=datetime.utcnow)

    model_config = ConfigDict(json_encoders={datetime: lambda v: v.isoformat()})


class AnalysisRequest(BaseModel):
    """Full analysis request with options."""

    messages: list[Message]
    include_recommendations: bool = True
    include_metadata: bool = True
    check_format: bool = True
    detection_mode: Literal["strict", "moderate", "permissive"] | None = None


class AnalysisResponse(BaseModel):
    """Comprehensive analysis response."""

    verdict: Verdict
    confidence: float = Field(ge=0.0, le=1.0)
    per_message_analysis: list[dict] = Field(default_factory=list)
    overall_risk_score: float = Field(ge=0.0, le=1.0)
    reasons: list[DetectionReason] = Field(default_factory=list)
    format_analysis: dict = Field(default_factory=dict)
    recommendations: list[FormatRecommendation] = Field(default_factory=list)
    metadata: dict = Field(default_factory=dict)
    processing_time_ms: float
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class HealthResponse(BaseModel):
    """Health check response."""

    status: Literal["healthy", "degraded", "unhealthy"]
    version: str
    uptime_seconds: float
    providers_status: dict[str, str]
    redis_connected: bool
    redis_latency_ms: float | None = None
    cache_stats: dict[str, Any] | None = None
    system_metrics: dict[str, Any] | None = None
    metadata: dict[str, Any] | None = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class CorpusEntry(BaseModel):
    """Corpus entry for testing."""

    prompt: str
    label: DetectionCategory
    source: str
    category: str
    created_at: datetime
    metadata: dict | None = None

    model_config = ConfigDict(json_encoders={datetime: lambda v: v.isoformat()})
