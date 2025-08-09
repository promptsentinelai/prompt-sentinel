"""Experiment configuration models and types.

This module defines the core data structures for A/B testing experiments,
including experiment types, variants, and configuration management.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

import structlog
from pydantic import BaseModel, Field, validator

logger = structlog.get_logger()


class ExperimentType(Enum):
    """Types of experiments supported by the framework."""

    STRATEGY = "strategy"  # Detection strategy optimization
    PROVIDER = "provider"  # LLM provider comparison
    THRESHOLD = "threshold"  # Confidence/complexity thresholds
    ALGORITHM = "algorithm"  # Detection algorithm comparison
    PERFORMANCE = "performance"  # Caching and optimization
    FEATURE = "feature"  # Feature flag testing


class ExperimentStatus(Enum):
    """Experiment lifecycle status."""

    DRAFT = "draft"  # Being configured
    SCHEDULED = "scheduled"  # Scheduled to start
    RUNNING = "running"  # Currently active
    PAUSED = "paused"  # Temporarily stopped
    COMPLETED = "completed"  # Finished successfully
    TERMINATED = "terminated"  # Stopped due to issues
    ARCHIVED = "archived"  # Moved to archive


class TrafficAllocation(BaseModel):
    """Traffic allocation configuration for experiment variants."""

    control: float = Field(ge=0.0, le=1.0, description="Control group percentage")
    treatment: float = Field(ge=0.0, le=1.0, description="Treatment group percentage")

    @validator("treatment")
    def validate_total_allocation(cls, v, values):
        """Ensure total allocation doesn't exceed 100%."""
        control = values.get("control", 0.0)
        if control + v > 1.0:
            raise ValueError("Total traffic allocation cannot exceed 100%")
        return v


class ExperimentVariant(BaseModel):
    """Configuration for a single experiment variant."""

    id: str = Field(description="Unique variant identifier")
    name: str = Field(description="Human-readable variant name")
    description: str = Field(description="Variant description")
    config: dict[str, Any] = Field(description="Variant-specific configuration")
    traffic_percentage: float = Field(ge=0.0, le=1.0, description="Traffic allocation")
    is_control: bool = Field(default=False, description="Whether this is the control variant")

    class Config:
        schema_extra = {
            "example": {
                "id": "fast_strategy",
                "name": "Fast Detection Strategy",
                "description": "Uses heuristic-only detection for performance",
                "config": {"strategy": "heuristic_only", "cache_ttl": 300},
                "traffic_percentage": 0.3,
                "is_control": False,
            }
        }


class GuardrailConfig(BaseModel):
    """Safety guardrail configuration."""

    metric_name: str = Field(description="Metric to monitor")
    threshold_type: str = Field(description="Type of threshold (min/max)")
    threshold_value: float = Field(description="Threshold value")
    window_minutes: int = Field(default=5, description="Monitoring window")
    action: str = Field(description="Action to take (pause/terminate)")

    @validator("threshold_type")
    def validate_threshold_type(cls, v):
        """Validate threshold type."""
        if v not in ["min", "max"]:
            raise ValueError("threshold_type must be 'min' or 'max'")
        return v

    @validator("action")
    def validate_action(cls, v):
        """Validate guardrail action."""
        if v not in ["pause", "terminate"]:
            raise ValueError("action must be 'pause' or 'terminate'")
        return v


class ExperimentConfig(BaseModel):
    """Complete experiment configuration."""

    id: str = Field(description="Unique experiment identifier")
    name: str = Field(description="Human-readable experiment name")
    description: str = Field(description="Experiment description and hypothesis")
    type: ExperimentType = Field(description="Type of experiment")
    status: ExperimentStatus = Field(default=ExperimentStatus.DRAFT)

    # Timing
    start_time: datetime | None = Field(description="Experiment start time")
    end_time: datetime | None = Field(description="Experiment end time")
    duration_hours: int | None = Field(description="Maximum duration in hours")

    # Variants
    variants: list[ExperimentVariant] = Field(description="List of experiment variants")

    # Targeting
    target_percentage: float = Field(
        default=0.1, ge=0.0, le=1.0, description="Percentage of traffic to include"
    )
    target_filters: dict[str, Any] = Field(
        default_factory=dict, description="Filters for user targeting"
    )

    # Metrics
    primary_metrics: list[str] = Field(description="Primary success metrics")
    secondary_metrics: list[str] = Field(
        default_factory=list, description="Secondary metrics to track"
    )

    # Statistical configuration
    min_sample_size: int = Field(default=1000, description="Minimum sample size per variant")
    confidence_level: float = Field(
        default=0.95, ge=0.8, le=0.99, description="Statistical confidence level"
    )
    effect_size: float = Field(
        default=0.05, ge=0.01, le=0.5, description="Minimum detectable effect size"
    )

    # Safety
    guardrails: list[GuardrailConfig] = Field(default_factory=list, description="Safety guardrails")
    auto_promote: bool = Field(default=False, description="Auto-promote winning variant")

    # Metadata
    created_by: str = Field(description="Experiment creator")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    tags: list[str] = Field(default_factory=list, description="Experiment tags")

    @validator("variants")
    def validate_variants(cls, v):
        """Validate experiment variants configuration."""
        if len(v) < 2:
            raise ValueError("Experiment must have at least 2 variants")

        # Check for exactly one control
        control_count = sum(1 for variant in v if variant.is_control)
        if control_count != 1:
            raise ValueError("Experiment must have exactly one control variant")

        # Check traffic allocation
        total_traffic = sum(variant.traffic_percentage for variant in v)
        if abs(total_traffic - 1.0) > 0.001:  # Allow for floating point precision
            raise ValueError("Variant traffic percentages must sum to 1.0")

        # Check unique IDs
        variant_ids = [variant.id for variant in v]
        if len(variant_ids) != len(set(variant_ids)):
            raise ValueError("Variant IDs must be unique")

        return v

    @validator("end_time")
    def validate_end_time(cls, v, values):
        """Validate end time is after start time."""
        start_time = values.get("start_time")
        if v and start_time and v <= start_time:
            raise ValueError("End time must be after start time")
        return v

    @validator("duration_hours")
    def validate_duration(cls, v):
        """Validate experiment duration."""
        if v is not None and v <= 0:
            raise ValueError("Duration must be positive")
        if v is not None and v > 8760:  # 1 year
            raise ValueError("Duration cannot exceed 1 year")
        return v

    def get_control_variant(self) -> ExperimentVariant:
        """Get the control variant."""
        for variant in self.variants:
            if variant.is_control:
                return variant
        raise ValueError("No control variant found")

    def get_treatment_variants(self) -> list[ExperimentVariant]:
        """Get all treatment variants."""
        return [variant for variant in self.variants if not variant.is_control]

    def is_active(self) -> bool:
        """Check if experiment is currently active."""
        if self.status != ExperimentStatus.RUNNING:
            return False

        now = datetime.utcnow()

        if self.start_time and now < self.start_time:
            return False

        if self.end_time and now > self.end_time:
            return False

        return True

    def get_variant_by_id(self, variant_id: str) -> ExperimentVariant | None:
        """Get variant by ID."""
        for variant in self.variants:
            if variant.id == variant_id:
                return variant
        return None

    class Config:
        use_enum_values = True
        json_encoders = {datetime: lambda dt: dt.isoformat()}
        schema_extra = {
            "example": {
                "id": "detection_strategy_test_001",
                "name": "Detection Strategy Optimization",
                "description": "Compare heuristic vs LLM detection strategies",
                "type": "strategy",
                "variants": [
                    {
                        "id": "control_standard",
                        "name": "Standard Detection",
                        "description": "Current production strategy",
                        "config": {"strategy": "heuristic_llm_cached"},
                        "traffic_percentage": 0.7,
                        "is_control": True,
                    },
                    {
                        "id": "treatment_fast",
                        "name": "Fast Heuristic Only",
                        "description": "Heuristic-only for speed",
                        "config": {"strategy": "heuristic_only"},
                        "traffic_percentage": 0.3,
                        "is_control": False,
                    },
                ],
                "primary_metrics": ["detection_accuracy", "response_time"],
                "secondary_metrics": ["cost_per_detection", "cache_hit_rate"],
                "min_sample_size": 5000,
                "confidence_level": 0.95,
                "created_by": "data_team",
            }
        }


@dataclass
class ExperimentAssignment:
    """User assignment to experiment variant."""

    user_id: str
    experiment_id: str
    variant_id: str
    assigned_at: datetime = field(default_factory=datetime.utcnow)
    sticky: bool = field(default=True)  # Keep same assignment across sessions

    def is_treatment(self, config: ExperimentConfig) -> bool:
        """Check if this is a treatment assignment."""
        variant = config.get_variant_by_id(self.variant_id)
        return variant is not None and not variant.is_control


class ExperimentMetadata(BaseModel):
    """Extended experiment metadata for analysis."""

    total_users: int = Field(description="Total users exposed to experiment")
    total_events: int = Field(description="Total events recorded")
    variant_stats: dict[str, dict[str, Any]] = Field(description="Per-variant statistics")
    last_updated: datetime = Field(default_factory=datetime.utcnow)

    # Statistical power
    current_power: float | None = Field(description="Current statistical power")
    estimated_completion: datetime | None = Field(description="Estimated completion time")

    # Performance metrics
    experiment_overhead_ms: float = Field(default=0.0, description="Average experiment overhead")
    assignment_cache_hit_rate: float = Field(default=0.0, description="Assignment cache hit rate")

    class Config:
        json_encoders = {datetime: lambda dt: dt.isoformat()}
