"""Pydantic schemas for experiment API endpoints."""

from datetime import datetime
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field
from prompt_sentinel.experiments.config import (
    ExperimentConfig,
    ExperimentVariant,
    ExperimentType,
    ExperimentStatus,
    GuardrailConfig,
)


class CreateExperimentRequest(BaseModel):
    """Request to create a new experiment."""

    name: str = Field(description="Human-readable experiment name")
    description: str = Field(description="Experiment description and hypothesis")
    type: ExperimentType = Field(description="Type of experiment")

    # Variants
    variants: List[ExperimentVariant] = Field(description="List of experiment variants")

    # Targeting
    target_percentage: float = Field(
        default=0.1, ge=0.0, le=1.0, description="Percentage of traffic to include"
    )
    target_filters: Dict[str, Any] = Field(
        default_factory=dict, description="Filters for user targeting"
    )

    # Metrics
    primary_metrics: List[str] = Field(description="Primary success metrics")
    secondary_metrics: List[str] = Field(
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
    guardrails: List[GuardrailConfig] = Field(default_factory=list, description="Safety guardrails")
    auto_promote: bool = Field(default=False, description="Auto-promote winning variant")

    # Timing
    duration_hours: Optional[int] = Field(default=None, description="Maximum duration in hours")
    start_immediately: bool = Field(default=False, description="Start immediately")

    # Metadata
    tags: List[str] = Field(default_factory=list, description="Experiment tags")


class UpdateExperimentRequest(BaseModel):
    """Request to update an experiment."""

    name: Optional[str] = None
    description: Optional[str] = None
    target_percentage: Optional[float] = Field(None, ge=0.0, le=1.0)
    target_filters: Optional[Dict[str, Any]] = None
    guardrails: Optional[List[GuardrailConfig]] = None
    auto_promote: Optional[bool] = None
    duration_hours: Optional[int] = None
    tags: Optional[List[str]] = None


class ExperimentStatusRequest(BaseModel):
    """Request to change experiment status."""

    status: ExperimentStatus = Field(description="New experiment status")
    reason: str = Field(description="Reason for status change")


class ExperimentSummary(BaseModel):
    """Summary information for an experiment."""

    id: str
    name: str
    type: str
    status: str
    created_at: datetime
    start_time: Optional[datetime]
    end_time: Optional[datetime]
    variants_count: int
    is_active: bool
    target_percentage: float
    total_assignments: int
    health_score: float


class ExperimentDetails(BaseModel):
    """Detailed experiment information."""

    experiment: ExperimentConfig
    assignment_stats: Dict[str, Any]
    safety_report: Dict[str, Any]
    runtime_metrics: Dict[str, Any]
    analysis_results: List[Dict[str, Any]]


class ExperimentMetricsQuery(BaseModel):
    """Query for experiment metrics."""

    experiment_id: str
    time_window_hours: int = Field(default=24, ge=1, le=168)  # Max 1 week
    variant_ids: Optional[List[str]] = None
    metric_names: Optional[List[str]] = None


class ExperimentMetricsResponse(BaseModel):
    """Response with experiment metrics."""

    experiment_id: str
    time_window_hours: int
    data: Dict[str, Dict[str, List[float]]]  # {metric_name: {variant_id: [values]}}
    aggregations: Dict[
        str, Dict[str, Dict[str, float]]
    ]  # {metric_name: {variant_id: {stat: value}}}
    generated_at: datetime


class ExperimentAssignmentRequest(BaseModel):
    """Request to assign user to experiment."""

    user_id: str = Field(description="User identifier")
    session_id: Optional[str] = Field(default=None, description="Session identifier")
    attributes: Optional[Dict[str, Any]] = Field(
        default=None, description="User attributes for targeting"
    )


class ExperimentAssignmentResponse(BaseModel):
    """Response with experiment assignment."""

    experiment_id: str
    variant_id: Optional[str]
    assigned: bool
    reason: str  # Why assigned or not assigned
    config: Optional[Dict[str, Any]]  # Variant configuration if assigned


class RecordMetricRequest(BaseModel):
    """Request to record experiment metric."""

    user_id: str = Field(description="User identifier")
    metric_name: str = Field(description="Name of the metric")
    value: float = Field(description="Metric value")
    metadata: Optional[Dict[str, Any]] = Field(default=None, description="Additional metadata")


class BatchMetricsRequest(BaseModel):
    """Request to record multiple metrics."""

    metrics: List[RecordMetricRequest] = Field(description="List of metrics to record")


class ExperimentResultsQuery(BaseModel):
    """Query for experiment analysis results."""

    experiment_id: str
    metric_names: Optional[List[str]] = None
    confidence_level: Optional[float] = Field(None, ge=0.8, le=0.99)
    include_historical: bool = Field(
        default=False, description="Include historical analysis results"
    )


class ExperimentResultsResponse(BaseModel):
    """Response with experiment analysis results."""

    experiment_id: str
    analyzed_at: datetime
    results: List[Dict[str, Any]]
    summary: Dict[str, Any]
    recommendations: List[str]


class ExperimentListQuery(BaseModel):
    """Query parameters for listing experiments."""

    status: Optional[ExperimentStatus] = None
    type: Optional[ExperimentType] = None
    tags: Optional[List[str]] = None
    created_after: Optional[datetime] = None
    created_before: Optional[datetime] = None
    limit: int = Field(default=100, ge=1, le=1000)
    offset: int = Field(default=0, ge=0)


class ExperimentStatsResponse(BaseModel):
    """Response with experiment statistics."""

    total_experiments: int
    experiments_by_status: Dict[str, int]
    experiments_by_type: Dict[str, int]
    total_assignments: int
    total_metrics_recorded: int
    active_experiments: int
