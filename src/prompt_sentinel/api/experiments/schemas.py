# Copyright 2025 PromptSentinel
# Licensed under the Elastic License 2.0; you may not use this file except
# in compliance with the Elastic License 2.0. You may obtain a copy of the
# License at https://www.elastic.co/licensing/elastic-license

"""Pydantic schemas for experiment API endpoints."""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from prompt_sentinel.experiments.config import (
    ExperimentConfig,
    ExperimentStatus,
    ExperimentType,
    ExperimentVariant,
    GuardrailConfig,
)


class CreateExperimentRequest(BaseModel):
    """Request to create a new experiment."""

    name: str = Field(description="Human-readable experiment name")
    description: str = Field(description="Experiment description and hypothesis")
    type: ExperimentType = Field(description="Type of experiment")

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

    # Timing
    duration_hours: int | None = Field(default=None, description="Maximum duration in hours")
    start_immediately: bool = Field(default=False, description="Start immediately")

    # Metadata
    tags: list[str] = Field(default_factory=list, description="Experiment tags")


class UpdateExperimentRequest(BaseModel):
    """Request to update an experiment."""

    name: str | None = None
    description: str | None = None
    target_percentage: float | None = Field(None, ge=0.0, le=1.0)
    target_filters: dict[str, Any] | None = None
    guardrails: list[GuardrailConfig] | None = None
    auto_promote: bool | None = None
    duration_hours: int | None = None
    tags: list[str] | None = None


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
    start_time: datetime | None
    end_time: datetime | None
    variants_count: int
    is_active: bool
    target_percentage: float
    total_assignments: int
    health_score: float


class ExperimentDetails(BaseModel):
    """Detailed experiment information."""

    experiment: ExperimentConfig
    assignment_stats: dict[str, Any]
    safety_report: dict[str, Any]
    runtime_metrics: dict[str, Any]
    analysis_results: list[dict[str, Any]]


class ExperimentMetricsQuery(BaseModel):
    """Query for experiment metrics."""

    experiment_id: str
    time_window_hours: int = Field(default=24, ge=1, le=168)  # Max 1 week
    variant_ids: list[str] | None = None
    metric_names: list[str] | None = None


class ExperimentMetricsResponse(BaseModel):
    """Response with experiment metrics."""

    experiment_id: str
    time_window_hours: int
    data: dict[str, dict[str, list[float]]]  # {metric_name: {variant_id: [values]}}
    aggregations: dict[
        str, dict[str, dict[str, float]]
    ]  # {metric_name: {variant_id: {stat: value}}}
    generated_at: datetime


class ExperimentAssignmentRequest(BaseModel):
    """Request to assign user to experiment."""

    user_id: str = Field(description="User identifier")
    session_id: str | None = Field(default=None, description="Session identifier")
    attributes: dict[str, Any] | None = Field(
        default=None, description="User attributes for targeting"
    )


class ExperimentAssignmentResponse(BaseModel):
    """Response with experiment assignment."""

    experiment_id: str
    variant_id: str | None
    assigned: bool
    reason: str  # Why assigned or not assigned
    config: dict[str, Any] | None  # Variant configuration if assigned


class RecordMetricRequest(BaseModel):
    """Request to record experiment metric."""

    user_id: str = Field(description="User identifier")
    metric_name: str = Field(description="Name of the metric")
    value: float = Field(description="Metric value")
    metadata: dict[str, Any] | None = Field(default=None, description="Additional metadata")


class BatchMetricsRequest(BaseModel):
    """Request to record multiple metrics."""

    metrics: list[RecordMetricRequest] = Field(description="List of metrics to record")


class ExperimentResultsQuery(BaseModel):
    """Query for experiment analysis results."""

    experiment_id: str
    metric_names: list[str] | None = None
    confidence_level: float | None = Field(None, ge=0.8, le=0.99)
    include_historical: bool = Field(
        default=False, description="Include historical analysis results"
    )


class ExperimentResultsResponse(BaseModel):
    """Response with experiment analysis results."""

    experiment_id: str
    analyzed_at: datetime
    results: list[dict[str, Any]]
    summary: dict[str, Any]
    recommendations: list[str]


class ExperimentListQuery(BaseModel):
    """Query parameters for listing experiments."""

    status: ExperimentStatus | None = None
    type: ExperimentType | None = None
    tags: list[str] | None = None
    created_after: datetime | None = None
    created_before: datetime | None = None
    limit: int = Field(default=100, ge=1, le=1000)
    offset: int = Field(default=0, ge=0)


class ExperimentStatsResponse(BaseModel):
    """Response with experiment statistics."""

    total_experiments: int
    experiments_by_status: dict[str, int]
    experiments_by_type: dict[str, int]
    total_assignments: int
    total_metrics_recorded: int
    active_experiments: int
