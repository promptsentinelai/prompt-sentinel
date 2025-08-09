"""A/B Testing Framework for PromptSentinel.

This module provides a comprehensive A/B testing framework for optimizing
detection strategies, provider performance, and system configurations through
data-driven experimentation.

Key Components:
- ExperimentManager: Central coordinator for running experiments
- StatisticalAnalyzer: Statistical significance testing and analysis
- AssignmentService: User bucketing and variant assignment
- MetricsCollector: Enhanced monitoring for experiment data
- SafetyControls: Guardrails and automatic rollback mechanisms
"""

from .analyzer import ExperimentResult, StatisticalAnalyzer
from .assignments import AssignmentService, BucketingStrategy
from .config import ExperimentConfig, ExperimentType, ExperimentVariant
from .manager import ExperimentManager
from .safety import GuardrailConfig, SafetyControls

__all__ = [
    "ExperimentManager",
    "ExperimentConfig",
    "ExperimentVariant",
    "ExperimentType",
    "AssignmentService",
    "BucketingStrategy",
    "StatisticalAnalyzer",
    "ExperimentResult",
    "SafetyControls",
    "GuardrailConfig",
]
