"""PromptSentinel - LLM Prompt Injection Detection Microservice.

A defensive security microservice for detecting and mitigating prompt
injection attacks in LLM-based systems. Provides multi-layered detection
using heuristic patterns, LLM-based classification, and PII detection.

Key features:
- Real-time injection detection with < 100ms latency
- Multi-provider LLM support with automatic failover
- PII detection and redaction capabilities
- Role separation validation
- Configurable detection sensitivity (strict/moderate/permissive)
- Comprehensive REST API with OpenAPI documentation

Usage:
    from prompt_sentinel.detection.detector import PromptDetector
    detector = PromptDetector()
    result = await detector.detect(messages)
"""

__version__ = "0.1.0"
__author__ = "PromptSentinel Team"

from prompt_sentinel.config.settings import settings

__all__ = ["settings", "__version__"]