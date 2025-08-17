# Copyright 2025 PromptSentinel
# Licensed under the Elastic License 2.0

"""Policy helpers for rate limiting decisions."""

from dataclasses import dataclass
from enum import IntEnum


class Priority(IntEnum):
    LOW = 0
    NORMAL = 1
    HIGH = 2
    CRITICAL = 3


@dataclass
class RateLimitConfig:
    # Global limits
    requests_per_minute: int = 60
    requests_per_hour: int = 1000
    tokens_per_minute: int = 10000
    tokens_per_hour: int = 100000

    # Per-client limits
    client_requests_per_minute: int = 20
    client_tokens_per_minute: int = 5000

    # Burst allowance
    burst_multiplier: float = 1.5

    # Adaptive limiting
    enable_adaptive: bool = True
    min_rate_percentage: float = 0.5
    max_rate_percentage: float = 1.5

    # Priority handling
    enable_priority: bool = True
    priority_reserved_percentage: float = 0.2


def is_high_priority(config: RateLimitConfig, priority: Priority) -> bool:
    return config.enable_priority and priority >= Priority.HIGH
