# Copyright 2025 PromptSentinel
# Licensed under the Elastic License 2.0; you may not use this file except
# in compliance with the Elastic License 2.0. You may obtain a copy of the
# License at https://www.elastic.co/licensing/elastic-license

"""Token bucket math for rate limiting."""

import time
from dataclasses import dataclass


@dataclass
class TokenBucket:
    """Token bucket for rate limiting with time-based refills."""

    capacity: float
    tokens: float
    refill_rate: float
    last_refill: float

    def _refill(self) -> None:
        now = time.time()
        elapsed = now - self.last_refill
        if elapsed <= 0:
            return
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate)
        self.last_refill = now

    def consume(self, tokens: int = 1) -> bool:
        """Consume tokens if available.

        Returns True on success, False otherwise.
        """
        self._refill()
        if self.tokens >= tokens:
            self.tokens -= tokens
            return True
        return False

    def can_consume(self, tokens: int = 1) -> bool:
        """Check availability without consuming."""
        # Compute current tokens without permanently mutating state
        now = time.time()
        elapsed = now - self.last_refill
        current_tokens = min(self.capacity, self.tokens + max(0.0, elapsed) * self.refill_rate)
        return current_tokens >= tokens

    def time_until_available(self, tokens: int = 1) -> float:
        """Seconds until requested tokens become available (0 if available now)."""
        now = time.time()
        elapsed = now - self.last_refill
        current_tokens = min(self.capacity, self.tokens + max(0.0, elapsed) * self.refill_rate)
        if current_tokens >= tokens:
            return 0.0
        tokens_needed = tokens - current_tokens
        if self.refill_rate <= 0:
            return float("inf")
        return tokens_needed / self.refill_rate
