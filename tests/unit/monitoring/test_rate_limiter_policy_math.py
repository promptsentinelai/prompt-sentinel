# Copyright 2025 PromptSentinel
# Licensed under the Elastic License 2.0

import time

import pytest

from prompt_sentinel.monitoring.policy import Priority, RateLimitConfig, is_high_priority
from prompt_sentinel.monitoring.token_bucket import TokenBucket


def test_token_bucket_basic_consume_and_refill():
    bucket = TokenBucket(capacity=10, tokens=1, refill_rate=1.0, last_refill=time.time())
    assert bucket.consume(1) is True
    assert bucket.consume(1) is False
    # Advance time artificially by manipulating last_refill
    bucket.last_refill -= 2.0
    assert bucket.can_consume(1) is True
    assert pytest.approx(bucket.time_until_available(1), 0.01) == 0.0


def test_policy_priority_helper():
    cfg = RateLimitConfig(enable_priority=True)
    assert is_high_priority(cfg, Priority.HIGH) is True
    assert is_high_priority(cfg, Priority.NORMAL) is False
    cfg.enable_priority = False
    assert is_high_priority(cfg, Priority.HIGH) is False
