# Copyright 2025 PromptSentinel
# Licensed under the Elastic License 2.0

"""Client bucket store for rate limiting (in-memory)."""

import time

from prompt_sentinel.monitoring.policy import RateLimitConfig
from prompt_sentinel.monitoring.token_bucket import TokenBucket


class ClientBucketStore:
    """Holds per-client request and token buckets."""

    def __init__(self, config: RateLimitConfig):
        self.config = config
        self.request_buckets: dict[str, TokenBucket] = {}
        self.token_buckets: dict[str, TokenBucket] = {}

    def ensure_client(self, client_id: str) -> None:
        if client_id not in self.request_buckets:
            self.request_buckets[client_id] = TokenBucket(
                capacity=self.config.client_requests_per_minute * self.config.burst_multiplier,
                tokens=self.config.client_requests_per_minute,
                refill_rate=self.config.client_requests_per_minute / 60,
                last_refill=time.time(),
            )
        if client_id not in self.token_buckets:
            self.token_buckets[client_id] = TokenBucket(
                capacity=self.config.client_tokens_per_minute * self.config.burst_multiplier,
                tokens=self.config.client_tokens_per_minute,
                refill_rate=self.config.client_tokens_per_minute / 60,
                last_refill=time.time(),
            )

    def get_request_bucket(self, client_id: str) -> TokenBucket:
        self.ensure_client(client_id)
        return self.request_buckets[client_id]

    def get_token_bucket(self, client_id: str) -> TokenBucket:
        self.ensure_client(client_id)
        return self.token_buckets[client_id]

    def reset_client(self, client_id: str) -> None:
        if client_id in self.request_buckets:
            del self.request_buckets[client_id]
        if client_id in self.token_buckets:
            del self.token_buckets[client_id]
