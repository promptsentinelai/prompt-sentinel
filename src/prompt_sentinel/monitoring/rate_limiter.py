# Copyright 2025 PromptSentinel
# Licensed under the Elastic License 2.0; you may not use this file except
# in compliance with the Elastic License 2.0. You may obtain a copy of the
# License at https://www.elastic.co/licensing/elastic-license

"""Rate limiting for API requests.

This module provides rate limiting functionality including:
- Token bucket algorithm for smooth rate limiting (via `monitoring.token_bucket`)
- Per-client and global rate limits (client buckets via `monitoring.client_store`)
- Adaptive rate limiting based on load
- Priority-based request handling (policy in `monitoring.policy`)
"""

import asyncio
import time
from collections import defaultdict

import structlog

from prompt_sentinel.monitoring.client_store import ClientBucketStore

# Re-export policy types for backwards compatibility with imports
from prompt_sentinel.monitoring.policy import Priority, RateLimitConfig, is_high_priority
from prompt_sentinel.monitoring.token_bucket import TokenBucket

logger = structlog.get_logger()


class RateLimiter:
    """Rate limiter for API requests.

    Implements token bucket algorithm with support for:
    - Global and per-client limits
    - Request and token-based limiting
    - Priority-based request handling
    - Adaptive rate adjustment
    """

    def __init__(self, config: RateLimitConfig):
        """Initialize rate limiter.

        Args:
            config: Rate limit configuration
        """
        self.config = config

        # Global buckets
        self.global_request_bucket = TokenBucket(
            capacity=config.requests_per_minute * config.burst_multiplier,
            tokens=config.requests_per_minute,
            refill_rate=config.requests_per_minute / 60,
            last_refill=time.time(),
        )

        self.global_token_bucket = TokenBucket(
            capacity=config.tokens_per_minute * config.burst_multiplier,
            tokens=config.tokens_per_minute,
            refill_rate=config.tokens_per_minute / 60,
            last_refill=time.time(),
        )

        # Per-client buckets
        self.client_store = ClientBucketStore(config)

        # Metrics
        self.total_requests = 0
        self.accepted_requests = 0
        self.rejected_requests = 0
        self.total_tokens = 0

        # Priority queue for pending requests
        self.pending_requests: dict[Priority, list] = defaultdict(list)

        # Adaptive rate adjustment
        self.current_load = 0.0
        self.load_history: list = []

        # Background tasks (started in initialize)
        self._cleanup_task: asyncio.Task | None = None
        self._adjust_task: asyncio.Task | None = None
        self._initialized = False

    async def initialize(self) -> None:
        """Initialize background tasks."""
        if self._initialized:
            return

        # Start background tasks
        self._cleanup_task = asyncio.create_task(self._cleanup_old_clients())
        if self.config.enable_adaptive:
            self._adjust_task = asyncio.create_task(self._adjust_rates())
        self._initialized = True

    async def check_rate_limit(
        self, client_id: str | None = None, tokens: int = 0, priority: Priority = Priority.NORMAL
    ) -> tuple[bool, float | None]:
        """Check if request is within rate limits.

        Args:
            client_id: Optional client identifier
            tokens: Number of tokens for request
            priority: Request priority

        Returns:
            Tuple of (allowed, wait_time_seconds)
        """
        self.total_requests += 1
        self.total_tokens += tokens

        # Priority handling via policy helper
        high_priority = is_high_priority(self.config, priority)

        # Check global request limit
        if not self.global_request_bucket.can_consume(1):
            wait_time = self.global_request_bucket.time_until_available(1)
            if not high_priority or wait_time > 1.0:
                self.rejected_requests += 1
                logger.debug(
                    "Global request rate limit exceeded", client=client_id, wait_time=wait_time
                )
                return False, wait_time

        # Check global token limit
        if tokens > 0 and not self.global_token_bucket.can_consume(tokens):
            wait_time = self.global_token_bucket.time_until_available(tokens)
            if not high_priority or wait_time > 1.0:
                self.rejected_requests += 1
                logger.debug(
                    "Global token rate limit exceeded",
                    client=client_id,
                    tokens=tokens,
                    wait_time=wait_time,
                )
                return False, wait_time

        # Check per-client limits
        if client_id:
            # Check client request limit
            client_request_bucket = self.client_store.get_request_bucket(client_id)
            if not client_request_bucket.can_consume(1):
                wait_time = client_request_bucket.time_until_available(1)
                self.rejected_requests += 1
                logger.debug(
                    "Client request rate limit exceeded", client=client_id, wait_time=wait_time
                )
                return False, wait_time

            # Check client token limit
            if tokens > 0:
                client_token_bucket = self.client_store.get_token_bucket(client_id)
                if not client_token_bucket.can_consume(tokens):
                    wait_time = client_token_bucket.time_until_available(tokens)
                    self.rejected_requests += 1
                    logger.debug(
                        "Client token rate limit exceeded",
                        client=client_id,
                        tokens=tokens,
                        wait_time=wait_time,
                    )
                    return False, wait_time

        # All checks passed
        self.accepted_requests += 1
        return True, None

    async def consume_tokens(self, client_id: str | None = None, tokens: int = 0) -> bool:
        """Consume tokens from rate limit buckets.

        Args:
            client_id: Optional client identifier
            tokens: Number of tokens to consume

        Returns:
            True if tokens were consumed
        """
        # Consume from global buckets
        if not self.global_request_bucket.consume(1):
            return False

        if tokens > 0 and not self.global_token_bucket.consume(tokens):
            # Rollback request consumption
            self.global_request_bucket.tokens += 1
            return False

        # Consume from client buckets
        if client_id:
            # Request bucket consumption
            try:
                client_request_bucket = self.client_store.get_request_bucket(client_id)
                if not client_request_bucket.consume(1):
                    # Rollback global consumption
                    self.global_request_bucket.tokens += 1
                    if tokens > 0:
                        self.global_token_bucket.tokens += tokens
                    return False
            except Exception:
                # Defensive: if store fails, rollback
                self.global_request_bucket.tokens += 1
                if tokens > 0:
                    self.global_token_bucket.tokens += tokens
                return False

            # Token bucket consumption
            if tokens > 0:
                client_token_bucket = self.client_store.get_token_bucket(client_id)
                if not client_token_bucket.consume(tokens):
                    # Rollback all consumption
                    self.global_request_bucket.tokens += 1
                    self.global_token_bucket.tokens += tokens
                    client_request_bucket.tokens += 1
                    return False

        # Update load metrics
        self.current_load = 1.0 - (
            self.global_request_bucket.tokens / self.global_request_bucket.capacity
        )

        return True

    async def wait_if_needed(
        self,
        client_id: str | None = None,
        tokens: int = 0,
        priority: Priority = Priority.NORMAL,
        max_wait: float = 5.0,
    ) -> bool:
        """Wait for rate limit if needed.

        Args:
            client_id: Optional client identifier
            tokens: Number of tokens needed
            priority: Request priority
            max_wait: Maximum seconds to wait

        Returns:
            True if request can proceed, False if wait exceeded
        """
        allowed, wait_time = await self.check_rate_limit(client_id, tokens, priority)

        if allowed:
            return await self.consume_tokens(client_id, tokens)

        if wait_time and wait_time <= max_wait:
            logger.debug(f"Rate limited, waiting {wait_time:.1f}s")
            await asyncio.sleep(wait_time)

            # Retry after waiting
            allowed, _ = await self.check_rate_limit(client_id, tokens, priority)
            if allowed:
                return await self.consume_tokens(client_id, tokens)

        return False

    async def _cleanup_old_clients(self) -> None:
        """Remove inactive client buckets to save memory."""
        while True:
            await asyncio.sleep(300)  # Every 5 minutes

            try:
                now = time.time()
                inactive_threshold = 600  # 10 minutes

                # Clean up inactive clients
                inactive_clients = []
                for client_id, bucket in list(self.client_store.request_buckets.items()):
                    if now - bucket.last_refill > inactive_threshold:
                        inactive_clients.append(client_id)
                        self.client_store.reset_client(client_id)

                if inactive_clients:
                    logger.debug(f"Cleaned up {len(inactive_clients)} inactive clients")

            except Exception as e:
                logger.error("Client cleanup error", error=str(e))

    async def _adjust_rates(self) -> None:
        """Adaptively adjust rate limits based on load."""
        while True:
            await asyncio.sleep(60)  # Every minute

            try:
                # Track load history
                self.load_history.append(self.current_load)
                if len(self.load_history) > 10:
                    self.load_history.pop(0)

                # Calculate average load
                avg_load = (
                    sum(self.load_history) / len(self.load_history) if self.load_history else 0.5
                )

                # Adjust rates based on load
                if avg_load > 0.8:
                    # High load - reduce rates
                    adjustment = max(self.config.min_rate_percentage, 1.0 - (avg_load - 0.8))
                elif avg_load < 0.3:
                    # Low load - increase rates
                    adjustment = min(self.config.max_rate_percentage, 1.0 + (0.3 - avg_load))
                else:
                    # Normal load
                    adjustment = 1.0

                # Apply adjustment
                if adjustment != 1.0:
                    self.global_request_bucket.refill_rate = (
                        self.config.requests_per_minute / 60 * adjustment
                    )
                    self.global_token_bucket.refill_rate = (
                        self.config.tokens_per_minute / 60 * adjustment
                    )

                    logger.debug("Adjusted rate limits", load=avg_load, adjustment=adjustment)

            except Exception as e:
                logger.error("Rate adjustment error", error=str(e))

    def get_metrics(self) -> dict:
        """Get rate limiter metrics.

        Returns:
            Dictionary with current metrics
        """
        acceptance_rate = (
            (self.accepted_requests / max(self.total_requests, 1))
            if self.total_requests > 0
            else 1.0
        )

        return {
            "total_requests": self.total_requests,
            "accepted_requests": self.accepted_requests,
            "rejected_requests": self.rejected_requests,
            "acceptance_rate": acceptance_rate,
            "total_tokens": self.total_tokens,
            "current_load": self.current_load,
            "active_clients": len(self.client_store.request_buckets),
            "global_tokens_available": self.global_request_bucket.tokens,
            "config": {
                "requests_per_minute": self.config.requests_per_minute,
                "tokens_per_minute": self.config.tokens_per_minute,
                "client_requests_per_minute": self.config.client_requests_per_minute,
            },
        }

    def reset_client(self, client_id: str) -> None:
        """Reset rate limits for a specific client.

        Args:
            client_id: Client identifier to reset
        """
        self.client_store.reset_client(client_id)

        logger.info("Reset rate limits for client", client=client_id)

    # Backwards-compatible accessors for tests expecting old attributes
    @property
    def client_request_buckets(self) -> dict[str, TokenBucket]:
        return self.client_store.request_buckets

    @property
    def client_token_buckets(self) -> dict[str, TokenBucket]:
        return self.client_store.token_buckets
