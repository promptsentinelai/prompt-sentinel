# Elastic License 2.0
#
# Copyright (c) 2024-present, PromptSentinel
#
# This source code is licensed under the Elastic License 2.0 found in the
# LICENSE file in the root directory of this source tree.

"""Circuit breaker implementation for LLM provider resilience."""

import asyncio
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class CircuitState(str, Enum):
    """Circuit breaker states."""

    CLOSED = "closed"  # Normal operation
    OPEN = "open"  # Circuit is open, requests fail fast
    HALF_OPEN = "half_open"  # Testing if service has recovered


@dataclass
class CircuitBreakerConfig:
    """Configuration for circuit breaker."""

    failure_threshold: int = 5  # Number of failures before opening
    recovery_timeout: int = 60  # Seconds to wait before trying again
    success_threshold: int = 3  # Successes needed to close circuit
    timeout_seconds: float = 30.0  # Request timeout
    expected_errors: list[type] = field(
        default_factory=lambda: [ConnectionError, TimeoutError, OSError, asyncio.TimeoutError]
    )


class CircuitBreakerStats:
    """Statistics for circuit breaker monitoring."""

    def __init__(self):
        """Initialize circuit breaker statistics."""
        self.total_requests = 0
        self.successful_requests = 0
        self.failed_requests = 0
        self.circuit_open_count = 0
        self.last_failure_time: float | None = None
        self.last_success_time: float | None = None


class CircuitBreakerError(Exception):
    """Exception raised when circuit breaker is open."""

    pass


class LLMCircuitBreaker:
    """Circuit breaker specifically designed for LLM provider resilience."""

    def __init__(self, provider_name: str, config: CircuitBreakerConfig):
        """
        Initialize LLM circuit breaker.

        Args:
            provider_name: Name of the LLM provider
            config: Circuit breaker configuration
        """
        self.provider_name = provider_name
        self.config = config
        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.success_count = 0
        self.last_failure_time: float | None = None
        self.stats = CircuitBreakerStats()
        self._lock = asyncio.Lock()

    async def call(self, func: Callable, *args, **kwargs) -> Any:
        """Execute function with circuit breaker protection."""
        async with self._lock:
            self.stats.total_requests += 1

            # Check if circuit should remain open
            if self.state == CircuitState.OPEN:
                if not self._should_attempt_reset():
                    raise CircuitBreakerError(
                        f"Circuit breaker OPEN for {self.provider_name}. "
                        f"Next attempt in {self._time_until_reset():.1f}s"
                    )
                else:
                    self.state = CircuitState.HALF_OPEN
                    self.success_count = 0
                    logger.info(
                        "Circuit breaker entering HALF_OPEN state", provider=self.provider_name
                    )

        try:
            # Execute with timeout
            result = await asyncio.wait_for(
                func(*args, **kwargs), timeout=self.config.timeout_seconds
            )

            # Success handling
            await self._on_success()
            return result

        except Exception as e:
            await self._on_failure(e)
            raise

    async def _on_success(self):
        """Handle successful request."""
        async with self._lock:
            self.stats.successful_requests += 1
            self.stats.last_success_time = time.time()

            if self.state == CircuitState.HALF_OPEN:
                self.success_count += 1
                if self.success_count >= self.config.success_threshold:
                    self._close_circuit()
            elif self.state == CircuitState.CLOSED:
                # Reset failure count on success
                self.failure_count = 0

    async def _on_failure(self, exception: Exception):
        """Handle failed request."""
        async with self._lock:
            self.stats.failed_requests += 1
            self.stats.last_failure_time = time.time()

            # Only count expected errors
            if any(isinstance(exception, err_type) for err_type in self.config.expected_errors):
                self.failure_count += 1
                self.last_failure_time = time.time()

                if self.state == CircuitState.CLOSED:
                    if self.failure_count >= self.config.failure_threshold:
                        self._open_circuit()
                elif self.state == CircuitState.HALF_OPEN:
                    self._open_circuit()

            logger.warning(
                "Circuit breaker recorded failure",
                provider=self.provider_name,
                error=str(exception)[:100],  # Truncate long error messages
                failure_count=self.failure_count,
                state=self.state.value,
            )

    def _open_circuit(self):
        """Open the circuit breaker."""
        self.state = CircuitState.OPEN
        self.stats.circuit_open_count += 1
        logger.error(f"Circuit breaker OPENED for {self.provider_name}")

    def _close_circuit(self):
        """Close the circuit breaker."""
        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.success_count = 0
        logger.info(f"Circuit breaker CLOSED for {self.provider_name}")

    def _should_attempt_reset(self) -> bool:
        """Check if circuit breaker should attempt reset."""
        if self.last_failure_time is None:
            return True
        return time.time() - self.last_failure_time >= self.config.recovery_timeout

    def _time_until_reset(self) -> float:
        """Calculate time until next reset attempt."""
        if self.last_failure_time is None:
            return 0.0
        elapsed = time.time() - self.last_failure_time
        return max(0.0, self.config.recovery_timeout - elapsed)

    def get_stats(self) -> dict[str, Any]:
        """Get circuit breaker statistics."""
        return {
            "provider": self.provider_name,
            "state": self.state.value,
            "failure_count": self.failure_count,
            "success_count": self.success_count,
            "stats": {
                "total_requests": self.stats.total_requests,
                "successful_requests": self.stats.successful_requests,
                "failed_requests": self.stats.failed_requests,
                "circuit_open_count": self.stats.circuit_open_count,
                "success_rate": (
                    self.stats.successful_requests / max(self.stats.total_requests, 1) * 100
                ),
                "last_failure_time": self.stats.last_failure_time,
                "last_success_time": self.stats.last_success_time,
                "time_until_reset": (
                    self._time_until_reset() if self.state == CircuitState.OPEN else 0
                ),
            },
        }


class LLMProviderError(Exception):
    """Exception for LLM provider failures."""

    pass


class LLMProviderCircuitBreakerManager:
    """Manages circuit breakers for all LLM providers."""

    def __init__(self):
        """Initialize circuit breaker manager for LLM providers."""
        self.circuit_breakers: dict[str, LLMCircuitBreaker] = {}
        self.fallback_chain: list[str] = []

    def register_provider(self, provider_name: str, config: CircuitBreakerConfig | None = None):
        """Register a new provider with circuit breaker protection."""
        if config is None:
            # Provider-specific configurations
            if provider_name == "anthropic":
                config = CircuitBreakerConfig(
                    failure_threshold=5,
                    recovery_timeout=60,
                    success_threshold=3,
                    timeout_seconds=30.0,
                )
            elif provider_name == "openai":
                config = CircuitBreakerConfig(
                    failure_threshold=3,  # OpenAI can be less reliable
                    recovery_timeout=45,
                    success_threshold=2,
                    timeout_seconds=25.0,
                )
            elif provider_name == "gemini":
                config = CircuitBreakerConfig(
                    failure_threshold=4,
                    recovery_timeout=90,  # Longer recovery for Gemini
                    success_threshold=3,
                    timeout_seconds=35.0,
                )
            else:
                config = CircuitBreakerConfig()  # Default

        self.circuit_breakers[provider_name] = LLMCircuitBreaker(provider_name, config)
        logger.info(f"Registered circuit breaker for provider: {provider_name}")

    def set_fallback_chain(self, providers: list[str]):
        """Set the fallback chain for provider selection."""
        self.fallback_chain = providers
        logger.info(f"Set fallback chain: {' -> '.join(providers)}")

    async def call_with_fallback(
        self, func: Callable, *args, primary_provider: str | None = None, **kwargs
    ) -> Any:
        """Call function with automatic provider fallback."""
        last_exception = None
        providers_to_try = []

        # If primary provider specified, try it first
        if primary_provider and primary_provider in self.circuit_breakers:
            providers_to_try.append(primary_provider)

        # Add fallback chain
        providers_to_try.extend([p for p in self.fallback_chain if p not in providers_to_try])

        for provider_name in providers_to_try:
            if provider_name not in self.circuit_breakers:
                continue

            circuit_breaker = self.circuit_breakers[provider_name]

            try:
                # Check if we can use this provider
                if circuit_breaker.state == CircuitState.OPEN:
                    logger.debug(f"Skipping {provider_name} - circuit breaker open")
                    continue

                # Modify function call to use specific provider
                if hasattr(func, "__self__") and hasattr(func.__self__, "current_provider"):
                    func.__self__.current_provider = provider_name
                elif "provider" in kwargs:
                    kwargs["provider"] = provider_name

                result = await circuit_breaker.call(func, *args, **kwargs)

                logger.info(f"Successfully used provider: {provider_name}")
                return result

            except CircuitBreakerError as e:
                logger.warning(f"Provider {provider_name} circuit breaker open: {e}")
                last_exception = e
                continue
            except Exception as e:
                logger.error(f"Provider {provider_name} failed: {e}")
                last_exception = e
                continue

        # All providers failed
        raise LLMProviderError(
            f"All providers in fallback chain failed. Last error: {last_exception}"
        )

    def get_provider_stats(self) -> dict[str, Any]:
        """Get statistics for all circuit breakers."""
        return {provider: cb.get_stats() for provider, cb in self.circuit_breakers.items()}

    def get_healthy_providers(self) -> list[str]:
        """Get list of providers with closed circuit breakers."""
        return [
            provider
            for provider, cb in self.circuit_breakers.items()
            if cb.state == CircuitState.CLOSED
        ]

    def get_provider_health_summary(self) -> dict[str, str]:
        """Get health summary for all providers."""
        summary = {}
        for provider, cb in self.circuit_breakers.items():
            if cb.state == CircuitState.CLOSED:
                summary[provider] = "healthy"
            elif cb.state == CircuitState.HALF_OPEN:
                summary[provider] = "recovering"
            else:
                summary[provider] = "unhealthy"
        return summary

    async def manual_reset(self, provider_name: str) -> bool:
        """Manually reset a circuit breaker."""
        if provider_name not in self.circuit_breakers:
            return False

        cb = self.circuit_breakers[provider_name]
        async with cb._lock:
            cb.state = CircuitState.CLOSED
            cb.failure_count = 0
            cb.success_count = 0
            cb.last_failure_time = None

        logger.info(f"Manually reset circuit breaker for {provider_name}")
        return True


# Enhanced LLM classifier wrapper with circuit breaker support
class ResilientLLMClassifier:
    """LLM classifier with circuit breaker protection."""

    def __init__(self, base_classifier, circuit_breaker_manager: LLMProviderCircuitBreakerManager):
        """
        Initialize resilient LLM classifier with circuit breaker protection.

        Args:
            base_classifier: Base LLM classifier instance
            circuit_breaker_manager: Circuit breaker manager for handling failures
        """
        self.base_classifier = base_classifier
        self.circuit_manager = circuit_breaker_manager

        # Register providers from settings
        from prompt_sentinel.config.settings import settings

        for provider in settings.llm_providers:
            self.circuit_manager.register_provider(provider)

        self.circuit_manager.set_fallback_chain(settings.llm_providers)

    async def classify(self, messages: list[str], **kwargs) -> Any:
        """Classify with circuit breaker protection and fallback."""

        async def _classify_with_provider(*args, **kwargs):
            """Internal method to classify using the base classifier."""
            # This would be your actual LLM classification logic
            return await self.base_classifier.classify(*args, **kwargs)

        try:
            return await self.circuit_manager.call_with_fallback(
                _classify_with_provider, messages, **kwargs
            )
        except LLMProviderError as e:
            logger.error("All LLM providers failed", error=str(e))
            # Return safe default or raise exception based on your needs
            raise

    async def health_check(self) -> dict[str, Any]:
        """Check health of all providers."""
        health_summary = self.circuit_manager.get_provider_health_summary()
        provider_stats = self.circuit_manager.get_provider_stats()

        return {
            "healthy_providers": self.circuit_manager.get_healthy_providers(),
            "provider_health": health_summary,
            "detailed_stats": provider_stats,
            "fallback_chain": self.circuit_manager.fallback_chain,
        }


# Global circuit breaker manager instance
circuit_breaker_manager = LLMProviderCircuitBreakerManager()
