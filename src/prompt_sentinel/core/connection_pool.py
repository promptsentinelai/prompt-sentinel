# Elastic License 2.0
#
# Copyright (c) 2024-present, PromptSentinel
#
# This source code is licensed under the Elastic License 2.0 found in the
# LICENSE file in the root directory of this source tree.

"""Optimized connection pooling for external services."""

from contextlib import asynccontextmanager
from typing import Any

import httpx
import redis.asyncio as redis
import structlog

from prompt_sentinel.config.settings import settings

logger = structlog.get_logger()


class ConnectionPoolManager:
    """Manages connection pools for all external services."""

    def __init__(self):
        """Initialize connection pool manager."""
        self.redis_pool: redis.ConnectionPool | None = None
        self.http_clients: dict[str, httpx.AsyncClient] = {}
        self.initialized = False

    async def initialize(self) -> None:
        """Initialize all connection pools."""
        if self.initialized:
            return

        logger.info("Initializing connection pools")

        # Initialize Redis pool
        await self._init_redis_pool()

        # Initialize HTTP clients
        await self._init_http_clients()

        self.initialized = True
        logger.info("Connection pools initialized")

    async def _init_redis_pool(self) -> None:
        """Initialize Redis connection pool."""
        if not settings.redis_enabled:
            logger.info("Redis disabled, skipping pool initialization")
            return

        try:
            self.redis_pool = redis.ConnectionPool(
                host=settings.redis_host,
                port=settings.redis_port,
                password=settings.redis_password if settings.redis_password else None,
                decode_responses=True,
                # Connection pool settings
                max_connections=50,
                socket_connect_timeout=2,
                socket_timeout=2,
                socket_keepalive=True,
                socket_keepalive_options={},
                health_check_interval=30,
                retry_on_timeout=True,
                retry_on_error=[redis.ConnectionError],
            )

            # Test connection
            async with self.get_redis_client() as client:
                await client.ping()

            logger.info("Redis connection pool initialized", max_connections=50)

        except Exception as e:
            logger.error("Failed to initialize Redis pool", error=str(e))
            self.redis_pool = None

    async def _init_http_clients(self) -> None:
        """Initialize HTTP client pools for LLM providers."""
        # Anthropic client
        self.http_clients["anthropic"] = httpx.AsyncClient(  # nosec B113
            base_url="https://api.anthropic.com",
            headers={
                "x-api-key": settings.anthropic_api_key or "",
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            limits=httpx.Limits(
                max_keepalive_connections=20, max_connections=50, keepalive_expiry=30
            ),
            timeout=httpx.Timeout(30.0, connect=5.0),
            http2=True,  # Enable HTTP/2 for better performance
        )

        # OpenAI client
        self.http_clients["openai"] = httpx.AsyncClient(  # nosec B113
            base_url="https://api.openai.com",
            headers={
                "Authorization": f"Bearer {settings.openai_api_key or ''}",
                "content-type": "application/json",
            },
            limits=httpx.Limits(
                max_keepalive_connections=20, max_connections=50, keepalive_expiry=30
            ),
            timeout=httpx.Timeout(30.0, connect=5.0),
            http2=True,
        )

        # Google/Gemini client
        self.http_clients["gemini"] = httpx.AsyncClient(  # nosec B113
            base_url="https://generativelanguage.googleapis.com",
            headers={"content-type": "application/json"},
            limits=httpx.Limits(
                max_keepalive_connections=20, max_connections=50, keepalive_expiry=30
            ),
            timeout=httpx.Timeout(30.0, connect=5.0),
            http2=True,
        )

        logger.info("HTTP client pools initialized", providers=list(self.http_clients.keys()))

    @asynccontextmanager
    async def get_redis_client(self):
        """
        Get Redis client from pool.

        Yields:
            Redis client instance
        """
        if not self.redis_pool:
            raise RuntimeError("Redis pool not initialized")

        client = redis.Redis(connection_pool=self.redis_pool)
        try:
            yield client
        finally:
            await client.close(close_connection_pool=False)

    def get_http_client(self, provider: str) -> httpx.AsyncClient:
        """
        Get HTTP client for a provider.

        Args:
            provider: Provider name (anthropic, openai, gemini)

        Returns:
            HTTP client instance

        Raises:
            KeyError: If provider not found
        """
        if provider not in self.http_clients:
            raise KeyError(f"HTTP client for {provider} not found")

        return self.http_clients[provider]

    async def close(self) -> None:
        """Close all connection pools."""
        logger.info("Closing connection pools")

        # Close Redis pool
        if self.redis_pool:
            await self.redis_pool.disconnect()
            self.redis_pool = None

        # Close HTTP clients
        for _provider, client in self.http_clients.items():
            await client.aclose()
        self.http_clients.clear()

        self.initialized = False
        logger.info("Connection pools closed")

    async def health_check(self) -> dict[str, Any]:
        """
        Check health of all connection pools.

        Returns:
            Health status for each pool
        """
        health_status = {}

        # Check Redis
        if self.redis_pool:
            try:
                async with self.get_redis_client() as client:
                    await client.ping()
                health_status["redis"] = {
                    "status": "healthy",
                    "connections": self.redis_pool.connection_kwargs,
                }
            except Exception as e:
                health_status["redis"] = {"status": "unhealthy", "error": str(e)}
        else:
            health_status["redis"] = {"status": "disabled"}

        # Check HTTP clients
        for provider, client in self.http_clients.items():
            try:
                # Simple connectivity check
                health_status[provider] = {"status": "healthy", "base_url": str(client.base_url)}
            except Exception as e:
                health_status[provider] = {"status": "unhealthy", "error": str(e)}

        return health_status


# Global connection pool manager
connection_pool_manager = ConnectionPoolManager()


async def get_redis_client():
    """
    Dependency for getting Redis client.

    Yields:
        Redis client from pool
    """
    if not connection_pool_manager.initialized:
        await connection_pool_manager.initialize()

    async with connection_pool_manager.get_redis_client() as client:
        yield client


def get_http_client(provider: str) -> httpx.AsyncClient:
    """
    Get HTTP client for a provider.

    Args:
        provider: Provider name

    Returns:
        HTTP client instance
    """
    if not connection_pool_manager.initialized:
        raise RuntimeError("Connection pools not initialized")

    return connection_pool_manager.get_http_client(provider)
