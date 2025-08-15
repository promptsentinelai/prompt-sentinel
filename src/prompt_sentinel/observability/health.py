# Copyright 2025 PromptSentinel
# Licensed under the Elastic License 2.0; you may not use this file except
# in compliance with the Elastic License 2.0. You may obtain a copy of the
# License at https://www.elastic.co/licensing/elastic-license

"""Health checks for observability."""

import time
from collections.abc import Callable
from enum import Enum
from typing import Any


class HealthStatus(str, Enum):
    """Health check status."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"


class HealthCheck:
    """Individual health check."""

    def __init__(self, name: str, check_fn: Callable):
        """Initialize health check."""
        self.name = name
        self.check_fn = check_fn
        self.last_check_time: float | None = None
        self.last_status: HealthStatus | None = None
        self.last_message: str | None = None

    async def execute(self) -> tuple[HealthStatus, str]:
        """Execute health check."""
        try:
            result = await self.check_fn()
            self.last_check_time = time.time()

            if isinstance(result, bool):
                status = HealthStatus.HEALTHY if result else HealthStatus.UNHEALTHY
                message = "OK" if result else "Failed"
            elif isinstance(result, tuple):
                status, message = result
            else:
                status = HealthStatus.HEALTHY
                message = str(result)

            self.last_status = status
            self.last_message = message
            return status, message

        except Exception as e:
            self.last_check_time = time.time()
            self.last_status = HealthStatus.UNHEALTHY
            self.last_message = str(e)
            return HealthStatus.UNHEALTHY, str(e)


class HealthMonitor:
    """Monitor system health."""

    def __init__(self):
        """Initialize health monitor."""
        self.checks: dict[str, HealthCheck] = {}
        self.startup_time = time.time()

    def register_check(self, name: str, check_fn: Callable) -> None:
        """Register a health check."""
        self.checks[name] = HealthCheck(name, check_fn)

    async def check_health(self, check_name: str | None = None) -> dict[str, Any]:
        """Run health checks."""
        if check_name:
            if check_name not in self.checks:
                return {
                    "status": HealthStatus.UNHEALTHY,
                    "message": f"Check {check_name} not found",
                }

            status, message = await self.checks[check_name].execute()
            return {"status": status, "message": message, "timestamp": time.time()}

        # Run all checks
        results = {}
        overall_status = HealthStatus.HEALTHY

        for name, check in self.checks.items():
            status, message = await check.execute()
            results[name] = {"status": status, "message": message}

            if status == HealthStatus.UNHEALTHY:
                overall_status = HealthStatus.UNHEALTHY
            elif status == HealthStatus.DEGRADED and overall_status == HealthStatus.HEALTHY:
                overall_status = HealthStatus.DEGRADED

        return {
            "status": overall_status,
            "checks": results,
            "timestamp": time.time(),
            "uptime": time.time() - self.startup_time,
        }

    async def liveness_check(self) -> bool:
        """Check if service is alive."""
        # Basic liveness - service is responding
        return True

    async def readiness_check(self) -> bool:
        """Check if service is ready to serve traffic."""
        # Check critical dependencies
        result = await self.check_health()
        return result["status"] != HealthStatus.UNHEALTHY

    async def startup_check(self) -> bool:
        """Check if service can start up."""
        # Check initial configuration
        return True

    def get_status(self) -> dict[str, Any]:
        """Get current health status without running checks."""
        results = {}
        overall_status = HealthStatus.HEALTHY

        for name, check in self.checks.items():
            if check.last_status:
                results[name] = {
                    "status": check.last_status,
                    "message": check.last_message,
                    "last_check": check.last_check_time,
                }

                if check.last_status == HealthStatus.UNHEALTHY:
                    overall_status = HealthStatus.UNHEALTHY
                elif (
                    check.last_status == HealthStatus.DEGRADED
                    and overall_status == HealthStatus.HEALTHY
                ):
                    overall_status = HealthStatus.DEGRADED

        return {
            "status": overall_status,
            "checks": results,
            "timestamp": time.time(),
            "uptime": time.time() - self.startup_time,
        }
