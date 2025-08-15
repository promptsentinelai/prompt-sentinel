# Elastic License 2.0
#
# Copyright (c) 2024-present, PromptSentinel
#
# This source code is licensed under the Elastic License 2.0 found in the
# LICENSE file in the root directory of this source tree.

"""Security API endpoints for metrics and monitoring."""

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel

from prompt_sentinel.gdpr.lifecycle import (
    DataCategory,
    lifecycle_manager,
)
from prompt_sentinel.security.auth_system import UserRole, require_role
from prompt_sentinel.security.metrics_dashboard import (
    AlertSeverity,
    MetricType,
    security_dashboard,
)

router = APIRouter(prefix="/api/v1/security", tags=["security"])


class MetricRecord(BaseModel):
    """Request to record a metric."""

    metric_type: MetricType
    name: str
    value: float
    unit: str = "count"
    metadata: dict[str, Any] | None = None
    tags: list[str] | None = None


class ThresholdConfig(BaseModel):
    """Alert threshold configuration."""

    name: str
    metric_type: MetricType
    metric_name: str
    threshold: float
    severity: AlertSeverity = AlertSeverity.MEDIUM
    window_minutes: int = 5
    description: str | None = None
    action: str | None = None


class DeletionRequest(BaseModel):
    """GDPR deletion request."""

    data_subject_id: str
    categories: list[DataCategory] | None = None
    reason: str = "user_request"


class ExportRequest(BaseModel):
    """GDPR data export request."""

    data_subject_id: str
    categories: list[DataCategory] | None = None


@router.get("/metrics/dashboard")
async def get_dashboard(_: Any = Depends(require_role(UserRole.READONLY))) -> dict[str, Any]:
    """
    Get security metrics dashboard summary.

    Returns comprehensive dashboard with metrics, alerts, and statistics.
    """
    return security_dashboard.get_dashboard_summary()


@router.get("/metrics/history/{metric_type}/{metric_name}")
async def get_metric_history(
    metric_type: MetricType,
    metric_name: str,
    minutes: int = Query(60, ge=1, le=1440),
    _: Any = Depends(require_role(UserRole.READONLY)),
) -> list[dict[str, Any]]:
    """
    Get historical data for specific metric.

    Args:
        metric_type: Type of metric
        metric_name: Name of metric
        minutes: History window in minutes (max 24 hours)

    Returns:
        List of metric data points
    """
    return security_dashboard.get_metric_history(metric_type, metric_name, minutes)


@router.get("/metrics/export")
async def export_metrics(
    format: str = Query("json", pattern="^(json|prometheus|csv)$"),
    _: Any = Depends(require_role(UserRole.ADMIN)),
) -> str:
    """
    Export metrics in specified format.

    Args:
        format: Export format (json, prometheus, csv)

    Returns:
        Exported metrics as string
    """
    return security_dashboard.export_metrics(format)


@router.post("/metrics/record")
async def record_metric(
    metric: MetricRecord, _: Any = Depends(require_role(UserRole.SERVICE))
) -> dict[str, str]:
    """
    Record a security metric.

    Args:
        metric: Metric to record

    Returns:
        Confirmation message
    """
    await security_dashboard.record_metric(
        metric.metric_type, metric.name, metric.value, metric.unit, metric.metadata, metric.tags
    )

    return {"status": "recorded", "metric": metric.name}


@router.post("/metrics/threshold")
async def set_threshold(
    config: ThresholdConfig, _: Any = Depends(require_role(UserRole.ADMIN))
) -> dict[str, str]:
    """
    Set or update alert threshold.

    Args:
        config: Threshold configuration

    Returns:
        Confirmation message
    """
    security_dashboard.set_threshold(
        config.name,
        config.metric_type,
        config.metric_name,
        config.threshold,
        config.severity,
        config.window_minutes,
        config.description or "",
        config.action or "",
    )

    return {"status": "configured", "threshold": config.name}


@router.get("/health")
async def health_check(_: Any = Depends(require_role(UserRole.READONLY))) -> dict[str, Any]:
    """
    Run security health check.

    Returns comprehensive health status report.
    """
    return await security_dashboard.run_health_check()


@router.get("/alerts/recent")
async def get_recent_alerts(
    limit: int = Query(10, ge=1, le=100),
    severity: AlertSeverity | None = None,
    _: Any = Depends(require_role(UserRole.READONLY)),
) -> list[dict[str, Any]]:
    """
    Get recent security alerts.

    Args:
        limit: Maximum number of alerts to return
        severity: Filter by severity level

    Returns:
        List of recent alerts
    """
    all_alerts = []

    for agg in security_dashboard.aggregations.values():
        all_alerts.extend(list(agg.alerts))

    # Sort by timestamp
    all_alerts.sort(key=lambda x: x.timestamp, reverse=True)

    # Filter by severity if specified
    if severity:
        all_alerts = [a for a in all_alerts if a.severity == severity]

    # Limit results
    all_alerts = all_alerts[:limit]

    return [
        {
            "alert_id": alert.alert_id,
            "severity": alert.severity.value,
            "metric_type": alert.metric_type.value,
            "title": alert.title,
            "description": alert.description,
            "timestamp": alert.timestamp.isoformat(),
            "actual_value": alert.actual_value,
            "threshold_value": alert.threshold_value,
            "recommended_action": alert.recommended_action,
            "auto_resolved": alert.auto_resolved,
        }
        for alert in all_alerts
    ]


# GDPR Compliance Endpoints


@router.post("/gdpr/deletion")
async def handle_deletion_request(
    request: DeletionRequest, _: Any = Depends(require_role(UserRole.ADMIN))
) -> dict[str, Any]:
    """
    Handle GDPR deletion request (Right to be Forgotten).

    Args:
        request: Deletion request details

    Returns:
        Deletion summary
    """
    result = await lifecycle_manager.handle_deletion_request(
        request.data_subject_id, request.categories, request.reason
    )

    return result


@router.post("/gdpr/export")
async def handle_export_request(
    request: ExportRequest, _: Any = Depends(require_role(UserRole.ADMIN))
) -> dict[str, Any]:
    """
    Handle GDPR data export request (Right to Data Portability).

    Args:
        request: Export request details

    Returns:
        Exported data in portable format
    """
    result = await lifecycle_manager.handle_data_export_request(
        request.data_subject_id, request.categories
    )

    return result


@router.get("/gdpr/retention-policies")
async def get_retention_policies(
    _: Any = Depends(require_role(UserRole.READONLY)),
) -> dict[str, Any]:
    """
    Get current data retention policies.

    Returns:
        Retention policy report
    """
    return lifecycle_manager.get_retention_report()


@router.post("/gdpr/retention-cleanup")
async def run_retention_cleanup(_: Any = Depends(require_role(UserRole.ADMIN))) -> dict[str, Any]:
    """
    Manually trigger retention cleanup.

    Returns:
        Cleanup summary
    """
    result = await lifecycle_manager.run_retention_cleanup()
    return result


# Security Configuration Endpoints


@router.get("/config/validation")
async def validate_security_config(
    _: Any = Depends(require_role(UserRole.ADMIN)),
) -> dict[str, Any]:
    """
    Validate current security configuration.

    Returns:
        Configuration validation report
    """
    from prompt_sentinel.security.config_validator import security_validator

    report = security_validator.validate_all()
    return report


@router.get("/config/recommendations")
async def get_security_recommendations(
    _: Any = Depends(require_role(UserRole.ADMIN)),
) -> dict[str, Any]:
    """
    Get security configuration recommendations.

    Returns:
        List of recommended security improvements
    """
    from prompt_sentinel.security.config_validator import security_validator

    recommendations = []
    report = security_validator.validate_all()

    for check, result in report["checks"].items():
        if result["status"] != "passed":
            recommendations.append(
                {
                    "check": check,
                    "severity": result.get("severity", "medium"),
                    "recommendation": result.get("recommendation", "Review configuration"),
                    "current_value": result.get("details"),
                }
            )

    return {
        "timestamp": datetime.utcnow().isoformat(),
        "recommendations": recommendations,
        "total_issues": len(recommendations),
        "compliance_score": report["score"],
    }


# Rate Limiting Status


@router.get("/rate-limits/status")
async def get_rate_limit_status(
    client_id: str | None = Query(None), _: Any = Depends(require_role(UserRole.READONLY))
) -> dict[str, Any]:
    """
    Get rate limiting status for client or overall.

    Args:
        client_id: Optional client ID to check

    Returns:
        Rate limit status information
    """
    from prompt_sentinel.security.enhanced_rate_limiter import (
        ddos_protection,
        rate_limiter,
    )

    status: dict[str, Any] = {
        "timestamp": datetime.utcnow().isoformat(),
        "global_status": "active",
        "ddos_protection": "enabled",
    }

    if client_id:
        # Get client-specific status
        client_status = {}

        # Check token bucket
        if rate_limiter and hasattr(rate_limiter, "get_client_status"):
            client_status["token_bucket"] = rate_limiter.get_client_status(client_id)

        # Check sliding window
        if rate_limiter and hasattr(rate_limiter, "sliding_window") and rate_limiter.sliding_window:
            remaining = await rate_limiter.sliding_window.get_remaining(client_id)
            client_status["sliding_window"] = {
                "remaining_requests": remaining,
                "window_size": rate_limiter.sliding_window.window_size,
            }

        # Check if blocked
        if (
            ddos_protection
            and hasattr(ddos_protection, "blocked_ips")
            and client_id in ddos_protection.blocked_ips
        ):
            block_info = ddos_protection.blocked_ips[client_id]
            client_status["blocked"] = {
                "until": block_info["until"].isoformat(),
                "reason": block_info["reason"],
            }

        status["client_status"] = client_status

    else:
        # Get overall statistics
        status["statistics"] = {
            "blocked_ips": (
                len(getattr(ddos_protection, "blocked_ips", {})) if ddos_protection else 0
            ),
            "rate_limited_clients": 0,  # Would need to track this
        }

    return status


# Circuit Breaker Status


@router.get("/circuit-breakers/status")
async def get_circuit_breaker_status(
    _: Any = Depends(require_role(UserRole.READONLY)),
) -> dict[str, Any]:
    """
    Get circuit breaker status for all providers.

    Returns:
        Circuit breaker status for each provider
    """
    from prompt_sentinel.security.circuit_breaker import circuit_breaker_manager

    status: dict[str, Any] = {"timestamp": datetime.utcnow().isoformat(), "providers": {}}

    for provider_name, breaker in circuit_breaker_manager.circuit_breakers.items():
        status["providers"][provider_name] = {
            "state": breaker.state.value,
            "failure_count": breaker.failure_count,
            "success_count": breaker.success_count,
            "last_failure_time": (
                datetime.fromtimestamp(breaker.last_failure_time).isoformat()
                if breaker.last_failure_time
                else None
            ),
            "half_open_attempts": breaker.half_open_attempts,
        }

    return status


@router.post("/circuit-breakers/{provider}/reset")
async def reset_circuit_breaker(
    provider: str, _: Any = Depends(require_role(UserRole.ADMIN))
) -> dict[str, str]:
    """
    Manually reset a circuit breaker.

    Args:
        provider: Provider name

    Returns:
        Confirmation message
    """
    from prompt_sentinel.security.circuit_breaker import circuit_breaker_manager

    if provider not in circuit_breaker_manager.circuit_breakers:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Circuit breaker for provider '{provider}' not found",
        )

    circuit_breaker_manager.circuit_breakers[provider].reset()

    return {"status": "reset", "provider": provider, "timestamp": datetime.utcnow().isoformat()}
