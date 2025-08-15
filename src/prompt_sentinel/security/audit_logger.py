# Elastic License 2.0
#
# Copyright (c) 2024-present, PromptSentinel
#
# This source code is licensed under the Elastic License 2.0 found in the
# LICENSE file in the root directory of this source tree.

"""Security audit logging for compliance and threat detection."""

import time
from datetime import datetime
from enum import Enum
from typing import Any

import structlog
from fastapi import Request

logger = structlog.get_logger()


class SecurityEventType(str, Enum):
    """Types of security events to audit."""

    # Authentication events
    AUTH_SUCCESS = "auth_success"
    AUTH_FAILURE = "auth_failure"
    AUTH_BYPASS = "auth_bypass"

    # Access control events
    ACCESS_GRANTED = "access_granted"
    ACCESS_DENIED = "access_denied"
    PRIVILEGE_ESCALATION = "privilege_escalation"

    # Input validation events
    INVALID_INPUT = "invalid_input"
    SUSPICIOUS_PATTERN = "suspicious_pattern"
    INJECTION_ATTEMPT = "injection_attempt"

    # Rate limiting events
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    DDOS_DETECTED = "ddos_detected"
    ABUSE_DETECTED = "abuse_detected"

    # Data protection events
    PII_DETECTED = "pii_detected"
    DATA_LEAK_PREVENTED = "data_leak_prevented"
    SENSITIVE_DATA_ACCESS = "sensitive_data_access"

    # System security events
    SECURITY_CONFIG_CHANGE = "security_config_change"
    VULNERABILITY_DETECTED = "vulnerability_detected"
    ANOMALY_DETECTED = "anomaly_detected"


class SecurityAuditLogger:
    """Enhanced audit logger for security events."""

    def __init__(self):
        """Initialize security audit logger."""
        self.logger = structlog.get_logger("security.audit")

    async def log_security_event(
        self,
        event_type: SecurityEventType,
        description: str,
        request: Request | None = None,
        client_id: str | None = None,
        severity: str = "medium",
        additional_data: dict[str, Any] | None = None,
    ) -> None:
        """Log a security event with full context."""

        event_data = {
            "event_type": event_type.value,
            "description": description,
            "severity": severity,
            "timestamp": datetime.utcnow().isoformat(),
            "event_id": self._generate_event_id(),
        }

        # Add request context if available
        if request:
            event_data.update(
                {
                    "client_ip": self._get_client_ip(request),
                    "user_agent": request.headers.get("user-agent", ""),
                    "path": request.url.path,
                    "method": request.method,
                    "query_params": dict(request.query_params),
                    "headers": self._sanitize_headers(dict(request.headers)),
                    "referer": request.headers.get("referer", ""),
                }
            )

        # Add client information
        if client_id:
            event_data["client_id"] = client_id

        # Add additional data
        if additional_data:
            event_data.update(additional_data)

        # Log with appropriate level based on severity
        if severity == "critical":
            self.logger.critical("Security event", **event_data)
        elif severity == "high":
            self.logger.error("Security event", **event_data)
        elif severity == "medium":
            self.logger.warning("Security event", **event_data)
        else:
            self.logger.info("Security event", **event_data)

    async def log_authentication_event(
        self,
        success: bool,
        request: Request,
        client_id: str | None = None,
        auth_method: str = "api_key",
        failure_reason: str | None = None,
    ) -> None:
        """Log authentication attempt."""

        event_type = SecurityEventType.AUTH_SUCCESS if success else SecurityEventType.AUTH_FAILURE
        description = f"Authentication {'succeeded' if success else 'failed'} using {auth_method}"

        additional_data = {
            "auth_method": auth_method,
            "success": success,
        }

        if not success and failure_reason:
            additional_data["failure_reason"] = failure_reason

        severity = "low" if success else "medium"

        await self.log_security_event(
            event_type=event_type,
            description=description,
            request=request,
            client_id=client_id,
            severity=severity,
            additional_data=additional_data,
        )

    async def log_rate_limit_event(
        self,
        request: Request,
        client_id: str | None = None,
        limit_type: str = "requests_per_minute",
        current_count: int = 0,
        limit: int = 0,
    ) -> None:
        """Log rate limiting event."""

        description = f"Rate limit exceeded: {current_count}/{limit} {limit_type}"

        additional_data = {
            "limit_type": limit_type,
            "current_count": current_count,
            "limit": limit,
            "exceeded_by": current_count - limit,
        }

        await self.log_security_event(
            event_type=SecurityEventType.RATE_LIMIT_EXCEEDED,
            description=description,
            request=request,
            client_id=client_id,
            severity="medium",
            additional_data=additional_data,
        )

    async def log_suspicious_activity(
        self,
        request: Request,
        pattern_type: str,
        pattern_details: str,
        client_id: str | None = None,
        confidence: float = 0.0,
    ) -> None:
        """Log suspicious activity detection."""

        description = f"Suspicious {pattern_type} detected: {pattern_details}"

        additional_data = {
            "pattern_type": pattern_type,
            "pattern_details": pattern_details,
            "confidence": confidence,
        }

        # Determine severity based on confidence
        if confidence >= 0.9:
            severity = "high"
        elif confidence >= 0.7:
            severity = "medium"
        else:
            severity = "low"

        await self.log_security_event(
            event_type=SecurityEventType.SUSPICIOUS_PATTERN,
            description=description,
            request=request,
            client_id=client_id,
            severity=severity,
            additional_data=additional_data,
        )

    async def log_pii_detection(
        self,
        request: Request,
        pii_types: list[str],
        action_taken: str,
        client_id: str | None = None,
    ) -> None:
        """Log PII detection event."""

        description = f"PII detected: {', '.join(pii_types)}. Action: {action_taken}"

        additional_data = {
            "pii_types": pii_types,
            "action_taken": action_taken,
            "pii_count": len(pii_types),
        }

        await self.log_security_event(
            event_type=SecurityEventType.PII_DETECTED,
            description=description,
            request=request,
            client_id=client_id,
            severity="medium",
            additional_data=additional_data,
        )

    async def log_input_validation_failure(
        self,
        request: Request,
        validation_type: str,
        details: str,
        client_id: str | None = None,
    ) -> None:
        """Log input validation failure."""

        description = f"Input validation failed: {validation_type} - {details}"

        additional_data = {
            "validation_type": validation_type,
            "validation_details": details,
        }

        await self.log_security_event(
            event_type=SecurityEventType.INVALID_INPUT,
            description=description,
            request=request,
            client_id=client_id,
            severity="medium",
            additional_data=additional_data,
        )

    def _generate_event_id(self) -> str:
        """Generate unique event ID."""
        return f"sec_{int(time.time() * 1000000)}"

    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP address."""
        # Check forwarded headers first (for proxy setups)
        forwarded_for = request.headers.get("x-forwarded-for")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()

        real_ip = request.headers.get("x-real-ip")
        if real_ip:
            return real_ip

        return request.client.host if request.client else "unknown"

    def _sanitize_headers(self, headers: dict[str, str]) -> dict[str, str]:
        """Sanitize headers for logging (remove sensitive data)."""
        sensitive_headers = {
            "authorization",
            "x-api-key",
            "cookie",
            "set-cookie",
            "proxy-authorization",
        }

        sanitized = {}
        for key, value in headers.items():
            key_lower = key.lower()
            if key_lower in sensitive_headers:
                # Log presence but not value
                sanitized[key] = "[REDACTED]"
            elif len(value) > 200:
                # Truncate very long headers
                sanitized[key] = value[:200] + "..."
            else:
                sanitized[key] = value

        return sanitized


# Middleware for automatic security event logging
from starlette.middleware.base import BaseHTTPMiddleware


class SecurityAuditMiddleware(BaseHTTPMiddleware):
    """Middleware for automatic security event logging."""

    def __init__(self, app):
        """
        Initialize audit logging middleware.

        Args:
            app: FastAPI application instance
        """
        super().__init__(app)
        self.audit_logger = SecurityAuditLogger()

    async def dispatch(self, request: Request, call_next):
        """Log security-relevant events automatically."""
        start_time = time.time()

        # Get client information
        client = getattr(request.state, "client", None)
        client_id = client.client_id if client else None

        try:
            response = await call_next(request)

            # Log successful API access for sensitive endpoints
            if self._should_audit_endpoint(request.url.path):
                processing_time = time.time() - start_time

                await self.audit_logger.log_security_event(
                    event_type=SecurityEventType.ACCESS_GRANTED,
                    description=f"API access to {request.url.path}",
                    request=request,
                    client_id=client_id,
                    severity="low",
                    additional_data={
                        "status_code": response.status_code,
                        "processing_time_ms": round(processing_time * 1000, 2),
                        "endpoint": request.url.path,
                    },
                )

            return response

        except Exception as e:
            # Log security-relevant errors
            if self._is_security_error(e):
                await self.audit_logger.log_security_event(
                    event_type=SecurityEventType.ACCESS_DENIED,
                    description=f"Access denied: {str(e)}",
                    request=request,
                    client_id=client_id,
                    severity="medium",
                    additional_data={
                        "error_type": type(e).__name__,
                        "error_message": str(e),
                    },
                )
            raise

    def _should_audit_endpoint(self, path: str) -> bool:
        """
        Determine if endpoint should be audited.

        Args:
            path: Request path to check

        Returns:
            True if endpoint should be audited
        """
        sensitive_endpoints = [
            "/api/v1/detect",
            "/api/v1/analyze",
            "/api/v1/batch",
            "/api/v1/client",
            "/api/v1/admin",
        ]
        return any(path.startswith(endpoint) for endpoint in sensitive_endpoints)

    def _is_security_error(self, exception: Exception) -> bool:
        """
        Check if exception is security-related.

        Args:
            exception: Exception to check

        Returns:
            True if exception is security-related
        """
        from fastapi import HTTPException

        if isinstance(exception, HTTPException):
            # Log auth failures, forbidden access, etc.
            return exception.status_code in [401, 403, 413, 429]

        return False


# Global audit logger instance
security_audit_logger = SecurityAuditLogger()
