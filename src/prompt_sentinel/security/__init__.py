# Elastic License 2.0
#
# Copyright (c) 2024-present, PromptSentinel
#
# This source code is licensed under the Elastic License 2.0 found in the
# LICENSE file in the root directory of this source tree.

"""Security module for PromptSentinel."""

from .audit_logger import (
    SecurityAuditLogger,
    SecurityAuditMiddleware,
    SecurityEventType,
    security_audit_logger,
)
from .auth_system import (
    APIKey,
    APIKeyManager,
    AuthenticatedUser,
    EnhancedAuthMiddleware,
    Permission,
    UserRole,
    api_key_manager,
    auth_middleware,
    auth_router,
    get_current_user,
    require_authentication,
    require_permission,
    require_role,
)
from .circuit_breaker import (
    CircuitBreakerConfig,
    CircuitState,
    LLMCircuitBreaker,
    LLMProviderCircuitBreakerManager,
    LLMProviderError,
    ResilientLLMClassifier,
    circuit_breaker_manager,
)
from .config_validator import (
    SecretManager,
    SecurityConfigValidator,
    check_secrets_security,
    secret_manager,
    security_validator,
    validate_startup_security,
)
from .enhanced_rate_limiter import (
    DDoSConfig,
    DDoSProtectionMiddleware,
    EnhancedRateLimitingMiddleware,
    SlidingWindowConfig,
    SlidingWindowLimiter,
    ThreatLevel,
)
from .headers_middleware import (
    ContentTypeMiddleware,
    RequestSizeLimitMiddleware,
    SecurityHeadersMiddleware,
    add_security_middleware,
    configure_secure_cors,
    validate_security_configuration,
)
from .validation_middleware import (
    BatchPromptRequest,
    EnhancedPromptRequest,
    SecurityValidationMiddleware,
    sanitize_output,
)

__all__ = [
    # Audit logging
    "SecurityAuditLogger",
    "SecurityAuditMiddleware",
    "SecurityEventType",
    "security_audit_logger",
    # Authentication and authorization
    "APIKey",
    "APIKeyManager",
    "AuthenticatedUser",
    "EnhancedAuthMiddleware",
    "Permission",
    "UserRole",
    "api_key_manager",
    "auth_middleware",
    "auth_router",
    "get_current_user",
    "require_authentication",
    "require_permission",
    "require_role",
    # Circuit breakers
    "CircuitBreakerConfig",
    "CircuitState",
    "LLMCircuitBreaker",
    "LLMProviderCircuitBreakerManager",
    "LLMProviderError",
    "ResilientLLMClassifier",
    "circuit_breaker_manager",
    # Configuration validation
    "SecretManager",
    "SecurityConfigValidator",
    "check_secrets_security",
    "secret_manager",
    "security_validator",
    "validate_startup_security",
    # Enhanced rate limiting
    "DDoSConfig",
    "DDoSProtectionMiddleware",
    "EnhancedRateLimitingMiddleware",
    "SlidingWindowConfig",
    "SlidingWindowLimiter",
    "ThreatLevel",
    # Security headers and middleware
    "ContentTypeMiddleware",
    "RequestSizeLimitMiddleware",
    "SecurityHeadersMiddleware",
    "add_security_middleware",
    "configure_secure_cors",
    "validate_security_configuration",
    # Input validation
    "BatchPromptRequest",
    "EnhancedPromptRequest",
    "SecurityValidationMiddleware",
    "sanitize_output",
]


def initialize_security_components():
    """Initialize all security components."""
    import structlog

    logger = structlog.get_logger()

    # Validate security configuration
    validation_result = validate_startup_security()

    if not validation_result["validation_passed"]:
        logger.error(
            "Security validation failed",
            critical_issues=validation_result["critical_issues"],
            high_issues=validation_result["high_issues"],
        )

        # In production, fail hard on critical issues
        from prompt_sentinel.config.settings import settings

        if settings.api_env == "production" and validation_result["critical_issues"]:
            raise RuntimeError("Critical security issues must be resolved before starting")

    # Check for exposed secrets
    secret_check = check_secrets_security()
    if secret_check["issues_found"]:
        logger.warning("Potential secret exposure detected", issues=secret_check["issues"])

    # Initialize circuit breakers for LLM providers
    from prompt_sentinel.config.settings import settings

    for provider in settings.llm_providers:
        circuit_breaker_manager.register_provider(provider)

    circuit_breaker_manager.set_fallback_chain(settings.llm_providers)

    logger.info(
        "Security components initialized",
        validation_status=validation_result["status"],
        issues_count=validation_result["total_issues"],
        circuit_breakers=list(circuit_breaker_manager.circuit_breakers.keys()),
    )


def get_security_status() -> dict:
    """Get comprehensive security status."""
    return {
        "configuration": validate_startup_security(),
        "secrets": check_secrets_security(),
        "circuit_breakers": circuit_breaker_manager.get_provider_stats(),
        "providers_health": circuit_breaker_manager.get_provider_health_summary(),
    }
