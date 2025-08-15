# Elastic License 2.0
#
# Copyright (c) 2024-present, PromptSentinel
#
# This source code is licensed under the Elastic License 2.0 found in the
# LICENSE file in the root directory of this source tree.

"""Security configuration validation and secret management."""

import os
import re
from typing import Any

import structlog

from prompt_sentinel.config.settings import settings

logger = structlog.get_logger()


class SecurityConfigValidator:
    """Validates security configuration at startup."""

    def __init__(self):
        self.issues: list[dict[str, Any]] = []
        self.warnings: list[dict[str, Any]] = []

    def validate_all(self) -> dict[str, Any]:
        """Validate all security configurations."""
        logger.info("Starting security configuration validation")

        # Run all validation checks
        self._validate_environment()
        self._validate_authentication()
        self._validate_encryption()
        self._validate_rate_limiting()
        self._validate_network_security()
        self._validate_logging_security()
        self._validate_api_keys()

        # Categorize results
        critical_issues = [issue for issue in self.issues if issue["severity"] == "critical"]
        high_issues = [issue for issue in self.issues if issue["severity"] == "high"]
        medium_issues = [issue for issue in self.issues if issue["severity"] == "medium"]

        result = {
            "status": "pass" if not critical_issues and not high_issues else "fail",
            "critical_issues": critical_issues,
            "high_issues": high_issues,
            "medium_issues": medium_issues,
            "warnings": self.warnings,
            "total_issues": len(self.issues),
            "validation_passed": len(critical_issues) == 0 and len(high_issues) == 0,
        }

        # Log results
        if critical_issues:
            logger.critical("Critical security issues found", issues=critical_issues)
        if high_issues:
            logger.error("High severity security issues found", issues=high_issues)
        if medium_issues:
            logger.warning("Medium severity security issues found", issues=medium_issues)

        if result["validation_passed"]:
            logger.info("Security configuration validation passed")
        else:
            logger.error("Security configuration validation failed")

        return result

    def _validate_environment(self):
        """Validate environment-specific settings."""
        # Check for debug mode in production
        if settings.api_env == "production" and settings.debug:
            self._add_issue(
                "critical",
                "Debug mode enabled in production",
                "DEBUG=true in production environment",
                "Set DEBUG=false in production",
            )

        # Check environment variable
        if not os.environ.get("API_ENV"):
            self._add_warning(
                "API_ENV not set",
                "Environment not explicitly configured",
                "Set API_ENV=production/staging/development",
            )

        # Check for development settings in production
        if settings.api_env == "production":
            if settings.api_host == "0.0.0.0":  # nosec B104
                self._add_issue(
                    "medium",
                    "Permissive host binding in production",
                    "API_HOST=0.0.0.0 may expose service unnecessarily",
                    "Set specific host IP for production",
                )

    def _validate_authentication(self):
        """Validate authentication configuration."""
        # Check for disabled auth in production
        if settings.auth_mode == "none" and settings.api_env == "production":
            self._add_issue(
                "critical",
                "Authentication disabled in production",
                "AUTH_MODE=none in production environment",
                "Enable authentication in production",
            )

        # Check HTTPS enforcement
        if not settings.auth_enforce_https and settings.api_env == "production":
            self._add_issue(
                "high",
                "HTTPS not enforced in production",
                "AUTH_ENFORCE_HTTPS=false in production",
                "Enable HTTPS enforcement",
            )

        # Check API key configuration
        if settings.api_key_prefix == "psk_" and settings.api_env == "production":
            self._add_issue(
                "medium",
                "Default API key prefix in production",
                "Using default API_KEY_PREFIX",
                "Use custom API key prefix for production",
            )

        # Check API key length
        if settings.api_key_length < 32:
            self._add_issue(
                "medium",
                "API key length too short",
                f"API_KEY_LENGTH={settings.api_key_length} < 32",
                "Use API key length >= 32 characters",
            )

    def _validate_encryption(self):
        """Validate encryption settings."""
        # Check for encryption key
        master_key = os.environ.get("GDPR_MASTER_KEY")
        if not master_key:
            self._add_warning(
                "Encryption master key not set",
                "GDPR_MASTER_KEY not configured",
                "Set GDPR_MASTER_KEY for field-level encryption",
            )
        elif len(master_key) < 32:
            self._add_issue(
                "high",
                "Weak encryption master key",
                "GDPR_MASTER_KEY length < 32 characters",
                "Use encryption key >= 32 characters",
            )

        # Check TLS configuration
        if settings.api_env == "production" and not settings.auth_enforce_https:
            self._add_issue(
                "high",
                "TLS not enforced",
                "HTTPS not required for production API",
                "Enable HTTPS enforcement",
            )

    def _validate_rate_limiting(self):
        """Validate rate limiting configuration."""
        # Check if rate limiting is too permissive
        if settings.rate_limit_requests_per_minute > 1000:
            self._add_warning(
                "High rate limits configured",
                f"RATE_LIMIT_REQUESTS_PER_MINUTE={settings.rate_limit_requests_per_minute}",
                "Consider lowering rate limits for better protection",
            )

        # Check token limits
        if settings.rate_limit_tokens_per_minute > 100000:
            self._add_warning(
                "High token rate limits",
                f"RATE_LIMIT_TOKENS_PER_MINUTE={settings.rate_limit_tokens_per_minute}",
                "Consider token rate limits for cost control",
            )

        # Check unauthenticated limits
        if settings.auth_unauthenticated_rpm > 100:
            self._add_issue(
                "medium",
                "High unauthenticated rate limits",
                f"AUTH_UNAUTHENTICATED_RPM={settings.auth_unauthenticated_rpm}",
                "Lower unauthenticated rate limits",
            )

    def _validate_network_security(self):
        """Validate network security settings."""
        # Check CORS configuration
        dev_origins = settings.dev_cors_origins
        if dev_origins and settings.api_env == "production":
            if "*" in dev_origins:
                self._add_issue(
                    "critical",
                    "Wildcard CORS in production",
                    "DEV_CORS_ORIGINS contains '*' in production",
                    "Remove wildcard CORS origins",
                )

        # Check for localhost in production CORS
        if dev_origins and settings.api_env == "production":
            if "localhost" in dev_origins or "127.0.0.1" in dev_origins:
                self._add_issue(
                    "medium",
                    "Development CORS origins in production",
                    "localhost/127.0.0.1 in CORS origins",
                    "Remove development origins from production",
                )

    def _validate_logging_security(self):
        """Validate logging security configuration."""
        # Check log level in production
        if settings.log_level == "DEBUG" and settings.api_env == "production":
            self._add_issue(
                "medium",
                "Debug logging in production",
                "LOG_LEVEL=DEBUG in production",
                "Use INFO or WARNING log level in production",
            )

        # Check PII logging
        if settings.pii_log_detected and settings.api_env == "production":
            self._add_issue(
                "high",
                "PII logging enabled in production",
                "PII_LOG_DETECTED=true may log sensitive data",
                "Disable PII logging in production",
            )

    def _validate_api_keys(self):
        """Validate API key configurations."""
        # Check for API keys in environment
        api_keys = {
            "ANTHROPIC_API_KEY": settings.anthropic_api_key,
            "OPENAI_API_KEY": settings.openai_api_key,
            "GEMINI_API_KEY": settings.gemini_api_key,
        }

        missing_keys = []
        for key_name, key_value in api_keys.items():
            if not key_value:
                missing_keys.append(key_name)

        if missing_keys and settings.api_env == "production":
            self._add_issue(
                "high",
                "Missing LLM API keys in production",
                f"Missing keys: {', '.join(missing_keys)}",
                "Configure all required API keys",
            )

        # Validate API key formats
        for key_name, key_value in api_keys.items():
            if key_value:
                if not self._validate_api_key_format(key_name, key_value):
                    self._add_issue(
                        "medium",
                        f"Invalid {key_name} format",
                        f"{key_name} doesn't match expected format",
                        f"Verify {key_name} is correct",
                    )

    def _validate_api_key_format(self, key_name: str, key_value: str) -> bool:
        """Validate API key format for different providers."""
        if key_name == "ANTHROPIC_API_KEY":
            return key_value.startswith("sk-ant-") and len(key_value) > 20
        elif key_name == "OPENAI_API_KEY":
            return key_value.startswith("sk-") and len(key_value) > 40
        elif key_name == "GEMINI_API_KEY":
            return len(key_value) > 20  # Gemini keys don't have consistent prefix
        return True

    def _add_issue(self, severity: str, title: str, description: str, recommendation: str):
        """Add a security issue."""
        self.issues.append(
            {
                "severity": severity,
                "title": title,
                "description": description,
                "recommendation": recommendation,
                "component": "security_config",
            }
        )

    def _add_warning(self, title: str, description: str, recommendation: str):
        """Add a security warning."""
        self.warnings.append(
            {
                "title": title,
                "description": description,
                "recommendation": recommendation,
                "component": "security_config",
            }
        )


class SecretManager:
    """Manages secret validation and rotation."""

    def __init__(self):
        self.secrets = {}
        self.validation_patterns = {
            "api_key": r"^[a-zA-Z0-9_-]{20,}$",
            "token": r"^[a-zA-Z0-9_-]{32,}$",
            "password": r"^.{12,}$",  # Minimum 12 characters
        }

    def validate_secret(
        self,
        secret_name: str,
        secret_value: str,
        secret_type: str = "api_key",  # noqa: S107
    ) -> bool:
        """Validate secret format and strength."""
        if not secret_value:
            return False

        pattern = self.validation_patterns.get(secret_type)
        if pattern and not re.match(pattern, secret_value):
            logger.warning(f"Secret {secret_name} doesn't match expected pattern")
            return False

        # Check for common weak patterns
        if self._is_weak_secret(secret_value):
            logger.warning(f"Secret {secret_name} appears to be weak")
            return False

        return True

    def _is_weak_secret(self, secret: str) -> bool:
        """Check if secret is weak."""
        weak_patterns = [
            "password",
            "123456",
            "test",
            "demo",
            "example",
            "default",
            "admin",
            "secret",
        ]

        secret_lower = secret.lower()
        return any(pattern in secret_lower for pattern in weak_patterns)

    def scan_for_exposed_secrets(self, text: str) -> list[dict[str, Any]]:
        """Scan text for exposed secrets."""
        exposed_secrets = []

        # Patterns for common secret formats
        secret_patterns = {
            "api_key": [
                r"sk-[a-zA-Z0-9]{20,}",  # OpenAI style
                r"sk-ant-[a-zA-Z0-9_-]{20,}",  # Anthropic style
                r"[a-zA-Z0-9]{32,}",  # Generic long strings
            ],
            "password": [
                r"password[\"'\s]*[:=][\"'\s]*([^\"'\s]{8,})",
            ],
            "token": [
                r"[a-zA-Z0-9_-]{40,}",  # JWT-like tokens
            ],
        }

        for secret_type, patterns in secret_patterns.items():
            for pattern in patterns:
                matches = re.finditer(pattern, text, re.IGNORECASE)
                for match in matches:
                    exposed_secrets.append(
                        {
                            "type": secret_type,
                            "value": match.group()[:10] + "...",  # Don't log full secret
                            "position": match.span(),
                            "pattern": pattern,
                        }
                    )

        return exposed_secrets


def validate_startup_security() -> dict[str, Any]:
    """Validate security configuration at startup."""
    validator = SecurityConfigValidator()
    return validator.validate_all()


def check_secrets_security() -> dict[str, Any]:
    """Check for secret security issues."""
    secret_manager = SecretManager()

    # Check environment variables for exposed secrets
    issues = []
    for key, value in os.environ.items():
        if value and len(value) > 20:  # Only check substantial values
            exposed = secret_manager.scan_for_exposed_secrets(value)
            if exposed:
                issues.append({"env_var": key, "exposed_secrets": exposed})

    return {
        "issues_found": len(issues) > 0,
        "issues": issues,
        "recommendation": "Review environment variables for exposed secrets",
    }


# Global instances
security_validator = SecurityConfigValidator()
secret_manager = SecretManager()
