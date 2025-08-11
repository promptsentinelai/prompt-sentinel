# Copyright 2025 PromptSentinel
# Licensed under the Elastic License 2.0; you may not use this file except
# in compliance with the Elastic License 2.0. You may obtain a copy of the
# License at https://www.elastic.co/licensing/elastic-license

"""Authentication and API key models.

This module defines the data models for API key management and client authentication.
"""

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class AuthMode(str, Enum):
    """Authentication mode for the service."""

    NONE = "none"  # No authentication required (sidecar/internal)
    OPTIONAL = "optional"  # Authentication optional (mixed mode)
    REQUIRED = "required"  # Authentication required (public/SaaS)


class AuthMethod(str, Enum):
    """How the request was authenticated."""

    NONE = "none"  # No auth (AUTH_MODE=none)
    BYPASS = "bypass"  # Bypassed (trusted network/header)
    API_KEY = "api_key"  # Authenticated with API key
    ANONYMOUS = "anonymous"  # No auth provided (AUTH_MODE=optional)


class UsageTier(str, Enum):
    """Client usage tier for rate limiting and features."""

    FREE = "free"
    BASIC = "basic"
    PRO = "pro"
    ENTERPRISE = "enterprise"
    INTERNAL = "internal"  # For internal/sidecar deployments


class ClientPermission(str, Enum):
    """Granular permissions for API access."""

    DETECT_READ = "detect:read"  # Can perform detection
    DETECT_WRITE = "detect:write"  # Can submit feedback
    ADMIN_READ = "admin:read"  # Can view admin data
    ADMIN_WRITE = "admin:write"  # Can modify settings
    EXPERIMENT_READ = "experiment:read"  # Can view experiments
    EXPERIMENT_WRITE = "experiment:write"  # Can create experiments
    ML_READ = "ml:read"  # Can view ML patterns
    ML_WRITE = "ml:write"  # Can trigger ML operations


class APIKeyStatus(str, Enum):
    """Status of an API key."""

    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"
    ROTATING = "rotating"  # In process of rotation


class APIKey(BaseModel):
    """API key model for storage and management."""

    model_config = ConfigDict(from_attributes=True)

    key_id: str = Field(..., description="Unique identifier for the key")
    key_hash: str = Field(..., description="SHA-256 hash of the actual key")
    client_id: str = Field(..., description="Associated client ID")
    client_name: str = Field(..., description="Human-readable client name")

    # Lifecycle
    created_at: datetime = Field(default_factory=datetime.utcnow)
    expires_at: datetime | None = Field(None, description="Expiration time")
    last_used_at: datetime | None = Field(None, description="Last usage time")
    status: APIKeyStatus = Field(default=APIKeyStatus.ACTIVE)

    # Access control
    usage_tier: UsageTier = Field(default=UsageTier.FREE)
    permissions: list[ClientPermission] = Field(
        default_factory=lambda: [ClientPermission.DETECT_READ]
    )

    # Rate limits (override defaults)
    rate_limits: dict[str, int] | None = Field(None, description="Custom rate limits")

    # Metadata
    description: str | None = Field(None, description="Key description/purpose")
    metadata: dict[str, Any] = Field(default_factory=dict)

    def is_valid(self) -> bool:
        """Check if the key is currently valid."""
        if self.status != APIKeyStatus.ACTIVE:
            return False
        if self.expires_at and datetime.utcnow() > self.expires_at:
            return False
        return True

    def has_permission(self, permission: ClientPermission) -> bool:
        """Check if the key has a specific permission."""
        return permission in self.permissions


class Client(BaseModel):
    """Client model with authentication details."""

    model_config = ConfigDict(from_attributes=True)

    client_id: str = Field(..., description="Unique client identifier")
    client_name: str = Field(..., description="Client name")
    auth_method: AuthMethod = Field(..., description="How client was authenticated")

    # For authenticated clients
    api_key: APIKey | None = Field(None, description="Associated API key")

    # Rate limiting
    usage_tier: UsageTier = Field(default=UsageTier.FREE)
    rate_limits: dict[str, int] = Field(default_factory=dict)

    # Usage tracking
    request_count: int = Field(default=0)
    token_count: int = Field(default=0)
    last_request_at: datetime | None = None

    @property
    def is_authenticated(self) -> bool:
        """Check if client is authenticated."""
        return self.auth_method in [AuthMethod.API_KEY, AuthMethod.BYPASS]

    @property
    def is_anonymous(self) -> bool:
        """Check if client is anonymous."""
        return self.auth_method == AuthMethod.ANONYMOUS


class CreateAPIKeyRequest(BaseModel):
    """Request to create a new API key."""

    client_name: str = Field(..., min_length=1, max_length=100)
    description: str | None = Field(None, max_length=500)
    expires_in_days: int | None = Field(None, ge=1, le=365)
    usage_tier: UsageTier = Field(default=UsageTier.FREE)
    permissions: list[ClientPermission] = Field(
        default_factory=lambda: [ClientPermission.DETECT_READ]
    )
    rate_limits: dict[str, int] | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class CreateAPIKeyResponse(BaseModel):
    """Response after creating an API key."""

    api_key: str = Field(..., description="The actual API key (show once)")
    key_id: str = Field(..., description="Key identifier for management")
    client_id: str = Field(..., description="Associated client ID")
    client_name: str = Field(..., description="Client name")
    created_at: datetime
    expires_at: datetime | None
    usage_tier: UsageTier
    permissions: list[ClientPermission]


class APIKeyInfo(BaseModel):
    """Public information about an API key (no sensitive data)."""

    key_id: str
    client_id: str
    client_name: str
    created_at: datetime
    expires_at: datetime | None
    last_used_at: datetime | None
    status: APIKeyStatus
    usage_tier: UsageTier
    permissions: list[ClientPermission]
    description: str | None


class AuthConfig(BaseModel):
    """Authentication configuration."""

    mode: AuthMode = Field(default=AuthMode.OPTIONAL)
    enforce_https: bool = Field(default=False)

    # Bypass rules
    bypass_networks: list[str] = Field(
        default_factory=list, description="CIDR networks to bypass auth"
    )
    bypass_headers: dict[str, str] = Field(
        default_factory=dict, description="Headers that bypass auth"
    )
    allow_localhost: bool = Field(default=True, description="Allow localhost without auth")

    # Rate limiting for unauthenticated
    unauthenticated_rpm: int = Field(default=10)
    unauthenticated_tpm: int = Field(default=1000)

    # Security
    api_key_prefix: str = Field(default="psk_", description="Prefix for API keys")
    api_key_length: int = Field(default=32, description="Length of random part")
    max_keys_per_client: int = Field(default=5)
    key_rotation_days: int = Field(default=90)
