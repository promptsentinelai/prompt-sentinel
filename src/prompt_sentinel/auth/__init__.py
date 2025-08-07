"""Authentication module for PromptSentinel.

This module provides flexible authentication with support for:
- API key authentication
- Multiple deployment modes (none/optional/required)
- Network and header bypass rules
- Rate limiting integration
"""

from .models import (
    AuthMode,
    AuthMethod,
    UsageTier,
    ClientPermission,
    APIKeyStatus,
    APIKey,
    Client,
    CreateAPIKeyRequest,
    CreateAPIKeyResponse,
    APIKeyInfo,
    AuthConfig
)
from .api_key_manager import APIKeyManager
from .dependencies import (
    get_auth_config,
    get_api_key_manager,
    get_current_client,
    get_optional_client,
    require_permission,
    require_authenticated,
    require_admin
)

__all__ = [
    # Models
    "AuthMode",
    "AuthMethod",
    "UsageTier",
    "ClientPermission",
    "APIKeyStatus",
    "APIKey",
    "Client",
    "CreateAPIKeyRequest",
    "CreateAPIKeyResponse",
    "APIKeyInfo",
    "AuthConfig",
    # Manager
    "APIKeyManager",
    # Dependencies
    "get_auth_config",
    "get_api_key_manager",
    "get_current_client",
    "get_optional_client",
    "require_permission",
    "require_authenticated",
    "require_admin"
]