# Copyright 2025 PromptSentinel
# Licensed under the Elastic License 2.0; you may not use this file except
# in compliance with the Elastic License 2.0. You may obtain a copy of the
# License at https://www.elastic.co/licensing/elastic-license

"""Authentication module for PromptSentinel.

This module provides flexible authentication with support for:
- API key authentication
- Multiple deployment modes (none/optional/required)
- Network and header bypass rules
- Rate limiting integration
"""

from .api_key_manager import APIKeyManager
from .dependencies import (
    get_api_key_manager,
    get_auth_config,
    get_current_client,
    get_optional_client,
    require_admin,
    require_authenticated,
    require_permission,
)
from .models import (
    APIKey,
    APIKeyInfo,
    APIKeyStatus,
    AuthConfig,
    AuthMethod,
    AuthMode,
    Client,
    ClientPermission,
    CreateAPIKeyRequest,
    CreateAPIKeyResponse,
    UsageTier,
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
    "require_admin",
]
