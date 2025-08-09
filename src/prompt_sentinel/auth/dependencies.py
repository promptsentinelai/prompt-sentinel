"""FastAPI dependencies for authentication.

This module provides dependency injection functions for authentication,
supporting multiple auth modes and bypass rules.
"""

from typing import Optional, Annotated
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import APIKeyHeader

import structlog
from prompt_sentinel.config.settings import settings
from .models import Client, AuthMethod, AuthMode, UsageTier, AuthConfig, ClientPermission
from .api_key_manager import APIKeyManager

logger = structlog.get_logger()

# Security scheme for API key
api_key_header = APIKeyHeader(
    name="X-API-Key", auto_error=False  # Don't auto-error, handle in dependency
)


def get_auth_config() -> AuthConfig:
    """Get authentication configuration from settings.

    Returns:
        Authentication configuration
    """
    # Determine auth mode
    auth_mode = AuthMode(settings.auth_mode)

    # Auto-detect if not explicitly set to required
    if settings.auth_mode == "optional":
        if _is_kubernetes_pod():
            auth_mode = AuthMode.NONE
        elif _is_docker_container() and not _has_public_endpoint():
            auth_mode = AuthMode.NONE

    return AuthConfig(
        mode=auth_mode,
        enforce_https=settings.auth_enforce_https,
        bypass_networks=settings.auth_bypass_networks_list,
        bypass_headers=settings.auth_bypass_headers_dict,
        allow_localhost=settings.auth_allow_localhost,
        unauthenticated_rpm=settings.auth_unauthenticated_rpm,
        unauthenticated_tpm=settings.auth_unauthenticated_tpm,
        api_key_prefix=settings.api_key_prefix,
        api_key_length=settings.api_key_length,
    )


def get_api_key_manager(config: Annotated[AuthConfig, Depends(get_auth_config)]) -> APIKeyManager:
    """Get API key manager instance.

    Args:
        config: Authentication configuration

    Returns:
        API key manager instance
    """
    return APIKeyManager(config)


async def get_current_client(
    request: Request,
    api_key: Annotated[Optional[str], Depends(api_key_header)],
    config: Annotated[AuthConfig, Depends(get_auth_config)],
    manager: Annotated[APIKeyManager, Depends(get_api_key_manager)],
) -> Client:
    """Get the current client from the request.

    This is the main authentication dependency that handles all auth modes
    and bypass rules.

    Args:
        request: FastAPI request object
        api_key: Optional API key from header
        config: Authentication configuration
        manager: API key manager

    Returns:
        Client object with authentication details

    Raises:
        HTTPException: If authentication fails when required
    """
    # 1. Check auth mode - no auth needed
    if config.mode == AuthMode.NONE:
        return Client(
            client_id="local",
            client_name="Local Client",
            auth_method=AuthMethod.NONE,
            usage_tier=UsageTier.INTERNAL,
            rate_limits={},  # No limits for local
        )

    # 2. Check bypass conditions
    client_host = request.client.host if request.client else "unknown"

    # Check localhost bypass
    if config.allow_localhost and client_host in ["127.0.0.1", "::1", "localhost"]:
        return Client(
            client_id=f"localhost",
            client_name="Localhost",
            auth_method=AuthMethod.BYPASS,
            usage_tier=UsageTier.INTERNAL,
            rate_limits={},
        )

    # Check network bypass
    if manager.check_network_bypass(client_host):
        return Client(
            client_id=f"network_{client_host}",
            client_name=f"Internal Network ({client_host})",
            auth_method=AuthMethod.BYPASS,
            usage_tier=UsageTier.INTERNAL,
            rate_limits={},
        )

    # Check header bypass
    headers = dict(request.headers)
    if manager.check_header_bypass(headers):
        return Client(
            client_id=f"header_bypass",
            client_name="Header Bypass",
            auth_method=AuthMethod.BYPASS,
            usage_tier=UsageTier.INTERNAL,
            rate_limits={},
        )

    # 3. Check API key authentication
    if api_key:
        client = await manager.validate_api_key(api_key)
        if client:
            return client
        elif config.mode == AuthMode.REQUIRED:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid API key",
                headers={"WWW-Authenticate": "ApiKey"},
            )

    # 4. Handle unauthenticated requests
    if config.mode == AuthMode.REQUIRED:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key required",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    # Optional mode - allow anonymous
    return Client(
        client_id=f"anon_{client_host}",
        client_name=f"Anonymous ({client_host})",
        auth_method=AuthMethod.ANONYMOUS,
        usage_tier=UsageTier.FREE,
        rate_limits={"rpm": config.unauthenticated_rpm, "tpm": config.unauthenticated_tpm},
    )


async def get_optional_client(
    request: Request,
    api_key: Annotated[Optional[str], Depends(api_key_header)],
    config: Annotated[AuthConfig, Depends(get_auth_config)],
    manager: Annotated[APIKeyManager, Depends(get_api_key_manager)],
) -> Optional[Client]:
    """Get client if authenticated, None otherwise.

    This dependency never raises exceptions, useful for endpoints
    that want to provide enhanced features for authenticated users.

    Args:
        request: FastAPI request object
        api_key: Optional API key from header
        config: Authentication configuration
        manager: API key manager

    Returns:
        Client object if authenticated, None otherwise
    """
    try:
        return await get_current_client(request, api_key, config, manager)
    except HTTPException:
        return None


def require_permission(permission: ClientPermission):
    """Create a dependency that requires a specific permission.

    Args:
        permission: The required permission

    Returns:
        Dependency function that checks the permission
    """

    async def check_permission(client: Annotated[Client, Depends(get_current_client)]) -> Client:
        """Check if client has required permission.

        Args:
            client: Current authenticated client

        Returns:
            Client if permission granted

        Raises:
            HTTPException: If permission denied
        """
        # Internal clients have all permissions
        if client.usage_tier == UsageTier.INTERNAL:
            return client

        # Check API key permissions
        if client.api_key and client.api_key.has_permission(permission):
            return client

        # Anonymous users only have basic read
        if client.is_anonymous and permission == ClientPermission.DETECT_READ:
            return client

        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail=f"Permission denied: {permission.value}"
        )

    return check_permission


def require_authenticated():
    """Dependency that requires authentication (no anonymous).

    Returns:
        Dependency function that checks authentication
    """

    async def check_authenticated(client: Annotated[Client, Depends(get_current_client)]) -> Client:
        """Check if client is authenticated.

        Args:
            client: Current client

        Returns:
            Client if authenticated

        Raises:
            HTTPException: If not authenticated
        """
        if client.is_authenticated:
            return client

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    return check_authenticated


def require_admin():
    """Dependency that requires admin permissions.

    Returns:
        Dependency function that checks admin access
    """
    return require_permission(ClientPermission.ADMIN_WRITE)


# Helper functions for environment detection


def _is_kubernetes_pod() -> bool:
    """Check if running in a Kubernetes pod."""
    import os

    return os.path.exists("/var/run/secrets/kubernetes.io")


def _is_docker_container() -> bool:
    """Check if running in a Docker container."""
    import os

    return os.path.exists("/.dockerenv") or os.path.exists("/run/.containerenv")


def _has_public_endpoint() -> bool:
    """Check if service has a public endpoint configured."""
    import os

    public_indicators = ["PUBLIC_URL", "EXTERNAL_HOSTNAME", "INGRESS_HOST"]
    return any(os.getenv(ind) for ind in public_indicators)
