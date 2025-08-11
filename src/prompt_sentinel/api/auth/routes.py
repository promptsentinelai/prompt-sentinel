# Copyright 2025 PromptSentinel
# Licensed under the Elastic License 2.0; you may not use this file except
# in compliance with the Elastic License 2.0. You may obtain a copy of the
# License at https://www.elastic.co/licensing/elastic-license

"""API routes for authentication and API key management.

This module provides admin endpoints for creating, managing, and revoking API keys.
"""

from typing import Annotated

import structlog
from fastapi import APIRouter, Depends, HTTPException, Path, Query, status

from prompt_sentinel.auth import (
    APIKeyInfo,
    APIKeyManager,
    APIKeyStatus,
    Client,
    CreateAPIKeyRequest,
    CreateAPIKeyResponse,
    get_api_key_manager,
    get_current_client,
    require_admin,
)

logger = structlog.get_logger()

router = APIRouter(
    prefix="/admin/api-keys",
    tags=["Authentication"],
    responses={
        401: {"description": "Authentication required"},
        403: {"description": "Insufficient permissions"},
    },
)


@router.post(
    "/",
    response_model=CreateAPIKeyResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create API key",
    description="Generate a new API key for client authentication",
    dependencies=[Depends(require_admin())],
)
async def create_api_key(
    request: CreateAPIKeyRequest, manager: Annotated[APIKeyManager, Depends(get_api_key_manager)]
) -> CreateAPIKeyResponse:
    """Create a new API key.

    Requires admin permissions. The API key is returned only once
    and should be securely stored by the client.

    Args:
        request: API key creation parameters
        manager: API key manager

    Returns:
        Response with the new API key (shown once)

    Raises:
        HTTPException: If creation fails
    """
    try:
        response = await manager.create_api_key(request)

        logger.info(
            "API key created via admin endpoint",
            key_id=response.key_id,
            client_name=response.client_name,
            usage_tier=response.usage_tier.value,
        )

        return response
    except Exception as e:
        logger.error("Failed to create API key", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to create API key"
        ) from e


@router.get(
    "/",
    response_model=list[APIKeyInfo],
    summary="List API keys",
    description="List all API keys with optional filters",
    dependencies=[Depends(require_admin())],
)
async def list_api_keys(
    manager: Annotated[APIKeyManager, Depends(get_api_key_manager)],
    client_id: str | None = Query(None, description="Filter by client ID"),
    status: APIKeyStatus | None = Query(None, description="Filter by status"),
) -> list[APIKeyInfo]:
    """List API keys with optional filters.

    Requires admin permissions.

    Args:
        manager: API key manager
        client_id: Optional client ID filter
        status: Optional status filter

    Returns:
        List of API key information
    """
    try:
        keys = await manager.list_api_keys(client_id=client_id, status=status)

        logger.info(
            "API keys listed",
            count=len(keys),
            client_id_filter=client_id,
            status_filter=status.value if status else None,
        )

        return keys
    except Exception as e:
        logger.error("Failed to list API keys", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to list API keys"
        ) from e


@router.get(
    "/{key_id}",
    response_model=APIKeyInfo,
    summary="Get API key details",
    description="Get detailed information about a specific API key",
    dependencies=[Depends(require_admin())],
)
async def get_api_key(
    key_id: Annotated[str, Path(description="API key identifier")],
    manager: Annotated[APIKeyManager, Depends(get_api_key_manager)],
) -> APIKeyInfo:
    """Get information about a specific API key.

    Requires admin permissions.

    Args:
        key_id: API key identifier
        manager: API key manager

    Returns:
        API key information

    Raises:
        HTTPException: If key not found
    """
    key_info = await manager.get_api_key(key_id)
    if not key_info:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"API key {key_id} not found"
        )

    return key_info


@router.delete(
    "/{key_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Revoke API key",
    description="Revoke an API key to prevent further use",
    dependencies=[Depends(require_admin())],
)
async def revoke_api_key(
    key_id: Annotated[str, Path(description="API key identifier")],
    manager: Annotated[APIKeyManager, Depends(get_api_key_manager)],
):
    """Revoke an API key.

    Requires admin permissions. The key will be immediately invalidated.

    Args:
        key_id: API key identifier
        manager: API key manager

    Raises:
        HTTPException: If key not found
    """
    success = await manager.revoke_api_key(key_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"API key {key_id} not found"
        )

    logger.info("API key revoked via admin endpoint", key_id=key_id)


@router.post(
    "/{key_id}/rotate",
    response_model=CreateAPIKeyResponse,
    summary="Rotate API key",
    description="Create a new API key to replace an existing one",
    dependencies=[Depends(require_admin())],
)
async def rotate_api_key(
    key_id: Annotated[str, Path(description="API key identifier to rotate")],
    manager: Annotated[APIKeyManager, Depends(get_api_key_manager)],
) -> CreateAPIKeyResponse:
    """Rotate an API key.

    Requires admin permissions. Creates a new key with the same settings
    and marks the old key for rotation.

    Args:
        key_id: API key identifier to rotate
        manager: API key manager

    Returns:
        New API key response

    Raises:
        HTTPException: If key not found or rotation fails
    """
    try:
        response = await manager.rotate_api_key(key_id)
        if not response:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail=f"API key {key_id} not found"
            )

        logger.info(
            "API key rotated via admin endpoint", old_key_id=key_id, new_key_id=response.key_id
        )

        return response
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to rotate API key", key_id=key_id, error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to rotate API key"
        ) from e


@router.get(
    "/me/info",
    response_model=dict,
    summary="Get current client info",
    description="Get information about the currently authenticated client",
)
async def get_current_client_info(client: Annotated[Client, Depends(get_current_client)]) -> dict:
    """Get information about the current authenticated client.

    This endpoint is available to all authenticated clients to check
    their own authentication status and permissions.

    Args:
        client: Current authenticated client

    Returns:
        Client information dictionary
    """
    return {
        "client_id": client.client_id,
        "client_name": client.client_name,
        "auth_method": client.auth_method.value,
        "usage_tier": client.usage_tier.value,
        "is_authenticated": client.is_authenticated,
        "is_anonymous": client.is_anonymous,
        "permissions": [p.value for p in client.api_key.permissions] if client.api_key else [],
        "rate_limits": client.rate_limits,
    }
