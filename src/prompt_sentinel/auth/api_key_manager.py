"""API key generation, validation, and lifecycle management.

This module handles the creation, validation, storage, and rotation of API keys.
It uses Redis for fast lookups and implements secure key generation and hashing.
"""

import hashlib
import ipaddress
import json
import secrets
import uuid
from datetime import datetime, timedelta
from typing import Any

import structlog

from prompt_sentinel.cache.cache_manager import cache_manager

from .models import (
    APIKey,
    APIKeyInfo,
    APIKeyStatus,
    AuthConfig,
    AuthMethod,
    Client,
    CreateAPIKeyRequest,
    CreateAPIKeyResponse,
)

logger = structlog.get_logger()


class APIKeyManager:
    """Manages API key lifecycle and validation.

    Handles:
    - Secure key generation
    - Key validation and lookup
    - Key rotation and expiration
    - Usage tracking
    - Storage in Redis
    """

    def __init__(self, config: AuthConfig):
        """Initialize API key manager.

        Args:
            config: Authentication configuration
        """
        self.config = config
        self.prefix = config.api_key_prefix
        self.key_length = config.api_key_length

    def _generate_key(self) -> str:
        """Generate a secure API key.

        Returns:
            A secure random API key with configured prefix
        """
        random_part = secrets.token_urlsafe(self.key_length)
        return f"{self.prefix}{random_part}"

    def _hash_key(self, api_key: str) -> str:
        """Hash an API key for secure storage.

        Args:
            api_key: The plaintext API key

        Returns:
            SHA-256 hash of the key
        """
        return hashlib.sha256(api_key.encode()).hexdigest()

    def _constant_time_compare(self, a: str, b: str) -> bool:
        """Compare two strings in constant time to prevent timing attacks.

        Args:
            a: First string
            b: Second string

        Returns:
            True if strings are equal
        """
        return secrets.compare_digest(a, b)

    async def create_api_key(self, request: CreateAPIKeyRequest) -> CreateAPIKeyResponse:
        """Create a new API key.

        Args:
            request: API key creation request

        Returns:
            Response with the new API key (shown once)

        Raises:
            ValueError: If creation fails
        """
        # Generate unique identifiers
        api_key = self._generate_key()
        key_hash = self._hash_key(api_key)
        key_id = str(uuid.uuid4())
        client_id = str(uuid.uuid4())

        # Calculate expiration
        expires_at = None
        if request.expires_in_days:
            expires_at = datetime.utcnow() + timedelta(days=request.expires_in_days)

        # Create API key model
        api_key_model = APIKey(
            key_id=key_id,
            key_hash=key_hash,
            client_id=client_id,
            client_name=request.client_name,
            created_at=datetime.utcnow(),
            expires_at=expires_at,
            status=APIKeyStatus.ACTIVE,
            usage_tier=request.usage_tier,
            permissions=request.permissions,
            rate_limits=request.rate_limits,
            description=request.description,
            metadata=request.metadata,
        )

        # Store in Redis
        await self._store_api_key(api_key_model)

        logger.info(
            "API key created",
            key_id=key_id,
            client_id=client_id,
            client_name=request.client_name,
            usage_tier=request.usage_tier.value,
        )

        return CreateAPIKeyResponse(
            api_key=api_key,  # Return plaintext key (show once)
            key_id=key_id,
            client_id=client_id,
            client_name=request.client_name,
            created_at=api_key_model.created_at,
            expires_at=expires_at,
            usage_tier=request.usage_tier,
            permissions=request.permissions,
        )

    async def validate_api_key(self, api_key: str) -> Client | None:
        """Validate an API key and return client information.

        Args:
            api_key: The API key to validate

        Returns:
            Client object if valid, None otherwise
        """
        if not api_key or not api_key.startswith(self.prefix):
            return None

        key_hash = self._hash_key(api_key)

        # Try to get from cache first
        cache_key = f"api_key_validated:{key_hash}"
        if cache_manager.enabled:
            cached = await cache_manager.get(cache_key)
            if cached:
                return Client(**json.loads(cached))

        # Look up in Redis
        api_key_model = await self._get_api_key_by_hash(key_hash)
        if not api_key_model:
            logger.warning("Invalid API key attempted", key_hash=key_hash[:8])
            return None

        # Check if key is valid
        if not api_key_model.is_valid():
            logger.warning(
                "Expired or revoked API key used",
                key_id=api_key_model.key_id,
                status=api_key_model.status.value,
            )
            return None

        # Update last used timestamp
        await self._update_last_used(api_key_model.key_id)

        # Create client object
        client = Client(
            client_id=api_key_model.client_id,
            client_name=api_key_model.client_name,
            auth_method=AuthMethod.API_KEY,
            api_key=api_key_model,
            usage_tier=api_key_model.usage_tier,
            rate_limits=api_key_model.rate_limits or {},
        )

        # Cache the validated client (5 minutes)
        if cache_manager.enabled:
            await cache_manager.set(cache_key, client.model_dump_json(), ttl=300)

        return client

    async def get_api_key(self, key_id: str) -> APIKeyInfo | None:
        """Get information about an API key.

        Args:
            key_id: The key identifier

        Returns:
            API key information if found
        """
        api_key_model = await self._get_api_key_by_id(key_id)
        if not api_key_model:
            return None

        return APIKeyInfo(
            key_id=api_key_model.key_id,
            client_id=api_key_model.client_id,
            client_name=api_key_model.client_name,
            created_at=api_key_model.created_at,
            expires_at=api_key_model.expires_at,
            last_used_at=api_key_model.last_used_at,
            status=api_key_model.status,
            usage_tier=api_key_model.usage_tier,
            permissions=api_key_model.permissions,
            description=api_key_model.description,
        )

    async def list_api_keys(
        self, client_id: str | None = None, status: APIKeyStatus | None = None
    ) -> list[APIKeyInfo]:
        """List API keys with optional filters.

        Args:
            client_id: Filter by client ID
            status: Filter by status

        Returns:
            List of API key information
        """
        # Get all keys from Redis
        keys = await self._list_all_keys()

        result = []
        for key_data in keys:
            api_key = APIKey(**key_data)

            # Apply filters
            if client_id and api_key.client_id != client_id:
                continue
            if status and api_key.status != status:
                continue

            result.append(
                APIKeyInfo(
                    key_id=api_key.key_id,
                    client_id=api_key.client_id,
                    client_name=api_key.client_name,
                    created_at=api_key.created_at,
                    expires_at=api_key.expires_at,
                    last_used_at=api_key.last_used_at,
                    status=api_key.status,
                    usage_tier=api_key.usage_tier,
                    permissions=api_key.permissions,
                    description=api_key.description,
                )
            )

        return result

    async def revoke_api_key(self, key_id: str) -> bool:
        """Revoke an API key.

        Args:
            key_id: The key identifier

        Returns:
            True if revoked successfully
        """
        api_key = await self._get_api_key_by_id(key_id)
        if not api_key:
            return False

        api_key.status = APIKeyStatus.REVOKED
        await self._store_api_key(api_key)

        # Invalidate cache
        cache_key = f"api_key_validated:{api_key.key_hash}"
        if cache_manager.enabled:
            await cache_manager.delete(cache_key)

        logger.info("API key revoked", key_id=key_id, client_id=api_key.client_id)

        return True

    async def rotate_api_key(self, key_id: str) -> CreateAPIKeyResponse | None:
        """Rotate an API key (create new, mark old as rotating).

        Args:
            key_id: The key identifier to rotate

        Returns:
            New API key response if successful
        """
        old_key = await self._get_api_key_by_id(key_id)
        if not old_key:
            return None

        # Mark old key as rotating
        old_key.status = APIKeyStatus.ROTATING
        await self._store_api_key(old_key)

        # Create new key with same settings
        request = CreateAPIKeyRequest(
            client_name=old_key.client_name,
            description=f"Rotated from {key_id}",
            expires_in_days=self.config.key_rotation_days,
            usage_tier=old_key.usage_tier,
            permissions=old_key.permissions,
            rate_limits=old_key.rate_limits,
            metadata={**old_key.metadata, "rotated_from": key_id},
        )

        new_key = await self.create_api_key(request)

        logger.info(
            "API key rotated",
            old_key_id=key_id,
            new_key_id=new_key.key_id,
            client_id=old_key.client_id,
        )

        return new_key

    def check_network_bypass(self, client_ip: str) -> bool:
        """Check if IP is in bypass network.

        Args:
            client_ip: Client IP address

        Returns:
            True if IP should bypass authentication
        """
        if not self.config.bypass_networks:
            return False

        try:
            ip = ipaddress.ip_address(client_ip)
            for network_str in self.config.bypass_networks:
                network = ipaddress.ip_network(network_str)
                if ip in network:
                    logger.debug("IP in bypass network", ip=str(ip), network=str(network))
                    return True
        except (ValueError, ipaddress.AddressValueError) as e:
            logger.warning("Invalid IP for bypass check", ip=client_ip, error=str(e))

        return False

    def check_header_bypass(self, headers: dict[str, str]) -> bool:
        """Check if headers match bypass rules.

        Args:
            headers: Request headers

        Returns:
            True if headers should bypass authentication
        """
        if not self.config.bypass_headers:
            return False

        for header, expected_value in self.config.bypass_headers.items():
            if headers.get(header) == expected_value:
                logger.debug("Header bypass matched", header=header)
                return True

        return False

    # Redis storage methods (private)

    async def _store_api_key(self, api_key: APIKey):
        """Store API key in Redis."""
        if not cache_manager.enabled:
            logger.warning("Redis not enabled, cannot store API key")
            return

        # Store by key hash for validation
        await cache_manager.client.hset(
            "api_keys:by_hash", api_key.key_hash, api_key.model_dump_json()
        )

        # Store by key ID for management
        await cache_manager.client.hset("api_keys:by_id", api_key.key_id, api_key.model_dump_json())

        # Store client -> keys mapping
        await cache_manager.client.sadd(f"api_keys:client:{api_key.client_id}", api_key.key_id)

    async def _get_api_key_by_hash(self, key_hash: str) -> APIKey | None:
        """Get API key by hash from Redis."""
        if not cache_manager.enabled:
            return None

        data = await cache_manager.client.hget("api_keys:by_hash", key_hash)
        if data:
            return APIKey(**json.loads(data))
        return None

    async def _get_api_key_by_id(self, key_id: str) -> APIKey | None:
        """Get API key by ID from Redis."""
        if not cache_manager.enabled:
            return None

        data = await cache_manager.client.hget("api_keys:by_id", key_id)
        if data:
            return APIKey(**json.loads(data))
        return None

    async def _update_last_used(self, key_id: str):
        """Update last used timestamp for a key."""
        api_key = await self._get_api_key_by_id(key_id)
        if api_key:
            api_key.last_used_at = datetime.utcnow()
            await self._store_api_key(api_key)

    async def _list_all_keys(self) -> list[dict[str, Any]]:
        """List all API keys from Redis."""
        if not cache_manager.enabled:
            return []

        all_data = await cache_manager.client.hgetall("api_keys:by_id")
        return [json.loads(data) for data in all_data.values()]
