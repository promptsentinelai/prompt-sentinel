# Copyright 2025 PromptSentinel
# Licensed under the Elastic License 2.0; you may not use this file except
# in compliance with the Elastic License 2.0. You may obtain a copy of the
# License at https://www.elastic.co/licensing/elastic-license

"""Comprehensive tests for the APIKeyManager module."""

import hashlib
import ipaddress
import json
import secrets
import uuid
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import structlog

from prompt_sentinel.auth.api_key_manager import APIKeyManager
from prompt_sentinel.auth.models import (
    APIKey,
    APIKeyInfo,
    APIKeyStatus,
    AuthConfig,
    AuthMethod,
    Client,
    ClientPermission,
    CreateAPIKeyRequest,
    CreateAPIKeyResponse,
    UsageTier,
)


class TestAPIKeyManager:
    """Test suite for APIKeyManager."""

    @pytest.fixture
    def auth_config(self):
        """Create test auth configuration."""
        return AuthConfig(
            api_key_prefix="psk_",
            api_key_length=32,
            max_keys_per_client=5,
            key_rotation_days=90,
            bypass_networks=["127.0.0.1/32", "10.0.0.0/8"],
            bypass_headers={"X-Internal": "true", "X-Service": "trusted"},
        )

    @pytest.fixture
    def manager(self, auth_config):
        """Create APIKeyManager instance."""
        return APIKeyManager(auth_config)

    @pytest.fixture
    def sample_create_request(self):
        """Create sample API key creation request."""
        return CreateAPIKeyRequest(
            client_name="Test Client",
            description="Test API Key",
            expires_in_days=30,
            usage_tier=UsageTier.PRO,
            permissions=[ClientPermission.DETECT_READ, ClientPermission.DETECT_WRITE],
            rate_limits={"requests_per_minute": 100, "requests_per_day": 10000},
            metadata={"environment": "test", "version": "1.0"},
        )

    @pytest.fixture
    def sample_api_key(self):
        """Create sample APIKey object."""
        return APIKey(
            key_id="test_key_id",
            key_hash="test_key_hash",
            client_id="test_client_id",
            client_name="Test Client",
            created_at=datetime.utcnow(),
            expires_at=datetime.utcnow() + timedelta(days=30),
            status=APIKeyStatus.ACTIVE,
            usage_tier=UsageTier.PRO,
            permissions=[ClientPermission.DETECT_READ],
            rate_limits={"requests_per_minute": 100},
            description="Test key",
            metadata={"test": "value"},
        )

    @pytest.fixture
    def mock_cache_manager(self):
        """Mock cache manager."""
        with patch('prompt_sentinel.auth.api_key_manager.cache_manager') as mock:
            mock.enabled = True
            mock.client = AsyncMock()
            mock.get = AsyncMock(return_value=None)
            mock.set = AsyncMock(return_value=True)
            mock.delete = AsyncMock(return_value=True)
            yield mock

    def test_initialization(self, auth_config):
        """Test APIKeyManager initialization."""
        manager = APIKeyManager(auth_config)
        
        assert manager.config == auth_config
        assert manager.prefix == "psk_"
        assert manager.key_length == 32

    def test_generate_key(self, manager):
        """Test API key generation."""
        key = manager._generate_key()
        
        assert key.startswith("psk_")
        assert len(key) > len("psk_")
        
        # Generate multiple keys and ensure they're unique
        keys = [manager._generate_key() for _ in range(10)]
        assert len(set(keys)) == 10

    def test_hash_key(self, manager):
        """Test API key hashing."""
        api_key = "psk_test_key_123"
        hashed = manager._hash_key(api_key)
        
        assert isinstance(hashed, str)
        assert len(hashed) == 64  # SHA-256 produces 64 hex characters
        
        # Same key should produce same hash
        assert hashed == manager._hash_key(api_key)
        
        # Different keys should produce different hashes
        assert hashed != manager._hash_key("psk_different_key")

    def test_constant_time_compare(self, manager):
        """Test constant time string comparison."""
        # Equal strings
        assert manager._constant_time_compare("test123", "test123") is True
        
        # Different strings
        assert manager._constant_time_compare("test123", "test456") is False
        
        # Different lengths
        assert manager._constant_time_compare("short", "longer_string") is False
        
        # Empty strings
        assert manager._constant_time_compare("", "") is True
        assert manager._constant_time_compare("test", "") is False

    @pytest.mark.asyncio
    async def test_create_api_key_success(self, manager, sample_create_request, mock_cache_manager):
        """Test successful API key creation."""
        with patch.object(manager, '_store_api_key', new=AsyncMock()) as mock_store:
            with patch('prompt_sentinel.auth.api_key_manager.uuid.uuid4', side_effect=['key_id_123', 'client_id_456']):
                with patch.object(manager, '_generate_key', return_value='psk_generated_key'):
                    response = await manager.create_api_key(sample_create_request)
        
        assert isinstance(response, CreateAPIKeyResponse)
        assert response.api_key == 'psk_generated_key'
        assert response.key_id == 'key_id_123'
        assert response.client_id == 'client_id_456'
        assert response.client_name == "Test Client"
        assert response.usage_tier == UsageTier.PRO
        assert response.permissions == [ClientPermission.DETECT_READ, ClientPermission.DETECT_WRITE]
        assert response.expires_at is not None
        
        mock_store.assert_called_once()
        stored_key = mock_store.call_args[0][0]
        assert isinstance(stored_key, APIKey)
        assert stored_key.key_hash == manager._hash_key('psk_generated_key')

    @pytest.mark.asyncio
    async def test_create_api_key_no_expiration(self, manager, mock_cache_manager):
        """Test API key creation without expiration."""
        request = CreateAPIKeyRequest(
            client_name="Permanent Client",
            description="No expiration",
            expires_in_days=None,  # No expiration
            usage_tier=UsageTier.FREE,
            permissions=[],
        )
        
        with patch.object(manager, '_store_api_key', new=AsyncMock()):
            response = await manager.create_api_key(request)
        
        assert response.expires_at is None

    @pytest.mark.asyncio
    async def test_validate_api_key_success(self, manager, sample_api_key, mock_cache_manager):
        """Test successful API key validation."""
        api_key = "psk_valid_key"
        key_hash = manager._hash_key(api_key)
        sample_api_key.key_hash = key_hash
        
        with patch.object(manager, '_get_api_key_by_hash', return_value=sample_api_key):
            with patch.object(manager, '_update_last_used', new=AsyncMock()):
                client = await manager.validate_api_key(api_key)
        
        assert isinstance(client, Client)
        assert client.client_id == sample_api_key.client_id
        assert client.client_name == sample_api_key.client_name
        assert client.auth_method == AuthMethod.API_KEY
        assert client.usage_tier == sample_api_key.usage_tier

    @pytest.mark.asyncio
    async def test_validate_api_key_invalid_prefix(self, manager):
        """Test API key validation with invalid prefix."""
        client = await manager.validate_api_key("invalid_prefix_key")
        assert client is None

    @pytest.mark.asyncio
    async def test_validate_api_key_empty(self, manager):
        """Test API key validation with empty key."""
        client = await manager.validate_api_key("")
        assert client is None
        
        client = await manager.validate_api_key(None)
        assert client is None

    @pytest.mark.asyncio
    async def test_validate_api_key_not_found(self, manager, mock_cache_manager):
        """Test API key validation when key not found."""
        api_key = "psk_nonexistent"
        
        with patch.object(manager, '_get_api_key_by_hash', return_value=None):
            client = await manager.validate_api_key(api_key)
        
        assert client is None

    @pytest.mark.asyncio
    async def test_validate_api_key_expired(self, manager, sample_api_key, mock_cache_manager):
        """Test API key validation with expired key."""
        api_key = "psk_expired_key"
        key_hash = manager._hash_key(api_key)
        sample_api_key.key_hash = key_hash
        sample_api_key.expires_at = datetime.utcnow() - timedelta(days=1)  # Expired
        
        with patch.object(manager, '_get_api_key_by_hash', return_value=sample_api_key):
            client = await manager.validate_api_key(api_key)
        
        assert client is None

    @pytest.mark.asyncio
    async def test_validate_api_key_revoked(self, manager, sample_api_key, mock_cache_manager):
        """Test API key validation with revoked key."""
        api_key = "psk_revoked_key"
        key_hash = manager._hash_key(api_key)
        sample_api_key.key_hash = key_hash
        sample_api_key.status = APIKeyStatus.REVOKED
        
        with patch.object(manager, '_get_api_key_by_hash', return_value=sample_api_key):
            client = await manager.validate_api_key(api_key)
        
        assert client is None

    @pytest.mark.asyncio
    async def test_validate_api_key_with_cache_hit(self, manager, mock_cache_manager):
        """Test API key validation with cache hit."""
        api_key = "psk_cached_key"
        cached_client = {
            "client_id": "cached_client_id",
            "client_name": "Cached Client",
            "auth_method": "api_key",
            "usage_tier": "pro",
            "rate_limits": {},
        }
        
        mock_cache_manager.get.return_value = json.dumps(cached_client)
        
        # Should not call _get_api_key_by_hash when cache hit
        with patch.object(manager, '_get_api_key_by_hash') as mock_get:
            client = await manager.validate_api_key(api_key)
            mock_get.assert_not_called()

    @pytest.mark.asyncio
    async def test_get_api_key_success(self, manager, sample_api_key):
        """Test getting API key information."""
        with patch.object(manager, '_get_api_key_by_id', return_value=sample_api_key):
            info = await manager.get_api_key("test_key_id")
        
        assert isinstance(info, APIKeyInfo)
        assert info.key_id == sample_api_key.key_id
        assert info.client_id == sample_api_key.client_id
        assert info.client_name == sample_api_key.client_name
        assert info.status == sample_api_key.status
        assert info.usage_tier == sample_api_key.usage_tier

    @pytest.mark.asyncio
    async def test_get_api_key_not_found(self, manager):
        """Test getting non-existent API key."""
        with patch.object(manager, '_get_api_key_by_id', return_value=None):
            info = await manager.get_api_key("nonexistent")
        
        assert info is None

    @pytest.mark.asyncio
    async def test_list_api_keys_no_filter(self, manager, sample_api_key):
        """Test listing all API keys without filter."""
        keys_data = [
            sample_api_key.model_dump(),
            {**sample_api_key.model_dump(), "key_id": "key_2", "client_id": "client_2"},
        ]
        
        with patch.object(manager, '_list_all_keys', return_value=keys_data):
            keys = await manager.list_api_keys()
        
        assert len(keys) == 2
        assert all(isinstance(k, APIKeyInfo) for k in keys)

    @pytest.mark.asyncio
    async def test_list_api_keys_filter_by_client(self, manager, sample_api_key):
        """Test listing API keys filtered by client ID."""
        keys_data = [
            sample_api_key.model_dump(),
            {**sample_api_key.model_dump(), "key_id": "key_2", "client_id": "other_client"},
        ]
        
        with patch.object(manager, '_list_all_keys', return_value=keys_data):
            keys = await manager.list_api_keys(client_id="test_client_id")
        
        assert len(keys) == 1
        assert keys[0].client_id == "test_client_id"

    @pytest.mark.asyncio
    async def test_list_api_keys_filter_by_status(self, manager, sample_api_key):
        """Test listing API keys filtered by status."""
        keys_data = [
            sample_api_key.model_dump(),
            {**sample_api_key.model_dump(), "key_id": "key_2", "status": APIKeyStatus.REVOKED},
        ]
        
        with patch.object(manager, '_list_all_keys', return_value=keys_data):
            keys = await manager.list_api_keys(status=APIKeyStatus.ACTIVE)
        
        assert len(keys) == 1
        assert keys[0].status == APIKeyStatus.ACTIVE

    @pytest.mark.asyncio
    async def test_revoke_api_key_success(self, manager, sample_api_key, mock_cache_manager):
        """Test successful API key revocation."""
        with patch.object(manager, '_get_api_key_by_id', return_value=sample_api_key):
            with patch.object(manager, '_store_api_key', new=AsyncMock()) as mock_store:
                result = await manager.revoke_api_key("test_key_id")
        
        assert result is True
        assert sample_api_key.status == APIKeyStatus.REVOKED
        mock_store.assert_called_once_with(sample_api_key)
        mock_cache_manager.delete.assert_called_once()

    @pytest.mark.asyncio
    async def test_revoke_api_key_not_found(self, manager):
        """Test revoking non-existent API key."""
        with patch.object(manager, '_get_api_key_by_id', return_value=None):
            result = await manager.revoke_api_key("nonexistent")
        
        assert result is False

    @pytest.mark.asyncio
    async def test_rotate_api_key_success(self, manager, sample_api_key, mock_cache_manager):
        """Test successful API key rotation."""
        with patch.object(manager, '_get_api_key_by_id', return_value=sample_api_key):
            with patch.object(manager, '_store_api_key', new=AsyncMock()):
                with patch.object(manager, 'create_api_key') as mock_create:
                    mock_create.return_value = CreateAPIKeyResponse(
                        api_key="psk_new_key",
                        key_id="new_key_id",
                        client_id="test_client_id",
                        client_name="Test Client",
                        created_at=datetime.utcnow(),
                        expires_at=None,
                        usage_tier=UsageTier.PRO,
                        permissions=[],
                    )
                    
                    result = await manager.rotate_api_key("test_key_id")
        
        assert result is not None
        assert result.key_id == "new_key_id"
        assert sample_api_key.status == APIKeyStatus.ROTATING
        
        # Check the create request
        create_call = mock_create.call_args[0][0]
        assert create_call.client_name == sample_api_key.client_name
        assert "Rotated from test_key_id" in create_call.description
        assert create_call.metadata["rotated_from"] == "test_key_id"

    @pytest.mark.asyncio
    async def test_rotate_api_key_not_found(self, manager):
        """Test rotating non-existent API key."""
        with patch.object(manager, '_get_api_key_by_id', return_value=None):
            result = await manager.rotate_api_key("nonexistent")
        
        assert result is None

    def test_check_network_bypass_allowed(self, manager):
        """Test network bypass for allowed IPs."""
        # Localhost
        assert manager.check_network_bypass("127.0.0.1") is True
        
        # 10.x.x.x network
        assert manager.check_network_bypass("10.0.0.1") is True
        assert manager.check_network_bypass("10.255.255.254") is True

    def test_check_network_bypass_denied(self, manager):
        """Test network bypass for disallowed IPs."""
        assert manager.check_network_bypass("192.168.1.1") is False
        assert manager.check_network_bypass("8.8.8.8") is False

    def test_check_network_bypass_invalid_ip(self, manager):
        """Test network bypass with invalid IP."""
        assert manager.check_network_bypass("not_an_ip") is False
        assert manager.check_network_bypass("256.256.256.256") is False
        assert manager.check_network_bypass("") is False

    def test_check_network_bypass_no_config(self, auth_config):
        """Test network bypass when no networks configured."""
        auth_config.bypass_networks = []
        manager = APIKeyManager(auth_config)
        
        assert manager.check_network_bypass("127.0.0.1") is False

    def test_check_header_bypass_allowed(self, manager):
        """Test header bypass with matching headers."""
        headers = {"X-Internal": "true", "Other-Header": "value"}
        assert manager.check_header_bypass(headers) is True
        
        headers = {"X-Service": "trusted"}
        assert manager.check_header_bypass(headers) is True

    def test_check_header_bypass_denied(self, manager):
        """Test header bypass with non-matching headers."""
        headers = {"X-Internal": "false"}  # Wrong value
        assert manager.check_header_bypass(headers) is False
        
        headers = {"Other-Header": "value"}  # Missing required header
        assert manager.check_header_bypass(headers) is False
        
        headers = {}  # No headers
        assert manager.check_header_bypass(headers) is False

    def test_check_header_bypass_no_config(self, auth_config):
        """Test header bypass when no headers configured."""
        auth_config.bypass_headers = {}
        manager = APIKeyManager(auth_config)
        
        headers = {"X-Internal": "true"}
        assert manager.check_header_bypass(headers) is False

    @pytest.mark.asyncio
    async def test_store_api_key_redis_enabled(self, manager, sample_api_key, mock_cache_manager):
        """Test storing API key when Redis is enabled."""
        await manager._store_api_key(sample_api_key)
        
        # Should call Redis hset for both hash and ID storage
        assert mock_cache_manager.client.hset.call_count == 2
        
        # Should add to client set
        mock_cache_manager.client.sadd.assert_called_once_with(
            f"api_keys:client:{sample_api_key.client_id}",
            sample_api_key.key_id
        )

    @pytest.mark.asyncio
    async def test_store_api_key_redis_disabled(self, manager, sample_api_key):
        """Test storing API key when Redis is disabled."""
        with patch('prompt_sentinel.auth.api_key_manager.cache_manager') as mock_cache:
            mock_cache.enabled = False
            
            # Should complete without error
            await manager._store_api_key(sample_api_key)

    @pytest.mark.asyncio
    async def test_get_api_key_by_hash_success(self, manager, sample_api_key, mock_cache_manager):
        """Test getting API key by hash."""
        mock_cache_manager.client.hget.return_value = sample_api_key.model_dump_json()
        
        result = await manager._get_api_key_by_hash("test_hash")
        
        assert isinstance(result, APIKey)
        assert result.key_id == sample_api_key.key_id

    @pytest.mark.asyncio
    async def test_get_api_key_by_hash_not_found(self, manager, mock_cache_manager):
        """Test getting non-existent API key by hash."""
        mock_cache_manager.client.hget.return_value = None
        
        result = await manager._get_api_key_by_hash("nonexistent_hash")
        
        assert result is None

    @pytest.mark.asyncio
    async def test_get_api_key_by_hash_redis_disabled(self, manager):
        """Test getting API key by hash when Redis is disabled."""
        with patch('prompt_sentinel.auth.api_key_manager.cache_manager') as mock_cache:
            mock_cache.enabled = False
            
            result = await manager._get_api_key_by_hash("test_hash")
            
            assert result is None

    @pytest.mark.asyncio
    async def test_get_api_key_by_id_success(self, manager, sample_api_key, mock_cache_manager):
        """Test getting API key by ID."""
        mock_cache_manager.client.hget.return_value = sample_api_key.model_dump_json()
        
        result = await manager._get_api_key_by_id("test_key_id")
        
        assert isinstance(result, APIKey)
        assert result.key_id == sample_api_key.key_id

    @pytest.mark.asyncio
    async def test_get_api_key_by_id_not_found(self, manager, mock_cache_manager):
        """Test getting non-existent API key by ID."""
        mock_cache_manager.client.hget.return_value = None
        
        result = await manager._get_api_key_by_id("nonexistent_id")
        
        assert result is None

    @pytest.mark.asyncio
    async def test_get_api_key_by_id_redis_disabled(self, manager):
        """Test getting API key by ID when Redis is disabled."""
        with patch('prompt_sentinel.auth.api_key_manager.cache_manager') as mock_cache:
            mock_cache.enabled = False
            
            result = await manager._get_api_key_by_id("test_id")
            
            assert result is None

    @pytest.mark.asyncio
    async def test_update_last_used_success(self, manager, sample_api_key):
        """Test updating last used timestamp."""
        original_timestamp = sample_api_key.last_used_at
        
        with patch.object(manager, '_get_api_key_by_id', return_value=sample_api_key):
            with patch.object(manager, '_store_api_key', new=AsyncMock()) as mock_store:
                await manager._update_last_used("test_key_id")
        
        assert sample_api_key.last_used_at != original_timestamp
        assert sample_api_key.last_used_at > datetime.utcnow() - timedelta(seconds=1)
        mock_store.assert_called_once_with(sample_api_key)

    @pytest.mark.asyncio
    async def test_update_last_used_not_found(self, manager):
        """Test updating last used for non-existent key."""
        with patch.object(manager, '_get_api_key_by_id', return_value=None):
            with patch.object(manager, '_store_api_key', new=AsyncMock()) as mock_store:
                await manager._update_last_used("nonexistent")
                
                mock_store.assert_not_called()

    @pytest.mark.asyncio
    async def test_list_all_keys_success(self, manager, sample_api_key, mock_cache_manager):
        """Test listing all keys from Redis."""
        # Use model_dump_json for both to ensure datetime serialization
        key1_data = sample_api_key.model_dump_json()
        key2_data = sample_api_key.model_copy(update={"key_id": "key2"}).model_dump_json()
        
        mock_cache_manager.client.hgetall.return_value = {
            "key1": key1_data,
            "key2": key2_data,
        }
        
        result = await manager._list_all_keys()
        
        assert len(result) == 2
        assert all(isinstance(item, dict) for item in result)

    @pytest.mark.asyncio
    async def test_list_all_keys_redis_disabled(self, manager):
        """Test listing all keys when Redis is disabled."""
        with patch('prompt_sentinel.auth.api_key_manager.cache_manager') as mock_cache:
            mock_cache.enabled = False
            
            result = await manager._list_all_keys()
            
            assert result == []

    @pytest.mark.asyncio
    async def test_validate_api_key_cache_disabled(self, manager, sample_api_key):
        """Test API key validation when cache is disabled."""
        api_key = "psk_valid_key"
        key_hash = manager._hash_key(api_key)
        sample_api_key.key_hash = key_hash
        
        with patch('prompt_sentinel.auth.api_key_manager.cache_manager') as mock_cache:
            mock_cache.enabled = False
            
            with patch.object(manager, '_get_api_key_by_hash', return_value=sample_api_key):
                with patch.object(manager, '_update_last_used', new=AsyncMock()):
                    client = await manager.validate_api_key(api_key)
        
        assert isinstance(client, Client)

    @pytest.mark.asyncio
    async def test_revoke_api_key_cache_disabled(self, manager, sample_api_key):
        """Test API key revocation when cache is disabled."""
        with patch('prompt_sentinel.auth.api_key_manager.cache_manager') as mock_cache:
            mock_cache.enabled = False
            
            with patch.object(manager, '_get_api_key_by_id', return_value=sample_api_key):
                with patch.object(manager, '_store_api_key', new=AsyncMock()):
                    result = await manager.revoke_api_key("test_key_id")
        
        assert result is True
        assert sample_api_key.status == APIKeyStatus.REVOKED

    def test_check_network_bypass_ipv6(self, auth_config):
        """Test network bypass with IPv6 addresses."""
        auth_config.bypass_networks = ["::1/128", "fe80::/10"]
        manager = APIKeyManager(auth_config)
        
        # Localhost IPv6
        assert manager.check_network_bypass("::1") is True
        
        # Link-local IPv6
        assert manager.check_network_bypass("fe80::1") is True
        
        # Public IPv6
        assert manager.check_network_bypass("2001:db8::1") is False

    def test_check_header_bypass_case_sensitive(self, manager):
        """Test that header bypass is case-sensitive for values."""
        headers = {"X-Internal": "True"}  # Capital T
        assert manager.check_header_bypass(headers) is False  # Should be "true"
        
        headers = {"X-Internal": "true"}  # Correct case
        assert manager.check_header_bypass(headers) is True

    @pytest.mark.asyncio
    async def test_create_api_key_with_empty_metadata(self, manager, mock_cache_manager):
        """Test API key creation with empty metadata."""
        request = CreateAPIKeyRequest(
            client_name="Client",
            description="Test",
            usage_tier=UsageTier.FREE,
            permissions=[],
            metadata={},  # Empty metadata
        )
        
        with patch.object(manager, '_store_api_key', new=AsyncMock()):
            response = await manager.create_api_key(request)
        
        assert response.api_key.startswith("psk_")
        assert isinstance(response, CreateAPIKeyResponse)