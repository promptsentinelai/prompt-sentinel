"""Comprehensive tests for API key manager."""

import hashlib
import hmac
import json
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from prompt_sentinel.auth.api_key_manager import APIKeyManager
from prompt_sentinel.auth.models import (
    APIKey,
    APIKeyInfo,
    APIKeyStatus,
    AuthConfig,
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
        """Create auth configuration."""
        return AuthConfig(
            api_key_prefix="psk_",
            api_key_length=32,
            max_keys_per_client=5,
            key_rotation_days=90,
            bypass_networks=["127.0.0.1/32", "10.0.0.0/8"],
            bypass_headers={"X-Internal": "true"},
        )

    @pytest.fixture
    def manager(self, auth_config):
        """Create API key manager."""
        return APIKeyManager(auth_config)

    @pytest.fixture
    def sample_api_key(self):
        """Create sample API key."""
        return APIKey(
            key_id="key_123",
            key_hash="hashed_key",
            name="Test Key",
            description="Test API key",
            client_id="client_123",
            created_at=datetime.utcnow(),
            expires_at=datetime.utcnow() + timedelta(days=30),
            last_used_at=None,
            status=APIKeyStatus.ACTIVE,
            permissions=[ClientPermission.DETECT_READ],
            usage_tier=UsageTier.FREE,
            rate_limit_rpm=100,
            rate_limit_tpm=10000,
            metadata={"source": "test"},
        )

    def test_init(self, auth_config):
        """Test API key manager initialization."""
        manager = APIKeyManager(auth_config)
        
        assert manager.config == auth_config
        assert manager._keys == {}
        assert manager._key_index == {}

    def test_generate_key(self, manager):
        """Test API key generation."""
        key = manager._generate_key()
        
        assert key.startswith("psk_")
        assert len(key) == 36  # psk_ (4) + 32 chars
        
        # Should generate unique keys
        key2 = manager._generate_key()
        assert key != key2

    def test_hash_key(self, manager):
        """Test API key hashing."""
        api_key = "psk_test123"
        
        hash1 = manager._hash_key(api_key)
        hash2 = manager._hash_key(api_key)
        
        # Should be deterministic
        assert hash1 == hash2
        
        # Should be a valid hash
        assert len(hash1) == 64  # SHA256 hex digest length
        
        # Different keys should have different hashes
        hash3 = manager._hash_key("psk_different")
        assert hash1 != hash3

    def test_constant_time_compare(self, manager):
        """Test constant time comparison."""
        # Equal strings
        assert manager._constant_time_compare("test", "test") == True
        
        # Different strings
        assert manager._constant_time_compare("test", "different") == False
        
        # Different lengths
        assert manager._constant_time_compare("short", "longer_string") == False
        
        # Empty strings
        assert manager._constant_time_compare("", "") == True

    @pytest.mark.asyncio
    async def test_create_api_key_success(self, manager):
        """Test successful API key creation."""
        request = CreateAPIKeyRequest(
            name="Test Key",
            description="A test API key",
            permissions=[ClientPermission.DETECT_READ, ClientPermission.DETECT_WRITE],
            expires_in_days=30,
            usage_tier=UsageTier.PRO,
        )
        
        response = await manager.create_api_key(request)
        
        assert isinstance(response, CreateAPIKeyResponse)
        assert response.api_key.startswith("psk_")
        assert response.key_id.startswith("key_")
        assert response.name == "Test Key"
        assert response.created_at is not None
        assert response.expires_at is not None
        
        # Check key was stored
        assert response.key_id in manager._keys
        stored_key = manager._keys[response.key_id]
        assert stored_key.name == "Test Key"
        assert stored_key.permissions == [
            ClientPermission.DETECT_READ,
            ClientPermission.DETECT_WRITE,
        ]

    @pytest.mark.asyncio
    async def test_create_api_key_with_metadata(self, manager):
        """Test API key creation with metadata."""
        request = CreateAPIKeyRequest(
            name="Metadata Key",
            metadata={"project": "test", "environment": "dev"},
        )
        
        response = await manager.create_api_key(request)
        
        stored_key = manager._keys[response.key_id]
        assert stored_key.metadata["project"] == "test"
        assert stored_key.metadata["environment"] == "dev"

    @pytest.mark.asyncio
    async def test_create_api_key_max_limit(self, manager):
        """Test API key creation respects max limit per client."""
        # Create max number of keys for same client
        for i in range(5):
            request = CreateAPIKeyRequest(
                name=f"Key {i}",
                metadata={"client_id": "same_client"},
            )
            await manager.create_api_key(request)
        
        # Sixth key should fail
        request = CreateAPIKeyRequest(
            name="Excess Key",
            metadata={"client_id": "same_client"},
        )
        
        # Mock the client ID lookup
        with patch.object(manager, "_get_client_key_count", return_value=5):
            with pytest.raises(ValueError, match="Maximum number of API keys"):
                await manager.create_api_key(request)

    @pytest.mark.asyncio
    async def test_validate_api_key_valid(self, manager, sample_api_key):
        """Test validation of valid API key."""
        # Store the key
        api_key_plain = "psk_test123"
        sample_api_key.key_hash = manager._hash_key(api_key_plain)
        manager._keys[sample_api_key.key_id] = sample_api_key
        manager._key_index[sample_api_key.key_hash] = sample_api_key.key_id
        
        client = await manager.validate_api_key(api_key_plain)
        
        assert isinstance(client, Client)
        assert client.client_id == "client_123"
        assert client.api_key_id == "key_123"
        assert client.authenticated == True
        assert client.permissions == [ClientPermission.DETECT_READ]
        
        # Check last_used_at was updated
        assert sample_api_key.last_used_at is not None

    @pytest.mark.asyncio
    async def test_validate_api_key_invalid(self, manager):
        """Test validation of invalid API key."""
        client = await manager.validate_api_key("psk_invalid")
        
        assert client is None

    @pytest.mark.asyncio
    async def test_validate_api_key_expired(self, manager, sample_api_key):
        """Test validation of expired API key."""
        api_key_plain = "psk_expired"
        sample_api_key.key_hash = manager._hash_key(api_key_plain)
        sample_api_key.expires_at = datetime.utcnow() - timedelta(days=1)
        manager._keys[sample_api_key.key_id] = sample_api_key
        manager._key_index[sample_api_key.key_hash] = sample_api_key.key_id
        
        client = await manager.validate_api_key(api_key_plain)
        
        assert client is None

    @pytest.mark.asyncio
    async def test_validate_api_key_revoked(self, manager, sample_api_key):
        """Test validation of revoked API key."""
        api_key_plain = "psk_revoked"
        sample_api_key.key_hash = manager._hash_key(api_key_plain)
        sample_api_key.status = APIKeyStatus.REVOKED
        manager._keys[sample_api_key.key_id] = sample_api_key
        manager._key_index[sample_api_key.key_hash] = sample_api_key.key_id
        
        client = await manager.validate_api_key(api_key_plain)
        
        assert client is None

    @pytest.mark.asyncio
    async def test_get_api_key(self, manager, sample_api_key):
        """Test getting API key info by ID."""
        manager._keys[sample_api_key.key_id] = sample_api_key
        
        info = await manager.get_api_key(sample_api_key.key_id)
        
        assert isinstance(info, APIKeyInfo)
        assert info.key_id == "key_123"
        assert info.name == "Test Key"
        assert info.status == APIKeyStatus.ACTIVE
        assert info.permissions == [ClientPermission.DETECT_READ]

    @pytest.mark.asyncio
    async def test_get_api_key_not_found(self, manager):
        """Test getting non-existent API key."""
        info = await manager.get_api_key("nonexistent")
        
        assert info is None

    @pytest.mark.asyncio
    async def test_list_api_keys(self, manager):
        """Test listing API keys."""
        # Create multiple keys
        keys = []
        for i in range(3):
            key = APIKey(
                key_id=f"key_{i}",
                key_hash=f"hash_{i}",
                name=f"Key {i}",
                client_id=f"client_{i}",
                status=APIKeyStatus.ACTIVE,
            )
            manager._keys[key.key_id] = key
            keys.append(key)
        
        # List all keys
        all_keys = await manager.list_api_keys()
        assert len(all_keys) == 3
        
        # List active keys only
        active_keys = await manager.list_api_keys(status=APIKeyStatus.ACTIVE)
        assert len(active_keys) == 3
        
        # List for specific client
        client_keys = await manager.list_api_keys(client_id="client_1")
        assert len(client_keys) == 1
        assert client_keys[0].name == "Key 1"

    @pytest.mark.asyncio
    async def test_list_api_keys_with_pagination(self, manager):
        """Test listing API keys with pagination."""
        # Create many keys
        for i in range(10):
            key = APIKey(
                key_id=f"key_{i:02d}",
                key_hash=f"hash_{i}",
                name=f"Key {i}",
                client_id="client",
            )
            manager._keys[key.key_id] = key
        
        # Get first page
        page1 = await manager.list_api_keys(limit=5, offset=0)
        assert len(page1) == 5
        
        # Get second page
        page2 = await manager.list_api_keys(limit=5, offset=5)
        assert len(page2) == 5
        
        # Verify no overlap
        page1_ids = {k.key_id for k in page1}
        page2_ids = {k.key_id for k in page2}
        assert len(page1_ids.intersection(page2_ids)) == 0

    @pytest.mark.asyncio
    async def test_revoke_api_key(self, manager, sample_api_key):
        """Test revoking an API key."""
        manager._keys[sample_api_key.key_id] = sample_api_key
        
        result = await manager.revoke_api_key(sample_api_key.key_id)
        
        assert result == True
        assert sample_api_key.status == APIKeyStatus.REVOKED
        assert sample_api_key.revoked_at is not None

    @pytest.mark.asyncio
    async def test_revoke_api_key_not_found(self, manager):
        """Test revoking non-existent API key."""
        result = await manager.revoke_api_key("nonexistent")
        
        assert result == False

    @pytest.mark.asyncio
    async def test_revoke_already_revoked(self, manager, sample_api_key):
        """Test revoking already revoked key."""
        sample_api_key.status = APIKeyStatus.REVOKED
        manager._keys[sample_api_key.key_id] = sample_api_key
        
        result = await manager.revoke_api_key(sample_api_key.key_id)
        
        assert result == False

    @pytest.mark.asyncio
    async def test_rotate_api_key(self, manager, sample_api_key):
        """Test rotating an API key."""
        old_key_plain = "psk_old123"
        sample_api_key.key_hash = manager._hash_key(old_key_plain)
        manager._keys[sample_api_key.key_id] = sample_api_key
        manager._key_index[sample_api_key.key_hash] = sample_api_key.key_id
        
        response = await manager.rotate_api_key(sample_api_key.key_id)
        
        assert isinstance(response, CreateAPIKeyResponse)
        assert response.api_key != old_key_plain
        assert response.api_key.startswith("psk_")
        
        # Old key should be revoked
        assert sample_api_key.status == APIKeyStatus.REVOKED
        
        # New key should exist
        assert response.key_id in manager._keys
        new_key = manager._keys[response.key_id]
        assert new_key.name == sample_api_key.name
        assert new_key.permissions == sample_api_key.permissions

    @pytest.mark.asyncio
    async def test_rotate_expired_key(self, manager, sample_api_key):
        """Test rotating an expired key."""
        sample_api_key.expires_at = datetime.utcnow() - timedelta(days=1)
        manager._keys[sample_api_key.key_id] = sample_api_key
        
        response = await manager.rotate_api_key(sample_api_key.key_id)
        
        assert response is None

    def test_check_network_bypass(self, manager):
        """Test network-based bypass checking."""
        # Localhost should bypass
        assert manager.check_network_bypass("127.0.0.1") == True
        
        # Private network in bypass list
        assert manager.check_network_bypass("10.0.0.5") == True
        
        # Public IP should not bypass
        assert manager.check_network_bypass("8.8.8.8") == False
        
        # Invalid IP should not bypass
        assert manager.check_network_bypass("invalid") == False

    def test_check_header_bypass(self, manager):
        """Test header-based bypass checking."""
        # Matching header should bypass
        headers = {"X-Internal": "true", "Other-Header": "value"}
        assert manager.check_header_bypass(headers) == True
        
        # Wrong value should not bypass
        headers = {"X-Internal": "false"}
        assert manager.check_header_bypass(headers) == False
        
        # Missing header should not bypass
        headers = {"Other-Header": "value"}
        assert manager.check_header_bypass(headers) == False

    @pytest.mark.asyncio
    async def test_store_and_retrieve_api_key(self, manager, sample_api_key):
        """Test storing and retrieving API keys."""
        await manager._store_api_key(sample_api_key)
        
        # Should be in main storage
        assert sample_api_key.key_id in manager._keys
        
        # Should be in index
        assert sample_api_key.key_hash in manager._key_index
        assert manager._key_index[sample_api_key.key_hash] == sample_api_key.key_id
        
        # Test retrieval by hash
        retrieved = await manager._get_api_key_by_hash(sample_api_key.key_hash)
        assert retrieved == sample_api_key
        
        # Test retrieval by ID
        retrieved = await manager._get_api_key_by_id(sample_api_key.key_id)
        assert retrieved == sample_api_key

    @pytest.mark.asyncio
    async def test_update_last_used(self, manager, sample_api_key):
        """Test updating last used timestamp."""
        manager._keys[sample_api_key.key_id] = sample_api_key
        original_time = sample_api_key.last_used_at
        
        await manager._update_last_used(sample_api_key.key_id)
        
        assert sample_api_key.last_used_at is not None
        assert sample_api_key.last_used_at != original_time

    @pytest.mark.asyncio
    async def test_list_all_keys_internal(self, manager):
        """Test internal list all keys method."""
        # Create keys with different statuses
        for i, status in enumerate([APIKeyStatus.ACTIVE, APIKeyStatus.EXPIRED, APIKeyStatus.REVOKED]):
            key = APIKey(
                key_id=f"key_{i}",
                key_hash=f"hash_{i}",
                name=f"Key {i}",
                client_id="client",
                status=status,
            )
            manager._keys[key.key_id] = key
        
        all_keys = await manager._list_all_keys()
        
        assert len(all_keys) == 3
        # Should return dict format
        assert all(isinstance(k, dict) for k in all_keys)

    def test_api_key_prefix_validation(self, auth_config):
        """Test API key prefix configuration."""
        # Custom prefix
        auth_config.api_key_prefix = "custom_"
        manager = APIKeyManager(auth_config)
        
        key = manager._generate_key()
        assert key.startswith("custom_")

    @pytest.mark.asyncio
    async def test_concurrent_key_operations(self, manager):
        """Test thread safety of concurrent operations."""
        import asyncio
        
        async def create_key(i):
            request = CreateAPIKeyRequest(name=f"Concurrent {i}")
            return await manager.create_api_key(request)
        
        # Create multiple keys concurrently
        tasks = [create_key(i) for i in range(10)]
        responses = await asyncio.gather(*tasks)
        
        # All should succeed
        assert len(responses) == 10
        assert all(r.api_key.startswith("psk_") for r in responses)
        
        # All keys should be unique
        api_keys = [r.api_key for r in responses]
        assert len(set(api_keys)) == 10


class TestAPIKeyManagerIntegration:
    """Integration tests for API key manager."""

    @pytest.mark.asyncio
    async def test_full_lifecycle(self):
        """Test complete API key lifecycle."""
        config = AuthConfig()
        manager = APIKeyManager(config)
        
        # 1. Create key
        create_req = CreateAPIKeyRequest(
            name="Lifecycle Key",
            description="Test lifecycle",
            permissions=[ClientPermission.DETECT_READ],
            expires_in_days=30,
        )
        create_resp = await manager.create_api_key(create_req)
        
        # 2. Validate key
        client = await manager.validate_api_key(create_resp.api_key)
        assert client is not None
        assert client.authenticated == True
        
        # 3. Get key info
        info = await manager.get_api_key(create_resp.key_id)
        assert info.name == "Lifecycle Key"
        assert info.status == APIKeyStatus.ACTIVE
        
        # 4. List keys
        keys = await manager.list_api_keys()
        assert len(keys) == 1
        
        # 5. Rotate key
        rotate_resp = await manager.rotate_api_key(create_resp.key_id)
        assert rotate_resp is not None
        
        # 6. Old key should not validate
        client = await manager.validate_api_key(create_resp.api_key)
        assert client is None
        
        # 7. New key should validate
        client = await manager.validate_api_key(rotate_resp.api_key)
        assert client is not None
        
        # 8. Revoke new key
        await manager.revoke_api_key(rotate_resp.key_id)
        
        # 9. Revoked key should not validate
        client = await manager.validate_api_key(rotate_resp.api_key)
        assert client is None

    @pytest.mark.asyncio
    async def test_permission_inheritance(self):
        """Test that permissions are properly inherited."""
        config = AuthConfig()
        manager = APIKeyManager(config)
        
        # Create key with specific permissions
        create_req = CreateAPIKeyRequest(
            name="Permission Test",
            permissions=[
                ClientPermission.DETECT_READ,
                ClientPermission.DETECT_WRITE,
                ClientPermission.ADMIN_READ,
            ],
            usage_tier=UsageTier.ENTERPRISE,
        )
        
        response = await manager.create_api_key(create_req)
        
        # Validate and check client
        client = await manager.validate_api_key(response.api_key)
        
        assert ClientPermission.DETECT_READ in client.permissions
        assert ClientPermission.DETECT_WRITE in client.permissions
        assert ClientPermission.ADMIN_READ in client.permissions
        assert ClientPermission.ADMIN_WRITE not in client.permissions
        assert client.usage_tier == UsageTier.ENTERPRISE


if __name__ == "__main__":
    pytest.main([__file__, "-v"])