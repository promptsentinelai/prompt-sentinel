"""Tests for authentication API routes."""

from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException, status
from fastapi.testclient import TestClient

from prompt_sentinel.auth import (
    APIKeyInfo,
    APIKeyManager,
    APIKeyStatus,
    Client,
    CreateAPIKeyRequest,
    CreateAPIKeyResponse,
)
from prompt_sentinel.auth.models import AuthMethod, UsageTier, ClientPermission
from prompt_sentinel.api.auth.routes import router
from prompt_sentinel.main import app


class TestAuthRoutes:
    """Test suite for authentication routes."""

    @pytest.fixture
    def client(self):
        """Create test client."""
        return TestClient(app)

    @pytest.fixture
    def mock_api_key_manager(self):
        """Create mock API key manager."""
        manager = MagicMock(spec=APIKeyManager)
        return manager

    @pytest.fixture
    def admin_client_mock(self):
        """Create mock admin client."""
        return Client(
            client_id="admin-123",
            client_name="Admin User",
            auth_method=AuthMethod.API_KEY
        )

    @pytest.fixture
    def regular_client_mock(self):
        """Create mock regular client."""
        return Client(
            client_id="user-456",
            client_name="Regular User",
            auth_method=AuthMethod.API_KEY
        )

    @pytest.fixture
    def sample_api_key_info(self):
        """Create sample API key info."""
        return APIKeyInfo(
            key_id="key-789",
            client_id="client-123",
            client_name="Test Client",
            created_at=datetime.utcnow(),
            last_used=datetime.utcnow(),
            status=APIKeyStatus.ACTIVE,
            usage_count=10,
            rate_limit=100,
            expires_at=datetime.utcnow() + timedelta(days=30)
        )

    def test_create_api_key_success(self, client, mock_api_key_manager, admin_client_mock):
        """Test successful API key creation."""
        # Mock dependencies
        with patch("prompt_sentinel.api.auth.routes.get_api_key_manager", return_value=mock_api_key_manager):
            with patch("prompt_sentinel.api.auth.routes.get_current_client", return_value=admin_client_mock):
                with patch("prompt_sentinel.api.auth.routes.require_admin", return_value=admin_client_mock):
                    
                    # Setup mock response
                    mock_api_key_manager.create_api_key.return_value = CreateAPIKeyResponse(
                        api_key="sk-test-123456",
                        key_id="key-new-123",
                        client_id="new-client-123",
                        client_name="Test Client",
                        created_at=datetime.utcnow(),
                        expires_at=datetime.utcnow() + timedelta(days=30),
                        usage_tier=UsageTier.FREE,
                        permissions=[ClientPermission.DETECT_READ]
                    )
                    
                    # Make request
                    response = client.post(
                        "/api/v1/admin/api-keys/",
                        json={
                            "client_name": "Test Client",
                            "rate_limit": 100,
                            "expires_in_days": 30
                        },
                        headers={"X-API-Key": "admin-key"}
                    )
                    
                    # Verify response
                    assert response.status_code == 201
                    data = response.json()
                    assert "api_key" in data
                    assert data["client_id"] == "new-client-123"

    def test_create_api_key_unauthorized(self, client, regular_client_mock):
        """Test API key creation without admin privileges."""
        with patch("prompt_sentinel.api.auth.routes.get_current_client", return_value=regular_client_mock):
            with patch("prompt_sentinel.api.auth.routes.require_admin", side_effect=HTTPException(status_code=403)):
                
                response = client.post(
                    "/api/v1/admin/api-keys/",
                    json={
                        "client_name": "Test Client",
                        "rate_limit": 100
                    },
                    headers={"X-API-Key": "user-key"}
                )
                
                assert response.status_code == 403

    def test_list_api_keys_success(self, client, mock_api_key_manager, admin_client_mock, sample_api_key_info):
        """Test successful API key listing."""
        with patch("prompt_sentinel.api.auth.routes.get_api_key_manager", return_value=mock_api_key_manager):
            with patch("prompt_sentinel.api.auth.routes.require_admin", return_value=admin_client_mock):
                
                # Setup mock response
                mock_api_key_manager.list_api_keys.return_value = [sample_api_key_info]
                
                response = client.get(
                    "/api/v1/admin/api-keys/",
                    headers={"X-API-Key": "admin-key"}
                )
                
                assert response.status_code == 200
                data = response.json()
                assert len(data) == 1
                assert data[0]["key_id"] == "key-789"
                assert data[0]["client_name"] == "Test Client"

    def test_list_api_keys_with_filters(self, client, mock_api_key_manager, admin_client_mock):
        """Test API key listing with status filter."""
        with patch("prompt_sentinel.api.auth.routes.get_api_key_manager", return_value=mock_api_key_manager):
            with patch("prompt_sentinel.api.auth.routes.require_admin", return_value=admin_client_mock):
                
                mock_api_key_manager.list_api_keys.return_value = []
                
                response = client.get(
                    "/api/v1/admin/api-keys/?status=ACTIVE",
                    headers={"X-API-Key": "admin-key"}
                )
                
                assert response.status_code == 200
                mock_api_key_manager.list_api_keys.assert_called_once_with(status="ACTIVE")

    def test_get_api_key_info_success(self, client, mock_api_key_manager, admin_client_mock, sample_api_key_info):
        """Test getting specific API key info."""
        with patch("prompt_sentinel.api.auth.routes.get_api_key_manager", return_value=mock_api_key_manager):
            with patch("prompt_sentinel.api.auth.routes.require_admin", return_value=admin_client_mock):
                
                mock_api_key_manager.get_api_key_info.return_value = sample_api_key_info
                
                response = client.get(
                    "/api/v1/admin/api-keys/client-123",
                    headers={"X-API-Key": "admin-key"}
                )
                
                assert response.status_code == 200
                data = response.json()
                assert data["client_id"] == "client-123"
                assert data["status"] == "ACTIVE"

    def test_get_api_key_info_not_found(self, client, mock_api_key_manager, admin_client_mock):
        """Test getting non-existent API key info."""
        with patch("prompt_sentinel.api.auth.routes.get_api_key_manager", return_value=mock_api_key_manager):
            with patch("prompt_sentinel.api.auth.routes.require_admin", return_value=admin_client_mock):
                
                mock_api_key_manager.get_api_key_info.return_value = None
                
                response = client.get(
                    "/api/v1/admin/api-keys/nonexistent",
                    headers={"X-API-Key": "admin-key"}
                )
                
                assert response.status_code == 404

    def test_revoke_api_key_success(self, client, mock_api_key_manager, admin_client_mock):
        """Test successful API key revocation."""
        with patch("prompt_sentinel.api.auth.routes.get_api_key_manager", return_value=mock_api_key_manager):
            with patch("prompt_sentinel.api.auth.routes.require_admin", return_value=admin_client_mock):
                
                mock_api_key_manager.revoke_api_key.return_value = True
                
                response = client.delete(
                    "/api/v1/admin/api-keys/client-123",
                    headers={"X-API-Key": "admin-key"}
                )
                
                assert response.status_code == 200
                data = response.json()
                assert data["message"] == "API key revoked successfully"

    def test_revoke_api_key_not_found(self, client, mock_api_key_manager, admin_client_mock):
        """Test revoking non-existent API key."""
        with patch("prompt_sentinel.api.auth.routes.get_api_key_manager", return_value=mock_api_key_manager):
            with patch("prompt_sentinel.api.auth.routes.require_admin", return_value=admin_client_mock):
                
                mock_api_key_manager.revoke_api_key.return_value = False
                
                response = client.delete(
                    "/api/v1/admin/api-keys/nonexistent",
                    headers={"X-API-Key": "admin-key"}
                )
                
                assert response.status_code == 404

    def test_rotate_api_key_success(self, client, mock_api_key_manager, admin_client_mock):
        """Test successful API key rotation."""
        with patch("prompt_sentinel.api.auth.routes.get_api_key_manager", return_value=mock_api_key_manager):
            with patch("prompt_sentinel.api.auth.routes.require_admin", return_value=admin_client_mock):
                
                mock_api_key_manager.rotate_api_key.return_value = CreateAPIKeyResponse(
                    api_key="sk-rotated-123456",
                    key_id="key-rotated-123",
                    client_id="client-123",
                    client_name="Test Client",
                    created_at=datetime.utcnow(),
                    expires_at=datetime.utcnow() + timedelta(days=30),
                    usage_tier=UsageTier.FREE,
                    permissions=[ClientPermission.DETECT_READ]
                )
                
                response = client.post(
                    "/api/v1/admin/api-keys/client-123/rotate",
                    headers={"X-API-Key": "admin-key"}
                )
                
                assert response.status_code == 200
                data = response.json()
                assert "api_key" in data
                assert data["api_key"].startswith("sk-rotated")

    def test_rotate_api_key_not_found(self, client, mock_api_key_manager, admin_client_mock):
        """Test rotating non-existent API key."""
        with patch("prompt_sentinel.api.auth.routes.get_api_key_manager", return_value=mock_api_key_manager):
            with patch("prompt_sentinel.api.auth.routes.require_admin", return_value=admin_client_mock):
                
                mock_api_key_manager.rotate_api_key.return_value = None
                
                response = client.post(
                    "/api/v1/admin/api-keys/nonexistent/rotate",
                    headers={"X-API-Key": "admin-key"}
                )
                
                assert response.status_code == 404

    def test_get_usage_statistics(self, client, mock_api_key_manager, admin_client_mock):
        """Test getting API key usage statistics."""
        with patch("prompt_sentinel.api.auth.routes.get_api_key_manager", return_value=mock_api_key_manager):
            with patch("prompt_sentinel.api.auth.routes.require_admin", return_value=admin_client_mock):
                
                mock_api_key_manager.get_usage_statistics.return_value = {
                    "total_keys": 10,
                    "active_keys": 8,
                    "revoked_keys": 2,
                    "total_requests": 1000,
                    "requests_today": 150
                }
                
                response = client.get(
                    "/api/v1/admin/api-keys/statistics",
                    headers={"X-API-Key": "admin-key"}
                )
                
                assert response.status_code == 200
                data = response.json()
                assert data["total_keys"] == 10
                assert data["active_keys"] == 8
                assert data["total_requests"] == 1000


class TestAuthRoutesIntegration:
    """Integration tests for auth routes."""

    @pytest.fixture
    def test_app(self):
        """Create test FastAPI app with routes."""
        from fastapi import FastAPI
        
        test_app = FastAPI()
        test_app.include_router(router)
        return test_app

    @pytest.fixture
    def test_client(self, test_app):
        """Create test client for integration tests."""
        return TestClient(test_app)

    def test_full_api_key_lifecycle(self, test_client, mock_api_key_manager, admin_client_mock):
        """Test complete API key lifecycle: create, list, rotate, revoke."""
        with patch("prompt_sentinel.api.auth.routes.get_api_key_manager", return_value=mock_api_key_manager):
            with patch("prompt_sentinel.api.auth.routes.require_admin", return_value=admin_client_mock):
                
                # 1. Create API key
                mock_api_key_manager.create_api_key.return_value = CreateAPIKeyResponse(
                    api_key="sk-test-123",
                    key_id="key-test-1",
                    client_id="client-new",
                    client_name="Test Client",
                    created_at=datetime.utcnow(),
                    expires_at=datetime.utcnow() + timedelta(days=30),
                    usage_tier=UsageTier.FREE,
                    permissions=[ClientPermission.DETECT_READ]
                )
                
                response = test_client.post(
                    "/api/v1/admin/api-keys/",
                    json={"client_name": "Test Client"},
                    headers={"X-API-Key": "admin-key"}
                )
                assert response.status_code == 201
                
                # 2. List API keys
                mock_api_key_manager.list_api_keys.return_value = [
                    APIKeyInfo(
                        key_id="key-1",
                        client_id="client-new",
                        client_name="Test Client",
                        created_at=datetime.utcnow(),
                        status=APIKeyStatus.ACTIVE,
                        usage_count=0,
                        rate_limit=100
                    )
                ]
                
                response = test_client.get(
                    "/api/v1/admin/api-keys/",
                    headers={"X-API-Key": "admin-key"}
                )
                assert response.status_code == 200
                assert len(response.json()) == 1
                
                # 3. Rotate API key
                mock_api_key_manager.rotate_api_key.return_value = CreateAPIKeyResponse(
                    api_key="sk-rotated-456",
                    key_id="key-rotated-1",
                    client_id="client-new",
                    client_name="Test Client",
                    created_at=datetime.utcnow(),
                    expires_at=datetime.utcnow() + timedelta(days=30),
                    usage_tier=UsageTier.FREE,
                    permissions=[ClientPermission.DETECT_READ]
                )
                
                response = test_client.post(
                    "/api/v1/admin/api-keys/client-new/rotate",
                    headers={"X-API-Key": "admin-key"}
                )
                assert response.status_code == 200
                
                # 4. Revoke API key
                mock_api_key_manager.revoke_api_key.return_value = True
                
                response = test_client.delete(
                    "/api/v1/admin/api-keys/client-new",
                    headers={"X-API-Key": "admin-key"}
                )
                assert response.status_code == 200

    def test_error_handling(self, test_client, mock_api_key_manager, admin_client_mock):
        """Test error handling in auth routes."""
        with patch("prompt_sentinel.api.auth.routes.get_api_key_manager", return_value=mock_api_key_manager):
            with patch("prompt_sentinel.api.auth.routes.require_admin", return_value=admin_client_mock):
                
                # Test database error
                mock_api_key_manager.create_api_key.side_effect = Exception("Database error")
                
                response = test_client.post(
                    "/api/v1/admin/api-keys/",
                    json={"client_name": "Test Client"},
                    headers={"X-API-Key": "admin-key"}
                )
                
                # Should handle error gracefully
                assert response.status_code in [500, 422]  # Internal error or validation error