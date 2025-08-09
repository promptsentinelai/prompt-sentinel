"""Comprehensive tests for authentication dependencies."""

import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException, Request
from fastapi.security import APIKeyHeader

from prompt_sentinel.auth.dependencies import (
    get_auth_config,
    get_api_key_manager,
    get_current_client,
    get_optional_client,
    require_permission,
    require_authenticated,
    require_admin,
    _is_kubernetes_pod,
    _is_docker_container,
    _has_public_endpoint,
)
from prompt_sentinel.auth.models import (
    AuthConfig,
    AuthMethod,
    AuthMode,
    Client,
    ClientPermission,
    UsageTier,
)


class TestAuthDependencies:
    """Test suite for auth dependencies."""

    @pytest.fixture
    def mock_request(self):
        """Create mock request."""
        request = MagicMock(spec=Request)
        request.headers = {}
        request.query_params = {}
        request.client = MagicMock()
        request.client.host = "127.0.0.1"
        request.url = MagicMock()
        request.url.path = "/test"
        request.state = MagicMock()
        return request

    @pytest.fixture
    def mock_auth_config(self):
        """Create mock auth config."""
        return AuthConfig(
            mode=AuthMode.OPTIONAL,
            enforce_https=False,
            bypass_networks=["127.0.0.1/32"],
            bypass_headers={"X-Internal": "true"},
            allow_localhost=True,
        )

    @pytest.fixture
    def mock_api_key_manager(self):
        """Create mock API key manager."""
        manager = MagicMock()
        manager.validate_api_key = AsyncMock(return_value=None)
        manager.check_network_bypass = MagicMock(return_value=False)
        manager.check_header_bypass = MagicMock(return_value=False)
        return manager

    @pytest.fixture
    def authenticated_client(self):
        """Create authenticated client."""
        return Client(
            client_id="test-client",
            api_key_id="key-123",
            name="Test Client",
            authenticated=True,
            auth_method=AuthMethod.API_KEY,
            permissions=[
                ClientPermission.DETECT_READ,
                ClientPermission.DETECT_WRITE,
            ],
            usage_tier=UsageTier.PRO,
        )

    @pytest.fixture
    def anonymous_client(self):
        """Create anonymous client."""
        return Client(
            client_id="anonymous",
            authenticated=False,
            auth_method=AuthMethod.NONE,
            permissions=[ClientPermission.DETECT_READ],
        )

    def test_get_auth_config_default(self):
        """Test getting auth config with defaults."""
        with patch("prompt_sentinel.auth.dependencies.settings") as mock_settings:
            mock_settings.auth_mode = "optional"
            mock_settings.auth_enforce_https = False
            mock_settings.auth_bypass_networks = []
            mock_settings.auth_bypass_headers = {}
            mock_settings.auth_allow_localhost = True
            
            config = get_auth_config()
            
            assert config.mode == AuthMode.OPTIONAL
            assert config.enforce_https == False
            assert config.allow_localhost == True

    def test_get_auth_config_from_settings(self):
        """Test getting auth config from settings."""
        with patch("prompt_sentinel.auth.dependencies.settings") as mock_settings:
            mock_settings.auth_mode = "required"
            mock_settings.auth_enforce_https = True
            mock_settings.auth_bypass_networks = ["10.0.0.0/8"]
            mock_settings.auth_bypass_headers = {"X-Secret": "value"}
            mock_settings.auth_allow_localhost = False
            
            config = get_auth_config()
            
            assert config.mode == AuthMode.REQUIRED
            assert config.enforce_https == True
            assert config.bypass_networks == ["10.0.0.0/8"]
            assert config.bypass_headers == {"X-Secret": "value"}
            assert config.allow_localhost == False

    def test_get_api_key_manager(self, mock_auth_config):
        """Test getting API key manager."""
        with patch("prompt_sentinel.auth.dependencies.APIKeyManager") as MockManager:
            mock_instance = MagicMock()
            MockManager.return_value = mock_instance
            
            manager = get_api_key_manager(mock_auth_config)
            
            assert manager == mock_instance
            MockManager.assert_called_once_with(mock_auth_config)

    @pytest.mark.asyncio
    async def test_get_current_client_from_state(self, mock_request, authenticated_client):
        """Test getting current client from request state."""
        mock_request.state.client = authenticated_client
        
        client = await get_current_client(
            request=mock_request,
            config=AuthConfig(mode=AuthMode.OPTIONAL),
            manager=MagicMock(),
        )
        
        assert client == authenticated_client

    @pytest.mark.asyncio
    async def test_get_current_client_api_key_header(
        self, mock_request, mock_auth_config, mock_api_key_manager, authenticated_client
    ):
        """Test getting client from API key in header."""
        mock_request.headers = {"Authorization": "Bearer psk_test123"}
        mock_request.state = MagicMock(spec=object)  # No client attribute
        mock_api_key_manager.validate_api_key.return_value = authenticated_client
        
        client = await get_current_client(
            request=mock_request,
            config=mock_auth_config,
            manager=mock_api_key_manager,
        )
        
        assert client == authenticated_client
        mock_api_key_manager.validate_api_key.assert_called_once_with("psk_test123")

    @pytest.mark.asyncio
    async def test_get_current_client_x_api_key_header(
        self, mock_request, mock_auth_config, mock_api_key_manager, authenticated_client
    ):
        """Test getting client from X-API-Key header."""
        mock_request.headers = {"X-API-Key": "psk_test456"}
        mock_request.state = MagicMock(spec=object)
        mock_api_key_manager.validate_api_key.return_value = authenticated_client
        
        client = await get_current_client(
            request=mock_request,
            config=mock_auth_config,
            manager=mock_api_key_manager,
        )
        
        assert client == authenticated_client
        mock_api_key_manager.validate_api_key.assert_called_once_with("psk_test456")

    @pytest.mark.asyncio
    async def test_get_current_client_query_param(
        self, mock_request, mock_auth_config, mock_api_key_manager, authenticated_client
    ):
        """Test getting client from query parameter."""
        mock_request.query_params = {"api_key": "psk_test789"}
        mock_request.state = MagicMock(spec=object)
        mock_api_key_manager.validate_api_key.return_value = authenticated_client
        
        client = await get_current_client(
            request=mock_request,
            config=mock_auth_config,
            manager=mock_api_key_manager,
        )
        
        assert client == authenticated_client
        mock_api_key_manager.validate_api_key.assert_called_once_with("psk_test789")

    @pytest.mark.asyncio
    async def test_get_current_client_localhost_bypass(
        self, mock_request, mock_auth_config, mock_api_key_manager
    ):
        """Test localhost bypass."""
        mock_request.client.host = "127.0.0.1"
        mock_request.state = MagicMock(spec=object)
        mock_auth_config.allow_localhost = True
        
        client = await get_current_client(
            request=mock_request,
            config=mock_auth_config,
            manager=mock_api_key_manager,
        )
        
        assert client.authenticated == True
        assert client.auth_method == AuthMethod.LOCALHOST

    @pytest.mark.asyncio
    async def test_get_current_client_network_bypass(
        self, mock_request, mock_auth_config, mock_api_key_manager
    ):
        """Test network bypass."""
        mock_request.client.host = "10.0.0.5"
        mock_request.state = MagicMock(spec=object)
        mock_api_key_manager.check_network_bypass.return_value = True
        
        client = await get_current_client(
            request=mock_request,
            config=mock_auth_config,
            manager=mock_api_key_manager,
        )
        
        assert client.authenticated == True
        assert client.auth_method == AuthMethod.NETWORK_BYPASS
        mock_api_key_manager.check_network_bypass.assert_called_once_with("10.0.0.5")

    @pytest.mark.asyncio
    async def test_get_current_client_header_bypass(
        self, mock_request, mock_auth_config, mock_api_key_manager
    ):
        """Test header bypass."""
        mock_request.headers = {"X-Internal": "true"}
        mock_request.state = MagicMock(spec=object)
        mock_api_key_manager.check_header_bypass.return_value = True
        
        client = await get_current_client(
            request=mock_request,
            config=mock_auth_config,
            manager=mock_api_key_manager,
        )
        
        assert client.authenticated == True
        assert client.auth_method == AuthMethod.HEADER_BYPASS

    @pytest.mark.asyncio
    async def test_get_current_client_required_mode_no_auth(
        self, mock_request, mock_auth_config, mock_api_key_manager
    ):
        """Test required mode without authentication."""
        mock_auth_config.mode = AuthMode.REQUIRED
        mock_request.state = MagicMock(spec=object)
        mock_request.client.host = "192.168.1.1"  # Not localhost
        
        with pytest.raises(HTTPException) as exc_info:
            await get_current_client(
                request=mock_request,
                config=mock_auth_config,
                manager=mock_api_key_manager,
            )
        
        assert exc_info.value.status_code == 401
        assert exc_info.value.detail == "Authentication required"

    @pytest.mark.asyncio
    async def test_get_current_client_optional_mode_no_auth(
        self, mock_request, mock_auth_config, mock_api_key_manager
    ):
        """Test optional mode without authentication."""
        mock_auth_config.mode = AuthMode.OPTIONAL
        mock_request.state = MagicMock(spec=object)
        
        client = await get_current_client(
            request=mock_request,
            config=mock_auth_config,
            manager=mock_api_key_manager,
        )
        
        assert client.authenticated == False
        assert client.auth_method == AuthMethod.NONE
        assert client.client_id == "anonymous"

    @pytest.mark.asyncio
    async def test_get_current_client_disabled_mode(
        self, mock_request, mock_auth_config, mock_api_key_manager
    ):
        """Test disabled mode."""
        mock_auth_config.mode = AuthMode.DISABLED
        mock_request.state = MagicMock(spec=object)
        
        client = await get_current_client(
            request=mock_request,
            config=mock_auth_config,
            manager=mock_api_key_manager,
        )
        
        assert client.authenticated == False
        assert client.client_id == "anonymous"

    @pytest.mark.asyncio
    async def test_get_optional_client(
        self, mock_request, mock_auth_config, mock_api_key_manager, authenticated_client
    ):
        """Test get_optional_client dependency."""
        mock_request.headers = {"Authorization": "Bearer psk_test"}
        mock_request.state = MagicMock(spec=object)
        mock_api_key_manager.validate_api_key.return_value = authenticated_client
        
        client = await get_optional_client(
            request=mock_request,
            config=mock_auth_config,
            manager=mock_api_key_manager,
        )
        
        assert client == authenticated_client

    @pytest.mark.asyncio
    async def test_get_optional_client_no_auth(
        self, mock_request, mock_auth_config, mock_api_key_manager
    ):
        """Test get_optional_client without authentication."""
        mock_request.state = MagicMock(spec=object)
        
        client = await get_optional_client(
            request=mock_request,
            config=mock_auth_config,
            manager=mock_api_key_manager,
        )
        
        assert client.authenticated == False
        assert client.client_id == "anonymous"

    @pytest.mark.asyncio
    async def test_require_permission_granted(self, authenticated_client):
        """Test require_permission when permission is granted."""
        check_permission = require_permission(ClientPermission.DETECT_READ)
        
        result = await check_permission(authenticated_client)
        
        assert result == authenticated_client

    @pytest.mark.asyncio
    async def test_require_permission_denied(self, authenticated_client):
        """Test require_permission when permission is denied."""
        check_permission = require_permission(ClientPermission.ADMIN_WRITE)
        
        with pytest.raises(HTTPException) as exc_info:
            await check_permission(authenticated_client)
        
        assert exc_info.value.status_code == 403
        assert "requires permission" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_require_authenticated_success(self, authenticated_client):
        """Test require_authenticated with authenticated client."""
        check_authenticated = require_authenticated()
        
        result = await check_authenticated(authenticated_client)
        
        assert result == authenticated_client

    @pytest.mark.asyncio
    async def test_require_authenticated_failure(self, anonymous_client):
        """Test require_authenticated with anonymous client."""
        check_authenticated = require_authenticated()
        
        with pytest.raises(HTTPException) as exc_info:
            await check_authenticated(anonymous_client)
        
        assert exc_info.value.status_code == 401
        assert exc_info.value.detail == "Authentication required"

    @pytest.mark.asyncio
    async def test_require_admin_success(self, authenticated_client):
        """Test require_admin with admin permissions."""
        authenticated_client.permissions.append(ClientPermission.ADMIN_WRITE)
        
        result = await require_admin()(authenticated_client)
        
        assert result == authenticated_client

    @pytest.mark.asyncio
    async def test_require_admin_failure(self, authenticated_client):
        """Test require_admin without admin permissions."""
        with pytest.raises(HTTPException) as exc_info:
            await require_admin()(authenticated_client)
        
        assert exc_info.value.status_code == 403
        assert "requires admin privileges" in exc_info.value.detail

    def test_is_kubernetes_pod(self):
        """Test Kubernetes pod detection."""
        # Test when not in Kubernetes
        with patch.dict(os.environ, {}, clear=True):
            with patch("os.path.exists", return_value=False):
                assert _is_kubernetes_pod() == False
        
        # Test when in Kubernetes (env var set)
        with patch.dict(os.environ, {"KUBERNETES_SERVICE_HOST": "10.0.0.1"}):
            assert _is_kubernetes_pod() == True
        
        # Test when in Kubernetes (service account exists)
        with patch.dict(os.environ, {}, clear=True):
            with patch("os.path.exists", return_value=True):
                assert _is_kubernetes_pod() == True

    def test_is_docker_container(self):
        """Test Docker container detection."""
        # Test when not in Docker
        with patch("os.path.exists", return_value=False):
            assert _is_docker_container() == False
        
        # Test when in Docker
        with patch("os.path.exists", return_value=True):
            assert _is_docker_container() == True

    def test_has_public_endpoint(self):
        """Test public endpoint detection."""
        # Test with no environment variables
        with patch.dict(os.environ, {}, clear=True):
            with patch("socket.gethostname", return_value="localhost"):
                assert _has_public_endpoint() == False
        
        # Test with public URL
        with patch.dict(os.environ, {"PUBLIC_URL": "https://api.example.com"}):
            assert _has_public_endpoint() == True
        
        # Test with API URL
        with patch.dict(os.environ, {"API_URL": "https://api.example.com"}):
            assert _has_public_endpoint() == True
        
        # Test with public hostname
        with patch("socket.gethostname", return_value="api.example.com"):
            assert _has_public_endpoint() == True


class TestAuthDependenciesIntegration:
    """Integration tests for auth dependencies."""

    @pytest.mark.asyncio
    async def test_full_auth_flow(self):
        """Test complete authentication flow."""
        from prompt_sentinel.auth.api_key_manager import APIKeyManager
        from prompt_sentinel.auth.models import CreateAPIKeyRequest
        
        # Setup
        config = AuthConfig(mode=AuthMode.REQUIRED)
        manager = APIKeyManager(config)
        
        # Create API key
        create_req = CreateAPIKeyRequest(
            name="Test Key",
            permissions=[ClientPermission.DETECT_READ, ClientPermission.DETECT_WRITE],
        )
        response = await manager.create_api_key(create_req)
        
        # Create request with API key
        request = MagicMock(spec=Request)
        request.headers = {"Authorization": f"Bearer {response.api_key}"}
        request.state = MagicMock(spec=object)
        request.client = MagicMock()
        request.client.host = "192.168.1.1"
        
        # Get client
        client = await get_current_client(request, config, manager)
        
        assert client.authenticated == True
        assert client.api_key_id == response.key_id
        assert ClientPermission.DETECT_READ in client.permissions
        assert ClientPermission.DETECT_WRITE in client.permissions

    @pytest.mark.asyncio
    async def test_permission_chain(self):
        """Test chaining permission requirements."""
        # Create client with limited permissions
        client = Client(
            client_id="limited",
            authenticated=True,
            permissions=[ClientPermission.DETECT_READ],
        )
        
        # Should pass read check
        read_check = require_permission(ClientPermission.DETECT_READ)
        result = await read_check(client)
        assert result == client
        
        # Should fail write check
        write_check = require_permission(ClientPermission.DETECT_WRITE)
        with pytest.raises(HTTPException) as exc:
            await write_check(client)
        assert exc.value.status_code == 403
        
        # Should fail admin check
        with pytest.raises(HTTPException) as exc:
            await require_admin()(client)
        assert exc.value.status_code == 403


if __name__ == "__main__":
    pytest.main([__file__, "-v"])