# Elastic License 2.0
#
# Copyright (c) 2024-present, PromptSentinel
#
# This source code is licensed under the Elastic License 2.0 found in the
# LICENSE file in the root directory of this source tree.

"""Enhanced authentication and authorization system."""

import hashlib
import secrets
from datetime import datetime, timedelta
from enum import Enum
from typing import Any

import structlog
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

from prompt_sentinel.config.settings import settings
from prompt_sentinel.security.audit_logger import SecurityEventType, security_audit_logger

logger = structlog.get_logger()


class UserRole(str, Enum):
    """User roles for RBAC."""

    ADMIN = "admin"
    USER = "user"
    READONLY = "readonly"
    SERVICE = "service"


class Permission(str, Enum):
    """Granular permissions."""

    READ_DETECTIONS = "read:detections"
    WRITE_DETECTIONS = "write:detections"
    READ_ANALYTICS = "read:analytics"
    WRITE_ANALYTICS = "write:analytics"
    MANAGE_CLIENTS = "manage:clients"
    MANAGE_SYSTEM = "manage:system"
    ACCESS_ADMIN = "access:admin"


class APIKeyStatus(str, Enum):
    """API key status."""

    ACTIVE = "active"
    DISABLED = "disabled"
    EXPIRED = "expired"
    REVOKED = "revoked"


class APIKey(BaseModel):
    """API key model."""

    key_id: str
    client_id: str
    name: str
    description: str | None = None
    key_hash: str  # Store hash, not actual key
    status: APIKeyStatus = APIKeyStatus.ACTIVE
    role: UserRole = UserRole.USER
    permissions: list[Permission] = Field(default_factory=list)

    # Metadata
    created_at: datetime
    expires_at: datetime | None = None
    last_used_at: datetime | None = None
    usage_count: int = 0

    # Rate limiting
    rate_limit_override: int | None = None
    daily_quota: int | None = None
    daily_usage: int = 0
    daily_reset_at: datetime = Field(
        default_factory=lambda: datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
        + timedelta(days=1)
    )

    # Security
    allowed_ips: list[str] = Field(default_factory=list)
    allowed_origins: list[str] = Field(default_factory=list)

    @property
    def is_valid(self) -> bool:
        """Check if API key is valid."""
        if self.status != APIKeyStatus.ACTIVE:
            return False

        if self.expires_at and self.expires_at < datetime.utcnow():
            return False

        if self.daily_quota and self.daily_usage >= self.daily_quota:
            if datetime.utcnow() < self.daily_reset_at:
                return False

        return True

    def has_permission(self, permission: Permission) -> bool:
        """Check if key has specific permission."""
        # Admin role has all permissions
        if self.role == UserRole.ADMIN:
            return True

        return permission in self.permissions


class AuthenticatedUser(BaseModel):
    """Authenticated user context."""

    client_id: str
    api_key_id: str
    role: UserRole
    permissions: list[Permission]
    rate_limit_override: int | None = None

    def has_permission(self, permission: Permission) -> bool:
        """Check if user has permission."""
        return self.role == UserRole.ADMIN or permission in self.permissions


class APIKeyManager:
    """Manages API keys and authentication."""

    def __init__(self):
        """Initialize API key manager."""
        self.api_keys: dict[str, APIKey] = {}  # In production, use proper storage
        self.key_hash_to_id: dict[str, str] = {}

    def generate_api_key(
        self,
        client_id: str,
        name: str,
        role: UserRole = UserRole.USER,
        permissions: list[Permission] | None = None,
        expires_in_days: int | None = None,
        description: str | None = None,
    ) -> tuple[str, APIKey]:
        """Generate new API key."""

        # Generate secure random key
        secrets.token_bytes(32)
        key_string = f"{settings.api_key_prefix}{secrets.token_urlsafe(32)}"

        # Hash the key for storage
        key_hash = hashlib.sha256(key_string.encode()).hexdigest()

        # Set expiration
        expires_at = None
        if expires_in_days:
            expires_at = datetime.utcnow() + timedelta(days=expires_in_days)

        # Set default permissions based on role
        if permissions is None:
            permissions = self._get_default_permissions(role)

        # Create API key record
        key_id = f"key_{secrets.token_urlsafe(8)}"
        api_key = APIKey(
            key_id=key_id,
            client_id=client_id,
            name=name,
            description=description,
            key_hash=key_hash,
            role=role,
            permissions=permissions,
            created_at=datetime.utcnow(),
            expires_at=expires_at,
        )

        # Store key
        self.api_keys[key_id] = api_key
        self.key_hash_to_id[key_hash] = key_id

        logger.info(
            "API key generated",
            key_id=key_id,
            client_id=client_id,
            role=role.value,
            expires_at=expires_at.isoformat() if expires_at else None,
        )

        return key_string, api_key

    def authenticate_key(self, key_string: str) -> APIKey | None:
        """Authenticate API key."""
        if not key_string or not key_string.startswith(settings.api_key_prefix):
            return None

        # Hash the provided key
        key_hash = hashlib.sha256(key_string.encode()).hexdigest()

        # Find key by hash
        key_id = self.key_hash_to_id.get(key_hash)
        if not key_id:
            return None

        api_key = self.api_keys.get(key_id)
        if not api_key or not api_key.is_valid:
            return None

        # Update usage statistics
        api_key.last_used_at = datetime.utcnow()
        api_key.usage_count += 1

        # Reset daily usage if needed
        if datetime.utcnow() >= api_key.daily_reset_at:
            api_key.daily_usage = 0
            api_key.daily_reset_at = datetime.utcnow().replace(
                hour=0, minute=0, second=0, microsecond=0
            ) + timedelta(days=1)

        api_key.daily_usage += 1

        return api_key

    def revoke_key(self, key_id: str) -> bool:
        """Revoke API key."""
        api_key = self.api_keys.get(key_id)
        if not api_key:
            return False

        api_key.status = APIKeyStatus.REVOKED

        logger.info("API key revoked", key_id=key_id, client_id=api_key.client_id)
        return True

    def list_keys(self, client_id: str) -> list[APIKey]:
        """List API keys for client."""
        return [key for key in self.api_keys.values() if key.client_id == client_id]

    def _get_default_permissions(self, role: UserRole) -> list[Permission]:
        """Get default permissions for role."""
        if role == UserRole.ADMIN:
            return list(Permission)
        elif role == UserRole.USER:
            return [
                Permission.READ_DETECTIONS,
                Permission.WRITE_DETECTIONS,
                Permission.READ_ANALYTICS,
            ]
        elif role == UserRole.READONLY:
            return [
                Permission.READ_DETECTIONS,
                Permission.READ_ANALYTICS,
            ]
        elif role == UserRole.SERVICE:
            return [
                Permission.READ_DETECTIONS,
                Permission.WRITE_DETECTIONS,
            ]

        return []


class EnhancedAuthMiddleware:
    """Enhanced authentication middleware with RBAC."""

    def __init__(self, api_key_manager: APIKeyManager):
        """
        Initialize enhanced authentication middleware.

        Args:
            api_key_manager: API key manager instance
        """
        self.api_key_manager = api_key_manager
        self.security = HTTPBearer(auto_error=False)

    async def authenticate_request(
        self, request: Request, credentials: HTTPAuthorizationCredentials | None = None
    ) -> AuthenticatedUser | None:
        """Authenticate request and return user context."""

        # Try different authentication methods
        api_key = None
        auth_method = "none"

        # 1. Bearer token authentication
        if credentials and credentials.scheme.lower() == "bearer":
            api_key = self.api_key_manager.authenticate_key(credentials.credentials)
            auth_method = "bearer_token"

        # 2. API key header
        if not api_key:
            api_key_header = request.headers.get("x-api-key")
            if api_key_header:
                api_key = self.api_key_manager.authenticate_key(api_key_header)
                auth_method = "api_key_header"

        # 3. Query parameter (least secure, only for development)
        if not api_key and settings.api_env != "production":
            api_key_param = request.query_params.get("api_key")
            if api_key_param:
                api_key = self.api_key_manager.authenticate_key(api_key_param)
                auth_method = "query_parameter"

        # Log authentication attempt
        success = api_key is not None
        await security_audit_logger.log_authentication_event(
            success=success,
            request=request,
            client_id=api_key.client_id if api_key else None,
            auth_method=auth_method,
            failure_reason="invalid_key" if not success and auth_method != "none" else None,
        )

        if not api_key:
            return None

        # Additional security checks
        if not self._check_ip_restrictions(request, api_key):
            await security_audit_logger.log_security_event(
                event_type=SecurityEventType.ACCESS_DENIED,
                description="IP address not allowed",
                request=request,
                client_id=api_key.client_id,
                severity="medium",
                additional_data={"allowed_ips": api_key.allowed_ips},
            )
            return None

        return AuthenticatedUser(
            client_id=api_key.client_id,
            api_key_id=api_key.key_id,
            role=api_key.role,
            permissions=api_key.permissions,
            rate_limit_override=api_key.rate_limit_override,
        )

    def _check_ip_restrictions(self, request: Request, api_key: APIKey) -> bool:
        """Check IP address restrictions."""
        if not api_key.allowed_ips:
            return True  # No restrictions

        client_ip = self._get_client_ip(request)

        # Check if IP is in allowed list
        import ipaddress

        try:
            client_addr = ipaddress.ip_address(client_ip)
            for allowed_ip in api_key.allowed_ips:
                if "/" in allowed_ip:  # CIDR notation
                    if client_addr in ipaddress.ip_network(allowed_ip):
                        return True
                else:  # Exact IP
                    if client_ip == allowed_ip:
                        return True
        except ValueError:
            logger.warning("Invalid IP address", client_ip=client_ip)
            return False

        return False

    def _get_client_ip(self, request: Request) -> str:
        """Get client IP address."""
        # Check forwarded headers first
        forwarded_for = request.headers.get("x-forwarded-for")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()

        real_ip = request.headers.get("x-real-ip")
        if real_ip:
            return real_ip

        return request.client.host if request.client else "unknown"


# Global instances
api_key_manager = APIKeyManager()
auth_middleware = EnhancedAuthMiddleware(api_key_manager)


# FastAPI dependencies
async def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(HTTPBearer(auto_error=False)),
) -> AuthenticatedUser | None:
    """FastAPI dependency to get current authenticated user."""
    return await auth_middleware.authenticate_request(request, credentials)


async def require_authentication(
    user: AuthenticatedUser | None = Depends(get_current_user),
) -> AuthenticatedUser:
    """FastAPI dependency to require authentication."""
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


def require_permission(permission: Permission):
    """FastAPI dependency factory to require specific permission."""

    async def check_permission(
        user: AuthenticatedUser = Depends(require_authentication),
    ) -> AuthenticatedUser:
        """Check if user has the required permission."""
        if not user.has_permission(permission):
            await security_audit_logger.log_security_event(
                event_type=SecurityEventType.ACCESS_DENIED,
                description=f"Permission denied: {permission.value}",
                client_id=user.client_id,
                severity="medium",
                additional_data={
                    "required_permission": permission.value,
                    "user_role": user.role.value,
                    "user_permissions": [p.value for p in user.permissions],
                },
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission required: {permission.value}",
            )
        return user

    return check_permission


def require_role(role: UserRole):
    """FastAPI dependency factory to require specific role."""

    async def check_role(
        user: AuthenticatedUser = Depends(require_authentication),
    ) -> AuthenticatedUser:
        """Check if user has the required role."""
        if user.role != role and user.role != UserRole.ADMIN:
            await security_audit_logger.log_security_event(
                event_type=SecurityEventType.ACCESS_DENIED,
                description=f"Role required: {role.value}",
                client_id=user.client_id,
                severity="medium",
                additional_data={"required_role": role.value, "user_role": user.role.value},
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail=f"Role required: {role.value}"
            )
        return user

    return check_role


# API key management endpoints
from fastapi import APIRouter

auth_router = APIRouter(prefix="/api/v1/auth", tags=["Authentication"])


class CreateAPIKeyRequest(BaseModel):
    """Request to create new API key."""

    name: str = Field(..., min_length=1, max_length=100)
    description: str | None = Field(None, max_length=500)
    role: UserRole = UserRole.USER
    permissions: list[Permission] | None = None
    expires_in_days: int | None = Field(None, gt=0, le=3650)


class APIKeyResponse(BaseModel):
    """API key response (without actual key)."""

    key_id: str
    name: str
    description: str | None
    role: UserRole
    permissions: list[Permission]
    status: APIKeyStatus
    created_at: datetime
    expires_at: datetime | None
    last_used_at: datetime | None
    usage_count: int


@auth_router.post("/keys", dependencies=[Depends(require_permission(Permission.MANAGE_CLIENTS))])
async def create_api_key(
    request: CreateAPIKeyRequest, current_user: AuthenticatedUser = Depends(require_authentication)
) -> dict[str, Any]:
    """Create new API key."""

    key_string, api_key = api_key_manager.generate_api_key(
        client_id=current_user.client_id,
        name=request.name,
        role=request.role,
        permissions=request.permissions,
        expires_in_days=request.expires_in_days,
        description=request.description,
    )

    return {
        "api_key": key_string,  # Only returned once!
        "key_info": APIKeyResponse(
            key_id=api_key.key_id,
            name=api_key.name,
            description=api_key.description,
            role=api_key.role,
            permissions=api_key.permissions,
            status=api_key.status,
            created_at=api_key.created_at,
            expires_at=api_key.expires_at,
            last_used_at=api_key.last_used_at,
            usage_count=api_key.usage_count,
        ),
    }


@auth_router.get("/keys")
async def list_api_keys(
    current_user: AuthenticatedUser = Depends(require_authentication),
) -> list[APIKeyResponse]:
    """List API keys for current user."""

    keys = api_key_manager.list_keys(current_user.client_id)

    return [
        APIKeyResponse(
            key_id=key.key_id,
            name=key.name,
            description=key.description,
            role=key.role,
            permissions=key.permissions,
            status=key.status,
            created_at=key.created_at,
            expires_at=key.expires_at,
            last_used_at=key.last_used_at,
            usage_count=key.usage_count,
        )
        for key in keys
    ]


@auth_router.delete("/keys/{key_id}")
async def revoke_api_key(
    key_id: str, current_user: AuthenticatedUser = Depends(require_authentication)
) -> dict[str, str]:
    """Revoke API key."""

    # Check if key belongs to current user
    api_key = api_key_manager.api_keys.get(key_id)
    if not api_key or api_key.client_id != current_user.client_id:
        raise HTTPException(status_code=404, detail="API key not found")

    success = api_key_manager.revoke_key(key_id)
    if not success:
        raise HTTPException(status_code=400, detail="Failed to revoke key")

    return {"status": "revoked", "key_id": key_id}
