"""
Identity-specific middleware for GraphQL presentation layer.
Authentication, authorization, and security context management.
"""

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from strawberry.extensions import Extension
from strawberry.types import Info

from app.core.cache import CacheManager
from app.core.logging import get_logger
from app.core.monitoring import metrics
from app.core.security import decode_token, is_token_expired
from app.modules.identity.application.dtos.command_params import AuditEventParams
from app.modules.identity.domain.errors import (
    AuthenticationError,
    AuthorizationError,
    MFARequiredError,
    SessionExpiredError,
)

logger = get_logger(__name__)


@dataclass
class SecurityContext:
    """Security context for GraphQL requests."""
    user_id: UUID | None = None
    session_id: UUID | None = None
    roles: list[str] = None
    permissions: list[str] = None
    ip_address: str = ""
    user_agent: str = ""
    risk_score: float = 0.0
    mfa_verified: bool = False
    device_trusted: bool = False
    correlation_id: str = ""
    
    def __post_init__(self):
        if self.roles is None:
            self.roles = []
        if self.permissions is None:
            self.permissions = []
    
    def has_permission(self, permission: str) -> bool:
        """Check if context has specific permission."""
        return permission in self.permissions
    
    def has_role(self, role: str) -> bool:
        """Check if context has specific role."""
        return role in self.roles
    
    def has_any_permission(self, permissions: list[str]) -> bool:
        """Check if context has any of the given permissions."""
        return any(p in self.permissions for p in permissions)
    
    def has_all_permissions(self, permissions: list[str]) -> bool:
        """Check if context has all of the given permissions."""
        return all(p in self.permissions for p in permissions)
    
    def is_authenticated(self) -> bool:
        """Check if user is authenticated."""
        return self.user_id is not None
    
    def requires_mfa(self) -> bool:
        """Check if MFA is required based on risk score."""
        return self.risk_score > 0.7 and not self.mfa_verified


class IdentityAuthenticationExtension(Extension):
    """GraphQL extension for authentication and security context creation."""
    
    def __init__(self, cache_manager: CacheManager):
        self._cache = cache_manager
        self._logger = logger
    
    async def on_request_start(self) -> None:
        """Called at the start of a request."""
        request = self.execution_context.context.request
        
        # Extract security context
        security_context = await self._extract_security_context(request)
        
        # Add to GraphQL context
        self.execution_context.context.security_context = security_context
        
        # Track authentication metrics
        if security_context.is_authenticated():
            metrics.authentication_success.labels(
                method="graphql",
                mfa_verified=str(security_context.mfa_verified)
            ).inc()
        
        # Log request start
        self._logger.info(
            "GraphQL request started",
            user_id=str(security_context.user_id) if security_context.user_id else None,
            correlation_id=security_context.correlation_id,
            operation_name=self.execution_context.operation_name
        )
    
    async def on_request_end(self) -> None:
        """Called at the end of a request."""
        # Log request completion
        security_context = getattr(self.execution_context.context, 'security_context', None)
        
        self._logger.info(
            "GraphQL request completed",
            user_id=str(security_context.user_id) if security_context and security_context.user_id else None,
            correlation_id=security_context.correlation_id if security_context else None,
            operation_name=self.execution_context.operation_name
        )
    
    async def _extract_security_context(self, request) -> SecurityContext:
        """Extract and validate security context from request."""
        # Get authorization header
        auth_header = request.headers.get("authorization", "")
        
        if not auth_header or not auth_header.startswith("Bearer "):
            # Return anonymous context
            return SecurityContext(
                ip_address=self._get_client_ip(request),
                user_agent=request.headers.get("user-agent", ""),
                correlation_id=request.headers.get("x-correlation-id", "")
            )
        
        token = auth_header.split(" ")[1]
        
        # Check token cache
        cache_key = f"graphql:token:{token[:16]}"
        cached_context = await self._cache.get(cache_key)
        
        if cached_context:
            return SecurityContext(**cached_context)
        
        # Validate token
        try:
            payload = decode_token(token)
            
            if is_token_expired(payload):
                raise SessionExpiredError("Token has expired")
            
            # Create security context
            security_context = SecurityContext(
                user_id=UUID(payload["sub"]),
                session_id=UUID(payload.get("session_id")) if payload.get("session_id") else None,
                roles=payload.get("roles", []),
                permissions=payload.get("permissions", []),
                ip_address=self._get_client_ip(request),
                user_agent=request.headers.get("user-agent", ""),
                mfa_verified=payload.get("mfa_verified", False),
                device_trusted=payload.get("device_trusted", False),
                correlation_id=request.headers.get("x-correlation-id", "")
            )
            
            # Calculate risk score
            security_context.risk_score = await self._calculate_risk_score(
                security_context, request
            )
            
            # Cache for 5 minutes
            await self._cache.set(
                cache_key,
                security_context.__dict__,
                ttl=300
            )
            
            return security_context
            
        except Exception as e:
            self._logger.warning(
                "Token validation failed",
                error=str(e),
                ip_address=self._get_client_ip(request)
            )
            
            # Return anonymous context on error
            return SecurityContext(
                ip_address=self._get_client_ip(request),
                user_agent=request.headers.get("user-agent", ""),
                correlation_id=request.headers.get("x-correlation-id", "")
            )
    
    async def _calculate_risk_score(
        self, context: SecurityContext, request
    ) -> float:
        """Calculate risk score for the request."""
        risk_score = 0.0
        
        # Base risk factors
        if not context.mfa_verified:
            risk_score += 0.3
        
        if not context.device_trusted:
            risk_score += 0.2
        
        # Time-based risk
        current_hour = datetime.now(UTC).hour
        if current_hour < 6 or current_hour > 22:
            risk_score += 0.1
        
        # User agent analysis
        if not context.user_agent or "bot" in context.user_agent.lower():
            risk_score += 0.2
        
        # GraphQL specific risks
        operation_name = self.execution_context.operation_name or ""
        if any(risky in operation_name.lower() for risky in ["admin", "delete", "update"]):
            risk_score += 0.1
        
        return min(risk_score, 1.0)
    
    def _get_client_ip(self, request) -> str:
        """Extract client IP address from request."""
        forwarded_for = request.headers.get("x-forwarded-for")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        
        real_ip = request.headers.get("x-real-ip")
        if real_ip:
            return real_ip
        
        return getattr(request.client, "host", "") if hasattr(request, "client") else ""


def require_authentication(func: Callable) -> Callable:
    """Decorator to require authentication for GraphQL resolvers."""
    async def wrapper(self, info: Info, *args, **kwargs):
        context = getattr(info.context, 'security_context', None)
        
        if not context or not context.is_authenticated():
            raise AuthenticationError(
                "Authentication required",
                user_message="Please log in to access this resource"
            )
        
        return await func(self, info, *args, **kwargs)
    
    return wrapper


def require_permission(permission: str) -> Callable:
    """Decorator to require specific permission for GraphQL resolvers."""
    def decorator(func: Callable) -> Callable:
        async def wrapper(self, info: Info, *args, **kwargs):
            context = getattr(info.context, 'security_context', None)
            
            if not context or not context.is_authenticated():
                raise AuthenticationError(
                    "Authentication required",
                    user_message="Please log in to access this resource"
                )
            
            if not context.has_permission(permission):
                raise AuthorizationError(
                    f"Missing required permission: {permission}",
                    user_message="You don't have permission to perform this action"
                )
            
            return await func(self, info, *args, **kwargs)
        
        return wrapper
    return decorator


def require_any_permission(permissions: list[str]) -> Callable:
    """Decorator to require any of the given permissions."""
    def decorator(func: Callable) -> Callable:
        async def wrapper(self, info: Info, *args, **kwargs):
            context = getattr(info.context, 'security_context', None)
            
            if not context or not context.is_authenticated():
                raise AuthenticationError(
                    "Authentication required",
                    user_message="Please log in to access this resource"
                )
            
            if not context.has_any_permission(permissions):
                raise AuthorizationError(
                    f"Missing required permissions: {', '.join(permissions)}",
                    user_message="You don't have permission to perform this action"
                )
            
            return await func(self, info, *args, **kwargs)
        
        return wrapper
    return decorator


def require_role(role: str) -> Callable:
    """Decorator to require specific role for GraphQL resolvers."""
    def decorator(func: Callable) -> Callable:
        async def wrapper(self, info: Info, *args, **kwargs):
            context = getattr(info.context, 'security_context', None)
            
            if not context or not context.is_authenticated():
                raise AuthenticationError(
                    "Authentication required",
                    user_message="Please log in to access this resource"
                )
            
            if not context.has_role(role):
                raise AuthorizationError(
                    f"Missing required role: {role}",
                    user_message="You don't have the required role to perform this action"
                )
            
            return await func(self, info, *args, **kwargs)
        
        return wrapper
    return decorator


def require_mfa(func: Callable) -> Callable:
    """Decorator to require MFA verification."""
    async def wrapper(self, info: Info, *args, **kwargs):
        context = getattr(info.context, 'security_context', None)
        
        if not context or not context.is_authenticated():
            raise AuthenticationError(
                "Authentication required",
                user_message="Please log in to access this resource"
            )
        
        if not context.mfa_verified:
            raise MFARequiredError(
                "MFA verification required",
                user_message="Please complete multi-factor authentication to continue"
            )
        
        return await func(self, info, *args, **kwargs)
    
    return wrapper


def risk_based_auth(max_risk: float = 0.7) -> Callable:
    """Decorator for risk-based authentication requirements."""
    def decorator(func: Callable) -> Callable:
        async def wrapper(self, info: Info, *args, **kwargs):
            context = getattr(info.context, 'security_context', None)
            
            if not context or not context.is_authenticated():
                raise AuthenticationError(
                    "Authentication required",
                    user_message="Please log in to access this resource"
                )
            
            if context.risk_score > max_risk and not context.mfa_verified:
                raise MFARequiredError(
                    f"High-risk operation requires MFA (risk score: {context.risk_score:.2f})",
                    user_message="This operation requires additional verification. Please complete MFA."
                )
            
            return await func(self, info, *args, **kwargs)
        
        return wrapper
    return decorator


def audit_operation(
    action: str,
    resource_type: str,
    include_result: bool = False
) -> Callable:
    """Decorator to audit GraphQL operations."""
    def decorator(func: Callable) -> Callable:
        async def wrapper(self, info: Info, *args, **kwargs):
            context = getattr(info.context, 'security_context', None)
            start_time = datetime.now(UTC)
            
            try:
                # Execute the operation
                result = await func(self, info, *args, **kwargs)
                
                # Log successful operation
                await _log_audit_event(
                    AuditEventParams(
                        context=context,
                        action=action,
                        resource_type=resource_type,
                        resource_id=None,
                        details={
                            "args": kwargs,
                            "result": result if include_result else None
                        }
                    ),
                    status="success",
                    duration=(datetime.now(UTC) - start_time).total_seconds()
                )
                
                return result
                
            except Exception as e:
                # Log failed operation
                await _log_audit_event(
                    AuditEventParams(
                        context=context,
                        action=action,
                        resource_type=resource_type,
                        resource_id=None,
                        details={
                            "args": kwargs,
                            "error": str(e)
                        }
                    ),
                    status="failed",
                    duration=(datetime.now(UTC) - start_time).total_seconds()
                )
                raise
        
        return wrapper
    return decorator


async def _log_audit_event(params: AuditEventParams, **kwargs: Any) -> None:
    """Log an audit event."""
    # Extract additional kwargs
    status = kwargs.get('status', 'unknown')
    duration = kwargs.get('duration', 0.0)
    
    # This would integrate with the audit service
    logger.info(
        "Audit event",
        user_id=str(params.context.user_id) if params.context and params.context.user_id else None,
        action=params.action,
        resource_type=params.resource_type,
        resource_id=params.resource_id,
        status=status,
        duration=duration,
        correlation_id=params.context.correlation_id if params.context else None,
        details=params.details
    )
    
    # Track metrics
    metrics.audit_events.labels(
        action=params.action,
        resource_type=params.resource_type,
        status=status
    ).inc()