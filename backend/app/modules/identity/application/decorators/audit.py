"""
Audit decorators for command and query handlers.

Provides automatic audit logging capabilities.
"""

import contextlib
import traceback
from collections.abc import Callable
from datetime import UTC, datetime
from functools import wraps
from typing import Any
from uuid import UUID, uuid4

from app.core.cqrs import Command, Query
from app.modules.identity.domain.entities import AuditLog
from app.modules.identity.domain.enums import AuditAction
from app.modules.identity.domain.events import AuditLogCreated

# Sensitive field names that should be masked in audit logs
SENSITIVE_FIELDS = {
    'password', 'new_password', 'old_password', 'current_password',
    'token', 'access_token', 'refresh_token', 'api_key', 'secret',
    'credit_card', 'ssn', 'tax_id', 'bank_account'
}


def mask_sensitive_data(data: Any, depth: int = 0, max_depth: int = 5) -> Any:
    """
    Recursively mask sensitive data in dictionaries and objects.
    
    Args:
        data: Data to mask
        depth: Current recursion depth
        max_depth: Maximum recursion depth
    """
    if depth > max_depth:
        return "..."
    
    if isinstance(data, dict):
        masked = {}
        for key, value in data.items():
            if any(sensitive in key.lower() for sensitive in SENSITIVE_FIELDS):
                masked[key] = "***MASKED***"
            else:
                masked[key] = mask_sensitive_data(value, depth + 1, max_depth)
        return masked
    
    if isinstance(data, list):
        return [mask_sensitive_data(item, depth + 1, max_depth) for item in data]
    
    if hasattr(data, '__dict__'):
        # Handle objects with attributes
        masked = {}
        for attr in dir(data):
            if not attr.startswith('_'):
                try:
                    value = getattr(data, attr)
                    if not callable(value):
                        if any(
                            sensitive in attr.lower() 
                            for sensitive in SENSITIVE_FIELDS
                        ):
                            masked[attr] = "***MASKED***"
                        else:
                            masked[attr] = mask_sensitive_data(
                                value, depth + 1, max_depth
                            )
                except (AttributeError, TypeError):
                    pass
        return masked
    
    # Primitive types
    return data


def serialize_for_audit(obj: Any) -> Any:
    """
    Serialize object for audit logging.
    
    Handles UUIDs, datetimes, and custom objects.
    """
    if isinstance(obj, UUID):
        return str(obj)
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, list | tuple):
        return [serialize_for_audit(item) for item in obj]
    if isinstance(obj, dict):
        return {k: serialize_for_audit(v) for k, v in obj.items()}
    if hasattr(obj, '__dict__'):
        return serialize_for_audit(obj.__dict__)
    return obj


def audit_action(
    action: AuditAction | None = None,
    resource_type: str | None = None,
    resource_id_attr: str | None = None,
    include_request: bool = True,
    include_response: bool = True,
    include_errors: bool = True
) -> Callable:
    """
    Decorator to automatically audit command/query execution.
    
    Args:
        action: Audit action type (auto-detected if not provided)
        resource_type: Type of resource being acted upon
        resource_id_attr: Attribute name containing resource ID
        include_request: Include request data in audit
        include_response: Include response data in audit
        include_errors: Include error details in audit
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(self, request: Command | Query, *args, **kwargs):
            # Prepare audit data
            audit_id = uuid4()
            start_time = datetime.now(UTC)
            
            # Get actor ID
            actor_id = None
            for attr in ['user_id', 'current_user_id', 'actor_id', 'requestor_id']:
                if hasattr(request, attr):
                    actor_id = getattr(request, attr)
                    break
            
            # Get resource ID
            resource_id = None
            if resource_id_attr and hasattr(request, resource_id_attr):
                resource_id = str(getattr(request, resource_id_attr))
            
            # Determine action
            audit_action = action
            if not audit_action:
                # Auto-detect based on handler name
                handler_name = func.__name__.lower()
                if 'create' in handler_name or 'add' in handler_name:
                    audit_action = AuditAction.CREATE
                elif 'update' in handler_name or 'edit' in handler_name:
                    audit_action = AuditAction.UPDATE
                elif 'delete' in handler_name or 'remove' in handler_name:
                    audit_action = AuditAction.DELETE
                elif 'login' in handler_name:
                    audit_action = AuditAction.LOGIN
                elif 'logout' in handler_name:
                    audit_action = AuditAction.LOGOUT
                else:
                    audit_action = AuditAction.READ
            
            # Prepare request data
            request_data = None
            if include_request:
                try:
                    serialized_request = serialize_for_audit(request)
                    request_data = mask_sensitive_data(serialized_request)
                except Exception:
                    request_data = {"error": "Failed to serialize request"}
            
            # Get IP address and user agent if available
            ip_address = getattr(request, 'ip_address', None)
            user_agent = getattr(request, 'user_agent', None)
            
            # Execute function
            response_data = None
            error_data = None
            success = False
            
            try:
                result = await func(self, request, *args, **kwargs)
                success = True
                
                # Capture response data
                if include_response:
                    try:
                        serialized_response = serialize_for_audit(result)
                        response_data = mask_sensitive_data(serialized_response)
                    except Exception:
                        response_data = {"error": "Failed to serialize response"}
                
                return result
                
            except Exception as e:
                # Capture error data
                if include_errors:
                    error_data = {
                        "type": type(e).__name__,
                        "message": str(e),
                        "traceback": (
                            traceback.format_exc() 
                            if hasattr(self, 'debug_mode') else None
                        )
                    }
                raise
                
            finally:
                # Calculate duration
                end_time = datetime.now(UTC)
                duration_ms = int((end_time - start_time).total_seconds() * 1000)
                
                # Create audit log
                audit_log = AuditLog(
                    id=audit_id,
                    actor_id=actor_id,
                    action=audit_action,
                    resource_type=resource_type or request.__class__.__name__,
                    resource_id=resource_id,
                    request_data=request_data,
                    response_data=response_data,
                    error_data=error_data,
                    success=success,
                    ip_address=ip_address,
                    user_agent=user_agent,
                    duration_ms=duration_ms,
                    created_at=start_time
                )
                
                # Log audit entry
                if hasattr(self, 'audit_repository'):
                    try:
                        await self.audit_repository.log(audit_log)
                    except Exception:
                        # Log audit failure but don't break the flow
                        import logging
                        logging.exception("Failed to log audit")
                
                # Publish audit event
                if hasattr(self, 'event_bus'):
                    with contextlib.suppress(Exception):
                        await self.event_bus.publish(
                            AuditLogCreated(
                                log_id=audit_id,
                                aggregate_id=actor_id,
                                actor_id=actor_id,
                                action=audit_action.value,
                                resource_type=audit_log.resource_type,
                                resource_id=resource_id,
                                success=success
                            )
                        )
        
        return wrapper
    return decorator


def audit_access(
    resource_type: str,
    resource_id_attr: str | None = None,
    purpose: str | None = None
) -> Callable:
    """
    Decorator to audit data access for compliance.
    
    Args:
        resource_type: Type of resource being accessed
        resource_id_attr: Attribute name containing resource ID
        purpose: Purpose of access
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(self, request: Command | Query, *args, **kwargs):
            # This is a simplified version that delegates to audit_action
            return await audit_action(
                action=AuditAction.READ,
                resource_type=resource_type,
                resource_id_attr=resource_id_attr,
                include_response=False  # Don't log actual data for privacy
            )(func)(self, request, *args, **kwargs)
        
        return wrapper
    return decorator


def audit_security_event(
    event_type: str,
    severity: str = 'info'
) -> Callable:
    """
    Decorator to audit security-related events.
    
    Args:
        event_type: Type of security event
        severity: Event severity (info, warning, error, critical)
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(self, request: Command | Query, *args, **kwargs):
            # Execute function and capture security context
            try:
                result = await func(self, request, *args, **kwargs)
                
                # Log security event
                if hasattr(self, 'security_repository'):
                    await self.security_repository.log_security_event({
                        'event_type': event_type,
                        'severity': severity,
                        'user_id': getattr(request, 'user_id', None),
                        'ip_address': getattr(request, 'ip_address', None),
                        'user_agent': getattr(request, 'user_agent', None),
                        'timestamp': datetime.now(UTC),
                        'success': True,
                        'details': {
                            'handler': func.__name__,
                            'request_type': request.__class__.__name__
                        }
                    })
                
                return result
                
            except Exception as e:
                # Log security failure
                if hasattr(self, 'security_repository'):
                    await self.security_repository.log_security_event({
                        'event_type': event_type,
                        'severity': 'error',
                        'user_id': getattr(request, 'user_id', None),
                        'ip_address': getattr(request, 'ip_address', None),
                        'user_agent': getattr(request, 'user_agent', None),
                        'timestamp': datetime.now(UTC),
                        'success': False,
                        'error': str(e),
                        'details': {
                            'handler': func.__name__,
                            'request_type': request.__class__.__name__
                        }
                    })
                raise
        
        return wrapper
    return decorator


def audit_compliance(
    regulation: str,
    article: str | None = None,
    data_categories: list[str] | None = None
) -> Callable:
    """
    Decorator to audit actions for compliance purposes.
    
    Args:
        regulation: Regulation name (e.g., 'GDPR', 'CCPA')
        article: Specific article or section
        data_categories: Categories of data being processed
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(self, request: Command | Query, *args, **kwargs):
            # Add compliance metadata to audit
            compliance_context = {
                'regulation': regulation,
                'article': article,
                'data_categories': data_categories,
                'lawful_basis': getattr(request, 'lawful_basis', None),
                'consent_id': getattr(request, 'consent_id', None)
            }
            
            # Execute with enhanced audit
            enhanced_func = audit_action(
                include_request=True,
                include_response=False  # Privacy by design
            )(func)
            
            # Add compliance context to kwargs
            kwargs['compliance_context'] = compliance_context
            
            return await enhanced_func(self, request, *args, **kwargs)
        
        return wrapper
    return decorator