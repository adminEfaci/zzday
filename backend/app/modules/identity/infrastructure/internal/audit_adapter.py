"""
Audit Adapter for Identity Module

Internal adapter that allows the Identity module to log audit events
to the Audit module following the established contract pattern.
"""

from typing import Optional, Dict, Any
from uuid import UUID
from datetime import datetime

from app.core.infrastructure.internal_adapter_base import BaseInternalAdapter
from app.core.logging import get_logger
from app.modules.audit.application.contracts.audit_contract import (
    IAuditContract,
    AuditEntryDTO,
    AuditActionType,
    AuditSeverity
)

logger = get_logger(__name__)


class AuditAdapter(BaseInternalAdapter):
    """
    Adapter for logging audit events from Identity module.
    
    This adapter provides convenient methods for the Identity module
    to log various types of security and access events.
    """
    
    def __init__(self, audit_service: IAuditContract):
        """
        Initialize Audit adapter.
        
        Args:
            audit_service: Audit service implementation
        """
        super().__init__(module_name="identity", target_module="audit")
        self._audit_service = audit_service
    
    async def health_check(self) -> bool:
        """Check if Audit module is healthy."""
        try:
            # Try to search with minimal criteria as health check
            from app.modules.audit.application.contracts.audit_contract import AuditSearchCriteriaDTO
            
            criteria = AuditSearchCriteriaDTO(limit=1)
            await self._audit_service.search_audit_logs(criteria)
            return True
        except Exception as e:
            logger.warning(
                "Audit module health check failed",
                error=str(e)
            )
            return False
    
    async def log_user_login(
        self,
        user_id: UUID,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        session_id: Optional[UUID] = None,
        success: bool = True,
        failure_reason: Optional[str] = None
    ) -> Optional[UUID]:
        """
        Log user login attempt.
        
        Args:
            user_id: User attempting login
            ip_address: Client IP address
            user_agent: Client user agent
            session_id: Session ID if login successful
            success: Whether login was successful
            failure_reason: Reason if login failed
            
        Returns:
            UUID of audit entry if logged successfully
        """
        try:
            metadata = {
                "success": success,
                "timestamp": datetime.utcnow().isoformat()
            }
            
            if failure_reason:
                metadata["failure_reason"] = failure_reason
            
            entry = AuditEntryDTO(
                user_id=user_id if success else None,
                action=AuditActionType.LOGIN,
                resource_type="user_session",
                resource_id=str(session_id) if session_id else None,
                severity=AuditSeverity.INFO if success else AuditSeverity.WARNING,
                description=f"User login {'successful' if success else 'failed'}",
                metadata=metadata,
                ip_address=ip_address,
                user_agent=user_agent,
                session_id=session_id if success else None
            )
            
            return await self._execute_with_resilience(
                "log_user_login",
                self._audit_service.log_event,
                entry
            )
        except Exception as e:
            logger.error(
                "Failed to log user login audit event",
                user_id=str(user_id),
                error=str(e)
            )
            return None
    
    async def log_user_logout(
        self,
        user_id: UUID,
        session_id: UUID,
        ip_address: Optional[str] = None,
        reason: str = "user_initiated"
    ) -> Optional[UUID]:
        """
        Log user logout event.
        
        Args:
            user_id: User logging out
            session_id: Session being terminated
            ip_address: Client IP address
            reason: Logout reason
            
        Returns:
            UUID of audit entry if logged successfully
        """
        try:
            entry = AuditEntryDTO(
                user_id=user_id,
                action=AuditActionType.LOGOUT,
                resource_type="user_session",
                resource_id=str(session_id),
                severity=AuditSeverity.INFO,
                description=f"User logout: {reason}",
                metadata={"reason": reason},
                ip_address=ip_address,
                session_id=session_id
            )
            
            return await self._execute_with_resilience(
                "log_user_logout",
                self._audit_service.log_event,
                entry
            )
        except Exception as e:
            logger.error(
                "Failed to log user logout audit event",
                user_id=str(user_id),
                error=str(e)
            )
            return None
    
    async def log_permission_check(
        self,
        user_id: UUID,
        permission: str,
        resource: Optional[str] = None,
        granted: bool = True,
        session_id: Optional[UUID] = None
    ) -> Optional[UUID]:
        """
        Log permission check event.
        
        Args:
            user_id: User being checked
            permission: Permission being checked
            resource: Resource being accessed
            granted: Whether permission was granted
            session_id: Current session ID
            
        Returns:
            UUID of audit entry if logged successfully
        """
        try:
            entry = AuditEntryDTO(
                user_id=user_id,
                action=AuditActionType.PERMISSION_GRANTED if granted else AuditActionType.PERMISSION_DENIED,
                resource_type="permission",
                resource_id=resource,
                severity=AuditSeverity.INFO if granted else AuditSeverity.WARNING,
                description=f"Permission '{permission}' {'granted' if granted else 'denied'}",
                metadata={
                    "permission": permission,
                    "granted": granted
                },
                session_id=session_id
            )
            
            return await self._execute_with_resilience(
                "log_permission_check",
                self._audit_service.log_event,
                entry
            )
        except Exception as e:
            logger.error(
                "Failed to log permission check audit event",
                user_id=str(user_id),
                permission=permission,
                error=str(e)
            )
            return None
    
    async def log_user_registration(
        self,
        user_id: UUID,
        email: str,
        ip_address: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Optional[UUID]:
        """
        Log new user registration.
        
        Args:
            user_id: New user ID
            email: User email
            ip_address: Registration IP address
            metadata: Additional registration metadata
            
        Returns:
            UUID of audit entry if logged successfully
        """
        try:
            entry_metadata = {
                "email": email,
                "registration_timestamp": datetime.utcnow().isoformat()
            }
            
            if metadata:
                entry_metadata.update(metadata)
            
            entry = AuditEntryDTO(
                user_id=user_id,
                action=AuditActionType.CREATE,
                resource_type="user_account",
                resource_id=str(user_id),
                severity=AuditSeverity.INFO,
                description=f"New user registration: {email}",
                metadata=entry_metadata,
                ip_address=ip_address
            )
            
            return await self._execute_with_resilience(
                "log_user_registration",
                self._audit_service.log_event,
                entry
            )
        except Exception as e:
            logger.error(
                "Failed to log user registration audit event",
                user_id=str(user_id),
                error=str(e)
            )
            return None
    
    async def log_password_change(
        self,
        user_id: UUID,
        ip_address: Optional[str] = None,
        session_id: Optional[UUID] = None,
        forced: bool = False
    ) -> Optional[UUID]:
        """
        Log password change event.
        
        Args:
            user_id: User changing password
            ip_address: Client IP address
            session_id: Current session ID
            forced: Whether change was forced
            
        Returns:
            UUID of audit entry if logged successfully
        """
        try:
            return await self._execute_with_resilience(
                "log_password_change",
                self._audit_service.log_security_event,
                user_id,
                "password_change",
                f"Password {'forcibly ' if forced else ''}changed",
                AuditSeverity.WARNING if forced else AuditSeverity.INFO,
                {
                    "forced": forced,
                    "ip_address": ip_address,
                    "session_id": str(session_id) if session_id else None
                }
            )
        except Exception as e:
            logger.error(
                "Failed to log password change audit event",
                user_id=str(user_id),
                error=str(e)
            )
            return None
    
    async def log_mfa_event(
        self,
        user_id: UUID,
        event_type: str,
        success: bool,
        method: str,
        ip_address: Optional[str] = None,
        session_id: Optional[UUID] = None
    ) -> Optional[UUID]:
        """
        Log MFA-related event.
        
        Args:
            user_id: User involved
            event_type: Type of MFA event
            success: Whether event was successful
            method: MFA method used
            ip_address: Client IP address
            session_id: Current session ID
            
        Returns:
            UUID of audit entry if logged successfully
        """
        try:
            severity = AuditSeverity.INFO if success else AuditSeverity.WARNING
            description = f"MFA {event_type} {'successful' if success else 'failed'} using {method}"
            
            return await self._execute_with_resilience(
                "log_mfa_event",
                self._audit_service.log_security_event,
                user_id,
                f"mfa_{event_type}",
                description,
                severity,
                {
                    "success": success,
                    "method": method,
                    "ip_address": ip_address,
                    "session_id": str(session_id) if session_id else None
                }
            )
        except Exception as e:
            logger.error(
                "Failed to log MFA audit event",
                user_id=str(user_id),
                event_type=event_type,
                error=str(e)
            )
            return None
    
    async def log_account_lockout(
        self,
        user_id: UUID,
        reason: str,
        duration_minutes: Optional[int] = None,
        ip_address: Optional[str] = None
    ) -> Optional[UUID]:
        """
        Log account lockout event.
        
        Args:
            user_id: User being locked out
            reason: Lockout reason
            duration_minutes: Lockout duration
            ip_address: Client IP address
            
        Returns:
            UUID of audit entry if logged successfully
        """
        try:
            metadata = {
                "reason": reason,
                "lockout_timestamp": datetime.utcnow().isoformat()
            }
            
            if duration_minutes:
                metadata["duration_minutes"] = duration_minutes
            
            if ip_address:
                metadata["ip_address"] = ip_address
            
            return await self._execute_with_resilience(
                "log_account_lockout",
                self._audit_service.log_security_event,
                user_id,
                "account_lockout",
                f"Account locked: {reason}",
                AuditSeverity.CRITICAL,
                metadata
            )
        except Exception as e:
            logger.error(
                "Failed to log account lockout audit event",
                user_id=str(user_id),
                error=str(e)
            )
            return None