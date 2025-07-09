"""
Identity Adapter for Audit Module

Internal adapter that allows the Audit module to communicate with the Identity module
following the established contract pattern. This ensures proper module boundaries
and prevents direct dependencies.
"""

from typing import List, Optional, Dict, Any
from uuid import UUID
from datetime import datetime

from app.core.infrastructure.internal_adapter_base import (
    BaseInternalAdapter,
    InternalAdapterError,
    ContractViolationError
)
from app.core.logging import get_logger
from app.modules.identity.application.contracts.identity_contract import (
    IIdentityContract,
    UserInfoDTO,
    UserAuthenticationDTO,
    UserPermissionCheckDTO,
    UserRoleDTO,
    SessionInfoDTO
)

logger = get_logger(__name__)


class IdentityAdapter(BaseInternalAdapter):
    """
    Adapter for communicating with Identity module from Audit module.
    
    This adapter implements the Identity contract and handles all
    communication with the Identity module, including error handling
    and resilience patterns.
    """
    
    def __init__(self, identity_service: IIdentityContract):
        """
        Initialize Identity adapter.
        
        Args:
            identity_service: Identity service implementation
        """
        super().__init__(module_name="audit", target_module="identity")
        self._identity_service = identity_service
    
    async def health_check(self) -> bool:
        """Check if Identity module is healthy."""
        try:
            # Try to get a known system user or perform a lightweight operation
            # This is a simple health check - can be enhanced based on requirements
            result = await self._identity_service.is_user_active(
                UUID("00000000-0000-0000-0000-000000000000")
            )
            return True  # If we get here without exception, service is healthy
        except Exception as e:
            logger.warning(
                "Identity module health check failed",
                error=str(e)
            )
            return False
    
    async def get_user_info(self, user_id: UUID) -> Optional[UserInfoDTO]:
        """
        Get user information for audit logging.
        
        Args:
            user_id: User identifier
            
        Returns:
            UserInfoDTO if user exists, None otherwise
        """
        return await self._execute_with_resilience(
            "get_user_info",
            self._identity_service.get_user_by_id,
            user_id
        )
    
    async def get_user_by_email(self, email: str) -> Optional[UserInfoDTO]:
        """
        Get user information by email.
        
        Args:
            email: User email address
            
        Returns:
            UserInfoDTO if user exists, None otherwise
        """
        return await self._execute_with_resilience(
            "get_user_by_email",
            self._identity_service.get_user_by_email,
            email
        )
    
    async def get_multiple_users(self, user_ids: List[UUID]) -> List[UserInfoDTO]:
        """
        Get information for multiple users.
        
        Args:
            user_ids: List of user identifiers
            
        Returns:
            List of UserInfoDTO for found users
        """
        if not user_ids:
            return []
        
        if len(user_ids) > 100:
            raise ContractViolationError(
                "Cannot request more than 100 users at once"
            )
        
        return await self._execute_with_resilience(
            "get_multiple_users",
            self._identity_service.get_users_by_ids,
            user_ids
        )
    
    async def validate_session(self, session_id: UUID) -> Optional[SessionInfoDTO]:
        """
        Validate session for audit context.
        
        Args:
            session_id: Session identifier
            
        Returns:
            SessionInfoDTO if session is valid, None otherwise
        """
        return await self._execute_with_resilience(
            "validate_session",
            self._identity_service.validate_session,
            session_id
        )
    
    async def check_audit_permission(
        self,
        user_id: UUID,
        audit_action: str,
        resource: Optional[str] = None
    ) -> bool:
        """
        Check if user has permission to perform audit action.
        
        Args:
            user_id: User identifier
            audit_action: Audit action to check
            resource: Optional resource identifier
            
        Returns:
            True if user has permission, False otherwise
        """
        # Map audit actions to identity permissions
        permission_map = {
            "view_audit_logs": "audit.logs.read",
            "export_audit_logs": "audit.logs.export",
            "delete_audit_logs": "audit.logs.delete",
            "view_compliance_reports": "audit.compliance.read",
            "generate_reports": "audit.reports.generate"
        }
        
        permission = permission_map.get(audit_action, f"audit.{audit_action}")
        
        result = await self._execute_with_resilience(
            "check_audit_permission",
            self._identity_service.check_permission,
            user_id,
            permission,
            resource
        )
        
        return result.is_allowed if result else False
    
    async def get_user_roles(self, user_id: UUID) -> List[str]:
        """
        Get user roles for audit context.
        
        Args:
            user_id: User identifier
            
        Returns:
            List of role names
        """
        roles = await self._execute_with_resilience(
            "get_user_roles",
            self._identity_service.get_user_roles,
            user_id
        )
        
        return [role.name for role in roles] if roles else []
    
    async def enrich_audit_entry_with_user_info(
        self,
        audit_entry: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Enrich audit entry with user information.
        
        Args:
            audit_entry: Audit entry to enrich
            
        Returns:
            Enriched audit entry
        """
        user_id = audit_entry.get("user_id")
        if not user_id:
            return audit_entry
        
        try:
            user_info = await self.get_user_info(UUID(user_id))
            if user_info:
                audit_entry["user_email"] = user_info.email
                audit_entry["user_username"] = user_info.username
                audit_entry["user_active"] = user_info.is_active
        except Exception as e:
            logger.warning(
                "Failed to enrich audit entry with user info",
                user_id=user_id,
                error=str(e)
            )
        
        return audit_entry