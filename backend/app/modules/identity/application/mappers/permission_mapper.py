"""
Permission mapper for converting between Permission domain objects and DTOs.

This module provides mapping functionality to convert Permission entities
to/from DTOs for API requests and responses.
"""

from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from app.modules.identity.application.dtos.response import (
    PermissionAuditResponse,
    PermissionCheckResponse,
    PermissionGrantResponse,
    PermissionResponse,
)
from app.modules.identity.domain.entities.role.permission import Permission


class PermissionMapper:
    """Mapper for Permission domain objects to DTOs."""
    
    @staticmethod
    def to_response(permission: Permission) -> PermissionResponse:
        """Convert Permission entity to PermissionResponse DTO.
        
        Args:
            permission: Permission entity
            
        Returns:
            PermissionResponse DTO
        """
        # Extract resource and action from permission code
        resource = permission.resource
        action = permission.action
        
        # Map domain permission scope to DTO scope
        from app.modules.identity.domain.entities.user.user_enums import (
            PermissionScope as DTOPermissionScope,
        )
        
        scope = DTOPermissionScope.GLOBAL  # Default scope
        if permission.scope:
            # Map domain scope to DTO scope (simplified mapping)
            scope_mapping = {
                'global': DTOPermissionScope.GLOBAL,
                'organization': DTOPermissionScope.ORGANIZATION,
                'department': DTOPermissionScope.DEPARTMENT,
                'team': DTOPermissionScope.TEAM,
                'personal': DTOPermissionScope.PERSONAL
            }
            
            # Try to map the scope, default to GLOBAL if not found
            scope_str = getattr(permission.scope, 'value', 'global')
            scope = scope_mapping.get(scope_str, DTOPermissionScope.GLOBAL)
        
        return PermissionResponse(
            id=permission.id,
            name=permission.name,
            resource=resource,
            action=action,
            scope=scope,
            description=permission.description
        )
    
    @staticmethod
    def from_code_to_response(permission_code: str) -> PermissionResponse:
        """Create PermissionResponse from permission code string.
        
        This is a utility method for cases where we only have the permission code
        and need to create a response DTO.
        
        Args:
            permission_code: Permission code (e.g., "users.read", "posts.write")
            
        Returns:
            PermissionResponse DTO
        """
        # Parse resource and action from code
        parts = permission_code.split('.')
        resource = parts[0] if parts else permission_code
        action = parts[-1] if len(parts) > 1 else "unknown"
        
        # Generate a reasonable name and description
        name = permission_code.replace('.', ' ').replace('_', ' ').title()
        description = f"Allows {action} operations on {resource}"
        
        from app.modules.identity.domain.entities.user.user_enums import (
            PermissionScope as DTOPermissionScope,
        )
        
        return PermissionResponse(
            id=uuid4(),  # Generate temporary ID
            name=name,
            resource=resource,
            action=action,
            scope=DTOPermissionScope.GLOBAL,  # Default scope
            description=description
        )
    
    @staticmethod
    def to_check_response(
        user_id: str,
        permission: str,
        allowed: bool,
        resource_type: str | None = None,
        resource_id: str | None = None,
        reason: str | None = None,
        denial_code: str | None = None
    ) -> PermissionCheckResponse:
        """Create PermissionCheckResponse DTO.
        
        Args:
            user_id: ID of user being checked
            permission: Permission being checked
            allowed: Whether the permission is allowed
            resource_type: Type of resource (optional)
            resource_id: Specific resource ID (optional)
            reason: Reason for the decision (optional)
            denial_code: Code explaining why permission was denied (optional)
            
        Returns:
            PermissionCheckResponse DTO
        """
        return PermissionCheckResponse(
            success=True,
            allowed=allowed,
            user_id=user_id,
            permission=permission,
            resource_type=resource_type,
            resource_id=resource_id,
            reason=reason,
            denial_code=denial_code
        )
    
    @staticmethod
    def to_grant_response(
        user_id: str,
        permission: str,
        granted_by: str,
        granted_at: datetime,
        expires_at: datetime | None = None,
        conditions: dict[str, Any] | None = None,
        resource_type: str | None = None,
        resource_id: str | None = None
    ) -> PermissionGrantResponse:
        """Create PermissionGrantResponse DTO.
        
        Args:
            user_id: ID of user who received the permission
            permission: Permission that was granted
            granted_by: ID of user who granted the permission
            granted_at: When the permission was granted
            expires_at: When the permission expires (if applicable)
            conditions: Additional conditions for the permission
            resource_type: Type of resource (optional)
            resource_id: Specific resource ID (optional)
            
        Returns:
            PermissionGrantResponse DTO
        """
        from app.modules.identity.domain.entities.user.user_enums import (
            PermissionScope as DTOPermissionScope,
        )
        
        # Default scope
        scope = DTOPermissionScope.GLOBAL
        
        # Try to determine scope from conditions or resource type
        if conditions and 'scope' in conditions:
            scope_str = conditions['scope']
            scope_mapping = {
                'global': DTOPermissionScope.GLOBAL,
                'organization': DTOPermissionScope.ORGANIZATION,
                'department': DTOPermissionScope.DEPARTMENT,
                'team': DTOPermissionScope.TEAM,
                'personal': DTOPermissionScope.PERSONAL
            }
            scope = scope_mapping.get(scope_str, DTOPermissionScope.GLOBAL)
        
        return PermissionGrantResponse(
            success=True,
            user_id=user_id,
            permission=permission,
            resource_type=resource_type,
            resource_id=resource_id,
            granted_by=granted_by,
            granted_at=granted_at,
            expires_at=expires_at,
            conditions=conditions,
            scope=scope
        )
    
    @staticmethod
    def to_audit_response(
        audit_id: str,
        period_start: datetime,
        period_end: datetime,
        permission_changes: list[dict[str, Any]]
    ) -> PermissionAuditResponse:
        """Create PermissionAuditResponse DTO.
        
        Args:
            audit_id: Unique audit identifier
            period_start: Start of audit period
            period_end: End of audit period
            permission_changes: List of permission changes
            
        Returns:
            PermissionAuditResponse DTO
        """
        # Analyze the changes
        total_changes = len(permission_changes)
        grants = len([c for c in permission_changes if c.get('action') == 'grant'])
        revocations = len([c for c in permission_changes if c.get('action') == 'revoke'])
        expirations = len([c for c in permission_changes if c.get('action') == 'expire'])
        delegations = len([c for c in permission_changes if c.get('action') == 'delegate'])
        
        # Group changes by user and role
        changes_by_user = {}
        changes_by_role = {}
        high_risk_changes = []
        
        for change in permission_changes:
            user_id = change.get('user_id')
            role_id = change.get('role_id')
            permission = change.get('permission', '')
            
            if user_id:
                if user_id not in changes_by_user:
                    changes_by_user[user_id] = 0
                changes_by_user[user_id] += 1
            
            if role_id:
                if role_id not in changes_by_role:
                    changes_by_role[role_id] = 0
                changes_by_role[role_id] += 1
            
            # Identify high-risk changes
            if (change.get('action') == 'grant' and 
                any(keyword in permission.lower() for keyword in ['admin', 'delete', 'destroy', 'sudo'])):
                high_risk_changes.append({
                    'change_id': change.get('id', str(uuid4())),
                    'user_id': user_id,
                    'permission': permission,
                    'action': change.get('action'),
                    'timestamp': change.get('timestamp', datetime.utcnow().isoformat()),
                    'risk_level': 'high',
                    'reason': 'Privileged permission granted'
                })
        
        return PermissionAuditResponse(
            success=True,
            audit_id=audit_id,
            period_start=period_start,
            period_end=period_end,
            total_changes=total_changes,
            grants=grants,
            revocations=revocations,
            expirations=expirations,
            delegations=delegations,
            changes_by_user=changes_by_user,
            changes_by_role=changes_by_role,
            high_risk_changes=high_risk_changes
        )
    
    @staticmethod
    def from_dict(data: dict[str, Any]) -> Permission:
        """Create Permission entity from dictionary data.
        
        Args:
            data: Dictionary containing permission data
            
        Returns:
            Permission entity
        """
        # Extract required fields
        permission_id = data.get('id')
        if isinstance(permission_id, str):
            permission_id = UUID(permission_id)
        
        # Map DTO enums to domain enums
        from app.modules.identity.domain.enums import PermissionType, ResourceType
        
        permission_type = PermissionType.CUSTOM  # Default
        if 'permission_type' in data:
            try:
                permission_type = PermissionType(data['permission_type'])
            except ValueError:
                permission_type = PermissionType.CUSTOM
        
        resource_type = ResourceType.GENERIC  # Default
        if 'resource_type' in data:
            try:
                resource_type = ResourceType(data['resource_type'])
            except ValueError:
                resource_type = ResourceType.GENERIC
        
        # Create scope if present
        scope = None
        if data.get('scope'):
            from app.modules.identity.domain.value_objects.permission_scope import (
                PermissionScope,
            )
            scope = PermissionScope.from_dict(data['scope'])
        
        # Create permission
        return Permission(
            id=permission_id,
            name=data['name'],
            code=data['code'],
            description=data.get('description', ''),
            permission_type=permission_type,
            resource_type=resource_type,
            parent_id=UUID(data['parent_id']) if data.get('parent_id') else None,
            path=data.get('path', ''),
            depth=data.get('depth', 0),
            scope=scope,
            constraints=data.get('constraints', {}),
            is_active=data.get('is_active', True),
            is_system=data.get('is_system', False),
            is_dangerous=data.get('is_dangerous', False),
            requires_mfa=data.get('requires_mfa', False),
            tags=set(data.get('tags', [])),
            metadata=data.get('metadata', {}),
            created_at=datetime.fromisoformat(data['created_at']) if 'created_at' in data else datetime.utcnow(),
            created_by=UUID(data['created_by']) if data.get('created_by') else None,
            modified_at=datetime.fromisoformat(data['modified_at']) if data.get('modified_at') else None,
            modified_by=UUID(data['modified_by']) if data.get('modified_by') else None
        )
        
    
    @staticmethod
    def get_permission_hierarchy(permissions: list[Permission]) -> dict[str, Any]:
        """Build permission hierarchy from list of permissions.
        
        Args:
            permissions: List of Permission entities
            
        Returns:
            Dictionary representing the permission hierarchy
        """
        # Build permission lookup
        {str(perm.id): perm for perm in permissions}
        
        # Find root permissions (no parent)
        roots = [perm for perm in permissions if perm.parent_id is None]
        
        def build_tree(permission: Permission) -> dict[str, Any]:
            """Recursively build permission tree."""
            children = [
                perm for perm in permissions
                if perm.parent_id == permission.id
            ]
            
            return {
                'id': str(permission.id),
                'name': permission.name,
                'code': permission.code,
                'description': permission.description,
                'depth': permission.depth,
                'is_active': permission.is_active,
                'is_system': permission.is_system,
                'is_dangerous': permission.is_dangerous,
                'requires_mfa': permission.requires_mfa,
                'children': [build_tree(child) for child in children]
            }
        
        return {
            'total_permissions': len(permissions),
            'root_permissions': len(roots),
            'max_depth': max([perm.depth for perm in permissions]) if permissions else 0,
            'system_permissions': len([perm for perm in permissions if perm.is_system]),
            'dangerous_permissions': len([perm for perm in permissions if perm.is_dangerous]),
            'hierarchy': [build_tree(root) for root in roots]
        }
    
    @staticmethod
    def analyze_permission_usage(
        permissions: list[Permission],
        usage_data: dict[str, int]
    ) -> dict[str, Any]:
        """Analyze permission usage patterns.
        
        Args:
            permissions: List of Permission entities
            usage_data: Dictionary mapping permission codes to usage counts
            
        Returns:
            Dictionary with usage analysis
        """
        # Calculate usage statistics
        total_permissions = len(permissions)
        used_permissions = len([perm for perm in permissions if usage_data.get(perm.code, 0) > 0])
        unused_permissions = total_permissions - used_permissions
        
        # Find most and least used permissions
        permission_usage = [
            {
                'id': str(perm.id),
                'name': perm.name,
                'code': perm.code,
                'usage_count': usage_data.get(perm.code, 0),
                'is_dangerous': perm.is_dangerous
            }
            for perm in permissions
        ]
        
        # Sort by usage
        permission_usage.sort(key=lambda x: x['usage_count'], reverse=True)
        
        most_used = permission_usage[:5]
        least_used = [p for p in permission_usage if p['usage_count'] == 0]
        
        # Identify potentially problematic patterns
        issues = []
        
        # Dangerous permissions with high usage
        dangerous_high_usage = [
            p for p in permission_usage
            if p['is_dangerous'] and p['usage_count'] > 100
        ]
        if dangerous_high_usage:
            issues.append({
                'type': 'high_dangerous_usage',
                'message': f'{len(dangerous_high_usage)} dangerous permissions have high usage',
                'permissions': dangerous_high_usage
            })
        
        # Many unused permissions
        if unused_permissions > total_permissions * 0.5:
            issues.append({
                'type': 'high_unused_ratio',
                'message': f'{unused_permissions} permissions are unused ({unused_permissions/total_permissions*100:.1f}%)',
                'count': unused_permissions
            })
        
        return {
            'total_permissions': total_permissions,
            'used_permissions': used_permissions,
            'unused_permissions': unused_permissions,
            'usage_rate': used_permissions / total_permissions if total_permissions > 0 else 0,
            'most_used': most_used,
            'least_used': least_used[:10],  # Top 10 least used
            'total_usage': sum(usage_data.values()),
            'average_usage': sum(usage_data.values()) / len(usage_data) if usage_data else 0,
            'issues': issues
        }