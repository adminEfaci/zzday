"""
Role mapper for converting between Role domain objects and DTOs.

This module provides mapping functionality to convert Role entities
to/from DTOs for API requests and responses.
"""

from datetime import datetime
from typing import Any

from app.modules.identity.application.dtos.response import (
    PermissionDelegationResponse,
    PermissionMatrixResponse,
    RoleAssignmentResponse,
    RoleDetailResponse,
    RoleResponse,
)
from app.modules.identity.domain.entities.role.role import Role


class RoleMapper:
    """Mapper for Role domain objects to DTOs."""
    
    @staticmethod
    def to_response(role: Role) -> RoleResponse:
        """Convert Role entity to RoleResponse DTO.
        
        Args:
            role: Role entity
            
        Returns:
            RoleResponse DTO
        """
        return RoleResponse(
            id=role.id,
            name=role.name,
            description=role.description,
            priority=role.level,  # Map level to priority
            permissions_count=len(role.permissions),
            is_system=role.is_system,
            created_at=role.created_at
        )
    
    @staticmethod
    def to_detail_response(
        role: Role,
        all_roles: dict[str, Role] | None = None,
        include_hierarchy: bool = True
    ) -> RoleDetailResponse:
        """Convert Role entity to detailed RoleDetailResponse DTO.
        
        Args:
            role: Role entity
            all_roles: Dictionary of all roles for hierarchy resolution
            include_hierarchy: Whether to include parent/child relationships
            
        Returns:
            RoleDetailResponse DTO
        """
        from .permission_mapper import PermissionMapper
        
        # Convert permissions to permission responses
        # Note: In the domain model, permissions are stored as strings
        # For a complete implementation, you'd need to resolve these to Permission entities
        permission_responses = []
        for perm_code in role.permissions:
            # Create a minimal permission response from the permission code
            # In a real implementation, you'd lookup the full Permission entity
            permission_responses.append(PermissionMapper.from_code_to_response(perm_code))
        
        # Get parent role if hierarchy is requested
        parent_role = None
        if include_hierarchy and role.parent_role_id and all_roles:
            parent_entity = all_roles.get(str(role.parent_role_id))
            if parent_entity:
                parent_role = RoleMapper.to_response(parent_entity)
        
        # Get child roles if hierarchy is requested
        child_roles = []
        if include_hierarchy and all_roles:
            for _, role_entity in all_roles.items():
                if role_entity.parent_role_id == role.id:
                    child_roles.append(RoleMapper.to_response(role_entity))
        
        return RoleDetailResponse(
            id=role.id,
            name=role.name,
            description=role.description,
            priority=role.level,
            permissions_count=len(role.permissions),
            is_system=role.is_system,
            created_at=role.created_at,
            permissions=permission_responses,
            parent_role=parent_role,
            child_roles=child_roles
        )
    
    @staticmethod
    def to_assignment_response(
        user_id: str,
        role: Role,
        assigned_by: str,
        assigned_at: datetime,
        expires_at: datetime | None = None
    ) -> RoleAssignmentResponse:
        """Create RoleAssignmentResponse DTO.
        
        Args:
            user_id: ID of user who received the role
            role: Role entity that was assigned
            assigned_by: ID of user who assigned the role
            assigned_at: When the role was assigned
            expires_at: When the role assignment expires (if applicable)
            
        Returns:
            RoleAssignmentResponse DTO
        """
        # Calculate effective permissions from role
        all_roles = {str(role.id): role}  # Simplified for this example
        effective_permissions = role.get_effective_permissions(all_roles)
        
        return RoleAssignmentResponse(
            success=True,
            user_id=user_id,
            role_id=role.id,
            role_name=role.name,
            assigned_by=assigned_by,
            assigned_at=assigned_at,
            expires_at=expires_at,
            inherited_permissions=list(role.permissions),
            effective_permissions=list(effective_permissions)
        )
    
    @staticmethod
    def to_permission_matrix_response(
        roles: list[Role],
        test_permissions: list[str],
        user_permissions: dict[str, list[str]] | None = None
    ) -> PermissionMatrixResponse:
        """Create PermissionMatrixResponse DTO.
        
        Args:
            roles: List of Role entities
            test_permissions: List of permissions to test
            user_permissions: Optional mapping of user IDs to their permissions
            
        Returns:
            PermissionMatrixResponse DTO
        """
        from .permission_mapper import PermissionMapper
        
        # Convert roles to responses
        role_responses = [RoleMapper.to_response(role) for role in roles]
        
        # Create permission responses for test permissions
        permission_responses = [
            PermissionMapper.from_code_to_response(perm_code)
            for perm_code in test_permissions
        ]
        
        # Build permission matrix
        matrix = {}
        all_roles_dict = {str(role.id): role for role in roles}
        
        for role in roles:
            role_id = str(role.id)
            matrix[role_id] = {}
            
            for permission in test_permissions:
                matrix[role_id][permission] = role.has_effective_permission(
                    permission, 
                    all_roles_dict
                )
        
        return PermissionMatrixResponse(
            success=True,
            roles=role_responses,
            permissions=permission_responses,
            matrix=matrix,
            effective_permissions_by_user=user_permissions
        )
    
    @staticmethod
    def to_delegation_response(
        delegation_id: str,
        from_user_id: str,
        to_user_id: str,
        permission: str,
        resource_type: str | None = None,
        resource_id: str | None = None,
        can_sub_delegate: bool = False,
        delegated_at: datetime | None = None,
        expires_at: datetime | None = None,
        conditions: dict[str, Any] | None = None,
        usage_count: int = 0
    ) -> PermissionDelegationResponse:
        """Create PermissionDelegationResponse DTO.
        
        Args:
            delegation_id: Unique delegation identifier
            from_user_id: User who delegated the permission
            to_user_id: User who received the permission
            permission: Permission that was delegated
            resource_type: Type of resource (optional)
            resource_id: Specific resource ID (optional)
            can_sub_delegate: Whether the recipient can further delegate
            delegated_at: When the delegation occurred
            expires_at: When the delegation expires
            conditions: Additional conditions for the delegation
            usage_count: How many times the permission has been used
            
        Returns:
            PermissionDelegationResponse DTO
        """
        return PermissionDelegationResponse(
            success=True,
            delegation_id=delegation_id,
            from_user_id=from_user_id,
            to_user_id=to_user_id,
            permission=permission,
            resource_type=resource_type,
            resource_id=resource_id,
            can_sub_delegate=can_sub_delegate,
            delegated_at=delegated_at or datetime.utcnow(),
            expires_at=expires_at,
            conditions=conditions,
            usage_count=usage_count
        )
    
    @staticmethod
    def from_dict(data: dict[str, Any]) -> Role:
        """Create Role entity from dictionary data.
        
        Args:
            data: Dictionary containing role data
            
        Returns:
            Role entity
        """
        # Extract required fields
        role_id = data.get('id')
        if isinstance(role_id, str):
            from uuid import UUID
            role_id = UUID(role_id)
        
        # Create role with required fields
        role = Role(
            id=role_id,
            name=data['name'],
            description=data.get('description', ''),
            level=data.get('level', 0),
            parent_role_id=data.get('parent_role_id'),
            permissions=data.get('permissions', []),
            is_system=data.get('is_system', False),
            is_active=data.get('is_active', True),
            created_at=datetime.fromisoformat(data['created_at']) if 'created_at' in data else datetime.utcnow(),
            updated_at=datetime.fromisoformat(data['updated_at']) if 'updated_at' in data else datetime.utcnow(),
            metadata=data.get('metadata', {})
        )
        
        # Set enhanced fields if present
        if 'parent_roles' in data:
            role.parent_roles = [UUID(pid) for pid in data['parent_roles']]
        
        if 'inheritance_mode' in data:
            from app.modules.identity.domain.entities.role.role_enums import (
                InheritanceMode,
            )
            role.inheritance_mode = InheritanceMode(data['inheritance_mode'])
        
        if 'permission_rules' in data:
            role.permission_rules = data['permission_rules']
        
        if 'denied_permissions' in data:
            role.denied_permissions = data['denied_permissions']
        
        if 'conditional_permissions' in data:
            role.conditional_permissions = data['conditional_permissions']
        
        if 'includes_roles' in data:
            role.includes_roles = [UUID(rid) for rid in data['includes_roles']]
        
        if 'excludes_roles' in data:
            role.excludes_roles = [UUID(rid) for rid in data['excludes_roles']]
        
        if 'is_template' in data:
            role.is_template = data['is_template']
        
        if 'template_variables' in data:
            role.template_variables = data['template_variables']
        
        if data.get('expires_at'):
            role.expires_at = datetime.fromisoformat(data['expires_at'])
        
        return role
    
    @staticmethod
    def get_role_summary(role: Role, context: dict[str, Any] | None = None) -> dict[str, Any]:
        """Get a summary representation of a role.
        
        Args:
            role: Role entity
            context: Optional context for conditional evaluation
            
        Returns:
            Dictionary with role summary information
        """
        # Calculate effective permissions with context
        all_roles = {str(role.id): role}  # Simplified
        effective_permissions = role.get_effective_permissions(all_roles, context)
        
        return {
            'id': str(role.id),
            'name': role.name,
            'description': role.description,
            'level': role.level,
            'is_system': role.is_system,
            'is_active': role.is_active,
            'is_template': role.is_template,
            'is_expired': role.is_expired(),
            'direct_permissions': len(role.permissions),
            'effective_permissions': len(effective_permissions),
            'has_wildcards': any('*' in perm for perm in role.permissions),
            'inheritance_mode': role.inheritance_mode.value,
            'has_conditions': bool(role.conditional_permissions),
            'has_denials': bool(role.denied_permissions),
            'parent_count': len(role.parent_roles),
            'composed_roles': len(role.includes_roles) + len(role.excludes_roles),
            'created_at': role.created_at.isoformat(),
            'updated_at': role.updated_at.isoformat()
        }
    
    @staticmethod
    def validate_role_hierarchy(roles: list[Role]) -> dict[str, Any]:
        """Validate role hierarchy for circular references and conflicts.
        
        Args:
            roles: List of Role entities to validate
            
        Returns:
            Dictionary with validation results
        """
        issues = []
        warnings = []
        
        # Build role lookup
        role_lookup = {str(role.id): role for role in roles}
        
        # Check each role
        for role in roles:
            try:
                # Validate hierarchy
                role.validate_hierarchy(role_lookup)
            except Exception as e:
                issues.append({
                    'role_id': str(role.id),
                    'role_name': role.name,
                    'issue': str(e)
                })
            
            # Check for level conflicts
            if role.parent_role_id and str(role.parent_role_id) in role_lookup:
                parent = role_lookup[str(role.parent_role_id)]
                if parent.level <= role.level:
                    warnings.append({
                        'role_id': str(role.id),
                        'role_name': role.name,
                        'warning': f'Role level ({role.level}) is not lower than parent level ({parent.level})'
                    })
            
            # Check for expired roles
            if role.is_expired():
                warnings.append({
                    'role_id': str(role.id),
                    'role_name': role.name,
                    'warning': 'Role has expired'
                })
        
        return {
            'is_valid': len(issues) == 0,
            'issues': issues,
            'warnings': warnings,
            'total_roles': len(roles),
            'system_roles': len([r for r in roles if r.is_system]),
            'template_roles': len([r for r in roles if r.is_template]),
            'expired_roles': len([r for r in roles if r.is_expired()])
        }