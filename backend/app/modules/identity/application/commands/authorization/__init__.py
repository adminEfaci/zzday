"""
Authorization command module.

Handles role and permission management for the identity domain.
"""

from .assign_role_command import AssignRoleCommand, AssignRoleCommandHandler
from .check_permission_command import (
    CheckPermissionCommand,
    CheckPermissionCommandHandler,
)
from .clone_permissions_command import (
    ClonePermissionsCommand,
    ClonePermissionsCommandHandler,
)
from .create_permission_command import (
    CreatePermissionCommand,
    CreatePermissionCommandHandler,
)
from .create_role_command import CreateRoleCommand, CreateRoleCommandHandler
from .delete_permission_command import (
    DeletePermissionCommand,
    DeletePermissionCommandHandler,
)
from .delete_role_command import DeleteRoleCommand, DeleteRoleCommandHandler
from .grant_permission_command import (
    GrantPermissionCommand,
    GrantPermissionCommandHandler,
)
from .revoke_permission_command import (
    RevokePermissionCommand,
    RevokePermissionCommandHandler,
)
from .revoke_role_command import RevokeRoleCommand, RevokeRoleCommandHandler
from .update_permission_command import (
    UpdatePermissionCommand,
    UpdatePermissionCommandHandler,
)
from .update_role_command import UpdateRoleCommand, UpdateRoleCommandHandler

__all__ = [
    # Role assignment
    "AssignRoleCommand",
    "AssignRoleCommandHandler",
    # Utilities
    "CheckPermissionCommand",
    "CheckPermissionCommandHandler",
    "ClonePermissionsCommand",
    "ClonePermissionsCommandHandler",
    # Permission CRUD
    "CreatePermissionCommand",
    "CreatePermissionCommandHandler",
    # Role CRUD
    "CreateRoleCommand",
    "CreateRoleCommandHandler",
    "DeletePermissionCommand",
    "DeletePermissionCommandHandler",
    "DeleteRoleCommand",
    "DeleteRoleCommandHandler",
    # Permission management
    "GrantPermissionCommand",
    "GrantPermissionCommandHandler",
    "RevokePermissionCommand",
    "RevokePermissionCommandHandler",
    "RevokeRoleCommand",
    "RevokeRoleCommandHandler",
    "UpdatePermissionCommand",
    "UpdatePermissionCommandHandler",
    "UpdateRoleCommand",
    "UpdateRoleCommandHandler"
]