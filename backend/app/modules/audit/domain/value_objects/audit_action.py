"""Audit action value object.

This module defines the AuditAction value object that represents
the type of action performed in an audit event.
"""


from typing import Any

from app.core.domain.base import ValueObject
from app.utils.validation import validate_string


class AuditAction(ValueObject):
    """
    Represents an action performed in the system.

    This value object encapsulates the action type, resource affected,
    and operation details for comprehensive audit tracking.

    Attributes:
        action_type: Type of action (e.g., 'create', 'update', 'delete', 'read')
        resource_type: Type of resource affected (e.g., 'user', 'order', 'payment')
        operation: Specific operation performed (e.g., 'login', 'password_change')
        description: Human-readable description of the action

    Usage:
        action = AuditAction(
            action_type="update",
            resource_type="user",
            operation="password_change",
            description="User changed their password"
        )
    """

    # Common action types
    ACTION_CREATE = "create"
    ACTION_READ = "read"
    ACTION_UPDATE = "update"
    ACTION_DELETE = "delete"
    ACTION_EXECUTE = "execute"
    ACTION_LOGIN = "login"
    ACTION_LOGOUT = "logout"
    ACTION_EXPORT = "export"
    ACTION_IMPORT = "import"

    def __init__(
        self,
        action_type: str,
        resource_type: str,
        operation: str,
        description: str | None = None,
    ):
        """
        Initialize audit action.

        Args:
            action_type: Type of action performed
            resource_type: Type of resource affected
            operation: Specific operation performed
            description: Optional human-readable description

        Raises:
            ValidationError: If any required field is invalid
        """
        super().__init__()

        # Validate and set action type
        self.validate_not_empty(action_type, "action_type")
        self.action_type = self._validate_action_type(action_type.lower().strip())

        # Validate and set resource type
        self.validate_not_empty(resource_type, "resource_type")
        self.resource_type = self._validate_resource_type(resource_type.lower().strip())

        # Validate and set operation
        self.validate_not_empty(operation, "operation")
        self.operation = self._validate_operation(operation.lower().strip())

        # Set optional description
        if description:
            self.description = description.strip()
        else:
            self.description = self._generate_description()

        # Freeze the value object
        self._freeze()

    def _validate_action_type(self, action_type: str) -> str:
        """Validate action type format and constraints."""
        return validate_string(
            action_type,
            "action_type",
            required=True,
            max_length=50,
            pattern=r'^[a-zA-Z0-9_]+$'
        )

    def _validate_resource_type(self, resource_type: str) -> str:
        """Validate resource type format and constraints."""
        return validate_string(
            resource_type,
            "resource_type",
            required=True,
            max_length=50,
            pattern=r'^[a-zA-Z0-9_]+$'
        )

    def _validate_operation(self, operation: str) -> str:
        """Validate operation format and constraints."""
        return validate_string(
            operation,
            "operation",
            required=True,
            max_length=100,
            pattern=r'^[a-zA-Z0-9_-]+$'
        )

    def _generate_description(self) -> str:
        """Generate a default description based on action details."""
        return f"{self.action_type} {self.resource_type} via {self.operation}"

    def is_read_action(self) -> bool:
        """Check if this is a read-only action."""
        read_actions = {self.ACTION_READ, "view", "list", "search", "export"}
        return self.action_type in read_actions

    def is_write_action(self) -> bool:
        """Check if this is a write action that modifies data."""
        write_actions = {
            self.ACTION_CREATE,
            self.ACTION_UPDATE,
            self.ACTION_DELETE,
            "import",
            "restore",
        }
        return self.action_type in write_actions

    def is_auth_action(self) -> bool:
        """Check if this is an authentication-related action."""
        auth_operations = {
            "login",
            "logout",
            "password_change",
            "password_reset",
            "mfa_enable",
            "mfa_disable",
        }
        return self.operation in auth_operations

    def get_severity_hint(self) -> str:
        """
        Get a severity hint based on the action type.

        Returns:
            Suggested severity level for this action
        """
        if self.action_type == self.ACTION_DELETE:
            return "high"
        if self.is_auth_action() or self.is_write_action():
            return "medium"
        return "low"

    def requires_approval(self) -> bool:
        """Check if this action typically requires approval."""
        high_risk_operations = {
            "delete", "purge", "export", "backup_restore", 
            "permission_escalate", "admin_override"
        }
        return (
            self.action_type == self.ACTION_DELETE or
            any(op in self.operation for op in high_risk_operations)
        )

    def is_reversible(self) -> bool:
        """Check if this action is typically reversible."""
        irreversible_actions = {self.ACTION_DELETE, "purge", "export"}
        irreversible_operations = {"delete", "purge", "export", "send_email"}
        
        return not (
            self.action_type in irreversible_actions or
            any(op in self.operation for op in irreversible_operations)
        )

    def get_risk_score(self) -> int:
        """Get a risk score (0-100) for this action."""
        base_score = {
            self.ACTION_DELETE: 80,
            self.ACTION_UPDATE: 40,
            self.ACTION_CREATE: 30,
            self.ACTION_EXPORT: 60,
            self.ACTION_EXECUTE: 50,
            self.ACTION_READ: 10,
        }.get(self.action_type, 20)
        
        # Adjust based on operation
        if "admin" in self.operation:
            base_score += 20
        if "system" in self.operation:
            base_score += 15
        if "bulk" in self.operation:
            base_score += 10
        
        return min(base_score, 100)

    def _get_atomic_values(self) -> tuple[Any, ...]:
        """Get atomic values for equality comparison."""
        return (
            self.action_type,
            self.resource_type,
            self.operation,
            self.description,
        )

    def __str__(self) -> str:
        """String representation of the audit action."""
        return f"{self.action_type}:{self.resource_type}:{self.operation}"

    @classmethod
    def create_login_action(cls, resource_type: str = "session") -> "AuditAction":
        """Factory method for login action."""
        return cls(
            action_type=cls.ACTION_LOGIN,
            resource_type=resource_type,
            operation="login",
            description="User logged in",
        )

    @classmethod
    def create_logout_action(cls, resource_type: str = "session") -> "AuditAction":
        """Factory method for logout action."""
        return cls(
            action_type=cls.ACTION_LOGOUT,
            resource_type=resource_type,
            operation="logout",
            description="User logged out",
        )

    @classmethod
    def create_crud_action(
        cls, action_type: str, resource_type: str, resource_name: str | None = None
    ) -> "AuditAction":
        """
        Factory method for CRUD actions.

        Args:
            action_type: CRUD action type (create, read, update, delete)
            resource_type: Type of resource
            resource_name: Optional human-readable resource name

        Returns:
            AuditAction for the CRUD operation
        """
        operation = f"{action_type}_{resource_type}"
        if resource_name:
            description = f"{action_type.capitalize()} {resource_name}"
        else:
            description = f"{action_type.capitalize()} {resource_type}"

        return cls(
            action_type=action_type,
            resource_type=resource_type,
            operation=operation,
            description=description,
        )

    @classmethod
    def create_password_action(
        cls, operation_type: str, resource_type: str = "user"
    ) -> "AuditAction":
        """Factory method for password-related actions."""
        operation_map = {
            "change": "password_change",
            "reset": "password_reset", 
            "expire": "password_expire",
            "validate": "password_validate",
        }
        
        operation = operation_map.get(operation_type, f"password_{operation_type}")
        description = f"Password {operation_type} operation"
        
        return cls(
            action_type=cls.ACTION_UPDATE,
            resource_type=resource_type,
            operation=operation,
            description=description,
        )

    @classmethod
    def create_mfa_action(
        cls, operation_type: str, resource_type: str = "user"
    ) -> "AuditAction":
        """Factory method for MFA-related actions."""
        operation_map = {
            "enable": "mfa_enable",
            "disable": "mfa_disable",
            "verify": "mfa_verify",
            "backup_generate": "mfa_backup_generate",
            "backup_use": "mfa_backup_use",
        }
        
        operation = operation_map.get(operation_type, f"mfa_{operation_type}")
        description = f"MFA {operation_type} operation"
        
        return cls(
            action_type=cls.ACTION_UPDATE,
            resource_type=resource_type,
            operation=operation,
            description=description,
        )

    @classmethod
    def create_permission_action(
        cls, operation_type: str, resource_type: str = "permission"
    ) -> "AuditAction":
        """Factory method for permission-related actions."""
        operation_map = {
            "grant": "permission_grant",
            "revoke": "permission_revoke",
            "check": "permission_check",
            "escalate": "permission_escalate",
        }
        
        operation = operation_map.get(operation_type, f"permission_{operation_type}")
        description = f"Permission {operation_type} operation"
        
        action_type = cls.ACTION_READ if operation_type == "check" else cls.ACTION_UPDATE
        
        return cls(
            action_type=action_type,
            resource_type=resource_type,
            operation=operation,
            description=description,
        )

    @classmethod
    def create_data_export_action(
        cls, export_type: str, resource_type: str = "data"
    ) -> "AuditAction":
        """Factory method for data export actions."""
        return cls(
            action_type=cls.ACTION_EXPORT,
            resource_type=resource_type,
            operation=f"export_{export_type}",
            description=f"Export {export_type} data",
        )

    @classmethod
    def create_compliance_action(
        cls, operation_type: str, regulation: str
    ) -> "AuditAction":
        """Factory method for compliance-related actions."""
        return cls(
            action_type=cls.ACTION_EXECUTE,
            resource_type="compliance",
            operation=f"compliance_{operation_type}_{regulation}",
            description=f"Compliance {operation_type} for {regulation}",
        )


__all__ = ["AuditAction"]
