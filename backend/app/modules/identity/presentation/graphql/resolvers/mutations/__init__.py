"""
Identity Module GraphQL Mutation Resolvers.

This package provides comprehensive GraphQL mutation resolvers for the identity module,
including authentication, user management, role/permission management, security operations,
and administrative functions with transaction support and audit logging.

Key Features:
- Complete authentication flow (login, logout, MFA, password management)
- User lifecycle management (CRUD, profiles, preferences)
- Role-based access control (roles, permissions, assignments)
- Security operations (events, blocking, session management)
- Administrative functions (bulk operations, data import/export)
- Transaction management with rollback support
- Optimistic concurrency control
- Comprehensive audit logging
- Rate limiting and abuse prevention
- GDPR compliance features

Usage:
    from app.modules.identity.presentation.graphql.resolvers.mutations import (
        AuthMutations,
        UserMutations,
        RoleMutations,
        SecurityMutations,
        AdminMutations
    )
"""

from .admin_mutations import AdminMutations
from .auth_mutations import AuthMutations
from .role_mutations import RoleMutations
from .security_mutations import SecurityMutations
from .user_mutations import UserMutations

__all__ = [
    "AdminMutations",
    "AuthMutations",
    "RoleMutations",
    "SecurityMutations",
    "UserMutations"
]

# Version info for tracking
__version__ = "1.0.0"
__author__ = "Identity Module Team"
__description__ = "GraphQL mutation resolvers for identity management"

# Mutation categories for documentation
MUTATION_CATEGORIES = {
    "authentication": [
        "login",
        "logout",
        "logout_all",
        "refresh_token",
        "register_user",
        "verify_email",
        "reset_password",
        "change_password",
        "setup_mfa",
        "verify_mfa",
        "disable_mfa"
    ],
    "user_management": [
        "create_user",
        "update_user",
        "delete_user",
        "suspend_user",
        "reactivate_user",
        "update_user_profile",
        "update_user_preferences",
        "upload_user_avatar",
        "anonymize_user"
    ],
    "role_permission": [
        "create_role",
        "update_role",
        "delete_role",
        "assign_role_to_user",
        "remove_role_from_user",
        "create_permission",
        "update_permission",
        "delete_permission",
        "assign_permission_to_role",
        "remove_permission_from_role"
    ],
    "security": [
        "create_security_event",
        "resolve_security_event",
        "block_user",
        "unblock_user",
        "add_to_blacklist",
        "remove_from_blacklist",
        "invalidate_session",
        "invalidate_all_sessions"
    ],
    "administration": [
        "bulk_update_users",
        "bulk_delete_users",
        "export_user_data",
        "import_users",
        "system_maintenance",
        "update_system_configuration"
    ]
}

# Security levels for operations
SECURITY_LEVELS = {
    "public": [
        "register_user",
        "verify_email",
        "reset_password"
    ],
    "authenticated": [
        "login",
        "logout",
        "logout_all",
        "refresh_token",
        "change_password",
        "setup_mfa",
        "verify_mfa",
        "disable_mfa",
        "update_user_profile",
        "update_user_preferences",
        "upload_user_avatar"
    ],
    "admin": [
        "create_user",
        "update_user",
        "delete_user",
        "suspend_user",
        "reactivate_user",
        "create_role",
        "update_role",
        "delete_role",
        "assign_role_to_user",
        "remove_role_from_user",
        "create_permission",
        "update_permission",
        "delete_permission",
        "assign_permission_to_role",
        "remove_permission_from_role",
        "create_security_event",
        "resolve_security_event",
        "block_user",
        "unblock_user",
        "add_to_blacklist",
        "remove_from_blacklist",
        "invalidate_session",
        "invalidate_all_sessions"
    ],
    "super_admin": [
        "anonymize_user",
        "bulk_update_users",
        "bulk_delete_users",
        "export_user_data",
        "import_users",
        "system_maintenance",
        "update_system_configuration"
    ]
}

# Transaction support levels
TRANSACTION_SUPPORT = {
    "full": [
        "create_user",
        "update_user",
        "delete_user",
        "register_user",
        "bulk_update_users",
        "bulk_delete_users",
        "import_users"
    ],
    "partial": [
        "login",
        "logout",
        "assign_role_to_user",
        "remove_role_from_user",
        "block_user",
        "unblock_user"
    ],
    "none": [
        "refresh_token",
        "verify_email",
        "upload_user_avatar"
    ]
}

# Rate limiting categories
RATE_LIMITS = {
    "strict": {
        "operations": ["login", "register_user", "reset_password"],
        "limit": "5/minute"
    },
    "moderate": {
        "operations": ["change_password", "setup_mfa", "verify_mfa"],
        "limit": "10/minute"
    },
    "lenient": {
        "operations": ["update_user_profile", "update_user_preferences"],
        "limit": "30/minute"
    },
    "admin": {
        "operations": ["bulk_update_users", "bulk_delete_users", "system_maintenance"],
        "limit": "1/minute"
    }
}

def get_mutation_info(mutation_name: str) -> dict:
    """
    Get comprehensive information about a specific mutation.
    
    Args:
        mutation_name: Name of the mutation
        
    Returns:
        Dictionary with mutation metadata
    """
    info = {
        "name": mutation_name,
        "category": None,
        "security_level": None,
        "transaction_support": None,
        "rate_limit": None
    }

    # Find category
    for category, mutations in MUTATION_CATEGORIES.items():
        if mutation_name in mutations:
            info["category"] = category
            break

    # Find security level
    for level, mutations in SECURITY_LEVELS.items():
        if mutation_name in mutations:
            info["security_level"] = level
            break

    # Find transaction support
    for support_level, mutations in TRANSACTION_SUPPORT.items():
        if mutation_name in mutations:
            info["transaction_support"] = support_level
            break

    # Find rate limit
    for limit_category, config in RATE_LIMITS.items():
        if mutation_name in config["operations"]:
            info["rate_limit"] = {
                "category": limit_category,
                "limit": config["limit"]
            }
            break

    return info

def get_mutations_by_category(category: str) -> list:
    """
    Get all mutations in a specific category.
    
    Args:
        category: Category name
        
    Returns:
        List of mutation names
    """
    return MUTATION_CATEGORIES.get(category, [])

def get_mutations_by_security_level(security_level: str) -> list:
    """
    Get all mutations requiring a specific security level.
    
    Args:
        security_level: Security level
        
    Returns:
        List of mutation names
    """
    return SECURITY_LEVELS.get(security_level, [])

def validate_mutation_access(mutation_name: str, user_permissions: list) -> bool:
    """
    Validate if user has access to a specific mutation.
    
    Args:
        mutation_name: Name of the mutation
        user_permissions: List of user permissions
        
    Returns:
        True if user has access, False otherwise
    """
    mutation_info = get_mutation_info(mutation_name)
    security_level = mutation_info.get("security_level")

    if security_level == "public":
        return True
    if security_level == "authenticated":
        return "authenticated" in user_permissions
    if security_level == "admin":
        return any(perm in user_permissions for perm in ["admin", "user:manage", "role:manage"])
    if security_level == "super_admin":
        return "super_admin" in user_permissions

    return False

# Export utility functions
__all__.extend([
    "MUTATION_CATEGORIES",
    "RATE_LIMITS",
    "SECURITY_LEVELS",
    "TRANSACTION_SUPPORT",
    "get_mutation_info",
    "get_mutations_by_category",
    "get_mutations_by_security_level",
    "validate_mutation_access"
])
