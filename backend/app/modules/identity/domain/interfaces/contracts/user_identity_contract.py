# domains/identity/domain/contracts/user_identity_contract.py

from typing import Protocol
from uuid import UUID


class UserIdentityContract(Protocol):
    """
    Contract interface for user identity operations.

    Allows other domains to reference users by ID and query status,
    role, etc. without direct coupling to internal identity models.
    """

    def exists(self, user_id: UUID) -> bool:
        """
        Return True if the user exists and is not soft-deleted.

        Args:
            user_id: The unique identifier of the user

        Returns:
            bool: True if user exists and is active, False otherwise
        """
        ...

    def is_active(self, user_id: UUID) -> bool:
        """
        Return True if the user is active (not suspended/terminated).

        Args:
            user_id: The unique identifier of the user

        Returns:
            bool: True if user is active, False if suspended/terminated/deactivated
        """
        ...

    def get_roles(self, user_id: UUID) -> list[str]:
        """
        Return a list of roles for this user (e.g. ['admin', 'loader']).

        Args:
            user_id: The unique identifier of the user

        Returns:
            List[str]: List of role names assigned to the user

        Raises:
            UserNotFoundError: If user does not exist
        """
        ...

    def get_email(self, user_id: UUID) -> str | None:
        """
        Return the user's email address, if present and allowed to share.

        Args:
            user_id: The unique identifier of the user

        Returns:
            Optional[str]: User's email address or None if not available/not allowed
        """
        ...

    def get_display_name(self, user_id: UUID) -> str | None:
        """
        Return the user's display name, if available.

        Args:
            user_id: The unique identifier of the user

        Returns:
            Optional[str]: User's display name or None if not available
        """
        ...

    def get_user_status(self, user_id: UUID) -> str | None:
        """
        Return the current status of the user.

        Args:
            user_id: The unique identifier of the user

        Returns:
            Optional[str]: User status (active, suspended, deactivated, etc.)
        """
        ...

    def has_permission(self, user_id: UUID, permission: str) -> bool:
        """
        Check if user has a specific permission.

        Args:
            user_id: The unique identifier of the user
            permission: The permission name to check

        Returns:
            bool: True if user has the permission, False otherwise
        """
        ...

    def get_permissions(self, user_id: UUID) -> list[str]:
        """
        Get all permissions for the user (direct and inherited from roles).

        Args:
            user_id: The unique identifier of the user

        Returns:
            List[str]: List of permission names
        """
        ...
