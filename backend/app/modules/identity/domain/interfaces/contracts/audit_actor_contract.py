# domains/identity/domain/contracts/audit_actor_contract.py

from typing import Any, Protocol
from uuid import UUID


class AuditActorContract(Protocol):
    """
    Contract interface for audit actor operations.

    Allows the audit or compliance domains to reference who performed
    an action without coupling to internal identity models.
    """

    def resolve_actor(self, actor_id: UUID) -> dict[str, Any] | None:
        """
        Resolve an actor (user) by ID and return public info for audit log.

        Args:
            actor_id: The unique identifier of the actor/user

        Returns:
            Optional[Dict[str, Any]]: Actor information for audit purposes:
                {
                    "user_id": str,
                    "display_name": str,
                    "email": str,
                    "roles": List[str],
                    "department": str,
                    "status": str
                }
                Returns None if actor not found.
        """
        ...

    def resolve_system_actor(self, system_id: str) -> dict[str, Any] | None:
        """
        Resolve a system actor for automated actions.

        Args:
            system_id: The system identifier (e.g., "scheduler", "api", "migration")

        Returns:
            Optional[Dict[str, Any]]: System actor information:
                {
                    "system_id": str,
                    "system_name": str,
                    "system_type": str,
                    "version": str
                }
        """
        ...

    def get_actor_context(self, actor_id: UUID, session_id: UUID | None = None) -> dict[str, Any] | None:
        """
        Get contextual information about an actor for audit purposes.

        Args:
            actor_id: The unique identifier of the actor/user
            session_id: Optional session ID for additional context

        Returns:
            Optional[Dict[str, Any]]: Extended actor context:
                {
                    "user_id": str,
                    "display_name": str,
                    "email": str,
                    "roles": List[str],
                    "session_id": str,
                    "ip_address": str,
                    "user_agent": str,
                    "device_info": Dict[str, Any],
                    "location": str,
                    "risk_score": float,
                    "mfa_verified": bool
                }
        """
        ...

    def get_actor_permissions_at_time(self, actor_id: UUID, timestamp: Any | None = None) -> list[str]:
        """
        Get actor's permissions at a specific point in time for audit trails.

        Args:
            actor_id: The unique identifier of the actor/user
            timestamp: Optional timestamp (defaults to current time)

        Returns:
            List[str]: List of permissions the actor had at that time
        """
        ...

    def is_privileged_actor(self, actor_id: UUID) -> bool:
        """
        Check if actor has privileged access (admin, system admin, etc.).

        Args:
            actor_id: The unique identifier of the actor/user

        Returns:
            bool: True if actor has privileged permissions
        """
        ...

    def get_actor_hierarchy(self, actor_id: UUID) -> dict[str, Any] | None:
        """
        Get organizational hierarchy information for the actor.

        Args:
            actor_id: The unique identifier of the actor/user

        Returns:
            Optional[Dict[str, Any]]: Hierarchy information:
                {
                    "user_id": str,
                    "department": str,
                    "manager_id": str,
                    "manager_name": str,
                    "organizational_unit": str,
                    "cost_center": str
                }
        """
        ...

    def get_impersonation_context(self, actor_id: UUID) -> dict[str, Any] | None:
        """
        Get impersonation context if actor is acting on behalf of another user.

        Args:
            actor_id: The unique identifier of the actor/user

        Returns:
            Optional[Dict[str, Any]]: Impersonation context:
                {
                    "impersonator_id": str,
                    "impersonator_name": str,
                    "target_user_id": str,
                    "target_user_name": str,
                    "impersonation_reason": str,
                    "impersonation_started_at": str,
                    "authorized_by": str
                }
                Returns None if not currently impersonating.
        """
        ...
