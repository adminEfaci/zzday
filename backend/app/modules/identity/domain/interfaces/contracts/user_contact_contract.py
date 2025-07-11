# domains/identity/domain/contracts/user_contact_contract.py

from typing import Any, Protocol
from uuid import UUID


class UserContactContract(Protocol):
    """
    Contract interface for user contact operations.

    Lets notifications or crew domains get user contact info in a
    decoupled way without coupling to internal user models.
    """

    def get_email(self, user_id: UUID) -> str | None:
        """
        Return the user's primary email address.

        Args:
            user_id: The unique identifier of the user

        Returns:
            Optional[str]: User's primary email address or None if not available
        """
        ...

    def get_phone(self, user_id: UUID) -> str | None:
        """
        Return the user's primary phone number, if available.

        Args:
            user_id: The unique identifier of the user

        Returns:
            Optional[str]: User's primary phone number or None if not available
        """
        ...

    def get_notification_preferences(self, user_id: UUID) -> dict[str, Any]:
        """
        Return a dict with notification preferences.

        Args:
            user_id: The unique identifier of the user

        Returns:
            Dict[str, Any]: Notification preferences:
                {
                    "email": bool,
                    "sms": bool,
                    "push": bool,
                    "in_app": bool,
                    "phone": bool,
                    "emergency_only": bool,
                    "quiet_hours": {
                        "enabled": bool,
                        "start_time": str,
                        "end_time": str,
                        "timezone": str
                    },
                    "frequency": {
                        "security": str,  # "immediate", "daily", "weekly"
                        "system": str,
                        "marketing": str
                    }
                }
        """
        ...

    def get_verified_email(self, user_id: UUID) -> str | None:
        """
        Return the user's verified email address only.

        Args:
            user_id: The unique identifier of the user

        Returns:
            Optional[str]: Verified email address or None if not verified
        """
        ...

    def get_verified_phone(self, user_id: UUID) -> str | None:
        """
        Return the user's verified phone number only.

        Args:
            user_id: The unique identifier of the user

        Returns:
            Optional[str]: Verified phone number or None if not verified
        """
        ...

    def is_email_verified(self, user_id: UUID) -> bool:
        """
        Check if the user's email is verified.

        Args:
            user_id: The unique identifier of the user

        Returns:
            bool: True if email is verified, False otherwise
        """
        ...

    def is_phone_verified(self, user_id: UUID) -> bool:
        """
        Check if the user's phone is verified.

        Args:
            user_id: The unique identifier of the user

        Returns:
            bool: True if phone is verified, False otherwise
        """
        ...

    def get_emergency_contacts(self, user_id: UUID) -> list[dict[str, Any]]:
        """
        Get emergency contacts for the user.

        Args:
            user_id: The unique identifier of the user

        Returns:
            List[Dict[str, Any]]: List of emergency contacts:
                [
                    {
                        "contact_id": str,
                        "name": str,
                        "relationship": str,
                        "phone": str,
                        "email": str,
                        "is_primary": bool,
                        "is_verified": bool
                    }
                ]
        """
        ...

    def get_contact_methods(self, user_id: UUID) -> list[str]:
        """
        Get available contact methods for the user.

        Args:
            user_id: The unique identifier of the user

        Returns:
            List[str]: Available contact methods ['email', 'sms', 'phone', 'push']
        """
        ...

    def can_receive_notifications(self, user_id: UUID, notification_type: str) -> bool:
        """
        Check if user can receive notifications of a specific type.

        Args:
            user_id: The unique identifier of the user
            notification_type: Type of notification ('security', 'system', 'marketing', etc.)

        Returns:
            bool: True if user can receive this type of notification
        """
        ...

    def get_preferred_language(self, user_id: UUID) -> str:
        """
        Get the user's preferred language for communications.

        Args:
            user_id: The unique identifier of the user

        Returns:
            str: Language code (e.g., 'en', 'es', 'fr') defaults to 'en'
        """
        ...

    def get_timezone(self, user_id: UUID) -> str:
        """
        Get the user's timezone for time-sensitive communications.

        Args:
            user_id: The unique identifier of the user

        Returns:
            str: Timezone string (e.g., 'America/New_York') defaults to 'UTC'
        """
        ...

    def is_in_quiet_hours(self, user_id: UUID) -> bool:
        """
        Check if user is currently in quiet hours (do not disturb).

        Args:
            user_id: The unique identifier of the user

        Returns:
            bool: True if currently in quiet hours, False otherwise
        """
        ...

    def get_contact_summary(self, user_id: UUID) -> dict[str, Any]:
        """
        Get a comprehensive summary of user contact information.

        Args:
            user_id: The unique identifier of the user

        Returns:
            Dict[str, Any]: Contact summary:
                {
                    "user_id": str,
                    "primary_email": str,
                    "primary_phone": str,
                    "email_verified": bool,
                    "phone_verified": bool,
                    "preferred_language": str,
                    "timezone": str,
                    "emergency_contacts_count": int,
                    "notification_preferences": Dict[str, Any],
                    "available_contact_methods": List[str],
                    "in_quiet_hours": bool,
                    "can_receive_notifications": bool
                }
        """
        ...
