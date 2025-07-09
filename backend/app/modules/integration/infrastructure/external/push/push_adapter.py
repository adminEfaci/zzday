"""Push notification channel adapter implementations."""

import json
from datetime import datetime
from typing import Any

import httpx
from firebase_admin import credentials, initialize_app, messaging
from firebase_admin.exceptions import FirebaseError

from app.modules.notification.domain.entities.notification import Notification
from app.modules.notification.domain.enums import DeliveryStatus
from app.modules.notification.infrastructure.adapters.base import (
    BaseChannelAdapter,
    ChannelAdapterError,
    DeliveryResult,
)


class PushChannelAdapter(BaseChannelAdapter):
    """Push notification channel adapter supporting FCM and APNS."""

    SUPPORTED_PROVIDERS = ["firebase", "apns", "expo"]

    def __init__(self, config):
        """Initialize push channel adapter."""
        super().__init__(config)

        # Initialize provider client
        if self.provider == "firebase":
            self._init_firebase()
        elif self.provider == "apns":
            self._init_apns()
        elif self.provider == "expo":
            self._init_expo()

    def _validate_config(self) -> None:
        """Validate push channel configuration."""
        if self.provider not in self.SUPPORTED_PROVIDERS:
            raise ValueError(f"Unsupported push provider: {self.provider}")

        # Validate provider-specific settings
        if self.provider == "firebase":
            self._validate_firebase_config()
        elif self.provider == "apns":
            self._validate_apns_config()
        elif self.provider == "expo":
            self._validate_expo_config()

    def _validate_firebase_config(self) -> None:
        """Validate Firebase configuration."""
        if "project_id" not in self.config.settings:
            raise ValueError("Firebase project_id required")

        if "service_account" not in self.config.credentials:
            raise ValueError("Firebase service account credentials required")

    def _validate_apns_config(self) -> None:
        """Validate APNS configuration."""
        required = ["bundle_id", "team_id", "key_id"]
        for setting in required:
            if setting not in self.config.settings:
                raise ValueError(f"APNS {setting} required")

        if "auth_key" not in self.config.credentials:
            raise ValueError("APNS auth key required")

    def _validate_expo_config(self) -> None:
        """Validate Expo configuration."""
        if "access_token" not in self.config.credentials:
            raise ValueError("Expo access token required")

    def _init_firebase(self) -> None:
        """Initialize Firebase Admin SDK."""
        try:
            # Check if already initialized
            if not hasattr(self, "_firebase_app"):
                cred = credentials.Certificate(
                    json.loads(self.config.credentials["service_account"])
                )
                self._firebase_app = initialize_app(
                    cred, name=f"notification_{self.config.settings['project_id']}"
                )
        except Exception as e:
            raise ValueError(f"Failed to initialize Firebase: {e!s}")

    def _init_apns(self) -> None:
        """Initialize APNS client."""
        # APNS initialization would go here
        # This would typically use a library like apns2

    def _init_expo(self) -> None:
        """Initialize Expo client."""
        self._expo_url = "https://exp.host/--/api/v2/push/send"
        self._expo_token = self.config.credentials["access_token"]

    async def send(self, notification: Notification) -> DeliveryResult:
        """Send push notification."""
        try:
            if self.provider == "firebase":
                return await self._send_firebase(notification)
            if self.provider == "apns":
                return await self._send_apns(notification)
            if self.provider == "expo":
                return await self._send_expo(notification)
            raise ChannelAdapterError(
                f"Unsupported provider: {self.provider}", is_retryable=False
            )
        except ChannelAdapterError:
            raise
        except Exception as e:
            raise ChannelAdapterError(
                f"Failed to send push notification: {e!s}", is_retryable=True
            )

    async def _send_firebase(self, notification: Notification) -> DeliveryResult:
        """Send push notification via Firebase Cloud Messaging."""
        try:
            # Create message
            message = messaging.Message(
                notification=messaging.Notification(
                    title=notification.content.subject or "Notification",
                    body=notification.content.body[:240],  # FCM limit
                ),
                token=notification.recipient_address.address,
                data=self._prepare_data_payload(notification),
                android=messaging.AndroidConfig(
                    priority="high"
                    if notification.priority.level.value in ["urgent", "high"]
                    else "normal",
                    notification=messaging.AndroidNotification(
                        icon="notification_icon", color="#f45342"
                    ),
                ),
                apns=messaging.APNSConfig(
                    payload=messaging.APNSPayload(
                        aps=messaging.Aps(
                            alert=messaging.ApsAlert(
                                title=notification.content.subject,
                                body=notification.content.body[:240],
                            ),
                            badge=1,
                            sound="default",
                        )
                    )
                ),
            )

            # Send message
            response = messaging.send(message, app=self._firebase_app)

            return DeliveryResult(
                status=DeliveryStatus.SENT,
                provider_message_id=response,
                provider_status="success",
                delivered_at=datetime.utcnow(),
                response_data={"message_id": response},
            )

        except FirebaseError as e:
            error_code = e.code if hasattr(e, "code") else None
            is_retryable = error_code not in [
                "invalid-registration-token",
                "registration-token-not-registered",
            ]

            raise ChannelAdapterError(
                f"Firebase error: {e!s}",
                error_code=error_code,
                is_retryable=is_retryable,
                provider_response={"error": str(e)},
            )

    async def _send_apns(self, notification: Notification) -> DeliveryResult:
        """Send push notification via Apple Push Notification Service."""
        # APNS implementation would go here
        # This would use the apns2 library or similar
        raise NotImplementedError("APNS adapter not yet implemented")

    async def _send_expo(self, notification: Notification) -> DeliveryResult:
        """Send push notification via Expo."""
        async with httpx.AsyncClient() as client:
            try:
                headers = {
                    "Accept": "application/json",
                    "Accept-Encoding": "gzip, deflate",
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {self._expo_token}",
                }

                # Prepare message
                message = {
                    "to": notification.recipient_address.address,
                    "title": notification.content.subject or "Notification",
                    "body": notification.content.body[:240],
                    "data": self._prepare_data_payload(notification),
                    "priority": "high"
                    if notification.priority.level.value in ["urgent", "high"]
                    else "default",
                    "sound": "default",
                    "badge": 1,
                }

                response = await client.post(
                    self._expo_url, headers=headers, json=message
                )

                response.raise_for_status()
                result = response.json()

                # Expo returns data in specific format
                if result.get("data") and len(result["data"]) > 0:
                    push_result = result["data"][0]

                    if push_result["status"] == "ok":
                        return DeliveryResult(
                            status=DeliveryStatus.SENT,
                            provider_message_id=push_result.get("id"),
                            provider_status="ok",
                            delivered_at=datetime.utcnow(),
                            response_data=result,
                        )
                    error_details = push_result.get("details", {})
                    error_type = error_details.get("error")

                    is_retryable = error_type not in [
                        "DeviceNotRegistered",
                        "InvalidCredentials",
                    ]

                    raise ChannelAdapterError(
                        f"Expo error: {push_result.get('message', 'Unknown error')}",
                        error_code=error_type,
                        is_retryable=is_retryable,
                        provider_response=result,
                    )
                raise ChannelAdapterError(
                    "Invalid Expo response", is_retryable=True, provider_response=result
                )

            except httpx.HTTPError as e:
                raise ChannelAdapterError(f"Expo HTTP error: {e!s}", is_retryable=True)

    def _prepare_data_payload(self, notification: Notification) -> dict[str, str]:
        """Prepare data payload for push notification.

        Args:
            notification: Notification entity

        Returns:
            Data payload dictionary
        """
        data = {
            "notification_id": str(notification.id),
            "type": notification.metadata.get("type", "general")
            if notification.metadata
            else "general",
            "timestamp": datetime.utcnow().isoformat(),
        }

        # Add custom data from metadata
        if notification.metadata and "push_data" in notification.metadata:
            push_data = notification.metadata["push_data"]
            if isinstance(push_data, dict):
                # Convert all values to strings (required by FCM)
                for key, value in push_data.items():
                    data[key] = str(value)

        return data

    async def check_status(self, provider_message_id: str) -> DeliveryResult | None:
        """Check push notification delivery status."""
        # Most push providers don't offer status checking
        # Delivery confirmation typically comes via analytics or logs
        return None

    async def validate_address(self, address: str) -> bool:
        """Validate device token format."""
        if self.provider == "firebase":
            # FCM tokens are typically 152+ characters
            return len(address) >= 152
        if self.provider == "apns":
            # APNS tokens are 64 hex characters
            return len(address) == 64 and all(
                c in "0123456789abcdef" for c in address.lower()
            )
        if self.provider == "expo":
            # Expo push tokens have specific format
            return address.startswith("ExponentPushToken[") and address.endswith("]")

        return False

    async def handle_webhook(
        self, webhook_data: dict[str, Any]
    ) -> DeliveryResult | None:
        """Handle push provider webhooks."""
        # Push providers typically don't use webhooks for delivery status
        # They use message receipts or analytics APIs
        return None

    async def register_device(
        self,
        user_id: str,
        device_token: str,
        platform: str,
        device_info: dict[str, Any] | None = None,
    ) -> bool:
        """Register a device for push notifications.

        Args:
            user_id: User ID
            device_token: Device push token
            platform: Device platform (ios, android)
            device_info: Additional device information

        Returns:
            True if registration successful
        """
        # This would typically store the device token in a database
        # and possibly subscribe to topics in FCM
        if self.provider == "firebase":
            try:
                # Subscribe to user topic
                response = messaging.subscribe_to_topic(
                    [device_token], f"user_{user_id}", app=self._firebase_app
                )
                return response.success_count > 0
            except (ValueError, AttributeError, Exception):
                return False

        return True

    async def unregister_device(
        self, device_token: str, user_id: str | None = None
    ) -> bool:
        """Unregister a device from push notifications.

        Args:
            device_token: Device push token
            user_id: Optional user ID for topic unsubscription

        Returns:
            True if unregistration successful
        """
        if self.provider == "firebase" and user_id:
            try:
                # Unsubscribe from user topic
                response = messaging.unsubscribe_from_topic(
                    [device_token], f"user_{user_id}", app=self._firebase_app
                )
                return response.success_count > 0
            except (ValueError, AttributeError, Exception):
                return False

        return True
