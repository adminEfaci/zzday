"""SMS channel adapter implementations."""

import contextlib
import re
from datetime import datetime
from typing import Any

import httpx
from twilio.base.exceptions import TwilioException
from twilio.rest import Client as TwilioClient

from app.modules.notification.domain.entities.notification import Notification
from app.modules.notification.domain.enums import DeliveryStatus
from app.modules.notification.infrastructure.adapters.base import (
    BaseChannelAdapter,
    ChannelAdapterError,
    DeliveryResult,
)

# Constants
MAX_SMS_LENGTH = 1600
MIN_SERVER_ERROR_STATUS = 500


class SMSChannelAdapter(BaseChannelAdapter):
    """SMS channel adapter supporting Twilio and other providers."""

    SUPPORTED_PROVIDERS = ["twilio", "messagebird", "vonage"]

    def _validate_config(self) -> None:
        """Validate SMS channel configuration."""
        if self.provider not in self.SUPPORTED_PROVIDERS:
            raise ValueError(f"Unsupported SMS provider: {self.provider}")

        # Validate common settings
        if "from_number" not in self.config.settings:
            raise ValueError("Missing required setting: from_number")

        # Validate provider-specific settings
        if self.provider == "twilio":
            self._validate_twilio_config()
        elif self.provider == "messagebird":
            self._validate_messagebird_config()
        elif self.provider == "vonage":
            self._validate_vonage_config()

    def _validate_twilio_config(self) -> None:
        """Validate Twilio configuration."""
        required_creds = ["account_sid", "auth_token"]
        for cred in required_creds:
            if cred not in self.config.credentials:
                raise ValueError(f"Missing Twilio credential: {cred}")

    def _validate_messagebird_config(self) -> None:
        """Validate MessageBird configuration."""
        if "access_key" not in self.config.credentials:
            raise ValueError("Missing MessageBird access key")

    def _validate_vonage_config(self) -> None:
        """Validate Vonage configuration."""
        required_creds = ["api_key", "api_secret"]
        for cred in required_creds:
            if cred not in self.config.credentials:
                raise ValueError(f"Missing Vonage credential: {cred}")

    async def send(self, notification: Notification) -> DeliveryResult:
        """Send SMS notification."""
        try:
            # Validate message length
            if len(notification.content.body) > MAX_SMS_LENGTH:
                raise ChannelAdapterError(
                    f"SMS message exceeds maximum length of {MAX_SMS_LENGTH} characters",
                    error_code="MESSAGE_TOO_LONG",
                    is_retryable=False,
                )

            if self.provider == "twilio":
                return await self._send_twilio(notification)
            if self.provider == "messagebird":
                return await self._send_messagebird(notification)
            if self.provider == "vonage":
                return await self._send_vonage(notification)
            raise ChannelAdapterError(
                f"Unsupported provider: {self.provider}", is_retryable=False
            )
        except ChannelAdapterError:
            raise
        except Exception as e:
            raise ChannelAdapterError(f"Failed to send SMS: {e!s}", is_retryable=True)

    async def _send_twilio(self, notification: Notification) -> DeliveryResult:
        """Send SMS via Twilio."""
        try:
            client = TwilioClient(
                self.config.credentials["account_sid"],
                self.config.credentials["auth_token"],
            )

            # Prepare message parameters
            message_params = {
                "body": notification.content.body,
                "from_": self.config.settings["from_number"],
                "to": notification.recipient_address.address,
            }

            # Add optional parameters
            if self.config.settings.get("messaging_service_sid"):
                message_params["messaging_service_sid"] = self.config.settings[
                    "messaging_service_sid"
                ]
                del message_params["from_"]  # Can't use both

            if notification.idempotency_key:
                message_params["provide_feedback"] = True
                # Twilio doesn't have direct idempotency key support

            # Send message
            message = client.messages.create(**message_params)

            # Calculate cost
            cost_amount = None
            cost_currency = None
            if message.price:
                # Convert to cents
                cost_amount = int(float(message.price) * 100)
                cost_currency = message.price_unit

            return DeliveryResult(
                status=DeliveryStatus.SENT,
                provider_message_id=message.sid,
                provider_status=message.status,
                delivered_at=datetime.utcnow(),
                cost_amount=cost_amount,
                cost_currency=cost_currency,
                response_data={
                    "sid": message.sid,
                    "status": message.status,
                    "segments": message.num_segments,
                    "direction": message.direction,
                },
            )

        except TwilioException as e:
            error_code = str(e.code) if hasattr(e, "code") else None
            is_retryable = error_code not in [
                "21211",
                "21612",
                "21614",
            ]  # Invalid numbers

            raise ChannelAdapterError(
                f"Twilio error: {e!s}",
                error_code=error_code,
                is_retryable=is_retryable,
                provider_response={"error": str(e)},
            )

    async def _send_messagebird(self, notification: Notification) -> DeliveryResult:
        """Send SMS via MessageBird."""
        async with httpx.AsyncClient() as client:
            try:
                headers = {
                    "Authorization": f"AccessKey {self.config.credentials['access_key']}",
                    "Content-Type": "application/json",
                }

                data = {
                    "originator": self.config.settings["from_number"],
                    "recipients": [notification.recipient_address.address],
                    "body": notification.content.body,
                }

                response = await client.post(
                    "https://rest.messagebird.com/messages", headers=headers, json=data
                )

                response.raise_for_status()
                result = response.json()

                return DeliveryResult(
                    status=DeliveryStatus.SENT,
                    provider_message_id=result["id"],
                    provider_status="sent",
                    delivered_at=datetime.utcnow(),
                    response_data=result,
                )

            except httpx.HTTPError as e:
                error_data = {}
                if hasattr(e, "response") and e.response:
                    with contextlib.suppress(Exception):
                        error_data = e.response.json()

                is_retryable = (
                    e.response.status_code >= MIN_SERVER_ERROR_STATUS if hasattr(e, "response") else True
                )

                raise ChannelAdapterError(
                    f"MessageBird error: {e!s}",
                    error_code=error_data.get("errors", [{}])[0].get("code"),
                    is_retryable=is_retryable,
                    provider_response=error_data,
                )

    async def _send_vonage(self, notification: Notification) -> DeliveryResult:
        """Send SMS via Vonage (formerly Nexmo)."""
        async with httpx.AsyncClient() as client:
            try:
                data = {
                    "api_key": self.config.credentials["api_key"],
                    "api_secret": self.config.credentials["api_secret"],
                    "from": self.config.settings["from_number"],
                    "to": notification.recipient_address.address.replace("+", ""),
                    "text": notification.content.body,
                }

                response = await client.post(
                    "https://rest.nexmo.com/sms/json", data=data
                )

                response.raise_for_status()
                result = response.json()

                # Vonage returns array of message results
                if result.get("messages") and len(result["messages"]) > 0:
                    msg = result["messages"][0]

                    if msg["status"] == "0":  # Success
                        return DeliveryResult(
                            status=DeliveryStatus.SENT,
                            provider_message_id=msg["message-id"],
                            provider_status="success",
                            delivered_at=datetime.utcnow(),
                            cost_amount=int(float(msg.get("message-price", 0)) * 100),
                            cost_currency="EUR",  # Vonage uses EUR by default
                            response_data=result,
                        )
                    raise ChannelAdapterError(
                        f"Vonage error: {msg.get('error-text', 'Unknown error')}",
                        error_code=msg["status"],
                        is_retryable=msg["status"]
                        not in ["4", "9"],  # Invalid number errors
                        provider_response=result,
                    )
                raise ChannelAdapterError(
                    "Invalid Vonage response",
                    is_retryable=True,
                    provider_response=result,
                )

            except httpx.HTTPError as e:
                raise ChannelAdapterError(
                    f"Vonage HTTP error: {e!s}", is_retryable=True
                )

    async def check_status(self, provider_message_id: str) -> DeliveryResult | None:
        """Check SMS delivery status."""
        if self.provider == "twilio":
            return await self._check_twilio_status(provider_message_id)
        if self.provider == "messagebird":
            return await self._check_messagebird_status(provider_message_id)

        # Vonage doesn't have status checking API
        return None

    async def _check_twilio_status(
        self, provider_message_id: str
    ) -> DeliveryResult | None:
        """Check Twilio message status."""
        try:
            client = TwilioClient(
                self.config.credentials["account_sid"],
                self.config.credentials["auth_token"],
            )

            message = client.messages(provider_message_id).fetch()

            # Map Twilio status to our status
            status_map = {
                "delivered": DeliveryStatus.DELIVERED,
                "undelivered": DeliveryStatus.FAILED,
                "failed": DeliveryStatus.FAILED,
                "sent": DeliveryStatus.SENT,
                "queued": DeliveryStatus.QUEUED,
                "sending": DeliveryStatus.SENDING,
            }

            status = status_map.get(message.status, DeliveryStatus.SENT)

            return DeliveryResult(
                status=status,
                provider_message_id=message.sid,
                provider_status=message.status,
                delivered_at=message.date_sent
                if status == DeliveryStatus.DELIVERED
                else None,
                error_code=message.error_code if message.error_code else None,
                error_message=message.error_message if message.error_message else None,
                is_retryable=status
                not in [DeliveryStatus.DELIVERED, DeliveryStatus.FAILED],
            )

        except Exception:
            return None

    async def _check_messagebird_status(
        self, provider_message_id: str
    ) -> DeliveryResult | None:
        """Check MessageBird message status."""
        async with httpx.AsyncClient() as client:
            try:
                headers = {
                    "Authorization": f"AccessKey {self.config.credentials['access_key']}"
                }

                response = await client.get(
                    f"https://rest.messagebird.com/messages/{provider_message_id}",
                    headers=headers,
                )

                response.raise_for_status()
                result = response.json()

                # Get first recipient status
                if result.get("recipients", {}).get("items"):
                    recipient = result["recipients"]["items"][0]

                    status_map = {
                        "delivered": DeliveryStatus.DELIVERED,
                        "failed": DeliveryStatus.FAILED,
                        "sent": DeliveryStatus.SENT,
                        "buffered": DeliveryStatus.QUEUED,
                        "expired": DeliveryStatus.FAILED,
                    }

                    status = status_map.get(recipient["status"], DeliveryStatus.SENT)

                    return DeliveryResult(
                        status=status,
                        provider_message_id=result["id"],
                        provider_status=recipient["status"],
                        delivered_at=recipient.get("statusDatetime"),
                        error_code=str(recipient.get("statusErrorCode"))
                        if recipient.get("statusErrorCode")
                        else None,
                        is_retryable=status
                        not in [DeliveryStatus.DELIVERED, DeliveryStatus.FAILED],
                    )

            except Exception:
                return None

        return None

    async def validate_address(self, address: str) -> bool:
        """Validate phone number format."""
        # Remove all non-digit characters except +
        cleaned = re.sub(r"[^\d+]", "", address)

        # Check if it starts with + and has 10-15 digits
        if not re.match(r"^\+\d{10,15}$", cleaned):
            return False

        # Additional validation can be added:
        # - Country code validation
        # - Carrier lookup
        # - Number portability check

        return True

    async def handle_webhook(
        self, webhook_data: dict[str, Any]
    ) -> DeliveryResult | None:
        """Handle SMS provider webhooks."""
        if self.provider == "twilio":
            return await self._handle_twilio_webhook(webhook_data)
        if self.provider == "messagebird":
            return await self._handle_messagebird_webhook(webhook_data)

        return None

    async def _handle_twilio_webhook(
        self, webhook_data: dict[str, Any]
    ) -> DeliveryResult | None:
        """Handle Twilio status callback."""
        message_sid = webhook_data.get("MessageSid")
        message_status = webhook_data.get("MessageStatus")

        if not message_sid or not message_status:
            return None

        status_map = {
            "delivered": DeliveryStatus.DELIVERED,
            "undelivered": DeliveryStatus.FAILED,
            "failed": DeliveryStatus.FAILED,
            "sent": DeliveryStatus.SENT,
            "queued": DeliveryStatus.QUEUED,
            "sending": DeliveryStatus.SENDING,
        }

        status = status_map.get(message_status, DeliveryStatus.SENT)

        return DeliveryResult(
            status=status,
            provider_message_id=message_sid,
            provider_status=message_status,
            delivered_at=datetime.utcnow()
            if status == DeliveryStatus.DELIVERED
            else None,
            error_code=webhook_data.get("ErrorCode"),
            error_message=webhook_data.get("ErrorMessage"),
            is_retryable=status
            not in [DeliveryStatus.DELIVERED, DeliveryStatus.FAILED],
            response_data=webhook_data,
        )

    async def _handle_messagebird_webhook(
        self, webhook_data: dict[str, Any]
    ) -> DeliveryResult | None:
        """Handle MessageBird webhook."""
        # MessageBird webhooks are similar to their API responses
        message_id = webhook_data.get("id")
        webhook_data.get("recipient")
        status = webhook_data.get("status")

        if not message_id or not status:
            return None

        status_map = {
            "delivered": DeliveryStatus.DELIVERED,
            "failed": DeliveryStatus.FAILED,
            "sent": DeliveryStatus.SENT,
            "buffered": DeliveryStatus.QUEUED,
            "expired": DeliveryStatus.FAILED,
        }

        delivery_status = status_map.get(status, DeliveryStatus.SENT)

        return DeliveryResult(
            status=delivery_status,
            provider_message_id=message_id,
            provider_status=status,
            delivered_at=webhook_data.get("statusDatetime"),
            error_code=str(webhook_data.get("statusErrorCode"))
            if webhook_data.get("statusErrorCode")
            else None,
            is_retryable=delivery_status
            not in [DeliveryStatus.DELIVERED, DeliveryStatus.FAILED],
            response_data=webhook_data,
        )
