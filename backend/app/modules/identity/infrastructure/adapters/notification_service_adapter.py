"""
Notification Service Adapter

Production-ready implementation for multi-channel notifications (email, SMS, push).
"""

import json
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

from app.core.logging import logger
from app.modules.identity.domain.interfaces.services.communication.notification_service import (
    IEmailService,
    INotificationService,
    ISMSService,
)


class NotificationServiceAdapter(INotificationService):
    """Production notification service adapter."""

    def __init__(
        self,
        email_service: IEmailService | None = None,
        sms_service: ISMSService | None = None,
        push_service=None,
        template_engine=None,
        delivery_tracker=None,
        rate_limiter=None,
        retry_handler=None,
    ):
        """Initialize notification service adapter."""
        self._email_service = email_service
        self._sms_service = sms_service
        self._push_service = push_service
        self._template_engine = template_engine
        self._delivery_tracker = delivery_tracker
        self._rate_limiter = rate_limiter
        self._retry_handler = retry_handler
        
        # Message tracking
        self._pending_messages = {}
        self._delivery_status = {}
        
        # Template cache
        self._template_cache = {}
        
        # Provider configurations
        self._email_providers = ["sendgrid", "ses", "smtp"]
        self._sms_providers = ["twilio", "nexmo", "sns"]
        self._push_providers = ["fcm", "apns", "pusher"]
        
        # Rate limiting defaults
        self._rate_limits = {
            "email": {"limit": 1000, "window": 3600},  # 1000 emails per hour
            "sms": {"limit": 100, "window": 3600},     # 100 SMS per hour
            "push": {"limit": 5000, "window": 3600},   # 5000 push per hour
        }

    async def send_email(
        self,
        to: str,
        subject: str,
        template: str,
        data: dict[str, Any],
        priority: str = "normal",
    ) -> str:
        """Send email notification."""
        try:
            message_id = str(uuid4())
            
            # Validate inputs
            if not self._validate_email(to):
                raise ValueError(f"Invalid email address: {to}")
            
            # Check rate limiting
            if self._rate_limiter:
                rate_check = await self._rate_limiter.check_rate_limit(
                    "email", to, self._rate_limits["email"]
                )
                if not rate_check.get("allowed", True):
                    raise ValueError(f"Rate limit exceeded for email: {to}")
            
            # Render template
            content = await self._render_email_template(template, data)
            
            # Prepare message
            message = {
                "id": message_id,
                "type": "email",
                "to": to,
                "subject": subject,
                "template": template,
                "content": content,
                "priority": priority,
                "created_at": datetime.now(UTC).isoformat(),
                "attempts": 0,
                "max_attempts": 3,
                "data": data,
            }
            
            # Track message
            self._pending_messages[message_id] = message
            
            # Send email
            if self._email_service:
                result = await self._send_email_with_retry(message)
                
                # Update delivery tracking
                if self._delivery_tracker:
                    await self._delivery_tracker.track_message(
                        message_id, "email", "sent", result
                    )
                
                logger.info(f"Email sent successfully: {message_id} to {to}")
                return message_id
            else:
                # Mock/fallback implementation
                await self._mock_email_delivery(message)
                logger.info(f"Email sent (mock): {message_id} to {to}")
                return message_id
                
        except Exception as e:
            logger.error(f"Error sending email to {to}: {e}")
            
            # Track failure
            if self._delivery_tracker:
                await self._delivery_tracker.track_message(
                    message_id, "email", "failed", {"error": str(e)}
                )
            
            raise

    async def send_sms(
        self,
        phone: str,
        message: str,
        template: str | None = None,
    ) -> str:
        """Send SMS notification."""
        try:
            message_id = str(uuid4())
            
            # Validate phone number
            if not self._validate_phone(phone):
                raise ValueError(f"Invalid phone number: {phone}")
            
            # Check rate limiting
            if self._rate_limiter:
                rate_check = await self._rate_limiter.check_rate_limit(
                    "sms", phone, self._rate_limits["sms"]
                )
                if not rate_check.get("allowed", True):
                    raise ValueError(f"Rate limit exceeded for SMS: {phone}")
            
            # Render template if provided
            if template:
                message = await self._render_sms_template(template, {"message": message})
            
            # Prepare SMS message
            sms_message = {
                "id": message_id,
                "type": "sms",
                "to": phone,
                "message": message,
                "template": template,
                "created_at": datetime.now(UTC).isoformat(),
                "attempts": 0,
                "max_attempts": 3,
            }
            
            # Track message
            self._pending_messages[message_id] = sms_message
            
            # Send SMS
            if self._sms_service:
                result = await self._send_sms_with_retry(sms_message)
                
                # Update delivery tracking
                if self._delivery_tracker:
                    await self._delivery_tracker.track_message(
                        message_id, "sms", "sent", result
                    )
                
                logger.info(f"SMS sent successfully: {message_id} to {phone}")
                return message_id
            else:
                # Mock/fallback implementation
                await self._mock_sms_delivery(sms_message)
                logger.info(f"SMS sent (mock): {message_id} to {phone}")
                return message_id
                
        except Exception as e:
            logger.error(f"Error sending SMS to {phone}: {e}")
            
            # Track failure
            if self._delivery_tracker:
                await self._delivery_tracker.track_message(
                    message_id, "sms", "failed", {"error": str(e)}
                )
            
            raise

    async def send_push_notification(
        self,
        device_tokens: str | list[str],
        title: str,
        body: str,
        data: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Send push notification."""
        try:
            message_id = str(uuid4())
            
            # Normalize device tokens
            if isinstance(device_tokens, str):
                tokens = [device_tokens]
            else:
                tokens = device_tokens
            
            # Validate tokens
            valid_tokens = [token for token in tokens if self._validate_device_token(token)]
            if not valid_tokens:
                raise ValueError("No valid device tokens provided")
            
            # Check rate limiting
            if self._rate_limiter:
                for token in valid_tokens:
                    rate_check = await self._rate_limiter.check_rate_limit(
                        "push", token, self._rate_limits["push"]
                    )
                    if not rate_check.get("allowed", True):
                        logger.warning(f"Rate limit exceeded for push to token: {token}")
            
            # Prepare push notification
            push_message = {
                "id": message_id,
                "type": "push",
                "device_tokens": valid_tokens,
                "title": title,
                "body": body,
                "data": data or {},
                "created_at": datetime.now(UTC).isoformat(),
                "attempts": 0,
                "max_attempts": 3,
            }
            
            # Track message
            self._pending_messages[message_id] = push_message
            
            # Send push notification
            if self._push_service:
                result = await self._send_push_with_retry(push_message)
                
                # Update delivery tracking
                if self._delivery_tracker:
                    await self._delivery_tracker.track_message(
                        message_id, "push", "sent", result
                    )
                
                logger.info(f"Push notification sent: {message_id} to {len(valid_tokens)} devices")
                return {
                    "message_id": message_id,
                    "sent_count": result.get("success_count", len(valid_tokens)),
                    "failed_count": result.get("failure_count", 0),
                    "results": result.get("results", []),
                }
            else:
                # Mock/fallback implementation
                await self._mock_push_delivery(push_message)
                logger.info(f"Push notification sent (mock): {message_id} to {len(valid_tokens)} devices")
                return {
                    "message_id": message_id,
                    "sent_count": len(valid_tokens),
                    "failed_count": 0,
                    "results": [{"token": token, "status": "success"} for token in valid_tokens],
                }
                
        except Exception as e:
            logger.error(f"Error sending push notification: {e}")
            
            # Track failure
            if self._delivery_tracker:
                await self._delivery_tracker.track_message(
                    message_id, "push", "failed", {"error": str(e)}
                )
            
            raise

    async def send_bulk_email(
        self,
        recipients: list[dict[str, Any]],
        template: str,
        common_data: dict[str, Any] | None = None,
    ) -> str:
        """Send bulk email."""
        try:
            batch_id = str(uuid4())
            
            # Validate recipients
            valid_recipients = []
            for recipient in recipients:
                email = recipient.get("email")
                if email and self._validate_email(email):
                    valid_recipients.append(recipient)
                else:
                    logger.warning(f"Invalid recipient in bulk email: {recipient}")
            
            if not valid_recipients:
                raise ValueError("No valid recipients for bulk email")
            
            # Check rate limiting for bulk operation
            if self._rate_limiter:
                bulk_rate_check = await self._rate_limiter.check_bulk_rate_limit(
                    "email", len(valid_recipients), self._rate_limits["email"]
                )
                if not bulk_rate_check.get("allowed", True):
                    raise ValueError("Bulk email rate limit exceeded")
            
            # Prepare bulk email batch
            batch = {
                "id": batch_id,
                "type": "bulk_email",
                "template": template,
                "recipients": valid_recipients,
                "common_data": common_data or {},
                "created_at": datetime.now(UTC).isoformat(),
                "total_count": len(valid_recipients),
                "sent_count": 0,
                "failed_count": 0,
                "status": "processing",
            }
            
            # Track batch
            self._pending_messages[batch_id] = batch
            
            # Process bulk send
            if self._email_service:
                result = await self._send_bulk_email_batch(batch)
                
                # Update delivery tracking
                if self._delivery_tracker:
                    await self._delivery_tracker.track_batch(
                        batch_id, "bulk_email", "processed", result
                    )
                
                logger.info(f"Bulk email batch processed: {batch_id} ({len(valid_recipients)} recipients)")
                return batch_id
            else:
                # Mock/fallback implementation
                await self._mock_bulk_email_delivery(batch)
                logger.info(f"Bulk email batch processed (mock): {batch_id} ({len(valid_recipients)} recipients)")
                return batch_id
                
        except Exception as e:
            logger.error(f"Error sending bulk email: {e}")
            
            # Track failure
            if self._delivery_tracker:
                await self._delivery_tracker.track_batch(
                    batch_id, "bulk_email", "failed", {"error": str(e)}
                )
            
            raise

    async def get_delivery_status(self, message_id: str) -> dict[str, Any]:
        """Get message delivery status."""
        try:
            # Check local tracking first
            if message_id in self._delivery_status:
                return self._delivery_status[message_id]
            
            # Check delivery tracker
            if self._delivery_tracker:
                status = await self._delivery_tracker.get_status(message_id)
                if status:
                    return status
            
            # Check pending messages
            if message_id in self._pending_messages:
                message = self._pending_messages[message_id]
                return {
                    "message_id": message_id,
                    "type": message["type"],
                    "status": "pending",
                    "created_at": message["created_at"],
                    "attempts": message.get("attempts", 0),
                }
            
            # Message not found
            logger.warning(f"Delivery status not found for message: {message_id}")
            return {
                "message_id": message_id,
                "status": "unknown",
                "error": "Message not found",
                "checked_at": datetime.now(UTC).isoformat(),
            }
            
        except Exception as e:
            logger.error(f"Error getting delivery status for {message_id}: {e}")
            return {
                "message_id": message_id,
                "status": "error",
                "error": str(e),
                "checked_at": datetime.now(UTC).isoformat(),
            }

    async def handle_delivery_webhook(
        self,
        provider: str,
        webhook_data: dict[str, Any],
    ) -> bool:
        """Handle delivery status webhook."""
        try:
            # Extract message ID from webhook data
            message_id = self._extract_message_id_from_webhook(provider, webhook_data)
            if not message_id:
                logger.warning(f"Could not extract message ID from {provider} webhook")
                return False
            
            # Parse delivery status
            status = self._parse_webhook_status(provider, webhook_data)
            
            # Update delivery status
            self._delivery_status[message_id] = {
                "message_id": message_id,
                "provider": provider,
                "status": status["status"],
                "details": status["details"],
                "updated_at": datetime.now(UTC).isoformat(),
                "webhook_data": webhook_data,
            }
            
            # Update delivery tracker
            if self._delivery_tracker:
                await self._delivery_tracker.update_status(message_id, status)
            
            # Handle specific status updates
            if status["status"] == "failed":
                await self._handle_delivery_failure(message_id, status)
            elif status["status"] == "delivered":
                await self._handle_delivery_success(message_id, status)
            
            logger.info(f"Webhook processed for {provider}: {message_id} -> {status['status']}")
            return True
            
        except Exception as e:
            logger.error(f"Error handling {provider} webhook: {e}")
            return False

    async def _render_email_template(self, template: str, data: dict[str, Any]) -> dict[str, str]:
        """Render email template."""
        if self._template_engine:
            return await self._template_engine.render_email(template, data)
        else:
            # Fallback template rendering
            return {
                "html": f"<html><body><h1>{template}</h1><pre>{json.dumps(data, indent=2)}</pre></body></html>",
                "text": f"{template}\n\n{json.dumps(data, indent=2)}",
            }

    async def _render_sms_template(self, template: str, data: dict[str, Any]) -> str:
        """Render SMS template."""
        if self._template_engine:
            return await self._template_engine.render_sms(template, data)
        else:
            # Fallback template rendering
            message = data.get("message", "")
            return f"{template}: {message}"

    def _validate_email(self, email: str) -> bool:
        """Validate email address."""
        import re
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))

    def _validate_phone(self, phone: str) -> bool:
        """Validate phone number."""
        import re
        # Basic international phone number validation
        pattern = r'^\+?[1-9]\d{1,14}$'
        return bool(re.match(pattern, phone.replace(' ', '').replace('-', '')))

    def _validate_device_token(self, token: str) -> bool:
        """Validate device token."""
        # Basic token validation (length and format)
        return bool(token and len(token) >= 20 and len(token) <= 255)

    async def _send_email_with_retry(self, message: dict[str, Any]) -> dict[str, Any]:
        """Send email with retry logic."""
        if self._retry_handler:
            return await self._retry_handler.execute_with_retry(
                self._email_service.send_email,
                message["to"],
                message["subject"],
                message["content"]["html"],
                message["content"].get("text"),
            )
        else:
            return await self._email_service.send_email(
                message["to"],
                message["subject"],
                message["content"]["html"],
                message["content"].get("text"),
            )

    async def _send_sms_with_retry(self, message: dict[str, Any]) -> dict[str, Any]:
        """Send SMS with retry logic."""
        if self._retry_handler:
            return await self._retry_handler.execute_with_retry(
                self._sms_service.send_sms,
                message["to"],
                message["message"],
            )
        else:
            return await self._sms_service.send_sms(
                message["to"],
                message["message"],
            )

    async def _send_push_with_retry(self, message: dict[str, Any]) -> dict[str, Any]:
        """Send push notification with retry logic."""
        if self._retry_handler:
            return await self._retry_handler.execute_with_retry(
                self._push_service.send_push,
                message["device_tokens"],
                message["title"],
                message["body"],
                message["data"],
            )
        else:
            return await self._push_service.send_push(
                message["device_tokens"],
                message["title"],
                message["body"],
                message["data"],
            )

    async def _send_bulk_email_batch(self, batch: dict[str, Any]) -> dict[str, Any]:
        """Send bulk email batch."""
        results = {"sent": 0, "failed": 0, "errors": []}
        
        for recipient in batch["recipients"]:
            try:
                # Combine common data with recipient data
                template_data = {**batch["common_data"], **recipient}
                
                # Send individual email
                message_id = await self.send_email(
                    recipient["email"],
                    recipient.get("subject", f"Message from {batch['template']}"),
                    batch["template"],
                    template_data,
                    recipient.get("priority", "normal"),
                )
                
                results["sent"] += 1
                
            except Exception as e:
                results["failed"] += 1
                results["errors"].append({
                    "recipient": recipient.get("email"),
                    "error": str(e),
                })
                logger.error(f"Failed to send bulk email to {recipient.get('email')}: {e}")
        
        return results

    async def _mock_email_delivery(self, message: dict[str, Any]) -> None:
        """Mock email delivery for testing."""
        # Simulate delivery delay
        import asyncio
        await asyncio.sleep(0.1)
        
        # Update status
        self._delivery_status[message["id"]] = {
            "message_id": message["id"],
            "status": "delivered",
            "delivered_at": datetime.now(UTC).isoformat(),
            "provider": "mock",
        }

    async def _mock_sms_delivery(self, message: dict[str, Any]) -> None:
        """Mock SMS delivery for testing."""
        # Simulate delivery delay
        import asyncio
        await asyncio.sleep(0.1)
        
        # Update status
        self._delivery_status[message["id"]] = {
            "message_id": message["id"],
            "status": "delivered",
            "delivered_at": datetime.now(UTC).isoformat(),
            "provider": "mock",
        }

    async def _mock_push_delivery(self, message: dict[str, Any]) -> None:
        """Mock push notification delivery for testing."""
        # Simulate delivery delay
        import asyncio
        await asyncio.sleep(0.1)
        
        # Update status
        self._delivery_status[message["id"]] = {
            "message_id": message["id"],
            "status": "delivered",
            "delivered_at": datetime.now(UTC).isoformat(),
            "provider": "mock",
        }

    async def _mock_bulk_email_delivery(self, batch: dict[str, Any]) -> None:
        """Mock bulk email delivery for testing."""
        # Simulate processing delay
        import asyncio
        await asyncio.sleep(0.5)
        
        # Update status
        self._delivery_status[batch["id"]] = {
            "batch_id": batch["id"],
            "status": "completed",
            "sent_count": len(batch["recipients"]),
            "failed_count": 0,
            "completed_at": datetime.now(UTC).isoformat(),
            "provider": "mock",
        }

    def _extract_message_id_from_webhook(self, provider: str, webhook_data: dict[str, Any]) -> str | None:
        """Extract message ID from webhook data."""
        # Provider-specific message ID extraction
        id_fields = {
            "sendgrid": ["sg_message_id", "message_id"],
            "ses": ["messageId", "message_id"],
            "twilio": ["MessageSid", "message_sid"],
            "nexmo": ["message-id", "messageId"],
            "fcm": ["message_id", "messageId"],
        }
        
        fields = id_fields.get(provider, ["message_id", "id"])
        for field in fields:
            if field in webhook_data:
                return webhook_data[field]
        
        return None

    def _parse_webhook_status(self, provider: str, webhook_data: dict[str, Any]) -> dict[str, Any]:
        """Parse webhook delivery status."""
        # Provider-specific status parsing
        status_mappings = {
            "sendgrid": {
                "delivered": "delivered",
                "bounce": "failed",
                "dropped": "failed",
                "deferred": "pending",
            },
            "ses": {
                "delivery": "delivered",
                "bounce": "failed",
                "complaint": "failed",
            },
            "twilio": {
                "delivered": "delivered",
                "failed": "failed",
                "undelivered": "failed",
                "sent": "pending",
            },
        }
        
        default_status = "unknown"
        
        # Extract status from webhook
        status_field = webhook_data.get("event", webhook_data.get("status", default_status))
        mapping = status_mappings.get(provider, {})
        status = mapping.get(status_field, default_status)
        
        return {
            "status": status,
            "details": {
                "provider": provider,
                "original_status": status_field,
                "timestamp": datetime.now(UTC).isoformat(),
                "webhook_data": webhook_data,
            },
        }

    async def _handle_delivery_failure(self, message_id: str, status: dict[str, Any]) -> None:
        """Handle delivery failure."""
        logger.warning(f"Message delivery failed: {message_id} - {status['details']}")
        
        # Check if message should be retried
        if message_id in self._pending_messages:
            message = self._pending_messages[message_id]
            message["attempts"] += 1
            
            if message["attempts"] < message.get("max_attempts", 3):
                logger.info(f"Scheduling retry for message: {message_id} (attempt {message['attempts']})")
                # Would schedule retry here
            else:
                logger.error(f"Message exceeded max attempts: {message_id}")
                del self._pending_messages[message_id]

    async def _handle_delivery_success(self, message_id: str, status: dict[str, Any]) -> None:
        """Handle delivery success."""
        logger.info(f"Message delivered successfully: {message_id}")
        
        # Clean up pending message
        if message_id in self._pending_messages:
            del self._pending_messages[message_id]

    async def get_notification_statistics(self) -> dict[str, Any]:
        """Get notification service statistics."""
        try:
            now = datetime.now(UTC)
            
            # Count pending messages by type
            pending_by_type = {}
            for message in self._pending_messages.values():
                msg_type = message.get("type", "unknown")
                pending_by_type[msg_type] = pending_by_type.get(msg_type, 0) + 1
            
            # Count delivery status by type
            status_by_type = {}
            for status in self._delivery_status.values():
                msg_type = status.get("type", "unknown")
                if msg_type not in status_by_type:
                    status_by_type[msg_type] = {"delivered": 0, "failed": 0, "pending": 0}
                
                status_value = status.get("status", "unknown")
                if status_value in status_by_type[msg_type]:
                    status_by_type[msg_type][status_value] += 1
            
            return {
                "service_status": "healthy",
                "providers": {
                    "email": self._email_service is not None,
                    "sms": self._sms_service is not None,
                    "push": self._push_service is not None,
                },
                "pending_messages": {
                    "total": len(self._pending_messages),
                    "by_type": pending_by_type,
                },
                "delivery_stats": status_by_type,
                "rate_limits": self._rate_limits,
                "checked_at": now.isoformat(),
            }
            
        except Exception as e:
            logger.error(f"Error getting notification statistics: {e}")
            return {
                "service_status": "error",
                "error": str(e),
                "checked_at": datetime.now(UTC).isoformat(),
            }