"""
SMS Adapter

Concrete implementation of ISMSService for sending SMS messages.
Supports multiple SMS providers through a common interface.
"""

import asyncio
import re
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from app.core.logging import logger
from app.modules.identity.application.contracts.ports import ISMSService


class TwilioSMSAdapter(ISMSService):
    """Twilio-based SMS service implementation.
    
    This adapter provides SMS sending capabilities using Twilio.
    In production, this would integrate with the Twilio API.
    """
    
    def __init__(
        self,
        account_sid: str,
        auth_token: str,
        from_number: str,
        messaging_service_sid: str | None = None
    ):
        """Initialize Twilio SMS adapter.
        
        Args:
            account_sid: Twilio account SID
            auth_token: Twilio auth token
            from_number: Twilio phone number to send from
            messaging_service_sid: Optional messaging service SID
        """
        self._account_sid = account_sid
        self._auth_token = auth_token
        self._from_number = from_number
        self._messaging_service_sid = messaging_service_sid
        self._sent_messages: list[dict[str, Any]] = []
    
    async def send_verification_code(self, phone_number: str, code: str) -> None:
        """Send verification code via SMS.
        
        Args:
            phone_number: Recipient phone number
            code: Verification code
        """
        message = f"Your Ezzday verification code is: {code}\n\nThis code will expire in 5 minutes."
        
        await self._send_sms(
            to_number=phone_number,
            message=message,
            sms_type="verification_code"
        )
    
    async def send_mfa_code(self, phone_number: str, code: str) -> None:
        """Send MFA code via SMS.
        
        Args:
            phone_number: Recipient phone number
            code: MFA code
        """
        message = f"Your Ezzday login code is: {code}\n\nDo not share this code with anyone."
        
        await self._send_sms(
            to_number=phone_number,
            message=message,
            sms_type="mfa_code"
        )
    
    async def send_security_alert(self, phone_number: str, message: str) -> None:
        """Send security alert via SMS.
        
        Args:
            phone_number: Recipient phone number
            message: Alert message
        """
        # Ensure message fits SMS limits (160 chars)
        truncated_message = message[:157] + "..." if len(message) > 160 else message
        
        await self._send_sms(
            to_number=phone_number,
            message=truncated_message,
            sms_type="security_alert"
        )
    
    async def _send_sms(
        self,
        to_number: str,
        message: str,
        sms_type: str
    ) -> None:
        """Send SMS through Twilio.
        
        Args:
            to_number: Recipient phone number
            message: SMS message
            sms_type: Type of SMS
        """
        try:
            # Validate phone number format
            if not self._is_valid_phone_number(to_number):
                raise ValueError(f"Invalid phone number format: {to_number}")
            
            # In a real implementation, this would use Twilio SDK
            # For now, we'll simulate the send
            await asyncio.sleep(0.2)  # Simulate API call delay
            
            # Log the message
            sms_record = {
                "to": to_number,
                "from": self._from_number,
                "message": message,
                "type": sms_type,
                "status": "delivered",
                "timestamp": datetime.now(UTC).isoformat(),
                "message_sid": f"SM{uuid4().hex[:32]}"
            }
            
            self._sent_messages.append(sms_record)
            
            logger.info(
                "SMS sent successfully",
                to=to_number,
                sms_type=sms_type,
                message_length=len(message)
            )
            
        except Exception as e:
            logger.error(
                f"Failed to send SMS: {e}",
                to=to_number,
                sms_type=sms_type,
                error=str(e)
            )
            # Don't raise - SMS failures should not break the application
    
    def _is_valid_phone_number(self, phone_number: str) -> bool:
        """Validate phone number format.
        
        Args:
            phone_number: Phone number to validate
            
        Returns:
            True if valid E.164 format
        """
        # E.164 format: +[country code][number]
        # Example: +1234567890
        pattern = r'^\+[1-9]\d{1,14}$'
        return bool(re.match(pattern, phone_number))
    
    def get_sent_messages(self) -> list[dict[str, Any]]:
        """Get sent messages log (for testing/debugging).
        
        Returns:
            List of sent SMS records
        """
        return self._sent_messages.copy()
    
    async def health_check(self) -> bool:
        """Check if SMS service is healthy.
        
        Returns:
            True if service is accessible
        """
        try:
            # In a real implementation, this would test Twilio API connection
            # For now, we'll just return True
            return True
        except Exception as e:
            logger.error(f"SMS service health check failed: {e}")
            return False


class AWSSNSSMSAdapter(ISMSService):
    """AWS SNS-based SMS service implementation."""
    
    def __init__(
        self,
        region: str,
        access_key_id: str,
        secret_access_key: str,
        sender_id: str = "Ezzday"
    ):
        """Initialize AWS SNS SMS adapter.
        
        Args:
            region: AWS region
            access_key_id: AWS access key ID
            secret_access_key: AWS secret access key
            sender_id: SMS sender ID
        """
        self._region = region
        self._access_key_id = access_key_id
        self._secret_access_key = secret_access_key
        self._sender_id = sender_id
        # In a real implementation, initialize AWS SNS client here
    
    async def send_verification_code(self, phone_number: str, code: str) -> None:
        """Send verification code using AWS SNS."""
        message = f"Your Ezzday verification code is: {code}"
        await self._send_sms(phone_number, message)
    
    async def send_mfa_code(self, phone_number: str, code: str) -> None:
        """Send MFA code using AWS SNS."""
        message = f"Your Ezzday login code is: {code}"
        await self._send_sms(phone_number, message)
    
    async def send_security_alert(self, phone_number: str, message: str) -> None:
        """Send security alert using AWS SNS."""
        await self._send_sms(phone_number, message[:160])
    
    async def _send_sms(self, phone_number: str, message: str) -> None:
        """Send SMS through AWS SNS."""
        # In a real implementation, this would use boto3
        await asyncio.sleep(0.15)
        logger.info(f"AWS SNS: SMS sent to {phone_number}")


class MockSMSAdapter(ISMSService):
    """Mock SMS service for testing."""
    
    def __init__(self):
        """Initialize mock SMS adapter."""
        self._sent_messages: list[dict[str, Any]] = []
    
    async def send_verification_code(self, phone_number: str, code: str) -> None:
        """Mock send verification code."""
        self._sent_messages.append({
            "to": phone_number,
            "type": "verification_code",
            "code": code,
            "timestamp": datetime.now(UTC).isoformat()
        })
        logger.debug(f"Mock SMS: Verification code {code} sent to {phone_number}")
    
    async def send_mfa_code(self, phone_number: str, code: str) -> None:
        """Mock send MFA code."""
        self._sent_messages.append({
            "to": phone_number,
            "type": "mfa_code",
            "code": code,
            "timestamp": datetime.now(UTC).isoformat()
        })
        logger.debug(f"Mock SMS: MFA code {code} sent to {phone_number}")
    
    async def send_security_alert(self, phone_number: str, message: str) -> None:
        """Mock send security alert."""
        self._sent_messages.append({
            "to": phone_number,
            "type": "security_alert",
            "message": message,
            "timestamp": datetime.now(UTC).isoformat()
        })
        logger.debug(f"Mock SMS: Security alert sent to {phone_number}")
    
    def get_sent_messages(self) -> list[dict[str, Any]]:
        """Get all sent messages."""
        return self._sent_messages.copy()
    
    def clear_messages(self) -> None:
        """Clear sent messages (for testing)."""
        self._sent_messages.clear()
