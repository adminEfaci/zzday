"""
Tests for Identity Module Adapters

Verifies that all adapters are properly implemented and functional.
"""

from uuid import uuid4

import pytest

from app.modules.identity.infrastructure.adapters.application_cache_adapter import (
    ApplicationCacheAdapter,
)
from app.modules.identity.infrastructure.adapters.email_adapter import (
    SMTPEmailAdapter,
)
from app.modules.identity.infrastructure.adapters.notification_adapter import (
    NotificationAdapter,
)
from app.modules.identity.infrastructure.adapters.sms_adapter import (
    MockSMSAdapter,
)


class TestCacheAdapter:
    """Test ApplicationCacheAdapter."""
    
    @pytest.mark.asyncio
    async def test_cache_operations(self):
        """Test basic cache operations."""
        # Create mock Redis client
        class MockRedis:
            def __init__(self):
                self.data = {}
                self.ttls = {}
            
            async def get(self, key):
                return self.data.get(key)
            
            async def set(self, key, value, ex=None):
                self.data[key] = value
                if ex:
                    self.ttls[key] = ex
                return "OK"
            
            async def delete(self, key):
                if key in self.data:
                    del self.data[key]
                    return 1
                return 0
            
            async def exists(self, key):
                return 1 if key in self.data else 0
            
            async def keys(self, pattern):
                # Simple pattern matching for testing
                import fnmatch
                return [k.encode() for k in self.data.keys() if fnmatch.fnmatch(k, pattern)]
        
        redis = MockRedis()
        cache = ApplicationCacheAdapter(redis)
        
        # Test set and get
        await cache.set("test_key", "test_value")
        value = await cache.get("test_key")
        assert value == "test_value"
        
        # Test complex object
        test_obj = {"user_id": str(uuid4()), "name": "Test User"}
        await cache.set("user:123", test_obj)
        retrieved = await cache.get("user:123")
        assert retrieved == test_obj
        
        # Test delete
        await cache.delete("test_key")
        value = await cache.get("test_key")
        assert value is None
        
        # Test exists
        assert await cache.exists("user:123") is True
        assert await cache.exists("nonexistent") is False


class TestNotificationAdapter:
    """Test NotificationAdapter."""
    
    @pytest.mark.asyncio
    async def test_send_notification(self):
        """Test sending notifications."""
        adapter = NotificationAdapter()
        
        user_id = uuid4()
        
        # Should not raise any exceptions
        await adapter.send_notification(
            user_id=user_id,
            notification_type="security_alert",
            title="Security Alert",
            message="New login detected",
            data={"ip": "192.168.1.1"}
        )
        
        # Check notification was logged
        logs = adapter.get_notification_log()
        assert len(logs) == 1
        assert logs[0]["user_id"] == str(user_id)
        assert logs[0]["type"] == "security_alert"
    
    @pytest.mark.asyncio
    async def test_bulk_notification(self):
        """Test sending bulk notifications."""
        adapter = NotificationAdapter()
        
        user_ids = [uuid4() for _ in range(5)]
        
        await adapter.send_bulk_notification(
            user_ids=user_ids,
            notification_type="general",
            title="System Update",
            message="Scheduled maintenance"
        )
        
        # Check all notifications were sent
        logs = adapter.get_notification_log()
        assert len(logs) == 5


class TestEmailAdapter:
    """Test SMTPEmailAdapter."""
    
    @pytest.mark.asyncio
    async def test_send_verification_email(self):
        """Test sending verification email."""
        adapter = SMTPEmailAdapter()
        
        # Should not raise any exceptions
        await adapter.send_verification_email(
            email="test@example.com",
            token="test_token_123"
        )
        
        # Check email was logged
        sent = adapter.get_sent_emails()
        assert len(sent) == 1
        assert sent[0]["to"] == "test@example.com"
        assert sent[0]["type"] == "verification"
    
    @pytest.mark.asyncio
    async def test_send_security_alert(self):
        """Test sending security alert email."""
        adapter = SMTPEmailAdapter()
        
        await adapter.send_security_alert(
            email="user@example.com",
            alert_type="new_login",
            details={
                "ip_address": "192.168.1.1",
                "location": "New York, US",
                "device": "Chrome on Windows"
            }
        )
        
        sent = adapter.get_sent_emails()
        assert len(sent) == 1
        assert sent[0]["priority"] == "high"


class TestSMSAdapter:
    """Test MockSMSAdapter."""
    
    @pytest.mark.asyncio
    async def test_send_verification_code(self):
        """Test sending verification code."""
        adapter = MockSMSAdapter()
        
        await adapter.send_verification_code(
            phone_number="+1234567890",
            code="123456"
        )
        
        messages = adapter.get_sent_messages()
        assert len(messages) == 1
        assert messages[0]["to"] == "+1234567890"
        assert messages[0]["code"] == "123456"
    
    @pytest.mark.asyncio
    async def test_send_mfa_code(self):
        """Test sending MFA code."""
        adapter = MockSMSAdapter()
        
        await adapter.send_mfa_code(
            phone_number="+1234567890",
            code="654321"
        )
        
        messages = adapter.get_sent_messages()
        assert len(messages) == 1
        assert messages[0]["type"] == "mfa_code"


@pytest.mark.asyncio
async def test_all_adapters_implement_interfaces():
    """Verify all adapters properly implement their interfaces."""
    # This test verifies that adapters can be instantiated and have required methods
    
    # Cache adapter
    cache = ApplicationCacheAdapter(None)  # Will fail if interface not implemented
    assert hasattr(cache, "get")
    assert hasattr(cache, "set")
    assert hasattr(cache, "delete")
    assert hasattr(cache, "exists")
    
    # Notification adapter
    notif = NotificationAdapter()
    assert hasattr(notif, "send_notification")
    assert hasattr(notif, "send_bulk_notification")
    
    # Email adapter
    email = SMTPEmailAdapter()
    assert hasattr(email, "send_verification_email")
    assert hasattr(email, "send_password_reset_email")
    assert hasattr(email, "send_welcome_email")
    assert hasattr(email, "send_security_alert")
    assert hasattr(email, "send_mfa_code")
    
    # SMS adapter
    sms = MockSMSAdapter()
    assert hasattr(sms, "send_verification_code")
    assert hasattr(sms, "send_mfa_code")
    assert hasattr(sms, "send_security_alert")
