"""Pytest configuration and fixtures for notification module tests.

This module provides comprehensive test fixtures for all notification components
including mock providers, test data generators, and performance testing utilities.
"""

import asyncio
from datetime import datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock, Mock
from uuid import UUID, uuid4

import pytest

from app.modules.notification.domain.aggregates.notification_batch import (
    NotificationBatch,
)
from app.modules.notification.domain.aggregates.notification_template import (
    NotificationTemplate,
)
from app.modules.notification.domain.entities.notification import Notification
from app.modules.notification.domain.entities.notification_recipient import (
    NotificationRecipient,
)
from app.modules.notification.domain.entities.notification_schedule import (
    NotificationSchedule,
)
from app.modules.notification.domain.enums import (
    DeliveryStatus,
    NotificationChannel,
    NotificationPriority,
    RecipientStatus,
    TemplateType,
    VariableType,
)
from app.modules.notification.domain.value_objects import (
    ChannelConfig,
    NotificationContent,
    NotificationPriorityValue,
    RecipientAddress,
    TemplateVariable,
)

# ============================================================================
# Basic Test Data
# ============================================================================


@pytest.fixture
def sample_user_id():
    """Sample user ID for testing."""
    return uuid4()


@pytest.fixture
def sample_recipient_id():
    """Sample recipient ID for testing."""
    return uuid4()


@pytest.fixture
def sample_template_id():
    """Sample template ID for testing."""
    return uuid4()


@pytest.fixture
def sample_notification_id():
    """Sample notification ID for testing."""
    return uuid4()


# ============================================================================
# Notification Content Fixtures
# ============================================================================


@pytest.fixture
def basic_notification_content():
    """Basic notification content for testing."""
    return NotificationContent(
        subject="Test Notification",
        body="This is a test notification body",
        html_body="<p>This is a test notification body</p>",
        variables={"user_name": "John Doe", "action": "login"},
        metadata={"test": True},
    )


@pytest.fixture
def email_notification_content():
    """Email-specific notification content."""
    return NotificationContent(
        subject="Welcome to Our Platform",
        body="Thank you for joining us, {{user_name}}!",
        html_body="<h1>Welcome {{user_name}}!</h1><p>Thank you for joining us!</p>",
        variables={"user_name": "John Doe"},
        attachments=[
            {
                "filename": "welcome.pdf",
                "content_type": "application/pdf",
                "size": 1024,
                "url": "https://example.com/welcome.pdf",
            }
        ],
    )


@pytest.fixture
def sms_notification_content():
    """SMS-specific notification content."""
    return NotificationContent(
        body="Your verification code is {{code}}. Valid for 5 minutes.",
        variables={"code": "123456"},
    )


@pytest.fixture
def push_notification_content():
    """Push notification content."""
    return NotificationContent(
        subject="New Message",
        body="You have a new message from {{sender}}",
        variables={"sender": "Alice"},
    )


@pytest.fixture
def long_content_for_truncation():
    """Long content for testing channel-specific truncation."""
    long_text = "This is a very long message " * 20  # 560 characters
    return NotificationContent(
        subject="Long Subject " * 10,  # 130 characters
        body=long_text,
        html_body=f"<p>{long_text}</p>",
    )


# ============================================================================
# Recipient Address Fixtures
# ============================================================================


@pytest.fixture
def email_recipient_address():
    """Email recipient address."""
    return RecipientAddress(
        channel=NotificationChannel.EMAIL,
        address="john.doe@example.com",
        display_name="John Doe",
    )


@pytest.fixture
def sms_recipient_address():
    """SMS recipient address."""
    return RecipientAddress(channel=NotificationChannel.SMS, address="+1234567890")


@pytest.fixture
def push_recipient_address():
    """Push notification recipient address."""
    return RecipientAddress(
        channel=NotificationChannel.PUSH,
        address="device_token_abc123xyz789device_token_abc123xyz789",
    )


@pytest.fixture
def in_app_recipient_address(sample_recipient_id):
    """In-app notification recipient address."""
    return RecipientAddress(
        channel=NotificationChannel.IN_APP,
        address=str(sample_recipient_id),
        display_name="John Doe",
    )


@pytest.fixture
def invalid_email_addresses():
    """List of invalid email addresses for testing."""
    return [
        "invalid-email",
        "@example.com",
        "test@",
        "test..test@example.com",
        "test@example",
        "",
        None,
    ]


@pytest.fixture
def invalid_phone_numbers():
    """List of invalid phone numbers for testing."""
    return [
        "123",  # Too short
        "abc123",  # Contains letters
        "+123456789012345678",  # Too long
        "",
        None,
    ]


# ============================================================================
# Notification Entity Fixtures
# ============================================================================


@pytest.fixture
def basic_notification(
    sample_recipient_id, email_recipient_address, basic_notification_content
):
    """Basic notification entity for testing."""
    return Notification(
        recipient_id=sample_recipient_id,
        channel=NotificationChannel.EMAIL,
        content=basic_notification_content,
        recipient_address=email_recipient_address,
        priority=NotificationPriorityValue(level=NotificationPriority.NORMAL),
        expires_at=datetime.utcnow() + timedelta(hours=24),
        idempotency_key="test-key-123",
        metadata={"test": True},
    )


@pytest.fixture
def email_notification(
    sample_recipient_id,
    sample_template_id,
    email_recipient_address,
    email_notification_content,
):
    """Email notification with template."""
    return Notification(
        recipient_id=sample_recipient_id,
        channel=NotificationChannel.EMAIL,
        content=email_notification_content,
        recipient_address=email_recipient_address,
        template_id=sample_template_id,
        priority=NotificationPriorityValue(level=NotificationPriority.HIGH),
        expires_at=datetime.utcnow() + timedelta(hours=12),
        metadata={"campaign": "welcome", "type": "transactional"},
    )


@pytest.fixture
def sms_notification(
    sample_recipient_id, sms_recipient_address, sms_notification_content
):
    """SMS notification for testing."""
    return Notification(
        recipient_id=sample_recipient_id,
        channel=NotificationChannel.SMS,
        content=sms_notification_content,
        recipient_address=sms_recipient_address,
        priority=NotificationPriorityValue(level=NotificationPriority.URGENT),
        expires_at=datetime.utcnow() + timedelta(minutes=5),
        metadata={"verification": True},
    )


@pytest.fixture
def push_notification(
    sample_recipient_id, push_recipient_address, push_notification_content
):
    """Push notification for testing."""
    return Notification(
        recipient_id=sample_recipient_id,
        channel=NotificationChannel.PUSH,
        content=push_notification_content,
        recipient_address=push_recipient_address,
        priority=NotificationPriorityValue(level=NotificationPriority.NORMAL),
        metadata={"app_version": "1.2.3"},
    )


@pytest.fixture
def expired_notification(
    sample_recipient_id, email_recipient_address, basic_notification_content
):
    """Expired notification for testing."""
    return Notification(
        recipient_id=sample_recipient_id,
        channel=NotificationChannel.EMAIL,
        content=basic_notification_content,
        recipient_address=email_recipient_address,
        expires_at=datetime.utcnow() - timedelta(hours=1),  # Already expired
        metadata={"expired": True},
    )


@pytest.fixture
def failed_notification(basic_notification):
    """Failed notification for retry testing."""
    notification = basic_notification
    notification.update_status(
        DeliveryStatus.FAILED, details="SMTP server unavailable", error_code="SMTP_503"
    )
    return notification


@pytest.fixture
def multi_retry_notification(basic_notification):
    """Notification with multiple retry attempts."""
    notification = basic_notification

    # First failure
    notification.update_status(
        DeliveryStatus.FAILED, details="Temporary failure", error_code="TEMP_FAIL"
    )
    notification.mark_for_retry()

    # Second failure
    notification.update_status(
        DeliveryStatus.FAILED,
        details="Another temporary failure",
        error_code="TEMP_FAIL_2",
    )
    notification.mark_for_retry()

    return notification


# ============================================================================
# Template Fixtures
# ============================================================================


@pytest.fixture
def basic_template_variables():
    """Basic template variables for testing."""
    return [
        TemplateVariable(
            name="user_name",
            var_type=VariableType.STRING,
            required=True,
            description="User's full name",
        ),
        TemplateVariable(
            name="verification_code",
            var_type=VariableType.STRING,
            required=True,
            description="6-digit verification code",
            validation_rules={"min_length": 6, "max_length": 6, "pattern": r"^\d{6}$"},
        ),
        TemplateVariable(
            name="amount",
            var_type=VariableType.CURRENCY,
            required=False,
            default_value=0.0,
            description="Transaction amount",
        ),
        TemplateVariable(
            name="expiry_date",
            var_type=VariableType.DATE,
            required=True,
            description="Expiration date",
        ),
    ]


@pytest.fixture
def email_template(sample_user_id, basic_template_variables):
    """Email notification template."""
    template = NotificationTemplate(
        name="Welcome Email Template",
        template_type=TemplateType.TRANSACTIONAL,
        created_by=sample_user_id,
        description="Welcome email for new users",
        tags=["welcome", "onboarding", "email"],
    )

    # Add email content
    content = NotificationContent(
        subject="Welcome to {{platform_name}}, {{user_name}}!",
        body="Hello {{user_name}},\n\nWelcome to {{platform_name}}! Your account is now active.\n\nBest regards,\nThe Team",
        html_body="<h1>Welcome {{user_name}}!</h1><p>Your account on {{platform_name}} is now active.</p>",
        variables={"user_name": "John Doe", "platform_name": "TestApp"},
    )

    template.add_channel_content(NotificationChannel.EMAIL, content, sample_user_id)

    # Define variables
    for variable in basic_template_variables:
        template.define_variable(variable, sample_user_id)

    return template


@pytest.fixture
def multi_channel_template(sample_user_id):
    """Template supporting multiple channels."""
    template = NotificationTemplate(
        name="Multi-Channel Alert",
        template_type=TemplateType.ALERT,
        created_by=sample_user_id,
        description="Critical system alert for all channels",
    )

    # Email content
    email_content = NotificationContent(
        subject="URGENT: {{alert_type}} Alert",
        body="Alert: {{message}}\nTime: {{timestamp}}\nSeverity: {{severity}}",
        html_body="<h2>URGENT ALERT</h2><p><strong>{{alert_type}}</strong></p><p>{{message}}</p>",
    )
    template.add_channel_content(
        NotificationChannel.EMAIL, email_content, sample_user_id
    )

    # SMS content
    sms_content = NotificationContent(
        body="ALERT: {{alert_type}} - {{message}} at {{timestamp}}"
    )
    template.add_channel_content(NotificationChannel.SMS, sms_content, sample_user_id)

    # Push content
    push_content = NotificationContent(
        subject="{{alert_type}} Alert", body="{{message}}"
    )
    template.add_channel_content(NotificationChannel.PUSH, push_content, sample_user_id)

    # In-app content
    in_app_content = NotificationContent(
        subject="System Alert",
        body="{{message}}",
        html_body="<div class='alert alert-{{severity}}'><h3>{{alert_type}}</h3><p>{{message}}</p></div>",
    )
    template.add_channel_content(
        NotificationChannel.IN_APP, in_app_content, sample_user_id
    )

    return template


@pytest.fixture
def marketing_template(sample_user_id):
    """Marketing email template."""
    template = NotificationTemplate(
        name="Monthly Newsletter",
        template_type=TemplateType.MARKETING,
        created_by=sample_user_id,
        description="Monthly newsletter template",
        tags=["newsletter", "marketing", "monthly"],
    )

    content = NotificationContent(
        subject="{{month}} Newsletter - {{company_name}}",
        body="Dear {{user_name}},\n\nHere's what's new this {{month}}:\n{{content}}\n\nUnsubscribe: {{unsubscribe_url}}",
        html_body="<html><body><h1>{{month}} Newsletter</h1><p>Dear {{user_name}},</p><div>{{content}}</div><p><a href='{{unsubscribe_url}}'>Unsubscribe</a></p></body></html>",
    )

    template.add_channel_content(NotificationChannel.EMAIL, content, sample_user_id)
    template.set_required_channels([NotificationChannel.EMAIL], sample_user_id)

    return template


@pytest.fixture
def inactive_template(sample_user_id):
    """Inactive template for testing."""
    template = NotificationTemplate(
        name="Inactive Template",
        template_type=TemplateType.SYSTEM,
        created_by=sample_user_id,
        description="This template is inactive",
    )
    template.deactivate(sample_user_id, "Testing purposes")
    return template


# ============================================================================
# Notification Batch Fixtures
# ============================================================================


@pytest.fixture
def sample_batch_notifications():
    """Sample notifications for batch testing."""
    notifications = []
    recipients = [uuid4() for _ in range(10)]

    for i, recipient_id in enumerate(recipients):
        notification_data = {
            "recipient_id": recipient_id,
            "channel": NotificationChannel.EMAIL,
            "content": {
                "subject": f"Batch Notification {i+1}",
                "body": f"This is batch notification number {i+1}",
                "variables": {"batch_number": i + 1, "recipient_name": f"User {i+1}"},
            },
            "priority": NotificationPriority.NORMAL,
            "metadata": {"batch_position": i + 1},
        }
        notifications.append(notification_data)

    return notifications


@pytest.fixture
def notification_batch(sample_user_id, sample_batch_notifications):
    """Notification batch for testing."""
    batch = NotificationBatch(
        name="Test Marketing Campaign",
        metadata={"campaign_id": "camp_123", "type": "marketing"},
    )
    batch.created_by = sample_user_id

    # Add notifications to batch
    for notification_data in sample_batch_notifications:
        batch.add_notification(notification_data)

    return batch


@pytest.fixture
def processing_batch(notification_batch):
    """Batch in processing state."""
    batch = notification_batch
    batch.start_processing()
    return batch


@pytest.fixture
def failed_batch(notification_batch):
    """Failed batch for testing."""
    batch = notification_batch
    batch.start_processing()
    batch.mark_failed("Processing failed due to provider error")
    return batch


# ============================================================================
# Recipient Fixtures
# ============================================================================


@pytest.fixture
def notification_recipient(sample_recipient_id):
    """Basic notification recipient."""
    return NotificationRecipient(
        recipient_id=sample_recipient_id,
        email_addresses=["john.doe@example.com", "john.work@company.com"],
        phone_numbers=["+1234567890", "+0987654321"],
        device_tokens=["device_token_123", "device_token_456"],
        preferences={
            "email_enabled": True,
            "sms_enabled": True,
            "push_enabled": True,
            "in_app_enabled": True,
            "marketing_enabled": False,
            "quiet_hours_enabled": True,
            "quiet_hours_start": "22:00",
            "quiet_hours_end": "08:00",
            "timezone": "UTC",
        },
    )


@pytest.fixture
def unsubscribed_recipient(sample_recipient_id):
    """Recipient who has unsubscribed from marketing."""
    recipient = NotificationRecipient(
        recipient_id=sample_recipient_id,
        email_addresses=["unsubscribed@example.com"],
        preferences={
            "email_enabled": True,
            "marketing_enabled": False,
            "transactional_enabled": True,
        },
    )
    recipient.block_channel(NotificationChannel.EMAIL, "User unsubscribed")
    return recipient


@pytest.fixture
def blocked_recipient(sample_recipient_id):
    """Recipient blocked due to bounces."""
    recipient = NotificationRecipient(
        recipient_id=sample_recipient_id,
        email_addresses=["blocked@example.com"],
        status=RecipientStatus.BOUNCED,
    )
    recipient.block_channel(NotificationChannel.EMAIL, "Hard bounce")
    return recipient


# ============================================================================
# Schedule Fixtures
# ============================================================================


@pytest.fixture
def basic_schedule(sample_user_id):
    """Basic notification schedule."""
    notification_request = {
        "recipient_id": uuid4(),
        "channel": NotificationChannel.EMAIL,
        "template_id": uuid4(),
        "variables": {"user_name": "John Doe"},
        "priority": NotificationPriority.NORMAL,
    }

    return NotificationSchedule(
        notification_request=notification_request,
        scheduled_for=datetime.utcnow() + timedelta(hours=1),
        created_by=sample_user_id,
        metadata={"test_schedule": True},
    )


@pytest.fixture
def recurring_schedule(sample_user_id):
    """Recurring notification schedule."""
    notification_request = {
        "recipient_id": uuid4(),
        "channel": NotificationChannel.EMAIL,
        "template_id": uuid4(),
        "variables": {"report_type": "daily"},
        "priority": NotificationPriority.NORMAL,
    }

    return NotificationSchedule(
        notification_request=notification_request,
        scheduled_for=datetime.utcnow() + timedelta(hours=1),
        is_recurring=True,
        recurrence_pattern="daily",
        recurrence_interval=1,
        recurrence_end_date=datetime.utcnow() + timedelta(days=30),
        created_by=sample_user_id,
        metadata={"schedule_type": "daily_report"},
    )


# ============================================================================
# Channel Configuration Fixtures
# ============================================================================


@pytest.fixture
def email_channel_config():
    """Email channel configuration."""
    return ChannelConfig(
        channel=NotificationChannel.EMAIL,
        provider="sendgrid",
        settings={
            "from_email": "noreply@example.com",
            "from_name": "Test Application",
            "reply_to": "support@example.com",
        },
        credentials={
            "api_key": "encrypted_sendgrid_key",
            "webhook_secret": "encrypted_webhook_secret",
        },
        rate_limits={"per_second": 100, "per_minute": 6000, "per_hour": 360000},
        features=["templates", "tracking", "webhooks", "attachments"],
    )


@pytest.fixture
def sms_channel_config():
    """SMS channel configuration."""
    return ChannelConfig(
        channel=NotificationChannel.SMS,
        provider="twilio",
        settings={
            "from_number": "+1234567890",
            "webhook_url": "https://api.example.com/webhooks/sms",
        },
        credentials={
            "account_sid": "encrypted_twilio_sid",
            "auth_token": "encrypted_twilio_token",
        },
        rate_limits={"per_second": 10, "per_minute": 600, "per_hour": 36000},
        features=["delivery_status", "webhooks"],
    )


@pytest.fixture
def push_channel_config():
    """Push notification channel configuration."""
    return ChannelConfig(
        channel=NotificationChannel.PUSH,
        provider="firebase",
        settings={
            "project_id": "test-project-123",
            "service_account_path": "/path/to/service-account.json",
        },
        credentials={
            "private_key": "encrypted_firebase_key",
            "client_email": "firebase-service@test-project.iam.gserviceaccount.com",
        },
        rate_limits={"per_second": 1000, "per_minute": 60000},
        features=["topic_messaging", "device_groups", "analytics"],
    )


# ============================================================================
# Mock Services and Adapters
# ============================================================================


@pytest.fixture
def mock_email_adapter():
    """Mock email adapter for testing."""
    adapter = Mock()
    adapter.send_email = AsyncMock(
        return_value={
            "message_id": "msg_123",
            "status": "sent",
            "provider_response": {"accepted": ["john.doe@example.com"]},
        }
    )
    adapter.get_delivery_status = AsyncMock(
        return_value={
            "status": "delivered",
            "delivered_at": datetime.utcnow().isoformat(),
        }
    )
    adapter.validate_configuration = Mock(return_value=True)
    adapter.get_rate_limits = Mock(return_value={"per_second": 100})
    return adapter


@pytest.fixture
def mock_sms_adapter():
    """Mock SMS adapter for testing."""
    adapter = Mock()
    adapter.send_sms = AsyncMock(
        return_value={
            "message_id": "sms_456",
            "status": "sent",
            "provider_response": {"sid": "SMS123456789"},
        }
    )
    adapter.get_delivery_status = AsyncMock(
        return_value={
            "status": "delivered",
            "delivered_at": datetime.utcnow().isoformat(),
        }
    )
    adapter.validate_phone_number = Mock(return_value=True)
    adapter.estimate_cost = Mock(return_value={"amount": 0.05, "currency": "USD"})
    return adapter


@pytest.fixture
def mock_push_adapter():
    """Mock push notification adapter for testing."""
    adapter = Mock()
    adapter.send_push = AsyncMock(
        return_value={
            "message_id": "push_789",
            "status": "sent",
            "provider_response": {"multicast_id": 123456789},
        }
    )
    adapter.validate_device_token = Mock(return_value=True)
    adapter.get_device_info = AsyncMock(
        return_value={
            "platform": "android",
            "app_version": "1.2.3",
            "last_seen": datetime.utcnow().isoformat(),
        }
    )
    return adapter


@pytest.fixture
def mock_queue_service():
    """Mock queue service for testing."""
    service = Mock()
    service.enqueue_notification = AsyncMock(return_value="queue_id_123")
    service.enqueue_batch = AsyncMock(return_value="batch_queue_id_456")
    service.get_queue_status = AsyncMock(
        return_value={"pending": 5, "processing": 2, "completed": 100, "failed": 3}
    )
    service.clear_queue = AsyncMock(return_value=True)
    return service


@pytest.fixture
def mock_template_repository():
    """Mock template repository for testing."""
    repo = Mock()
    repo.save = AsyncMock()
    repo.find_by_id = AsyncMock()
    repo.find_by_code = AsyncMock()
    repo.find_active_templates = AsyncMock(return_value=[])
    repo.search = AsyncMock(return_value=[])
    repo.delete = AsyncMock()
    return repo


@pytest.fixture
def mock_notification_repository():
    """Mock notification repository for testing."""
    repo = Mock()
    repo.save = AsyncMock()
    repo.find_by_id = AsyncMock()
    repo.find_by_idempotency_key = AsyncMock()
    repo.find_pending_notifications = AsyncMock(return_value=[])
    repo.find_failed_notifications = AsyncMock(return_value=[])
    repo.get_delivery_stats = AsyncMock(return_value={})
    return repo


@pytest.fixture
def mock_delivery_service():
    """Mock delivery service for testing."""
    service = Mock()
    service.send = AsyncMock()
    service.send_batch = AsyncMock()
    service.get_provider_status = AsyncMock(return_value={"status": "healthy"})
    service.estimate_delivery_time = Mock(return_value=timedelta(seconds=30))
    return service


# ============================================================================
# Performance Testing Fixtures
# ============================================================================


@pytest.fixture
def performance_test_data():
    """Generate large dataset for performance testing."""
    return {
        "recipients": [uuid4() for _ in range(1000)],
        "templates": [f"template_{i}" for i in range(20)],
        "notification_batches": [
            {
                "size": 100,
                "priority": NotificationPriority.NORMAL,
                "channel": NotificationChannel.EMAIL,
            },
            {
                "size": 500,
                "priority": NotificationPriority.HIGH,
                "channel": NotificationChannel.SMS,
            },
            {
                "size": 1000,
                "priority": NotificationPriority.LOW,
                "channel": NotificationChannel.PUSH,
            },
        ],
    }


@pytest.fixture
def memory_profiler():
    """Memory usage profiler for performance tests."""
    import os

    import psutil

    class MemoryProfiler:
        def __init__(self):
            self.process = psutil.Process(os.getpid())
            self.start_memory = None

        def start(self):
            self.start_memory = self.process.memory_info().rss

        def get_current_usage(self):
            return self.process.memory_info().rss

        def get_peak_usage(self):
            if self.start_memory:
                return self.get_current_usage() - self.start_memory
            return self.get_current_usage()

        def get_usage_mb(self):
            return self.get_peak_usage() / 1024 / 1024

    return MemoryProfiler()


@pytest.fixture
def time_profiler():
    """Time profiler for performance tests."""
    import time

    class TimeProfiler:
        def __init__(self):
            self.start_time = None
            self.checkpoints = []

        def start(self):
            self.start_time = time.perf_counter()

        def checkpoint(self, name: str):
            if self.start_time:
                elapsed = time.perf_counter() - self.start_time
                self.checkpoints.append((name, elapsed))

        def get_total_time(self):
            if self.start_time:
                return time.perf_counter() - self.start_time
            return 0

        def get_checkpoints(self):
            return self.checkpoints

        def reset(self):
            self.start_time = None
            self.checkpoints = []

    return TimeProfiler()


# ============================================================================
# Test Data Generators
# ============================================================================


@pytest.fixture
def notification_factory():
    """Factory for creating test notifications."""

    def create_notification(
        channel: NotificationChannel = NotificationChannel.EMAIL,
        priority: NotificationPriority = NotificationPriority.NORMAL,
        template_id: UUID | None = None,
        expires_in_hours: int = 24,
        metadata: dict[str, Any] | None = None,
    ) -> Notification:
        recipient_id = uuid4()

        # Create appropriate recipient address
        if channel == NotificationChannel.EMAIL:
            address = RecipientAddress(channel, "test@example.com")
        elif channel == NotificationChannel.SMS:
            address = RecipientAddress(channel, "+1234567890")
        elif channel == NotificationChannel.PUSH:
            address = RecipientAddress(channel, "device_token_123")
        else:
            address = RecipientAddress(channel, str(uuid4()))

        # Create content
        content = NotificationContent(
            subject="Test Subject"
            if channel in [NotificationChannel.EMAIL, NotificationChannel.PUSH]
            else None,
            body="Test notification body",
            metadata=metadata or {},
        )

        return Notification(
            recipient_id=recipient_id,
            channel=channel,
            content=content,
            recipient_address=address,
            template_id=template_id,
            priority=NotificationPriorityValue(level=priority),
            expires_at=datetime.utcnow() + timedelta(hours=expires_in_hours),
            metadata=metadata or {},
        )

    return create_notification


@pytest.fixture
def template_factory():
    """Factory for creating test templates."""

    def create_template(
        name: str = "Test Template",
        template_type: TemplateType = TemplateType.TRANSACTIONAL,
        channels: list[NotificationChannel] | None = None,
        variables: list[str] | None = None,
        is_active: bool = True,
    ) -> NotificationTemplate:
        user_id = uuid4()
        template = NotificationTemplate(
            name=name,
            template_type=template_type,
            created_by=user_id,
            description=f"Test template: {name}",
        )

        # Add content for specified channels
        channels = channels or [NotificationChannel.EMAIL]
        for channel in channels:
            if channel == NotificationChannel.EMAIL:
                content = NotificationContent(
                    subject="{{subject_var}} - {{user_name}}",
                    body="Hello {{user_name}}, {{message}}",
                    html_body="<p>Hello {{user_name}}, {{message}}</p>",
                )
            elif channel == NotificationChannel.SMS:
                content = NotificationContent(body="{{user_name}}: {{message}}")
            else:
                content = NotificationContent(
                    subject="{{subject_var}}", body="{{message}}"
                )

            template.add_channel_content(channel, content, user_id)

        # Add variables
        variables = variables or ["user_name", "message", "subject_var"]
        for var_name in variables:
            variable = TemplateVariable(
                name=var_name,
                var_type=VariableType.STRING,
                required=True,
                description=f"Test variable: {var_name}",
            )
            template.define_variable(variable, user_id)

        if not is_active:
            template.deactivate(user_id, "Test deactivation")

        return template

    return create_template


# ============================================================================
# Event Loop for Async Testing
# ============================================================================


@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


# ============================================================================
# Test Case Parametrization Data
# ============================================================================


@pytest.fixture
def all_notification_channels():
    """All available notification channels for parametrized tests."""
    return list(NotificationChannel)


@pytest.fixture
def all_notification_priorities():
    """All available notification priorities for parametrized tests."""
    return list(NotificationPriority)


@pytest.fixture
def all_template_types():
    """All available template types for parametrized tests."""
    return list(TemplateType)


@pytest.fixture
def all_delivery_statuses():
    """All available delivery statuses for parametrized tests."""
    return list(DeliveryStatus)


@pytest.fixture
def variable_type_test_data():
    """Test data for different variable types."""
    return {
        VariableType.STRING: ["hello", "world", "test string"],
        VariableType.NUMBER: [123, 45.67, 0, -10],
        VariableType.BOOLEAN: [True, False],
        VariableType.DATE: ["2023-12-25", "2024-01-01"],
        VariableType.DATETIME: ["2023-12-25T12:00:00Z", "2024-01-01T00:00:00Z"],
        VariableType.URL: ["https://example.com", "http://test.org"],
        VariableType.EMAIL: ["test@example.com", "user@domain.org"],
        VariableType.CURRENCY: [19.99, 100.0, 0.01],
    }


@pytest.fixture
def invalid_variable_type_test_data():
    """Invalid test data for different variable types."""
    return {
        VariableType.STRING: [123, True, None],
        VariableType.NUMBER: ["not_a_number", True, None],
        VariableType.BOOLEAN: ["true", 1, None],
        VariableType.URL: ["not_a_url", "ftp://invalid", None],
        VariableType.EMAIL: ["invalid_email", "@domain.com", None],
        VariableType.CURRENCY: ["not_currency", True, None],
    }
