"""Integration tests for multi-channel notification workflows.

This module tests end-to-end notification workflows across multiple channels,
including template rendering, channel-specific constraints, variable validation,
and complex delivery scenarios.
"""

from datetime import datetime, timedelta
from uuid import uuid4

import pytest

from app.modules.notification.domain.aggregates.notification_template import (
    NotificationTemplate,
)
from app.modules.notification.domain.entities.notification import Notification
from app.modules.notification.domain.enums import (
    DeliveryStatus,
    NotificationChannel,
    NotificationPriority,
    TemplateType,
    VariableType,
)
from app.modules.notification.domain.errors import (
    InvalidTemplateError,
    TemplateVariableError,
)
from app.modules.notification.domain.value_objects import (
    NotificationContent,
    NotificationPriorityValue,
    RecipientAddress,
    TemplateVariable,
)


class TestMultiChannelTemplateWorkflows:
    """Test suite for multi-channel template workflows."""

    def test_create_complete_multi_channel_template(self, sample_user_id):
        """Test creating a complete template supporting all channels."""
        template = NotificationTemplate(
            name="Complete Multi-Channel Alert",
            template_type=TemplateType.ALERT,
            created_by=sample_user_id,
            description="System alert template for all channels",
            tags=["alert", "system", "critical"],
        )

        # Define comprehensive variables
        variables = [
            TemplateVariable(
                name="alert_type",
                var_type=VariableType.STRING,
                required=True,
                description="Type of alert (e.g., 'Security', 'System')",
                validation_rules={"min_length": 3, "max_length": 50},
            ),
            TemplateVariable(
                name="message",
                var_type=VariableType.STRING,
                required=True,
                description="Alert message content",
                validation_rules={"min_length": 10, "max_length": 500},
            ),
            TemplateVariable(
                name="severity",
                var_type=VariableType.STRING,
                required=True,
                description="Alert severity level",
                validation_rules={"pattern": r"^(low|medium|high|critical)$"},
            ),
            TemplateVariable(
                name="timestamp",
                var_type=VariableType.DATETIME,
                required=True,
                description="When the alert occurred",
            ),
            TemplateVariable(
                name="action_url",
                var_type=VariableType.URL,
                required=False,
                description="URL for taking action on the alert",
            ),
            TemplateVariable(
                name="contact_email",
                var_type=VariableType.EMAIL,
                required=False,
                default_value="support@example.com",
                description="Contact email for support",
            ),
        ]

        for variable in variables:
            template.define_variable(variable, sample_user_id)

        # Add email content (detailed)
        email_content = NotificationContent(
            subject="🚨 {{alert_type}} Alert - {{severity|upper}}",
            body="""ALERT NOTIFICATION

Type: {{alert_type}}
Severity: {{severity|upper}}
Time: {{timestamp}}

Message:
{{message}}

{% if action_url %}
Take Action: {{action_url}}
{% endif %}

For assistance, contact: {{contact_email}}

This is an automated message. Please do not reply directly to this email.""",
            html_body="""
<html>
<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
    <div style="background-color: #f8f9fa; padding: 20px; border-radius: 8px;">
        <h1 style="color: #dc3545; margin-top: 0;">🚨 {{alert_type}} Alert</h1>
        <div style="background-color: {% if severity == 'critical' %}#dc3545{% elif severity == 'high' %}#fd7e14{% elif severity == 'medium' %}#ffc107{% else %}#20c997{% endif %}; color: white; padding: 8px 16px; border-radius: 4px; display: inline-block; font-weight: bold;">
            {{severity|upper}} SEVERITY
        </div>
        
        <div style="margin: 20px 0; padding: 15px; background-color: white; border-left: 4px solid #dc3545; border-radius: 4px;">
            <p style="margin: 0; font-size: 16px;"><strong>{{message}}</strong></p>
            <p style="margin: 10px 0 0 0; color: #666; font-size: 14px;">
                <strong>Time:</strong> {{timestamp}}<br>
                <strong>Type:</strong> {{alert_type}}
            </p>
        </div>
        
        {% if action_url %}
        <div style="text-align: center; margin: 20px 0;">
            <a href="{{action_url}}" style="background-color: #007bff; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; display: inline-block; font-weight: bold;">Take Action</a>
        </div>
        {% endif %}
        
        <hr style="border: none; border-top: 1px solid #dee2e6; margin: 20px 0;">
        <p style="color: #666; font-size: 12px; margin: 0;">
            For assistance, contact: <a href="mailto:{{contact_email}}">{{contact_email}}</a><br>
            This is an automated message. Please do not reply directly to this email.
        </p>
    </div>
</body>
</html>""",
            variables={"platform_name": "AlertSystem", "company_name": "TechCorp"},
        )
        template.add_channel_content(
            NotificationChannel.EMAIL, email_content, sample_user_id
        )

        # Add SMS content (concise)
        sms_content = NotificationContent(
            body="🚨 {{alert_type|upper}}: {{message|truncate:120}} - {{severity|upper}} at {{timestamp|date:'H:i'}}{% if action_url %} - {{action_url}}{% endif %}"
        )
        template.add_channel_content(
            NotificationChannel.SMS, sms_content, sample_user_id
        )

        # Add push notification content (brief)
        push_content = NotificationContent(
            subject="{{alert_type}} Alert",
            body="{{severity|upper}}: {{message|truncate:80}}",
        )
        template.add_channel_content(
            NotificationChannel.PUSH, push_content, sample_user_id
        )

        # Add in-app content (interactive)
        in_app_content = NotificationContent(
            subject="System Alert",
            body="{{message}}",
            html_body="""
<div class="alert alert-{{severity}}" data-alert-type="{{alert_type}}" data-timestamp="{{timestamp}}">
    <div class="alert-header">
        <span class="alert-icon">🚨</span>
        <h3>{{alert_type}} Alert</h3>
        <span class="severity-badge severity-{{severity}}">{{severity|upper}}</span>
    </div>
    <div class="alert-body">
        <p class="alert-message">{{message}}</p>
        <div class="alert-meta">
            <span class="timestamp">{{timestamp}}</span>
        </div>
    </div>
    {% if action_url %}
    <div class="alert-actions">
        <a href="{{action_url}}" class="btn btn-primary">Take Action</a>
        <button class="btn btn-secondary" onclick="dismissAlert()">Dismiss</button>
    </div>
    {% endif %}
</div>""",
            metadata={
                "dismissible": True,
                "priority": "{{severity}}",
                "category": "system_alert",
            },
        )
        template.add_channel_content(
            NotificationChannel.IN_APP, in_app_content, sample_user_id
        )

        # Set email and SMS as required channels
        template.set_required_channels(
            [NotificationChannel.EMAIL, NotificationChannel.SMS], sample_user_id
        )

        # Verify template creation
        assert template.name == "Complete Multi-Channel Alert"
        assert len(template.channel_contents) == 4
        assert len(template.variables) == 6  # Original variables
        assert len(template.required_channels) == 2
        assert template.version > 1  # Should have incremented during setup

        # Verify all channels are supported
        supported_channels = template.get_supported_channels()
        expected_channels = [
            NotificationChannel.EMAIL,
            NotificationChannel.SMS,
            NotificationChannel.PUSH,
            NotificationChannel.IN_APP,
        ]
        for channel in expected_channels:
            assert channel in supported_channels

        return template

    def test_render_template_for_all_channels(self, sample_user_id):
        """Test rendering the same template for all channels with different optimizations."""
        template = self.test_create_complete_multi_channel_template(sample_user_id)

        # Test variables
        test_variables = {
            "alert_type": "Security Breach",
            "message": "Unauthorized access attempt detected from IP 192.168.1.100. Immediate action required to secure the system.",
            "severity": "critical",
            "timestamp": "2023-12-25T14:30:00Z",
            "action_url": "https://admin.example.com/security/incidents/123",
            "contact_email": "security@example.com",
        }

        # Render for email
        email_content = template.render_for_channel(
            NotificationChannel.EMAIL, test_variables
        )
        assert "Security Breach Alert" in email_content.subject
        assert "CRITICAL" in email_content.subject
        assert "Security Breach" in email_content.body
        assert "Unauthorized access attempt detected" in email_content.body
        assert "security@example.com" in email_content.body
        assert "https://admin.example.com/security/incidents/123" in email_content.body
        assert "<html>" in email_content.html_body
        assert "CRITICAL SEVERITY" in email_content.html_body

        # Render for SMS
        sms_content = template.render_for_channel(
            NotificationChannel.SMS, test_variables
        )
        assert "SECURITY BREACH" in sms_content.body.upper()
        assert "CRITICAL" in sms_content.body
        assert len(sms_content.body) <= 160  # SMS length constraint
        assert sms_content.subject is None  # SMS doesn't use subject
        assert sms_content.html_body is None  # SMS doesn't use HTML

        # Render for push
        push_content = template.render_for_channel(
            NotificationChannel.PUSH, test_variables
        )
        assert push_content.subject == "Security Breach Alert"
        assert "CRITICAL:" in push_content.body
        assert len(push_content.body) <= 100  # Push length constraint
        assert sms_content.html_body is None  # Push doesn't use HTML in this case

        # Render for in-app
        in_app_content = template.render_for_channel(
            NotificationChannel.IN_APP, test_variables
        )
        assert in_app_content.subject == "System Alert"
        assert "Unauthorized access attempt detected" in in_app_content.body
        assert "alert-critical" in in_app_content.html_body
        assert "Take Action" in in_app_content.html_body
        assert in_app_content.metadata["dismissible"] is True

    def test_template_variable_validation_across_channels(self, sample_user_id):
        """Test template variable validation works consistently across channels."""
        template = self.test_create_complete_multi_channel_template(sample_user_id)

        # Test with valid variables
        valid_variables = {
            "alert_type": "System Maintenance",
            "message": "Scheduled maintenance will begin at 2 AM EST. Expected downtime: 30 minutes.",
            "severity": "medium",
            "timestamp": "2023-12-26T07:00:00Z",
            "action_url": "https://status.example.com",
            "contact_email": "support@example.com",
        }

        # Should work for all channels
        for channel in template.get_supported_channels():
            rendered = template.render_for_channel(channel, valid_variables)
            assert rendered is not None

        # Test with missing required variable
        invalid_variables_missing = {
            "alert_type": "System Alert",
            # Missing required 'message'
            "severity": "high",
            "timestamp": "2023-12-26T07:00:00Z",
        }

        with pytest.raises(TemplateVariableError) as exc_info:
            template.render_for_channel(
                NotificationChannel.EMAIL, invalid_variables_missing
            )

        error = exc_info.value
        assert "message" in error.missing_variables

        # Test with invalid variable format
        invalid_variables_format = {
            "alert_type": "System Alert",
            "message": "Valid message content here for testing purposes.",
            "severity": "invalid_severity",  # Should match pattern
            "timestamp": "2023-12-26T07:00:00Z",
            "action_url": "not_a_valid_url",  # Should be valid URL
            "contact_email": "invalid_email_format",  # Should be valid email
        }

        with pytest.raises(TemplateVariableError) as exc_info:
            template.render_for_channel(
                NotificationChannel.EMAIL, invalid_variables_format
            )

        error = exc_info.value
        assert len(error.invalid_variables) > 0

    def test_channel_specific_constraint_enforcement(self, sample_user_id):
        """Test that channel-specific constraints are enforced."""
        template = NotificationTemplate(
            name="Constraint Test Template",
            template_type=TemplateType.TRANSACTIONAL,
            created_by=sample_user_id,
        )

        # Test email requires subject
        email_content_no_subject = NotificationContent(
            body="Email body without subject"
        )

        with pytest.raises(
            InvalidTemplateError, match="Email templates require a subject"
        ):
            template.add_channel_content(
                NotificationChannel.EMAIL, email_content_no_subject, sample_user_id
            )

        # Test SMS length constraint
        long_sms_body = "A" * 1601  # Exceeds 1600 character limit
        sms_content_too_long = NotificationContent(body=long_sms_body)

        with pytest.raises(
            InvalidTemplateError,
            match="SMS template body cannot exceed 1600 characters",
        ):
            template.add_channel_content(
                NotificationChannel.SMS, sms_content_too_long, sample_user_id
            )

        # Test push notification title length constraint
        long_push_title = "A" * 66  # Exceeds 65 character limit
        push_content_long_title = NotificationContent(
            subject=long_push_title, body="Push body"
        )

        with pytest.raises(
            InvalidTemplateError,
            match="Push notification title cannot exceed 65 characters",
        ):
            template.add_channel_content(
                NotificationChannel.PUSH, push_content_long_title, sample_user_id
            )

        # Test push notification body length constraint
        long_push_body = "A" * 241  # Exceeds 240 character limit
        push_content_long_body = NotificationContent(
            subject="Push Title", body=long_push_body
        )

        with pytest.raises(
            InvalidTemplateError,
            match="Push notification body cannot exceed 240 characters",
        ):
            template.add_channel_content(
                NotificationChannel.PUSH, push_content_long_body, sample_user_id
            )

    def test_template_versioning_with_channel_changes(self, sample_user_id):
        """Test template versioning when making channel-specific changes."""
        template = NotificationTemplate(
            name="Version Test Template",
            template_type=TemplateType.SYSTEM,
            created_by=sample_user_id,
        )

        initial_version = template.version
        assert initial_version == 1

        # Add email content
        email_content = NotificationContent(
            subject="Email Subject v1", body="Email body v1"
        )
        template.add_channel_content(
            NotificationChannel.EMAIL, email_content, sample_user_id
        )
        assert template.version == initial_version + 1

        # Add SMS content
        sms_content = NotificationContent(body="SMS body v1")
        template.add_channel_content(
            NotificationChannel.SMS, sms_content, sample_user_id
        )
        assert template.version == initial_version + 2

        # Update existing email content
        updated_email_content = NotificationContent(
            subject="Email Subject v2", body="Email body v2 with changes"
        )
        template.add_channel_content(
            NotificationChannel.EMAIL, updated_email_content, sample_user_id
        )
        assert template.version == initial_version + 3

        # Remove SMS content
        template.remove_channel_content(NotificationChannel.SMS, sample_user_id)
        assert template.version == initial_version + 4

        # Add variable
        variable = TemplateVariable("test_var", VariableType.STRING, required=True)
        template.define_variable(variable, sample_user_id)
        assert template.version == initial_version + 5

        # Check version history
        assert len(template.version_history) == 5

        # Verify version history content
        history_descriptions = [
            entry["description"] for entry in template.version_history
        ]
        assert "Added/updated email content" in history_descriptions[0]
        assert "Added/updated sms content" in history_descriptions[1]
        assert "Added/updated email content" in history_descriptions[2]
        assert "Removed sms content" in history_descriptions[3]
        assert "defined variable test_var" in history_descriptions[4]


class TestMultiChannelNotificationWorkflows:
    """Test suite for multi-channel notification delivery workflows."""

    def test_create_notifications_for_all_channels(
        self, multi_channel_template, sample_user_id
    ):
        """Test creating notifications for all supported channels."""
        recipient_id = uuid4()

        # Test variables for rendering
        variables = {
            "alert_type": "Database Alert",
            "message": "Database connection pool exhausted. Immediate attention required.",
            "timestamp": "2023-12-25T15:45:00Z",
            "severity": "high",
        }

        notifications = {}

        # Create email notification
        email_address = RecipientAddress(
            channel=NotificationChannel.EMAIL,
            address="admin@example.com",
            display_name="System Administrator",
        )
        email_content = multi_channel_template.render_for_channel(
            NotificationChannel.EMAIL, variables
        )
        email_notification = Notification(
            recipient_id=recipient_id,
            channel=NotificationChannel.EMAIL,
            content=email_content,
            recipient_address=email_address,
            template_id=multi_channel_template.id,
            priority=NotificationPriorityValue(level=NotificationPriority.HIGH),
            metadata={"template_version": multi_channel_template.version},
        )
        notifications[NotificationChannel.EMAIL] = email_notification

        # Create SMS notification
        sms_address = RecipientAddress(
            channel=NotificationChannel.SMS, address="+1234567890"
        )
        sms_content = multi_channel_template.render_for_channel(
            NotificationChannel.SMS, variables
        )
        sms_notification = Notification(
            recipient_id=recipient_id,
            channel=NotificationChannel.SMS,
            content=sms_content,
            recipient_address=sms_address,
            template_id=multi_channel_template.id,
            priority=NotificationPriorityValue(level=NotificationPriority.URGENT),
            metadata={"template_version": multi_channel_template.version},
        )
        notifications[NotificationChannel.SMS] = sms_notification

        # Create push notification
        push_address = RecipientAddress(
            channel=NotificationChannel.PUSH,
            address="device_token_admin_mobile_app_xyz789",
        )
        push_content = multi_channel_template.render_for_channel(
            NotificationChannel.PUSH, variables
        )
        push_notification = Notification(
            recipient_id=recipient_id,
            channel=NotificationChannel.PUSH,
            content=push_content,
            recipient_address=push_address,
            template_id=multi_channel_template.id,
            priority=NotificationPriorityValue(level=NotificationPriority.HIGH),
            metadata={"template_version": multi_channel_template.version},
        )
        notifications[NotificationChannel.PUSH] = push_notification

        # Create in-app notification
        in_app_address = RecipientAddress(
            channel=NotificationChannel.IN_APP,
            address=str(recipient_id),
            display_name="System Administrator",
        )
        in_app_content = multi_channel_template.render_for_channel(
            NotificationChannel.IN_APP, variables
        )
        in_app_notification = Notification(
            recipient_id=recipient_id,
            channel=NotificationChannel.IN_APP,
            content=in_app_content,
            recipient_address=in_app_address,
            template_id=multi_channel_template.id,
            priority=NotificationPriorityValue(level=NotificationPriority.HIGH),
            metadata={"template_version": multi_channel_template.version},
        )
        notifications[NotificationChannel.IN_APP] = in_app_notification

        # Verify all notifications were created correctly
        assert len(notifications) == 4

        for channel, notification in notifications.items():
            assert notification.recipient_id == recipient_id
            assert notification.channel == channel
            assert notification.template_id == multi_channel_template.id
            assert notification.current_status == DeliveryStatus.PENDING
            assert (
                "Database Alert" in notification.content.body
                or "DATABASE ALERT" in notification.content.body.upper()
            )

            # Verify channel-specific content optimizations
            if channel == NotificationChannel.SMS:
                assert notification.content.subject is None
                assert len(notification.content.body) <= 160
            elif channel == NotificationChannel.PUSH:
                assert notification.content.subject is not None
                assert len(notification.content.body) <= 100
            elif channel == NotificationChannel.EMAIL:
                assert notification.content.subject is not None
                assert (
                    notification.content.html_body is None
                    or "alert" in notification.content.html_body.lower()
                )
            elif channel == NotificationChannel.IN_APP:
                assert notification.content.html_body is not None

        return notifications

    def test_priority_based_delivery_workflow(
        self, multi_channel_template, sample_user_id
    ):
        """Test notification delivery workflow based on priority levels."""
        notifications = self.test_create_notifications_for_all_channels(
            multi_channel_template, sample_user_id
        )

        # Simulate delivery workflow with different priorities
        priorities_and_channels = [
            (NotificationPriority.URGENT, NotificationChannel.SMS),
            (NotificationPriority.HIGH, NotificationChannel.EMAIL),
            (NotificationPriority.HIGH, NotificationChannel.PUSH),
            (NotificationPriority.NORMAL, NotificationChannel.IN_APP),
        ]

        for priority, channel in priorities_and_channels:
            notification = notifications[channel]

            # Update priority if needed
            if notification.priority.level != priority:
                notification.priority = NotificationPriorityValue(level=priority)

            # Simulate delivery process based on priority
            if priority == NotificationPriority.URGENT:
                # Urgent: immediate delivery
                notification.update_status(
                    DeliveryStatus.QUEUED, details="High priority queue"
                )
                notification.update_status(
                    DeliveryStatus.SENDING, details="Immediate send"
                )
                notification.update_status(
                    DeliveryStatus.SENT, details="Sent immediately"
                )

                # Verify urgent notification characteristics
                assert (
                    notification.max_retries
                    == NotificationPriority.URGENT.max_retry_attempts()
                )
                assert (
                    notification.priority.level.retry_delay_seconds() == 60
                )  # 1 minute

            elif priority == NotificationPriority.HIGH:
                # High: fast delivery
                notification.update_status(
                    DeliveryStatus.QUEUED, details="High priority queue"
                )
                notification.update_status(DeliveryStatus.SENDING, details="Fast send")
                notification.update_status(DeliveryStatus.SENT, details="Sent quickly")

                # Verify high priority characteristics
                assert (
                    notification.max_retries
                    == NotificationPriority.HIGH.max_retry_attempts()
                )
                assert (
                    notification.priority.level.retry_delay_seconds() == 300
                )  # 5 minutes

            else:
                # Normal: standard delivery
                notification.update_status(
                    DeliveryStatus.QUEUED, details="Standard queue"
                )

                # Verify normal priority characteristics
                assert (
                    notification.max_retries
                    == NotificationPriority.NORMAL.max_retry_attempts()
                )
                assert (
                    notification.priority.level.retry_delay_seconds() == 900
                )  # 15 minutes

        # Verify delivery order based on priority
        urgent_notification = notifications[NotificationChannel.SMS]
        high_notifications = [
            notifications[NotificationChannel.EMAIL],
            notifications[NotificationChannel.PUSH],
        ]
        normal_notification = notifications[NotificationChannel.IN_APP]

        assert urgent_notification.current_status == DeliveryStatus.SENT
        for high_notif in high_notifications:
            assert high_notif.current_status == DeliveryStatus.SENT
        assert normal_notification.current_status == DeliveryStatus.QUEUED

    def test_channel_fallback_workflow(self, multi_channel_template, sample_user_id):
        """Test fallback workflow when primary channels fail."""
        notifications = self.test_create_notifications_for_all_channels(
            multi_channel_template, sample_user_id
        )

        # Primary channel: Email (attempt and fail)
        email_notification = notifications[NotificationChannel.EMAIL]
        email_notification.update_status(DeliveryStatus.QUEUED)
        email_notification.update_status(DeliveryStatus.SENDING)
        email_notification.update_status(
            DeliveryStatus.FAILED,
            details="SMTP server unavailable",
            error_code="SMTP_503",
        )

        # Attempt retry and fail again
        email_notification.mark_for_retry()
        email_notification.update_status(DeliveryStatus.SENDING)
        email_notification.update_status(
            DeliveryStatus.FAILED,
            details="Recipient mailbox full",
            error_code="MAILBOX_FULL",
        )

        # Fallback to SMS
        sms_notification = notifications[NotificationChannel.SMS]
        sms_notification.update_status(DeliveryStatus.QUEUED, details="Email fallback")
        sms_notification.update_status(DeliveryStatus.SENDING)
        sms_notification.update_status(DeliveryStatus.SENT)
        sms_notification.update_status(DeliveryStatus.DELIVERED)

        # Also send push as additional channel
        push_notification = notifications[NotificationChannel.PUSH]
        push_notification.update_status(
            DeliveryStatus.QUEUED, details="Additional channel"
        )
        push_notification.update_status(DeliveryStatus.SENDING)
        push_notification.update_status(DeliveryStatus.SENT)
        push_notification.update_status(DeliveryStatus.DELIVERED)

        # In-app notification for persistent visibility
        in_app_notification = notifications[NotificationChannel.IN_APP]
        in_app_notification.update_status(
            DeliveryStatus.QUEUED, details="Persistent notification"
        )
        in_app_notification.update_status(DeliveryStatus.SENDING)
        in_app_notification.update_status(DeliveryStatus.SENT)
        in_app_notification.update_status(DeliveryStatus.DELIVERED)

        # Verify fallback strategy results
        assert email_notification.current_status == DeliveryStatus.FAILED
        assert email_notification.retry_count == 2
        assert sms_notification.is_successful
        assert push_notification.is_successful
        assert in_app_notification.is_successful

        # Verify delivery summary
        successful_channels = []
        failed_channels = []

        for channel, notification in notifications.items():
            if notification.is_successful:
                successful_channels.append(channel)
            else:
                failed_channels.append(channel)

        assert NotificationChannel.EMAIL in failed_channels
        assert NotificationChannel.SMS in successful_channels
        assert NotificationChannel.PUSH in successful_channels
        assert NotificationChannel.IN_APP in successful_channels

        return {
            "successful_channels": successful_channels,
            "failed_channels": failed_channels,
            "notifications": notifications,
        }

    def test_notification_batch_multi_channel_delivery(
        self, multi_channel_template, sample_user_id
    ):
        """Test batch delivery across multiple channels for multiple recipients."""
        recipients = [uuid4() for _ in range(5)]
        variables_template = {
            "alert_type": "Security Alert",
            "message": "Multiple failed login attempts detected for user accounts.",
            "timestamp": "2023-12-25T16:00:00Z",
            "severity": "high",
        }

        batch_notifications = []

        for i, recipient_id in enumerate(recipients):
            # Customize variables per recipient
            variables = variables_template.copy()
            variables["message"] = f"Failed login attempts detected for user {i+1}."

            # Create notifications for multiple channels per recipient
            channels_to_notify = [NotificationChannel.EMAIL, NotificationChannel.SMS]
            if i < 2:  # First two recipients also get push notifications
                channels_to_notify.append(NotificationChannel.PUSH)

            for channel in channels_to_notify:
                # Create appropriate address
                if channel == NotificationChannel.EMAIL:
                    address = RecipientAddress(channel, f"user{i+1}@example.com")
                elif channel == NotificationChannel.SMS:
                    address = RecipientAddress(channel, f"+123456789{i}")
                else:  # PUSH
                    address = RecipientAddress(channel, f"device_token_user_{i+1}")

                # Render content
                content = multi_channel_template.render_for_channel(channel, variables)

                # Create notification
                notification = Notification(
                    recipient_id=recipient_id,
                    channel=channel,
                    content=content,
                    recipient_address=address,
                    template_id=multi_channel_template.id,
                    priority=NotificationPriorityValue(level=NotificationPriority.HIGH),
                    metadata={
                        "batch_id": "security_batch_001",
                        "recipient_index": i,
                        "template_version": multi_channel_template.version,
                    },
                )

                batch_notifications.append(notification)

        # Verify batch creation
        assert len(batch_notifications) == 13  # 5*2 + 2*1 = 12 notifications + 1 extra

        # Group by channel for analysis
        channel_groups = {}
        for notification in batch_notifications:
            channel = notification.channel
            if channel not in channel_groups:
                channel_groups[channel] = []
            channel_groups[channel].append(notification)

        # Verify channel distribution
        assert len(channel_groups[NotificationChannel.EMAIL]) == 5
        assert len(channel_groups[NotificationChannel.SMS]) == 5
        assert len(channel_groups[NotificationChannel.PUSH]) == 2

        # Simulate batch processing
        processing_results = {
            "total": len(batch_notifications),
            "successful": 0,
            "failed": 0,
            "channel_stats": {},
        }

        for channel, notifications in channel_groups.items():
            channel_stats = {"successful": 0, "failed": 0}

            for i, notification in enumerate(notifications):
                notification.update_status(
                    DeliveryStatus.QUEUED, details="Batch processing"
                )
                notification.update_status(DeliveryStatus.SENDING)

                # Simulate some failures for testing
                if channel == NotificationChannel.SMS and i == 2:
                    # Simulate SMS failure
                    notification.update_status(
                        DeliveryStatus.FAILED,
                        details="Invalid phone number",
                        error_code="INVALID_NUMBER",
                    )
                    channel_stats["failed"] += 1
                    processing_results["failed"] += 1
                else:
                    # Successful delivery
                    notification.update_status(DeliveryStatus.SENT)
                    notification.update_status(DeliveryStatus.DELIVERED)
                    channel_stats["successful"] += 1
                    processing_results["successful"] += 1

            processing_results["channel_stats"][channel.value] = channel_stats

        # Verify batch processing results
        assert processing_results["total"] == 13
        assert processing_results["successful"] == 12
        assert processing_results["failed"] == 1
        assert processing_results["channel_stats"]["sms"]["failed"] == 1
        assert processing_results["channel_stats"]["email"]["successful"] == 5
        assert processing_results["channel_stats"]["push"]["successful"] == 2

        return {
            "notifications": batch_notifications,
            "processing_results": processing_results,
            "channel_groups": channel_groups,
        }


class TestComplexMultiChannelScenarios:
    """Test suite for complex multi-channel notification scenarios."""

    def test_time_sensitive_escalation_workflow(
        self, multi_channel_template, sample_user_id
    ):
        """Test time-sensitive notification with escalation across channels."""
        recipient_id = uuid4()

        # Critical security alert variables
        variables = {
            "alert_type": "Security Breach",
            "message": "Unauthorized root access detected on production server. Immediate action required.",
            "timestamp": "2023-12-25T18:30:00Z",
            "severity": "critical",
        }

        # Stage 1: Immediate SMS (most urgent)
        sms_address = RecipientAddress(NotificationChannel.SMS, "+1234567890")
        sms_content = multi_channel_template.render_for_channel(
            NotificationChannel.SMS, variables
        )
        sms_notification = Notification(
            recipient_id=recipient_id,
            channel=NotificationChannel.SMS,
            content=sms_content,
            recipient_address=sms_address,
            template_id=multi_channel_template.id,
            priority=NotificationPriorityValue(level=NotificationPriority.URGENT),
            expires_at=datetime.utcnow() + timedelta(minutes=5),
            metadata={"escalation_stage": 1, "escalation_type": "immediate"},
        )

        # Stage 2: Email with detailed information
        email_address = RecipientAddress(
            NotificationChannel.EMAIL, "security@example.com"
        )
        email_content = multi_channel_template.render_for_channel(
            NotificationChannel.EMAIL, variables
        )
        email_notification = Notification(
            recipient_id=recipient_id,
            channel=NotificationChannel.EMAIL,
            content=email_content,
            recipient_address=email_address,
            template_id=multi_channel_template.id,
            priority=NotificationPriorityValue(level=NotificationPriority.URGENT),
            expires_at=datetime.utcnow() + timedelta(minutes=10),
            metadata={"escalation_stage": 2, "escalation_type": "detailed"},
        )

        # Stage 3: Push notification for mobile response
        push_address = RecipientAddress(
            NotificationChannel.PUSH, "security_team_device_token"
        )
        push_content = multi_channel_template.render_for_channel(
            NotificationChannel.PUSH, variables
        )
        push_notification = Notification(
            recipient_id=recipient_id,
            channel=NotificationChannel.PUSH,
            content=push_content,
            recipient_address=push_address,
            template_id=multi_channel_template.id,
            priority=NotificationPriorityValue(level=NotificationPriority.URGENT),
            expires_at=datetime.utcnow() + timedelta(minutes=15),
            metadata={"escalation_stage": 3, "escalation_type": "mobile_alert"},
        )

        # Stage 4: In-app dashboard alert
        in_app_address = RecipientAddress(NotificationChannel.IN_APP, str(recipient_id))
        in_app_content = multi_channel_template.render_for_channel(
            NotificationChannel.IN_APP, variables
        )
        in_app_notification = Notification(
            recipient_id=recipient_id,
            channel=NotificationChannel.IN_APP,
            content=in_app_content,
            recipient_address=in_app_address,
            template_id=multi_channel_template.id,
            priority=NotificationPriorityValue(level=NotificationPriority.URGENT),
            expires_at=datetime.utcnow() + timedelta(hours=1),
            metadata={"escalation_stage": 4, "escalation_type": "dashboard_persistent"},
        )

        escalation_notifications = [
            sms_notification,
            email_notification,
            push_notification,
            in_app_notification,
        ]

        # Simulate escalation workflow
        for i, notification in enumerate(escalation_notifications, 1):
            # Add small delay between escalation stages
            import time

            if i > 1:
                time.sleep(0.01)

            notification.update_status(
                DeliveryStatus.QUEUED, details=f"Escalation stage {i}"
            )
            notification.update_status(DeliveryStatus.SENDING)
            notification.update_status(DeliveryStatus.SENT)

            # Simulate delivery confirmation
            if notification.channel in [
                NotificationChannel.SMS,
                NotificationChannel.EMAIL,
            ]:
                notification.update_status(DeliveryStatus.DELIVERED)

            # Verify escalation metadata
            assert notification.metadata["escalation_stage"] == i
            assert "escalation_type" in notification.metadata

        # Verify escalation characteristics
        assert sms_notification.expires_at < email_notification.expires_at
        assert email_notification.expires_at < push_notification.expires_at
        assert push_notification.expires_at < in_app_notification.expires_at

        # All should be urgent priority
        for notification in escalation_notifications:
            assert notification.priority.level == NotificationPriority.URGENT
            assert notification.max_retries == 10  # Urgent priority allows more retries

        return escalation_notifications

    def test_localized_multi_channel_template(self, sample_user_id):
        """Test multi-channel template with localization support."""
        template = NotificationTemplate(
            name="Localized Multi-Channel Template",
            template_type=TemplateType.TRANSACTIONAL,
            created_by=sample_user_id,
            description="Template supporting multiple languages",
            tags=["localized", "multi-language", "international"],
        )

        # Define localization variables
        variables = [
            TemplateVariable("user_name", VariableType.STRING, required=True),
            TemplateVariable(
                "locale",
                VariableType.STRING,
                required=True,
                validation_rules={"pattern": r"^(en|es|fr|de|ja)$"},
            ),
            TemplateVariable("product_name", VariableType.STRING, required=True),
            TemplateVariable("amount", VariableType.CURRENCY, required=True),
            TemplateVariable(
                "support_email",
                VariableType.EMAIL,
                required=False,
                default_value="support@example.com",
            ),
        ]

        for variable in variables:
            template.define_variable(variable, sample_user_id)

        # Add localized email content
        email_content = NotificationContent(
            subject="""{% if locale == 'es' %}
¡Gracias por tu compra, {{user_name}}!
{% elif locale == 'fr' %}
Merci pour votre achat, {{user_name}}!
{% elif locale == 'de' %}
Danke für Ihren Kauf, {{user_name}}!
{% elif locale == 'ja' %}
{{user_name}}さん、ご購入ありがとうございます！
{% else %}
Thank you for your purchase, {{user_name}}!
{% endif %}""",
            body="""{% if locale == 'es' %}
Hola {{user_name}},

Gracias por comprar {{product_name}}. 
Total pagado: {{amount}}

Para soporte, contacta: {{support_email}}

Saludos,
El equipo
{% elif locale == 'fr' %}
Bonjour {{user_name}},

Merci d'avoir acheté {{product_name}}.
Total payé: {{amount}}

Pour le support, contactez: {{support_email}}

Cordialement,
L'équipe
{% elif locale == 'de' %}
Hallo {{user_name}},

Vielen Dank für den Kauf von {{product_name}}.
Gezahlter Betrag: {{amount}}

Für Support kontaktieren Sie: {{support_email}}

Mit freundlichen Grüßen,
Das Team
{% elif locale == 'ja' %}
{{user_name}}さん、

{{product_name}}をご購入いただき、ありがとうございます。
お支払い金額: {{amount}}

サポートについては、{{support_email}}にお問い合わせください。

よろしくお願いいたします、
チーム一同
{% else %}
Hello {{user_name}},

Thank you for purchasing {{product_name}}.
Amount paid: {{amount}}

For support, contact: {{support_email}}

Best regards,
The Team
{% endif %}""",
        )
        template.add_channel_content(
            NotificationChannel.EMAIL, email_content, sample_user_id
        )

        # Add localized SMS content (shorter)
        sms_content = NotificationContent(
            body="""{% if locale == 'es' %}
Gracias {{user_name}} por comprar {{product_name}}. Total: {{amount}}
{% elif locale == 'fr' %}
Merci {{user_name}} pour l'achat de {{product_name}}. Total: {{amount}}
{% elif locale == 'de' %}
Danke {{user_name}} für den Kauf von {{product_name}}. Summe: {{amount}}
{% elif locale == 'ja' %}
{{user_name}}さん、{{product_name}}のご購入ありがとうございます。金額: {{amount}}
{% else %}
Thank you {{user_name}} for purchasing {{product_name}}. Total: {{amount}}
{% endif %}"""
        )
        template.add_channel_content(
            NotificationChannel.SMS, sms_content, sample_user_id
        )

        # Test rendering in different locales
        test_locales = [
            ("en", "Thank you for your purchase"),
            ("es", "Gracias por tu compra"),
            ("fr", "Merci pour votre achat"),
            ("de", "Danke für Ihren Kauf"),
            ("ja", "ご購入ありがとうございます"),
        ]

        for locale, expected_phrase in test_locales:
            variables_data = {
                "user_name": "John Doe",
                "locale": locale,
                "product_name": "Premium Plan",
                "amount": 99.99,
                "support_email": f"support-{locale}@example.com",
            }

            # Test email rendering
            email_rendered = template.render_for_channel(
                NotificationChannel.EMAIL, variables_data
            )
            assert (
                expected_phrase in email_rendered.subject
                or expected_phrase in email_rendered.body
            )
            assert "John Doe" in email_rendered.body
            assert "$99.99" in email_rendered.body

            # Test SMS rendering
            sms_rendered = template.render_for_channel(
                NotificationChannel.SMS, variables_data
            )
            assert "John Doe" in sms_rendered.body
            assert "$99.99" in sms_rendered.body

            # Verify locale-specific support email
            if locale != "en":
                assert f"support-{locale}@example.com" in email_rendered.body

        return template

    def test_adaptive_content_based_on_channel_capabilities(self, sample_user_id):
        """Test adaptive content rendering based on channel capabilities."""
        template = NotificationTemplate(
            name="Adaptive Content Template",
            template_type=TemplateType.MARKETING,
            created_by=sample_user_id,
            description="Template that adapts content based on channel capabilities",
        )

        # Define variables
        variables = [
            TemplateVariable("user_name", VariableType.STRING, required=True),
            TemplateVariable("product_name", VariableType.STRING, required=True),
            TemplateVariable("discount_percentage", VariableType.NUMBER, required=True),
            TemplateVariable("promo_code", VariableType.STRING, required=True),
            TemplateVariable("expiry_date", VariableType.DATE, required=True),
            TemplateVariable("product_image_url", VariableType.URL, required=False),
            TemplateVariable("landing_page_url", VariableType.URL, required=True),
        ]

        for variable in variables:
            template.define_variable(variable, sample_user_id)

        # Rich email content with images and styling
        email_content = NotificationContent(
            subject="🎉 {{discount_percentage}}% OFF {{product_name}} - Don't Miss Out!",
            body="""Hi {{user_name}},

Great news! Get {{discount_percentage}}% off {{product_name}} with code {{promo_code}}.

This exclusive offer expires on {{expiry_date}}.

Shop now: {{landing_page_url}}

Happy shopping!
The Sales Team""",
            html_body="""
<html>
<body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
    <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 20px; text-align: center; color: white;">
        <h1 style="margin: 0; font-size: 28px;">🎉 Special Offer!</h1>
        <p style="margin: 10px 0 0 0; font-size: 18px;">{{discount_percentage}}% OFF {{product_name}}</p>
    </div>
    
    {% if product_image_url %}
    <div style="text-align: center; padding: 20px;">
        <img src="{{product_image_url}}" alt="{{product_name}}" style="max-width: 300px; height: auto; border-radius: 8px;">
    </div>
    {% endif %}
    
    <div style="padding: 20px;">
        <h2 style="color: #333;">Hi {{user_name}},</h2>
        <p style="font-size: 16px; line-height: 1.6; color: #555;">
            We're excited to offer you <strong>{{discount_percentage}}% off</strong> on {{product_name}}! 
            This is our biggest discount of the year.
        </p>
        
        <div style="background-color: #f8f9fa; padding: 15px; border-radius: 8px; text-align: center; margin: 20px 0;">
            <p style="margin: 0; font-size: 14px; color: #666;">Use promo code:</p>
            <h3 style="margin: 5px 0; font-size: 24px; color: #007bff; letter-spacing: 2px;">{{promo_code}}</h3>
            <p style="margin: 0; font-size: 12px; color: #999;">Expires: {{expiry_date}}</p>
        </div>
        
        <div style="text-align: center; margin: 30px 0;">
            <a href="{{landing_page_url}}" style="background-color: #28a745; color: white; padding: 15px 30px; text-decoration: none; border-radius: 5px; font-weight: bold; display: inline-block;">Shop Now</a>
        </div>
        
        <p style="font-size: 12px; color: #999; text-align: center;">
            This offer expires on {{expiry_date}}. Don't miss out!
        </p>
    </div>
</body>
</html>""",
            metadata={
                "unsubscribe_required": True,
                "channel_capabilities": "rich_content",
            },
        )
        template.add_channel_content(
            NotificationChannel.EMAIL, email_content, sample_user_id
        )

        # Concise SMS content
        sms_content = NotificationContent(
            body="🎉 {{user_name}}: {{discount_percentage}}% OFF {{product_name}}! Code: {{promo_code}} Expires: {{expiry_date}} Shop: {{landing_page_url}}"
        )
        template.add_channel_content(
            NotificationChannel.SMS, sms_content, sample_user_id
        )

        # Push notification content
        push_content = NotificationContent(
            subject="{{discount_percentage}}% OFF {{product_name}}!",
            body="{{user_name}}, save {{discount_percentage}}% with code {{promo_code}}. Expires {{expiry_date}}!",
        )
        template.add_channel_content(
            NotificationChannel.PUSH, push_content, sample_user_id
        )

        # Interactive in-app content
        in_app_content = NotificationContent(
            subject="Exclusive Offer",
            body="Save {{discount_percentage}}% on {{product_name}}!",
            html_body="""
<div class="promo-card" data-promo-code="{{promo_code}}" data-expiry="{{expiry_date}}">
    <div class="promo-header">
        <span class="discount-badge">{{discount_percentage}}% OFF</span>
        <h3>{{product_name}}</h3>
    </div>
    
    {% if product_image_url %}
    <div class="product-image">
        <img src="{{product_image_url}}" alt="{{product_name}}" loading="lazy">
    </div>
    {% endif %}
    
    <div class="promo-content">
        <p>Hi {{user_name}}, exclusive offer just for you!</p>
        <div class="promo-code-section">
            <label>Promo Code:</label>
            <code class="promo-code" onclick="copyToClipboard('{{promo_code}}')">{{promo_code}}</code>
            <button class="copy-btn" onclick="copyToClipboard('{{promo_code}}')">Copy</button>
        </div>
        <p class="expiry">Expires: {{expiry_date}}</p>
    </div>
    
    <div class="promo-actions">
        <a href="{{landing_page_url}}" class="btn-primary">Shop Now</a>
        <button class="btn-secondary" onclick="dismissPromo()">Maybe Later</button>
    </div>
</div>""",
            metadata={"interactive": True, "dismissible": True},
        )
        template.add_channel_content(
            NotificationChannel.IN_APP, in_app_content, sample_user_id
        )

        # Test adaptive rendering
        test_variables = {
            "user_name": "Sarah Johnson",
            "product_name": "Premium Wireless Headphones",
            "discount_percentage": 25,
            "promo_code": "SAVE25",
            "expiry_date": "2023-12-31",
            "product_image_url": "https://example.com/headphones.jpg",
            "landing_page_url": "https://shop.example.com/headphones?promo=SAVE25",
        }

        # Test each channel's adaptive content
        channels_and_features = [
            (
                NotificationChannel.EMAIL,
                ["rich_html", "images", "styling", "unsubscribe"],
            ),
            (NotificationChannel.SMS, ["character_limit", "emoji", "url_shortening"]),
            (NotificationChannel.PUSH, ["title_limit", "body_limit", "emoji"]),
            (
                NotificationChannel.IN_APP,
                ["interactive", "rich_html", "images", "actions"],
            ),
        ]

        rendered_contents = {}

        for channel, _expected_features in channels_and_features:
            content = template.render_for_channel(channel, test_variables)
            rendered_contents[channel] = content

            # Verify channel-specific adaptations
            if channel == NotificationChannel.EMAIL:
                assert "<html>" in content.html_body
                assert "linear-gradient" in content.html_body  # Rich styling
                assert test_variables["product_image_url"] in content.html_body
                assert "🎉" in content.subject

            elif channel == NotificationChannel.SMS:
                assert content.subject is None
                assert len(content.body) <= 160
                assert "🎉" in content.body
                assert test_variables["promo_code"] in content.body

            elif channel == NotificationChannel.PUSH:
                assert len(content.subject) <= 65
                assert len(content.body) <= 100
                assert "25% OFF" in content.subject

            elif channel == NotificationChannel.IN_APP:
                assert "promo-card" in content.html_body
                assert "onclick=" in content.html_body  # Interactive elements
                assert "copyToClipboard" in content.html_body
                assert content.metadata["interactive"] is True

        return {
            "template": template,
            "rendered_contents": rendered_contents,
            "test_variables": test_variables,
        }
