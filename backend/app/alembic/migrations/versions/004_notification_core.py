"""Notification core: Notification system with templates and delivery tracking

Revision ID: 004_notification_core
Revises: 003_audit_foundation
Create Date: 2024-07-04 10:45:00.000000

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '004_notification_core'
down_revision: str | None = '003_audit_foundation'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade database schema."""
    # Create enum types for notification system
    notification_channel_enum = postgresql.ENUM(
        'EMAIL', 'SMS', 'PUSH', 'IN_APP', 'WEBHOOK', 'SLACK', 'TEAMS',
        name='notificationchannel'
    )
    notification_channel_enum.create(op.get_bind())
    
    notification_priority_enum = postgresql.ENUM(
        'LOW', 'NORMAL', 'HIGH', 'URGENT',
        name='notificationpriority'
    )
    notification_priority_enum.create(op.get_bind())
    
    delivery_status_enum = postgresql.ENUM(
        'PENDING', 'QUEUED', 'SENDING', 'SENT', 'DELIVERED', 'READ',
        'FAILED', 'BOUNCED', 'SPAM', 'UNSUBSCRIBED', 'EXPIRED',
        name='deliverystatus'
    )
    delivery_status_enum.create(op.get_bind())
    
    template_type_enum = postgresql.ENUM(
        'EMAIL', 'SMS', 'PUSH', 'IN_APP', 'WEBHOOK',
        name='templatetype'
    )
    template_type_enum.create(op.get_bind())
    
    batch_status_enum = postgresql.ENUM(
        'PENDING', 'PROCESSING', 'COMPLETED', 'FAILED', 'CANCELLED',
        name='batchstatus'
    )
    batch_status_enum.create(op.get_bind())
    
    schedule_type_enum = postgresql.ENUM(
        'IMMEDIATE', 'SCHEDULED', 'RECURRING', 'TRIGGERED',
        name='scheduletype'
    )
    schedule_type_enum.create(op.get_bind())
    
    # Create notification templates table
    op.create_table(
        'notification_templates',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('created_at', sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime, nullable=False, server_default=sa.func.now()),
        
        # Core fields
        sa.Column('name', sa.String(100), nullable=False),
        sa.Column('description', sa.Text),
        sa.Column('template_type', sa.Enum('EMAIL', 'SMS', 'PUSH', 'IN_APP', 'WEBHOOK', name='templatetype'), nullable=False),
        sa.Column('category', sa.String(50), nullable=False),  # 'auth', 'marketing', 'transactional', etc.
        
        # Template content
        sa.Column('subject_template', sa.String(200)),
        sa.Column('body_template', sa.Text, nullable=False),
        sa.Column('html_template', sa.Text),
        
        # Configuration
        sa.Column('variables', postgresql.JSONB, nullable=False, server_default='[]'),  # List of required variables
        sa.Column('default_values', postgresql.JSONB, nullable=False, server_default='{}'),  # Default variable values
        sa.Column('validation_rules', postgresql.JSONB, nullable=False, server_default='{}'),  # Variable validation rules
        
        # Localization
        sa.Column('language', sa.String(10), nullable=False, server_default='en'),
        sa.Column('localized_versions', postgresql.JSONB, nullable=False, server_default='{}'),  # Other language versions
        
        # Status and versioning
        sa.Column('is_active', sa.Boolean, nullable=False, server_default='true'),
        sa.Column('version', sa.String(20), nullable=False, server_default='1.0.0'),
        sa.Column('parent_template_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('notification_templates.id'), nullable=True),
        
        # Metadata
        sa.Column('tags', postgresql.JSONB, nullable=False, server_default='[]'),
        sa.Column('metadata', postgresql.JSONB, nullable=False, server_default='{}'),
        
        # Audit
        sa.Column('created_by', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('updated_by', postgresql.UUID(as_uuid=True), nullable=False),
    )
    
    # Create notifications table
    op.create_table(
        'notifications',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('created_at', sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime, nullable=False, server_default=sa.func.now()),
        
        # Core fields
        sa.Column('recipient_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('channel', sa.Enum('EMAIL', 'SMS', 'PUSH', 'IN_APP', 'WEBHOOK', 'SLACK', 'TEAMS', name='notificationchannel'), nullable=False),
        sa.Column('priority', sa.Enum('LOW', 'NORMAL', 'HIGH', 'URGENT', name='notificationpriority'), nullable=False, server_default='NORMAL'),
        
        # Content fields
        sa.Column('subject', sa.String(200)),
        sa.Column('body', sa.Text, nullable=False),
        sa.Column('html_body', sa.Text),
        sa.Column('variables', postgresql.JSONB, nullable=True),
        sa.Column('attachments', postgresql.JSONB, nullable=True),
        
        # Recipient address
        sa.Column('recipient_address', sa.String(500), nullable=False),
        sa.Column('recipient_display_name', sa.String(200)),
        
        # Template reference
        sa.Column('template_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('notification_templates.id'), nullable=True),
        
        # Status tracking
        sa.Column('current_status', sa.Enum('PENDING', 'QUEUED', 'SENDING', 'SENT', 'DELIVERED', 'READ', 'FAILED', 'BOUNCED', 'SPAM', 'UNSUBSCRIBED', 'EXPIRED', name='deliverystatus'), nullable=False, server_default='PENDING'),
        sa.Column('status_history', postgresql.JSONB, nullable=False, server_default='[]'),
        
        # Timestamps
        sa.Column('scheduled_for', sa.DateTime, nullable=True),
        sa.Column('sent_at', sa.DateTime, nullable=True),
        sa.Column('delivered_at', sa.DateTime, nullable=True),
        sa.Column('read_at', sa.DateTime, nullable=True),
        sa.Column('failed_at', sa.DateTime, nullable=True),
        sa.Column('expires_at', sa.DateTime, nullable=True),
        
        # Provider tracking
        sa.Column('provider', sa.String(100), nullable=True),
        sa.Column('provider_message_id', sa.String(500), nullable=True),
        sa.Column('provider_response', postgresql.JSONB, nullable=True),
        
        # Retry tracking
        sa.Column('retry_count', sa.Integer, nullable=False, server_default='0'),
        sa.Column('max_retries', sa.Integer, nullable=False, server_default='3'),
        sa.Column('next_retry_at', sa.DateTime, nullable=True),
        
        # Deduplication
        sa.Column('idempotency_key', sa.String(200), nullable=True, unique=True),
        
        # Metadata
        sa.Column('metadata', postgresql.JSONB, nullable=True),
    )
    
    # Create notification batches table
    op.create_table(
        'notification_batches',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('created_at', sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime, nullable=False, server_default=sa.func.now()),
        
        # Core fields
        sa.Column('name', sa.String(100), nullable=False),
        sa.Column('description', sa.Text),
        sa.Column('template_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('notification_templates.id'), nullable=False),
        sa.Column('channel', sa.Enum('EMAIL', 'SMS', 'PUSH', 'IN_APP', 'WEBHOOK', 'SLACK', 'TEAMS', name='notificationchannel'), nullable=False),
        
        # Batch configuration
        sa.Column('recipients', postgresql.JSONB, nullable=False),  # List of recipient configurations
        sa.Column('batch_size', sa.Integer, nullable=False, server_default='100'),
        sa.Column('delay_between_batches_seconds', sa.Integer, nullable=False, server_default='0'),
        
        # Status tracking
        sa.Column('status', sa.Enum('PENDING', 'PROCESSING', 'COMPLETED', 'FAILED', 'CANCELLED', name='batchstatus'), nullable=False, server_default='PENDING'),
        sa.Column('progress', postgresql.JSONB, nullable=False, server_default='{}'),  # Progress tracking
        
        # Scheduling
        sa.Column('scheduled_for', sa.DateTime, nullable=True),
        sa.Column('started_at', sa.DateTime, nullable=True),
        sa.Column('completed_at', sa.DateTime, nullable=True),
        sa.Column('cancelled_at', sa.DateTime, nullable=True),
        
        # Statistics
        sa.Column('total_recipients', sa.Integer, nullable=False, server_default='0'),
        sa.Column('processed_count', sa.Integer, nullable=False, server_default='0'),
        sa.Column('success_count', sa.Integer, nullable=False, server_default='0'),
        sa.Column('failure_count', sa.Integer, nullable=False, server_default='0'),
        
        # Configuration
        sa.Column('priority', sa.Enum('LOW', 'NORMAL', 'HIGH', 'URGENT', name='notificationpriority'), nullable=False, server_default='NORMAL'),
        sa.Column('variables', postgresql.JSONB, nullable=True),  # Global variables for the batch
        
        # Metadata
        sa.Column('metadata', postgresql.JSONB, nullable=True),
        sa.Column('created_by', postgresql.UUID(as_uuid=True), nullable=False),
    )
    
    # Create delivery logs table
    op.create_table(
        'delivery_logs',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('created_at', sa.DateTime, nullable=False, server_default=sa.func.now()),
        
        # References
        sa.Column('notification_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('notifications.id'), nullable=False),
        sa.Column('batch_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('notification_batches.id'), nullable=True),
        
        # Delivery attempt details
        sa.Column('attempt_number', sa.Integer, nullable=False),
        sa.Column('status', sa.Enum('PENDING', 'QUEUED', 'SENDING', 'SENT', 'DELIVERED', 'READ', 'FAILED', 'BOUNCED', 'SPAM', 'UNSUBSCRIBED', 'EXPIRED', name='deliverystatus'), nullable=False),
        sa.Column('provider', sa.String(100), nullable=False),
        sa.Column('provider_message_id', sa.String(500), nullable=True),
        
        # Response details
        sa.Column('response_code', sa.String(20)),
        sa.Column('response_message', sa.Text),
        sa.Column('response_headers', postgresql.JSONB),
        sa.Column('response_body', sa.Text),
        
        # Timing
        sa.Column('request_timestamp', sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.Column('response_timestamp', sa.DateTime, nullable=True),
        sa.Column('duration_ms', sa.Integer, nullable=True),
        
        # Error details
        sa.Column('error_code', sa.String(50)),
        sa.Column('error_message', sa.Text),
        sa.Column('error_details', postgresql.JSONB),
        
        # Metadata
        sa.Column('metadata', postgresql.JSONB, nullable=True),
    )
    
    # Create recipients table (for managing recipient preferences)
    op.create_table(
        'recipients',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('created_at', sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime, nullable=False, server_default=sa.func.now()),
        
        # Core fields
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=True),  # Can be null for external recipients
        sa.Column('email', sa.String(255)),
        sa.Column('phone_number', sa.String(50)),
        sa.Column('display_name', sa.String(200)),
        
        # Preferences
        sa.Column('email_enabled', sa.Boolean, nullable=False, server_default='true'),
        sa.Column('sms_enabled', sa.Boolean, nullable=False, server_default='true'),
        sa.Column('push_enabled', sa.Boolean, nullable=False, server_default='true'),
        sa.Column('in_app_enabled', sa.Boolean, nullable=False, server_default='true'),
        
        # Subscription preferences
        sa.Column('subscriptions', postgresql.JSONB, nullable=False, server_default='[]'),  # List of subscribed categories
        sa.Column('unsubscribed_categories', postgresql.JSONB, nullable=False, server_default='[]'),
        sa.Column('global_unsubscribe', sa.Boolean, nullable=False, server_default='false'),
        sa.Column('unsubscribed_at', sa.DateTime, nullable=True),
        
        # Verification status
        sa.Column('email_verified', sa.Boolean, nullable=False, server_default='false'),
        sa.Column('phone_verified', sa.Boolean, nullable=False, server_default='false'),
        sa.Column('email_verified_at', sa.DateTime, nullable=True),
        sa.Column('phone_verified_at', sa.DateTime, nullable=True),
        
        # Timezone and locale
        sa.Column('timezone', sa.String(50), server_default='UTC'),
        sa.Column('locale', sa.String(10), server_default='en'),
        
        # Statistics
        sa.Column('total_notifications_sent', sa.Integer, nullable=False, server_default='0'),
        sa.Column('total_notifications_delivered', sa.Integer, nullable=False, server_default='0'),
        sa.Column('total_notifications_read', sa.Integer, nullable=False, server_default='0'),
        sa.Column('last_notification_sent', sa.DateTime, nullable=True),
        sa.Column('last_notification_read', sa.DateTime, nullable=True),
        
        # Metadata
        sa.Column('metadata', postgresql.JSONB, nullable=True),
    )
    
    # Create schedules table (for recurring notifications)
    op.create_table(
        'schedules',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('created_at', sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime, nullable=False, server_default=sa.func.now()),
        
        # Core fields
        sa.Column('name', sa.String(100), nullable=False),
        sa.Column('description', sa.Text),
        sa.Column('template_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('notification_templates.id'), nullable=False),
        
        # Schedule configuration
        sa.Column('schedule_type', sa.Enum('IMMEDIATE', 'SCHEDULED', 'RECURRING', 'TRIGGERED', name='scheduletype'), nullable=False),
        sa.Column('cron_expression', sa.String(100)),  # For recurring schedules
        sa.Column('scheduled_at', sa.DateTime),  # For one-time schedules
        sa.Column('timezone', sa.String(50), server_default='UTC'),
        
        # Recipients
        sa.Column('recipients', postgresql.JSONB, nullable=False),  # List of recipient configurations
        sa.Column('recipient_filters', postgresql.JSONB, nullable=True),  # Dynamic recipient filters
        
        # Configuration
        sa.Column('variables', postgresql.JSONB, nullable=True),  # Template variables
        sa.Column('priority', sa.Enum('LOW', 'NORMAL', 'HIGH', 'URGENT', name='notificationpriority'), nullable=False, server_default='NORMAL'),
        sa.Column('max_recipients', sa.Integer, nullable=True),
        
        # Status
        sa.Column('is_active', sa.Boolean, nullable=False, server_default='true'),
        sa.Column('last_run_at', sa.DateTime, nullable=True),
        sa.Column('next_run_at', sa.DateTime, nullable=True),
        sa.Column('run_count', sa.Integer, nullable=False, server_default='0'),
        sa.Column('failure_count', sa.Integer, nullable=False, server_default='0'),
        
        # Metadata
        sa.Column('metadata', postgresql.JSONB, nullable=True),
        sa.Column('created_by', postgresql.UUID(as_uuid=True), nullable=False),
    )
    
    # Create indexes for notification_templates
    op.create_index('idx_notification_templates_name', 'notification_templates', ['name'])
    op.create_index('idx_notification_templates_type', 'notification_templates', ['template_type'])
    op.create_index('idx_notification_templates_category', 'notification_templates', ['category'])
    op.create_index('idx_notification_templates_active', 'notification_templates', ['is_active'])
    op.create_index('idx_notification_templates_parent', 'notification_templates', ['parent_template_id'])
    
    # Create indexes for notifications (performance critical)
    op.create_index('idx_notifications_recipient_status', 'notifications', ['recipient_id', 'current_status'])
    op.create_index('idx_notifications_channel_status', 'notifications', ['channel', 'current_status'])
    op.create_index('idx_notifications_created_at', 'notifications', ['created_at'])
    op.create_index('idx_notifications_scheduled', 'notifications', ['scheduled_for', 'current_status'])
    op.create_index('idx_notifications_retry', 'notifications', ['next_retry_at', 'current_status'])
    op.create_index('idx_notifications_template', 'notifications', ['template_id'])
    op.create_index('idx_notifications_provider_message', 'notifications', ['provider_message_id'])
    
    # Create indexes for notification_batches
    op.create_index('idx_notification_batches_template', 'notification_batches', ['template_id'])
    op.create_index('idx_notification_batches_status', 'notification_batches', ['status'])
    op.create_index('idx_notification_batches_scheduled', 'notification_batches', ['scheduled_for'])
    op.create_index('idx_notification_batches_created_by', 'notification_batches', ['created_by'])
    
    # Create indexes for delivery_logs
    op.create_index('idx_delivery_logs_notification', 'delivery_logs', ['notification_id'])
    op.create_index('idx_delivery_logs_batch', 'delivery_logs', ['batch_id'])
    op.create_index('idx_delivery_logs_status', 'delivery_logs', ['status'])
    op.create_index('idx_delivery_logs_provider', 'delivery_logs', ['provider'])
    op.create_index('idx_delivery_logs_timestamp', 'delivery_logs', ['request_timestamp'])
    
    # Create indexes for recipients
    op.create_index('idx_recipients_user_id', 'recipients', ['user_id'])
    op.create_index('idx_recipients_email', 'recipients', ['email'])
    op.create_index('idx_recipients_phone', 'recipients', ['phone_number'])
    op.create_index('idx_recipients_global_unsubscribe', 'recipients', ['global_unsubscribe'])
    op.create_index('idx_recipients_last_notification', 'recipients', ['last_notification_sent'])
    
    # Create indexes for schedules
    op.create_index('idx_schedules_template', 'schedules', ['template_id'])
    op.create_index('idx_schedules_type', 'schedules', ['schedule_type'])
    op.create_index('idx_schedules_active', 'schedules', ['is_active'])
    op.create_index('idx_schedules_next_run', 'schedules', ['next_run_at', 'is_active'])
    op.create_index('idx_schedules_created_by', 'schedules', ['created_by'])
    
    # Create unique constraints
    op.create_unique_constraint('uq_notification_templates_name', 'notification_templates', ['name'])
    op.create_unique_constraint('uq_notifications_idempotency', 'notifications', ['idempotency_key'])
    op.create_unique_constraint('uq_recipients_user_id', 'recipients', ['user_id'])
    op.create_unique_constraint('uq_recipients_email', 'recipients', ['email'])


def downgrade() -> None:
    """Downgrade database schema."""
    # Drop tables in reverse order
    op.drop_table('schedules')
    op.drop_table('recipients')
    op.drop_table('delivery_logs')
    op.drop_table('notification_batches')
    op.drop_table('notifications')
    op.drop_table('notification_templates')
    
    # Drop enum types
    op.execute('DROP TYPE IF EXISTS scheduletype')
    op.execute('DROP TYPE IF EXISTS batchstatus')
    op.execute('DROP TYPE IF EXISTS templatetype')
    op.execute('DROP TYPE IF EXISTS deliverystatus')
    op.execute('DROP TYPE IF EXISTS notificationpriority')
    op.execute('DROP TYPE IF EXISTS notificationchannel')