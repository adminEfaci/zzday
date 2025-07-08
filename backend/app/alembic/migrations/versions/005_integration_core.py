"""Integration core: Integration, webhooks, and sync job management

Revision ID: 005_integration_core
Revises: 004_notification_core
Create Date: 2024-07-04 11:00:00.000000

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '005_integration_core'
down_revision: str | None = '004_notification_core'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade database schema."""
    # Create enum types for integration system
    integration_type_enum = postgresql.ENUM(
        'REST_API', 'GRAPHQL', 'SOAP', 'GRPC', 'WEBHOOK', 'DATABASE', 'FILE_SYSTEM', 'MESSAGE_QUEUE',
        name='integrationtype'
    )
    integration_type_enum.create(op.get_bind())
    
    connection_status_enum = postgresql.ENUM(
        'DISCONNECTED', 'CONNECTING', 'CONNECTED', 'ERROR', 'MAINTENANCE',
        name='connectionstatus'
    )
    connection_status_enum.create(op.get_bind())
    
    credential_type_enum = postgresql.ENUM(
        'API_KEY', 'BEARER_TOKEN', 'BASIC_AUTH', 'OAUTH2', 'JWT', 'CERTIFICATE', 'SSH_KEY',
        name='credentialtype'
    )
    credential_type_enum.create(op.get_bind())
    
    sync_job_status_enum = postgresql.ENUM(
        'PENDING', 'RUNNING', 'COMPLETED', 'FAILED', 'CANCELLED', 'RETRYING',
        name='syncjobstatus'
    )
    sync_job_status_enum.create(op.get_bind())
    
    sync_direction_enum = postgresql.ENUM(
        'INBOUND', 'OUTBOUND', 'BIDIRECTIONAL',
        name='syncdirection'
    )
    sync_direction_enum.create(op.get_bind())
    
    webhook_event_type_enum = postgresql.ENUM(
        'CREATE', 'UPDATE', 'DELETE', 'CUSTOM', 'HEARTBEAT', 'ERROR',
        name='webhookeventtype'
    )
    webhook_event_type_enum.create(op.get_bind())
    
    webhook_status_enum = postgresql.ENUM(
        'ACTIVE', 'INACTIVE', 'FAILED', 'SUSPENDED',
        name='webhookstatus'
    )
    webhook_status_enum.create(op.get_bind())
    
    # Create integrations table
    op.create_table(
        'integrations',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('created_at', sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime, nullable=False, server_default=sa.func.now()),
        
        # Core attributes
        sa.Column('name', sa.String(100), nullable=False),
        sa.Column('integration_type', sa.Enum('REST_API', 'GRAPHQL', 'SOAP', 'GRPC', 'WEBHOOK', 'DATABASE', 'FILE_SYSTEM', 'MESSAGE_QUEUE', name='integrationtype'), nullable=False),
        sa.Column('system_name', sa.String(50), nullable=False),
        sa.Column('owner_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('description', sa.String(500)),
        
        # API endpoint configuration
        sa.Column('api_endpoint', postgresql.JSONB, nullable=False),
        
        # Rate limit configuration
        sa.Column('rate_limit', postgresql.JSONB, nullable=True),
        
        # Capabilities
        sa.Column('capabilities', postgresql.JSONB, nullable=False, server_default='[]'),
        
        # Additional configuration
        sa.Column('configuration', postgresql.JSONB, nullable=False, server_default='{}'),
        
        # State fields
        sa.Column('status', sa.Enum('DISCONNECTED', 'CONNECTING', 'CONNECTED', 'ERROR', 'MAINTENANCE', name='connectionstatus'), nullable=False, server_default='DISCONNECTED'),
        sa.Column('is_active', sa.Boolean, nullable=False, server_default='true'),
        
        # Health check fields
        sa.Column('last_health_check', sa.DateTime, nullable=True),
        sa.Column('health_check_failures', sa.Integer, nullable=False, server_default='0'),
        
        # Optimistic locking
        sa.Column('version', sa.Integer, nullable=False, server_default='1'),
    )
    
    # Create credentials table
    op.create_table(
        'credentials',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('created_at', sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.Column('integration_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('integrations.id'), nullable=False),
        
        # Core fields
        sa.Column('name', sa.String(100), nullable=False),
        sa.Column('credential_type', sa.Enum('API_KEY', 'BEARER_TOKEN', 'BASIC_AUTH', 'OAUTH2', 'JWT', 'CERTIFICATE', 'SSH_KEY', name='credentialtype'), nullable=False),
        sa.Column('description', sa.String(500)),
        
        # Credential data (encrypted)
        sa.Column('encrypted_data', sa.Text, nullable=False),
        sa.Column('encryption_key_id', sa.String(100), nullable=False),
        
        # OAuth2 specific fields
        sa.Column('oauth2_config', postgresql.JSONB, nullable=True),
        sa.Column('access_token_expires_at', sa.DateTime, nullable=True),
        sa.Column('refresh_token', sa.Text, nullable=True),
        
        # Certificate specific fields
        sa.Column('certificate_expires_at', sa.DateTime, nullable=True),
        sa.Column('certificate_fingerprint', sa.String(255), nullable=True),
        
        # Status and validation
        sa.Column('is_active', sa.Boolean, nullable=False, server_default='true'),
        sa.Column('last_validated_at', sa.DateTime, nullable=True),
        sa.Column('validation_error', sa.Text, nullable=True),
        
        # Usage tracking
        sa.Column('last_used_at', sa.DateTime, nullable=True),
        sa.Column('usage_count', sa.Integer, nullable=False, server_default='0'),
        
        # Metadata
        sa.Column('tags', postgresql.JSONB, nullable=False, server_default='[]'),
        sa.Column('metadata', postgresql.JSONB, nullable=False, server_default='{}'),
        
        # Audit
        sa.Column('created_by', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('updated_by', postgresql.UUID(as_uuid=True), nullable=False),
        
        # Optimistic locking
        sa.Column('version', sa.Integer, nullable=False, server_default='1'),
    )
    
    # Create mappings table
    op.create_table(
        'mappings',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('created_at', sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.Column('integration_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('integrations.id'), nullable=False),
        
        # Core fields
        sa.Column('name', sa.String(100), nullable=False),
        sa.Column('description', sa.String(500)),
        sa.Column('source_system', sa.String(50), nullable=False),
        sa.Column('target_system', sa.String(50), nullable=False),
        
        # Mapping configuration
        sa.Column('source_schema', postgresql.JSONB, nullable=False),
        sa.Column('target_schema', postgresql.JSONB, nullable=False),
        sa.Column('field_mappings', postgresql.JSONB, nullable=False),
        sa.Column('transformation_rules', postgresql.JSONB, nullable=False, server_default='[]'),
        sa.Column('validation_rules', postgresql.JSONB, nullable=False, server_default='[]'),
        
        # Data type and format configuration
        sa.Column('data_type_mappings', postgresql.JSONB, nullable=False, server_default='{}'),
        sa.Column('format_configurations', postgresql.JSONB, nullable=False, server_default='{}'),
        
        # Status and versioning
        sa.Column('is_active', sa.Boolean, nullable=False, server_default='true'),
        sa.Column('version', sa.String(20), nullable=False, server_default='1.0.0'),
        sa.Column('parent_mapping_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('mappings.id'), nullable=True),
        
        # Usage statistics
        sa.Column('usage_count', sa.Integer, nullable=False, server_default='0'),
        sa.Column('last_used_at', sa.DateTime, nullable=True),
        sa.Column('success_rate', sa.Float, nullable=False, server_default='0.0'),
        
        # Metadata
        sa.Column('tags', postgresql.JSONB, nullable=False, server_default='[]'),
        sa.Column('metadata', postgresql.JSONB, nullable=False, server_default='{}'),
        
        # Audit
        sa.Column('created_by', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('updated_by', postgresql.UUID(as_uuid=True), nullable=False),
    )
    
    # Create sync_jobs table
    op.create_table(
        'sync_jobs',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('created_at', sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.Column('integration_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('integrations.id'), nullable=False),
        
        # Core fields
        sa.Column('name', sa.String(100), nullable=False),
        sa.Column('description', sa.String(500)),
        sa.Column('job_type', sa.String(50), nullable=False),  # 'full_sync', 'incremental', 'delta', etc.
        sa.Column('direction', sa.Enum('INBOUND', 'OUTBOUND', 'BIDIRECTIONAL', name='syncdirection'), nullable=False),
        
        # Scheduling
        sa.Column('schedule_config', postgresql.JSONB, nullable=True),  # Cron expression or schedule config
        sa.Column('is_scheduled', sa.Boolean, nullable=False, server_default='false'),
        sa.Column('next_run_at', sa.DateTime, nullable=True),
        sa.Column('last_run_at', sa.DateTime, nullable=True),
        
        # Sync configuration
        sa.Column('source_config', postgresql.JSONB, nullable=False),
        sa.Column('target_config', postgresql.JSONB, nullable=False),
        sa.Column('mapping_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('mappings.id'), nullable=True),
        sa.Column('batch_size', sa.Integer, nullable=False, server_default='1000'),
        sa.Column('parallel_workers', sa.Integer, nullable=False, server_default='1'),
        
        # Status and execution
        sa.Column('status', sa.Enum('PENDING', 'RUNNING', 'COMPLETED', 'FAILED', 'CANCELLED', 'RETRYING', name='syncjobstatus'), nullable=False, server_default='PENDING'),
        sa.Column('current_execution_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('execution_history', postgresql.JSONB, nullable=False, server_default='[]'),
        
        # Progress tracking
        sa.Column('progress_data', postgresql.JSONB, nullable=False, server_default='{}'),
        sa.Column('records_processed', sa.Integer, nullable=False, server_default='0'),
        sa.Column('records_succeeded', sa.Integer, nullable=False, server_default='0'),
        sa.Column('records_failed', sa.Integer, nullable=False, server_default='0'),
        
        # Error handling
        sa.Column('retry_config', postgresql.JSONB, nullable=False, server_default='{}'),
        sa.Column('retry_count', sa.Integer, nullable=False, server_default='0'),
        sa.Column('max_retries', sa.Integer, nullable=False, server_default='3'),
        sa.Column('error_handling_strategy', sa.String(50), nullable=False, server_default='fail_fast'),
        
        # Timing
        sa.Column('started_at', sa.DateTime, nullable=True),
        sa.Column('completed_at', sa.DateTime, nullable=True),
        sa.Column('duration_seconds', sa.Integer, nullable=True),
        sa.Column('timeout_seconds', sa.Integer, nullable=True),
        
        # State and configuration
        sa.Column('is_active', sa.Boolean, nullable=False, server_default='true'),
        sa.Column('configuration', postgresql.JSONB, nullable=False, server_default='{}'),
        
        # Audit
        sa.Column('created_by', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('updated_by', postgresql.UUID(as_uuid=True), nullable=False),
        
        # Optimistic locking
        sa.Column('version', sa.Integer, nullable=False, server_default='1'),
    )
    
    # Create webhook_endpoints table
    op.create_table(
        'webhook_endpoints',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('created_at', sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.Column('integration_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('integrations.id'), nullable=False),
        
        # Core fields
        sa.Column('name', sa.String(100), nullable=False),
        sa.Column('description', sa.String(500)),
        sa.Column('url', sa.String(500), nullable=False),
        sa.Column('secret_token', sa.String(255), nullable=True),
        
        # Configuration
        sa.Column('supported_events', postgresql.JSONB, nullable=False, server_default='[]'),
        sa.Column('headers', postgresql.JSONB, nullable=False, server_default='{}'),
        sa.Column('timeout_seconds', sa.Integer, nullable=False, server_default='30'),
        sa.Column('retry_config', postgresql.JSONB, nullable=False, server_default='{}'),
        
        # Security
        sa.Column('signature_method', sa.String(50), nullable=False, server_default='hmac_sha256'),
        sa.Column('verify_ssl', sa.Boolean, nullable=False, server_default='true'),
        sa.Column('allowed_ips', postgresql.JSONB, nullable=False, server_default='[]'),
        
        # Status and health
        sa.Column('status', sa.Enum('ACTIVE', 'INACTIVE', 'FAILED', 'SUSPENDED', name='webhookstatus'), nullable=False, server_default='ACTIVE'),
        sa.Column('is_active', sa.Boolean, nullable=False, server_default='true'),
        sa.Column('last_triggered_at', sa.DateTime, nullable=True),
        sa.Column('last_success_at', sa.DateTime, nullable=True),
        sa.Column('last_failure_at', sa.DateTime, nullable=True),
        sa.Column('consecutive_failures', sa.Integer, nullable=False, server_default='0'),
        sa.Column('total_deliveries', sa.Integer, nullable=False, server_default='0'),
        sa.Column('successful_deliveries', sa.Integer, nullable=False, server_default='0'),
        
        # Metadata
        sa.Column('tags', postgresql.JSONB, nullable=False, server_default='[]'),
        sa.Column('metadata', postgresql.JSONB, nullable=False, server_default='{}'),
        
        # Audit
        sa.Column('created_by', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('updated_by', postgresql.UUID(as_uuid=True), nullable=False),
        
        # Optimistic locking
        sa.Column('version', sa.Integer, nullable=False, server_default='1'),
    )
    
    # Create webhook_events table
    op.create_table(
        'webhook_events',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('created_at', sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.Column('webhook_endpoint_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('webhook_endpoints.id'), nullable=False),
        
        # Event details
        sa.Column('event_type', sa.Enum('CREATE', 'UPDATE', 'DELETE', 'CUSTOM', 'HEARTBEAT', 'ERROR', name='webhookeventtype'), nullable=False),
        sa.Column('event_name', sa.String(100), nullable=False),
        sa.Column('event_data', postgresql.JSONB, nullable=False),
        sa.Column('event_timestamp', sa.DateTime, nullable=False, server_default=sa.func.now()),
        
        # Delivery details
        sa.Column('delivery_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('attempt_number', sa.Integer, nullable=False, server_default='1'),
        sa.Column('max_attempts', sa.Integer, nullable=False, server_default='3'),
        sa.Column('next_retry_at', sa.DateTime, nullable=True),
        
        # Request details
        sa.Column('request_headers', postgresql.JSONB, nullable=False, server_default='{}'),
        sa.Column('request_body', sa.Text, nullable=False),
        sa.Column('request_signature', sa.String(255), nullable=True),
        sa.Column('request_timestamp', sa.DateTime, nullable=False, server_default=sa.func.now()),
        
        # Response details
        sa.Column('response_status_code', sa.Integer, nullable=True),
        sa.Column('response_headers', postgresql.JSONB, nullable=True),
        sa.Column('response_body', sa.Text, nullable=True),
        sa.Column('response_timestamp', sa.DateTime, nullable=True),
        sa.Column('response_time_ms', sa.Integer, nullable=True),
        
        # Status
        sa.Column('status', sa.String(20), nullable=False, server_default='pending'),  # 'pending', 'delivered', 'failed', 'cancelled'
        sa.Column('error_message', sa.Text, nullable=True),
        sa.Column('error_details', postgresql.JSONB, nullable=True),
        
        # Metadata
        sa.Column('metadata', postgresql.JSONB, nullable=False, server_default='{}'),
    )
    
    # Create indexes for integrations
    op.create_index('idx_integrations_owner_id', 'integrations', ['owner_id'])
    op.create_index('idx_integrations_system_name', 'integrations', ['system_name'])
    op.create_index('idx_integrations_status', 'integrations', ['status'])
    op.create_index('idx_integrations_type', 'integrations', ['integration_type'])
    op.create_index('idx_integrations_active', 'integrations', ['is_active'])
    op.create_index('idx_integrations_health_check', 'integrations', ['last_health_check'])
    
    # Create indexes for credentials
    op.create_index('idx_credentials_integration_id', 'credentials', ['integration_id'])
    op.create_index('idx_credentials_type', 'credentials', ['credential_type'])
    op.create_index('idx_credentials_active', 'credentials', ['is_active'])
    op.create_index('idx_credentials_expires', 'credentials', ['access_token_expires_at'])
    op.create_index('idx_credentials_cert_expires', 'credentials', ['certificate_expires_at'])
    op.create_index('idx_credentials_last_used', 'credentials', ['last_used_at'])
    
    # Create indexes for mappings
    op.create_index('idx_mappings_integration_id', 'mappings', ['integration_id'])
    op.create_index('idx_mappings_source_target', 'mappings', ['source_system', 'target_system'])
    op.create_index('idx_mappings_active', 'mappings', ['is_active'])
    op.create_index('idx_mappings_parent', 'mappings', ['parent_mapping_id'])
    op.create_index('idx_mappings_last_used', 'mappings', ['last_used_at'])
    
    # Create indexes for sync_jobs
    op.create_index('idx_sync_jobs_integration_id', 'sync_jobs', ['integration_id'])
    op.create_index('idx_sync_jobs_status', 'sync_jobs', ['status'])
    op.create_index('idx_sync_jobs_scheduled', 'sync_jobs', ['is_scheduled', 'next_run_at'])
    op.create_index('idx_sync_jobs_mapping', 'sync_jobs', ['mapping_id'])
    op.create_index('idx_sync_jobs_active', 'sync_jobs', ['is_active'])
    op.create_index('idx_sync_jobs_type', 'sync_jobs', ['job_type'])
    op.create_index('idx_sync_jobs_direction', 'sync_jobs', ['direction'])
    op.create_index('idx_sync_jobs_last_run', 'sync_jobs', ['last_run_at'])
    
    # Create indexes for webhook_endpoints
    op.create_index('idx_webhook_endpoints_integration_id', 'webhook_endpoints', ['integration_id'])
    op.create_index('idx_webhook_endpoints_status', 'webhook_endpoints', ['status'])
    op.create_index('idx_webhook_endpoints_active', 'webhook_endpoints', ['is_active'])
    op.create_index('idx_webhook_endpoints_last_triggered', 'webhook_endpoints', ['last_triggered_at'])
    op.create_index('idx_webhook_endpoints_failures', 'webhook_endpoints', ['consecutive_failures'])
    
    # Create indexes for webhook_events
    op.create_index('idx_webhook_events_endpoint', 'webhook_events', ['webhook_endpoint_id'])
    op.create_index('idx_webhook_events_type', 'webhook_events', ['event_type'])
    op.create_index('idx_webhook_events_delivery', 'webhook_events', ['delivery_id'])
    op.create_index('idx_webhook_events_status', 'webhook_events', ['status'])
    op.create_index('idx_webhook_events_created', 'webhook_events', ['created_at'])
    op.create_index('idx_webhook_events_retry', 'webhook_events', ['next_retry_at', 'status'])
    op.create_index('idx_webhook_events_timestamp', 'webhook_events', ['event_timestamp'])
    
    # Create unique constraints
    op.create_unique_constraint('uq_integrations_name_owner', 'integrations', ['name', 'owner_id'])
    op.create_unique_constraint('uq_credentials_integration_name', 'credentials', ['integration_id', 'name'])
    op.create_unique_constraint('uq_mappings_integration_name', 'mappings', ['integration_id', 'name'])
    op.create_unique_constraint('uq_sync_jobs_integration_name', 'sync_jobs', ['integration_id', 'name'])
    op.create_unique_constraint('uq_webhook_endpoints_integration_name', 'webhook_endpoints', ['integration_id', 'name'])
    op.create_unique_constraint('uq_webhook_events_delivery', 'webhook_events', ['delivery_id', 'attempt_number'])


def downgrade() -> None:
    """Downgrade database schema."""
    # Drop tables in reverse order
    op.drop_table('webhook_events')
    op.drop_table('webhook_endpoints')
    op.drop_table('sync_jobs')
    op.drop_table('mappings')
    op.drop_table('credentials')
    op.drop_table('integrations')
    
    # Drop enum types
    op.execute('DROP TYPE IF EXISTS webhookstatus')
    op.execute('DROP TYPE IF EXISTS webhookeventtype')
    op.execute('DROP TYPE IF EXISTS syncdirection')
    op.execute('DROP TYPE IF EXISTS syncjobstatus')
    op.execute('DROP TYPE IF EXISTS credentialtype')
    op.execute('DROP TYPE IF EXISTS connectionstatus')
    op.execute('DROP TYPE IF EXISTS integrationtype')