"""Create audit tables for login attempts and security events

Revision ID: 006_audit_tables
Revises: 005_integration_core
Create Date: 2025-01-06

"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '006_audit_tables'
down_revision = '005_integration_core'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create audit tables."""
    
    # Create login_attempts table
    op.create_table(
        'login_attempts',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('email', sa.String(), nullable=False),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('session_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('success', sa.Boolean(), nullable=False),
        sa.Column('failure_reason', sa.String(), nullable=True),
        sa.Column('timestamp', sa.DateTime(timezone=True), nullable=False),
        
        # IP and device info
        sa.Column('ip_address', sa.String(), nullable=False),
        sa.Column('user_agent', sa.Text(), nullable=True),
        sa.Column('device_fingerprint', sa.String(), nullable=True),
        sa.Column('mfa_used', sa.Boolean(), nullable=False, default=False),
        
        # Location info
        sa.Column('country', sa.String(2), nullable=True),
        sa.Column('city', sa.String(), nullable=True),
        sa.Column('latitude', sa.Float(), nullable=True),
        sa.Column('longitude', sa.Float(), nullable=True),
        sa.Column('isp', sa.String(), nullable=True),
        sa.Column('organization', sa.String(), nullable=True),
        
        # Risk assessment
        sa.Column('risk_score', sa.Float(), nullable=False, default=0.0),
        sa.Column('risk_indicators', sa.JSON(), nullable=False, default=[]),
        sa.Column('risk_breakdown', sa.JSON(), nullable=False, default={}),
        
        # Behavioral analysis
        sa.Column('login_velocity', sa.Integer(), nullable=False, default=0),
        sa.Column('unique_ips_used', sa.Integer(), nullable=False, default=0),
        sa.Column('failed_attempts_24h', sa.Integer(), nullable=False, default=0),
        sa.Column('last_successful_login', sa.DateTime(timezone=True), nullable=True),
        sa.Column('typical_login_hours', sa.JSON(), nullable=False, default=[]),
        
        # Device and location trust
        sa.Column('device_trust_score', sa.Float(), nullable=False, default=0.0),
        sa.Column('location_trust_score', sa.Float(), nullable=False, default=0.0),
        sa.Column('is_known_device', sa.Boolean(), nullable=False, default=False),
        sa.Column('is_known_location', sa.Boolean(), nullable=False, default=False),
        
        # Attack patterns
        sa.Column('is_distributed_attack', sa.Boolean(), nullable=False, default=False),
        sa.Column('attack_pattern', sa.String(), nullable=True),
        sa.Column('credential_stuffing_score', sa.Float(), nullable=False, default=0.0),
        
        # ML features
        sa.Column('ml_risk_score', sa.Float(), nullable=True),
        sa.Column('ml_confidence', sa.Float(), nullable=True),
        sa.Column('ml_features', sa.JSON(), nullable=False, default={}),
        
        # Metadata
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('metadata', sa.JSON(), nullable=False, default={})
    )
    
    # Create indexes for login_attempts
    op.create_index('ix_login_attempts_email', 'login_attempts', ['email'])
    op.create_index('ix_login_attempts_user_id', 'login_attempts', ['user_id'])
    op.create_index('ix_login_attempts_session_id', 'login_attempts', ['session_id'])
    op.create_index('ix_login_attempts_ip_address', 'login_attempts', ['ip_address'])
    op.create_index('ix_login_attempts_device_fingerprint', 'login_attempts', ['device_fingerprint'])
    op.create_index('ix_login_attempts_timestamp', 'login_attempts', ['timestamp'])
    op.create_index('ix_login_attempts_success', 'login_attempts', ['success'])
    op.create_index('ix_login_attempts_failure_reason', 'login_attempts', ['failure_reason'])
    op.create_index('ix_login_attempts_risk_score', 'login_attempts', ['risk_score'])
    op.create_index('ix_login_attempts_country', 'login_attempts', ['country'])
    op.create_index('ix_login_attempts_created_at', 'login_attempts', ['created_at'])
    
    # Composite indexes for common queries
    op.create_index('ix_login_attempts_email_timestamp', 'login_attempts', ['email', 'timestamp'])
    op.create_index('ix_login_attempts_ip_timestamp', 'login_attempts', ['ip_address', 'timestamp'])
    op.create_index('ix_login_attempts_user_timestamp', 'login_attempts', ['user_id', 'timestamp'])
    op.create_index('ix_login_attempts_risk_failed', 'login_attempts', ['risk_score', 'timestamp'], 
                   postgresql_where=sa.text('success = false'))
    
    # Create security_events table
    op.create_table(
        'security_events',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('event_type', sa.String(), nullable=False),
        sa.Column('risk_level', sa.String(), nullable=False),
        sa.Column('status', sa.String(), nullable=False),
        sa.Column('timestamp', sa.DateTime(timezone=True), nullable=False),
        
        # User and session info
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('session_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('device_id', postgresql.UUID(as_uuid=True), nullable=True),
        
        # IP and device info
        sa.Column('ip_address', sa.String(), nullable=True),
        sa.Column('user_agent', sa.Text(), nullable=True),
        
        # Event details
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('details', sa.JSON(), nullable=False, default={}),
        sa.Column('affected_resources', sa.JSON(), nullable=False, default=[]),
        
        # Location info
        sa.Column('country', sa.String(2), nullable=True),
        sa.Column('city', sa.String(), nullable=True),
        sa.Column('latitude', sa.Float(), nullable=True),
        sa.Column('longitude', sa.Float(), nullable=True),
        
        # Investigation and response
        sa.Column('investigated_by', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('investigation_notes', sa.JSON(), nullable=False, default=[]),
        sa.Column('resolved_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('resolved_by', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('resolution', sa.Text(), nullable=True),
        sa.Column('false_positive_reason', sa.String(), nullable=True),
        
        # Correlation
        sa.Column('correlation_id', sa.String(), nullable=True),
        sa.Column('related_event_ids', sa.JSON(), nullable=False, default=[]),
        sa.Column('attack_pattern', sa.String(), nullable=True),
        
        # Metadata
        sa.Column('source_system', sa.String(), nullable=False, default='identity'),
        sa.Column('alert_sent', sa.Boolean(), nullable=False, default=False),
        sa.Column('auto_mitigated', sa.Boolean(), nullable=False, default=False),
        sa.Column('requires_review', sa.Boolean(), nullable=False, default=True),
        sa.Column('severity_score', sa.Float(), nullable=False, default=0.0),
        sa.Column('response_priority', sa.Integer(), nullable=False, default=5),
        
        # Timestamps and metadata
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('metadata', sa.JSON(), nullable=False, default={})
    )
    
    # Create indexes for security_events
    op.create_index('ix_security_events_event_type', 'security_events', ['event_type'])
    op.create_index('ix_security_events_risk_level', 'security_events', ['risk_level'])
    op.create_index('ix_security_events_status', 'security_events', ['status'])
    op.create_index('ix_security_events_timestamp', 'security_events', ['timestamp'])
    op.create_index('ix_security_events_user_id', 'security_events', ['user_id'])
    op.create_index('ix_security_events_ip_address', 'security_events', ['ip_address'])
    op.create_index('ix_security_events_correlation_id', 'security_events', ['correlation_id'])
    op.create_index('ix_security_events_attack_pattern', 'security_events', ['attack_pattern'])
    op.create_index('ix_security_events_source_system', 'security_events', ['source_system'])
    op.create_index('ix_security_events_requires_review', 'security_events', ['requires_review'])
    op.create_index('ix_security_events_created_at', 'security_events', ['created_at'])
    
    # Composite indexes for common queries
    op.create_index('ix_security_events_user_timestamp', 'security_events', ['user_id', 'timestamp'])
    op.create_index('ix_security_events_type_timestamp', 'security_events', ['event_type', 'timestamp'])
    op.create_index('ix_security_events_risk_status_timestamp', 'security_events', 
                   ['risk_level', 'status', 'timestamp'])
    op.create_index('ix_security_events_correlation', 'security_events', ['correlation_id'],
                   postgresql_where=sa.text('correlation_id IS NOT NULL'))


def downgrade() -> None:
    """Drop audit tables."""
    # Drop indexes first
    op.drop_index('ix_security_events_correlation')
    op.drop_index('ix_security_events_risk_status_timestamp')
    op.drop_index('ix_security_events_type_timestamp')
    op.drop_index('ix_security_events_user_timestamp')
    op.drop_index('ix_security_events_created_at')
    op.drop_index('ix_security_events_requires_review')
    op.drop_index('ix_security_events_source_system')
    op.drop_index('ix_security_events_attack_pattern')
    op.drop_index('ix_security_events_correlation_id')
    op.drop_index('ix_security_events_ip_address')
    op.drop_index('ix_security_events_user_id')
    op.drop_index('ix_security_events_timestamp')
    op.drop_index('ix_security_events_status')
    op.drop_index('ix_security_events_risk_level')
    op.drop_index('ix_security_events_event_type')
    
    op.drop_index('ix_login_attempts_risk_failed')
    op.drop_index('ix_login_attempts_user_timestamp')
    op.drop_index('ix_login_attempts_ip_timestamp')
    op.drop_index('ix_login_attempts_email_timestamp')
    op.drop_index('ix_login_attempts_created_at')
    op.drop_index('ix_login_attempts_country')
    op.drop_index('ix_login_attempts_risk_score')
    op.drop_index('ix_login_attempts_failure_reason')
    op.drop_index('ix_login_attempts_success')
    op.drop_index('ix_login_attempts_timestamp')
    op.drop_index('ix_login_attempts_device_fingerprint')
    op.drop_index('ix_login_attempts_ip_address')
    op.drop_index('ix_login_attempts_session_id')
    op.drop_index('ix_login_attempts_user_id')
    op.drop_index('ix_login_attempts_email')
    
    # Drop tables
    op.drop_table('security_events')
    op.drop_table('login_attempts')