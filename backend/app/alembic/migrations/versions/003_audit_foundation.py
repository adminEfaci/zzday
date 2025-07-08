"""Audit foundation: Comprehensive audit system with compliance support

Revision ID: 003_audit_foundation
Revises: 002_identity_extensions
Create Date: 2025-07-05 10:30:00.000000

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '003_audit_foundation'
down_revision: str | None = '002_identity_extensions'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create comprehensive audit system with compliance support."""
    
    # Create audit schema
    op.execute('CREATE SCHEMA IF NOT EXISTS audit')
    
    # Create enum types for audit system
    audit_severity_enum = postgresql.ENUM(
        'LOW', 'MEDIUM', 'HIGH', 'CRITICAL',
        name='audit_severity_enum'
    )
    audit_severity_enum.create(op.get_bind())
    
    audit_category_enum = postgresql.ENUM(
        'AUTHENTICATION', 'AUTHORIZATION', 'DATA_ACCESS', 'DATA_MODIFICATION',
        'SYSTEM_ACCESS', 'SECURITY', 'COMPLIANCE', 'ERROR', 'PERFORMANCE',
        name='audit_category_enum'
    )
    audit_category_enum.create(op.get_bind())
    
    audit_status_enum = postgresql.ENUM(
        'ACTIVE', 'PENDING_ARCHIVE', 'ARCHIVED',
        name='audit_status_enum'
    )
    audit_status_enum.create(op.get_bind())
    
    retention_policy_enum = postgresql.ENUM(
        'SHORT_TERM', 'MEDIUM_TERM', 'LONG_TERM', 'PERMANENT',
        name='retention_policy_enum'
    )
    retention_policy_enum.create(op.get_bind())
    
    # Create audit_logs table (parent table for partitioning)
    op.create_table(
        'audit_logs',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('created_at', sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime, nullable=False, server_default=sa.func.now()),
        
        # Basic fields
        sa.Column('title', sa.String(255), nullable=False),
        sa.Column('description', sa.Text),
        sa.Column('retention_policy', sa.Enum('SHORT_TERM', 'MEDIUM_TERM', 'LONG_TERM', 'PERMANENT', name='retention_policy_enum'), nullable=False),
        sa.Column('status', sa.Enum('ACTIVE', 'PENDING_ARCHIVE', 'ARCHIVED', name='audit_status_enum'), nullable=False, server_default='ACTIVE'),
        
        # Statistics
        sa.Column('entry_count', sa.Integer, nullable=False, server_default='0'),
        sa.Column('last_entry_at', sa.DateTime),
        
        # Archive fields
        sa.Column('archived_at', sa.DateTime),
        sa.Column('archive_location', sa.Text),
        sa.Column('archive_size_bytes', sa.BigInteger),
        
        # Metadata
        sa.Column('created_by', postgresql.UUID(as_uuid=True)),
    )
    
    # Create audit_sessions table
    op.create_table(
        'audit_sessions',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('created_at', sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime, nullable=False, server_default=sa.func.now()),
        
        # Session fields
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('correlation_id', sa.String(255), nullable=False),
        
        # Session metadata
        sa.Column('session_type', sa.String(50), nullable=False),  # 'web', 'api', 'mobile', etc.
        sa.Column('ip_address', sa.String(45)),  # Support IPv6
        sa.Column('user_agent', sa.Text),
        
        # Activity tracking
        sa.Column('is_active', sa.Boolean, nullable=False, server_default='true'),
        sa.Column('started_at', sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.Column('last_activity_at', sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.Column('ended_at', sa.DateTime),
        
        # Statistics
        sa.Column('entry_count', sa.Integer, nullable=False, server_default='0'),
        sa.Column('error_count', sa.Integer, nullable=False, server_default='0'),
        
        # Additional context
        sa.Column('context_data', postgresql.JSONB),
    )
    
    # Create audit_entries table (partitioned by created_at)
    op.create_table(
        'audit_entries',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        
        # Foreign keys
        sa.Column('audit_log_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('audit_logs.id'), nullable=False),
        sa.Column('session_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('audit_sessions.id')),
        
        # User information
        sa.Column('user_id', postgresql.UUID(as_uuid=True)),  # Nullable for system actions
        
        # Action information
        sa.Column('action_type', sa.String(50), nullable=False),  # 'create', 'update', 'delete', etc.
        sa.Column('operation', sa.String(100), nullable=False),  # Specific operation name
        sa.Column('action_description', sa.Text, nullable=False),
        
        # Resource information
        sa.Column('resource_type', sa.String(100), nullable=False),
        sa.Column('resource_id', sa.String(255)),
        sa.Column('resource_name', sa.String(255)),
        
        # Context information
        sa.Column('ip_address', sa.String(45)),
        sa.Column('user_agent', sa.Text),
        sa.Column('request_id', sa.String(255)),
        
        # Classification
        sa.Column('severity', sa.Enum('LOW', 'MEDIUM', 'HIGH', 'CRITICAL', name='audit_severity_enum'), nullable=False),
        sa.Column('category', sa.Enum('AUTHENTICATION', 'AUTHORIZATION', 'DATA_ACCESS', 'DATA_MODIFICATION', 'SYSTEM_ACCESS', 'SECURITY', 'COMPLIANCE', 'ERROR', 'PERFORMANCE', name='audit_category_enum'), nullable=False),
        
        # Outcome
        sa.Column('outcome', sa.String(20), nullable=False),  # 'success', 'failure', 'partial'
        sa.Column('error_details', postgresql.JSONB),
        
        # Performance
        sa.Column('duration_ms', sa.Integer),
        
        # Correlation
        sa.Column('correlation_id', sa.String(255), nullable=False),
        
        # Metadata
        sa.Column('metadata', postgresql.JSONB),
        
        # Immutable timestamp
        sa.Column('created_at', sa.DateTime, nullable=False, server_default=sa.func.now()),
    )
    
    # Create audit_fields table for field-level changes
    op.create_table(
        'audit_fields',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        
        # Foreign key
        sa.Column('audit_entry_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('audit_entries.id'), nullable=False),
        
        # Field information
        sa.Column('field_name', sa.String(255), nullable=False),
        sa.Column('field_path', sa.String(500)),  # For nested fields
        
        # Values (stored as JSON for flexibility)
        sa.Column('old_value', postgresql.JSONB),
        sa.Column('new_value', postgresql.JSONB),
        
        # Metadata
        sa.Column('value_type', sa.String(50)),
        sa.Column('is_sensitive', sa.Boolean, nullable=False, server_default='false'),
    )
    
    # Create audit_reports table
    op.create_table(
        'audit_reports',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('created_at', sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime, nullable=False, server_default=sa.func.now()),
        
        # Report metadata
        sa.Column('title', sa.String(255), nullable=False),
        sa.Column('description', sa.Text),
        sa.Column('report_type', sa.String(50), nullable=False),  # 'compliance', 'security', 'user_activity', etc.
        
        # Time period
        sa.Column('period_start', sa.DateTime, nullable=False),
        sa.Column('period_end', sa.DateTime, nullable=False),
        
        # Generation details
        sa.Column('generated_by', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('generation_duration_ms', sa.Integer),
        
        # Report data
        sa.Column('summary_data', postgresql.JSONB, nullable=False),
        sa.Column('detailed_data', postgresql.JSONB),
        
        # Status
        sa.Column('status', sa.String(20), nullable=False, server_default='completed'),
        sa.Column('error_message', sa.Text),
        
        # Storage
        sa.Column('file_location', sa.Text),  # If exported to file
        sa.Column('file_size_bytes', sa.BigInteger),
        sa.Column('file_format', sa.String(20)),  # 'json', 'csv', 'pdf', etc.
        
        # Access tracking
        sa.Column('access_count', sa.Integer, nullable=False, server_default='0'),
        sa.Column('last_accessed_at', sa.DateTime),
        
        # Retention
        sa.Column('expires_at', sa.DateTime),
        sa.Column('is_archived', sa.Boolean, nullable=False, server_default='false'),
    )
    
    # Create indexes for audit_logs
    op.create_index('idx_audit_logs_status_created', 'audit_logs', ['status', 'created_at'])
    op.create_index('idx_audit_logs_retention_status', 'audit_logs', ['retention_policy', 'status'])
    op.create_index('idx_audit_logs_archived', 'audit_logs', ['archived_at', 'archive_location'])
    
    # Create indexes for audit_sessions
    op.create_index('idx_audit_sessions_user_created', 'audit_sessions', ['user_id', 'created_at'])
    op.create_index('idx_audit_sessions_correlation', 'audit_sessions', ['correlation_id'])
    op.create_index('idx_audit_sessions_active', 'audit_sessions', ['is_active', 'last_activity_at'])
    
    # Create indexes for audit_entries (performance-critical)
    op.create_index('idx_audit_entries_log_created', 'audit_entries', ['audit_log_id', 'created_at'])
    op.create_index('idx_audit_entries_user_created', 'audit_entries', ['user_id', 'created_at'])
    op.create_index('idx_audit_entries_resource', 'audit_entries', ['resource_type', 'resource_id', 'created_at'])
    op.create_index('idx_audit_entries_action', 'audit_entries', ['action_type', 'operation', 'created_at'])
    op.create_index('idx_audit_entries_severity_category', 'audit_entries', ['severity', 'category', 'created_at'])
    op.create_index('idx_audit_entries_session', 'audit_entries', ['session_id', 'created_at'])
    op.create_index('idx_audit_entries_correlation', 'audit_entries', ['correlation_id', 'created_at'])
    
    # Create indexes for audit_fields
    op.create_index('idx_audit_fields_entry', 'audit_fields', ['audit_entry_id'])
    op.create_index('idx_audit_fields_name', 'audit_fields', ['field_name'])
    
    # Create indexes for audit_reports
    op.create_index('idx_audit_reports_type_created', 'audit_reports', ['report_type', 'created_at'])
    op.create_index('idx_audit_reports_period', 'audit_reports', ['period_start', 'period_end'])
    op.create_index('idx_audit_reports_status', 'audit_reports', ['status', 'created_at'])
    
    # Enable PostgreSQL extensions for better performance
    op.execute('CREATE EXTENSION IF NOT EXISTS "pg_trgm"')  # For trigram matching
    
    # Create specialized indexes for search performance
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_audit_entries_action_desc_gin 
        ON audit_entries USING gin (action_description gin_trgm_ops)
    """)
    
    # Create partial indexes for common queries
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_audit_entries_failures 
        ON audit_entries (created_at, severity) 
        WHERE outcome = 'failure'
    """)
    
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_audit_entries_high_severity 
        ON audit_entries (created_at, user_id) 
        WHERE severity IN ('HIGH', 'CRITICAL')
    """)
    
    # Create BRIN indexes for time-series data (space-efficient for large tables)
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_audit_entries_created_brin 
        ON audit_entries USING brin (created_at)
    """)
    
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_audit_logs_created_brin 
        ON audit_logs USING brin (created_at)
    """)


def downgrade() -> None:
    """Downgrade database schema."""
    # Drop tables in reverse order
    op.drop_table('audit_reports')
    op.drop_table('audit_fields')
    op.drop_table('audit_entries')
    op.drop_table('audit_sessions')
    op.drop_table('audit_logs')
    
    # Drop enum types
    op.execute('DROP TYPE IF EXISTS retention_policy_enum')
    op.execute('DROP TYPE IF EXISTS audit_status_enum')
    op.execute('DROP TYPE IF EXISTS audit_category_enum')
    op.execute('DROP TYPE IF EXISTS audit_severity_enum')