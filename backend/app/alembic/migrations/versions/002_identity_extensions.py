"""Identity Extensions: MFA, Sessions, Tokens

Revision ID: 002_identity_extensions
Revises: 001_identity_foundation
Create Date: 2025-07-04 12:30:00.000000

"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '002_identity_extensions'
down_revision = '001_identity_foundation'
branch_labels = None
depends_on = None


def upgrade():
    """Create identity extension tables for MFA, sessions, tokens, etc."""
    
    # User sessions table
    op.create_table('user_sessions',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=False, index=True),
        sa.Column('session_token', sa.String(255), nullable=False, unique=True, index=True),
        sa.Column('refresh_token', sa.String(255), nullable=True, unique=True, index=True),
        sa.Column('device_id', sa.String(255), nullable=True, index=True),
        sa.Column('device_name', sa.String(100), nullable=True),
        sa.Column('device_type', sa.String(50), nullable=True),
        sa.Column('user_agent', sa.Text(), nullable=True),
        sa.Column('ip_address', sa.String(45), nullable=True, index=True),
        sa.Column('country_code', sa.String(2), nullable=True),
        sa.Column('city', sa.String(100), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=False, default=True),
        sa.Column('is_trusted', sa.Boolean(), nullable=False, default=False),
        sa.Column('last_activity_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('CURRENT_TIMESTAMP')),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('revoked_by', postgresql.UUID(as_uuid=True), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['identity.users.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['revoked_by'], ['identity.users.id'], ondelete='SET NULL'),
        schema='identity'
    )
    
    # MFA devices table
    op.create_table('mfa_devices',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=False, index=True),
        sa.Column('device_type', sa.Enum('totp', 'sms', 'email', 'backup_codes', name='mfa_device_type'), nullable=False),
        sa.Column('device_name', sa.String(100), nullable=False),
        sa.Column('secret_key', sa.Text(), nullable=True),  # Encrypted
        sa.Column('phone_number', sa.String(20), nullable=True),  # For SMS
        sa.Column('email', sa.String(255), nullable=True),  # For email MFA
        sa.Column('backup_codes', sa.JSON(), nullable=True),  # Encrypted JSON array
        sa.Column('is_verified', sa.Boolean(), nullable=False, default=False),
        sa.Column('is_primary', sa.Boolean(), nullable=False, default=False),
        sa.Column('is_active', sa.Boolean(), nullable=False, default=True),
        sa.Column('last_used_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('failure_count', sa.Integer(), nullable=False, default=0),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('CURRENT_TIMESTAMP')),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('CURRENT_TIMESTAMP')),
        sa.ForeignKeyConstraint(['user_id'], ['identity.users.id'], ondelete='CASCADE'),
        schema='identity'
    )
    
    # Device registrations table
    op.create_table('device_registrations',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=False, index=True),
        sa.Column('device_id', sa.String(255), nullable=False, index=True),
        sa.Column('device_name', sa.String(100), nullable=False),
        sa.Column('device_type', sa.String(50), nullable=False),
        sa.Column('platform', sa.String(50), nullable=True),
        sa.Column('browser', sa.String(100), nullable=True),
        sa.Column('browser_version', sa.String(50), nullable=True),
        sa.Column('os', sa.String(100), nullable=True),
        sa.Column('os_version', sa.String(50), nullable=True),
        sa.Column('fingerprint', sa.String(255), nullable=True, index=True),
        sa.Column('trust_score', sa.Float(), nullable=False, default=0.0),
        sa.Column('is_trusted', sa.Boolean(), nullable=False, default=False),
        sa.Column('is_active', sa.Boolean(), nullable=False, default=True),
        sa.Column('first_seen_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('CURRENT_TIMESTAMP')),
        sa.Column('last_seen_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('CURRENT_TIMESTAMP')),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('CURRENT_TIMESTAMP')),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('CURRENT_TIMESTAMP')),
        sa.ForeignKeyConstraint(['user_id'], ['identity.users.id'], ondelete='CASCADE'),
        sa.UniqueConstraint('user_id', 'device_id', name='uq_user_device'),
        schema='identity'
    )
    
    # Access tokens table (for API access, password reset, email verification, etc.)
    op.create_table('access_tokens',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=False, index=True),
        sa.Column('token_type', sa.Enum('password_reset', 'email_verification', 'api_access', 'mfa_setup', name='token_type'), nullable=False),
        sa.Column('token_hash', sa.String(255), nullable=False, unique=True, index=True),
        sa.Column('selector', sa.String(255), nullable=False, index=True),
        sa.Column('purpose', sa.String(100), nullable=True),
        sa.Column('metadata', sa.JSON(), nullable=True),
        sa.Column('uses_remaining', sa.Integer(), nullable=True),  # For multi-use tokens
        sa.Column('is_used', sa.Boolean(), nullable=False, default=False),
        sa.Column('used_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('used_by_ip', sa.String(45), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('CURRENT_TIMESTAMP')),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['identity.users.id'], ondelete='CASCADE'),
        schema='identity'
    )
    
    # Password history table
    op.create_table('password_history',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=False, index=True),
        sa.Column('password_hash', sa.Text(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('CURRENT_TIMESTAMP')),
        sa.Column('is_current', sa.Boolean(), nullable=False, default=False),
        sa.ForeignKeyConstraint(['user_id'], ['identity.users.id'], ondelete='CASCADE'),
        schema='identity'
    )
    
    # Login attempts table (for security monitoring)
    op.create_table('login_attempts',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=True, index=True),
        sa.Column('email_or_username', sa.String(255), nullable=False, index=True),
        sa.Column('ip_address', sa.String(45), nullable=False, index=True),
        sa.Column('user_agent', sa.Text(), nullable=True),
        sa.Column('device_fingerprint', sa.String(255), nullable=True),
        sa.Column('attempt_type', sa.Enum('password', 'mfa', 'recovery', name='login_attempt_type'), nullable=False),
        sa.Column('result', sa.Enum('success', 'invalid_credentials', 'account_locked', 'mfa_required', 'mfa_failed', name='login_result'), nullable=False),
        sa.Column('failure_reason', sa.String(100), nullable=True),
        sa.Column('country_code', sa.String(2), nullable=True),
        sa.Column('city', sa.String(100), nullable=True),
        sa.Column('risk_score', sa.Float(), nullable=False, default=0.0),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('CURRENT_TIMESTAMP')),
        sa.ForeignKeyConstraint(['user_id'], ['identity.users.id'], ondelete='SET NULL'),
        schema='identity'
    )
    
    # Emergency contacts table
    op.create_table('emergency_contacts',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=False, index=True),
        sa.Column('contact_name', sa.String(200), nullable=False),
        sa.Column('contact_email', sa.String(255), nullable=False),
        sa.Column('contact_phone', sa.String(20), nullable=True),
        sa.Column('relationship', sa.String(50), nullable=True),
        sa.Column('is_verified', sa.Boolean(), nullable=False, default=False),
        sa.Column('verification_token', sa.String(255), nullable=True),
        sa.Column('verification_sent_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('verified_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=False, default=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('CURRENT_TIMESTAMP')),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('CURRENT_TIMESTAMP')),
        sa.ForeignKeyConstraint(['user_id'], ['identity.users.id'], ondelete='CASCADE'),
        schema='identity'
    )
    
    # User settings table
    op.create_table('user_settings',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=False, index=True),
        sa.Column('category', sa.String(50), nullable=False, index=True),
        sa.Column('key', sa.String(100), nullable=False, index=True),
        sa.Column('value', sa.JSON(), nullable=True),
        sa.Column('value_type', sa.String(20), nullable=False, default='string'),
        sa.Column('is_encrypted', sa.Boolean(), nullable=False, default=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('CURRENT_TIMESTAMP')),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('CURRENT_TIMESTAMP')),
        sa.ForeignKeyConstraint(['user_id'], ['identity.users.id'], ondelete='CASCADE'),
        sa.UniqueConstraint('user_id', 'category', 'key', name='uq_user_settings'),
        schema='identity'
    )
    
    # Create performance indexes
    op.create_index('idx_user_sessions_user_active', 'user_sessions', ['user_id', 'is_active'], schema='identity')
    op.create_index('idx_user_sessions_token', 'user_sessions', ['session_token'], unique=True, schema='identity')
    op.create_index('idx_user_sessions_expires', 'user_sessions', ['expires_at'], schema='identity')
    op.create_index('idx_user_sessions_device', 'user_sessions', ['device_id'], schema='identity')
    
    op.create_index('idx_mfa_devices_user_type', 'mfa_devices', ['user_id', 'device_type'], schema='identity')
    op.create_index('idx_mfa_devices_user_active', 'mfa_devices', ['user_id', 'is_active'], schema='identity')
    
    op.create_index('idx_device_registrations_fingerprint', 'device_registrations', ['fingerprint'], schema='identity')
    op.create_index('idx_device_registrations_trust', 'device_registrations', ['user_id', 'is_trusted'], schema='identity')
    
    op.create_index('idx_access_tokens_type_expires', 'access_tokens', ['token_type', 'expires_at'], schema='identity')
    op.create_index('idx_access_tokens_selector', 'access_tokens', ['selector'], schema='identity')
    
    op.create_index('idx_password_history_user_current', 'password_history', ['user_id', 'is_current'], schema='identity')
    op.create_index('idx_password_history_created', 'password_history', ['created_at'], schema='identity')
    
    op.create_index('idx_login_attempts_ip_time', 'login_attempts', ['ip_address', 'created_at'], schema='identity')
    op.create_index('idx_login_attempts_user_time', 'login_attempts', ['user_id', 'created_at'], schema='identity')
    op.create_index('idx_login_attempts_result_time', 'login_attempts', ['result', 'created_at'], schema='identity')
    
    op.create_index('idx_emergency_contacts_user_active', 'emergency_contacts', ['user_id', 'is_active'], schema='identity')
    
    op.create_index('idx_user_settings_category_key', 'user_settings', ['category', 'key'], schema='identity')


def downgrade():
    """Drop identity extension tables."""
    op.drop_table('user_settings', schema='identity')
    op.drop_table('emergency_contacts', schema='identity')
    op.drop_table('login_attempts', schema='identity')
    op.drop_table('password_history', schema='identity')
    op.drop_table('access_tokens', schema='identity')
    op.drop_table('device_registrations', schema='identity')
    op.drop_table('mfa_devices', schema='identity')
    op.drop_table('user_sessions', schema='identity')