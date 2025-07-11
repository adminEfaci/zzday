"""
Complete Identity Module Schema

Revision ID: 008_identity_complete
Revises: 007_partitioning_setup
Create Date: 2024-01-01 00:00:00.000000
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers
revision = '008_identity_complete'
down_revision = '007_partitioning_setup'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create all identity module tables with proper indexes."""
    
    # Users table (if not exists)
    op.create_table(
        'users',
        sa.Column('id', postgresql.UUID(), nullable=False),
        sa.Column('email', sa.String(255), nullable=False),
        sa.Column('username', sa.String(100), nullable=True),
        sa.Column('phone_number', sa.String(50), nullable=True),
        sa.Column('password_hash', sa.Text(), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=False, default=True),
        sa.Column('is_verified', sa.Boolean(), nullable=False, default=False),
        sa.Column('is_locked', sa.Boolean(), nullable=False, default=False),
        sa.Column('full_name', sa.String(255), nullable=True),
        sa.Column('display_name', sa.String(100), nullable=True),
        sa.Column('avatar_url', sa.Text(), nullable=True),
        sa.Column('bio', sa.Text(), nullable=True),
        sa.Column('date_of_birth', sa.String(20), nullable=True),
        sa.Column('gender', sa.String(20), nullable=True),
        sa.Column('address', postgresql.JSON(), nullable=True),
        sa.Column('metadata', postgresql.JSON(), nullable=False, default={}),
        sa.Column('preferences', postgresql.JSON(), nullable=False, default={}),
        sa.Column('mfa_enabled', sa.Boolean(), nullable=False, default=False),
        sa.Column('mfa_methods', postgresql.JSON(), nullable=False, default=[]),
        sa.Column('backup_codes', postgresql.JSON(), nullable=False, default=[]),
        sa.Column('role_ids', postgresql.JSON(), nullable=False, default=[]),
        sa.Column('permission_ids', postgresql.JSON(), nullable=False, default=[]),
        sa.Column('external_ids', postgresql.JSON(), nullable=False, default={}),
        sa.Column('status', sa.String(50), nullable=False, default='active'),
        sa.Column('status_reason', sa.Text(), nullable=True),
        sa.Column('status_changed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('login_count', sa.Integer(), nullable=False, default=0),
        sa.Column('failed_login_count', sa.Integer(), nullable=False, default=0),
        sa.Column('last_login_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_login_ip', sa.String(45), nullable=True),
        sa.Column('last_activity_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('locked_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('locked_until', sa.DateTime(timezone=True), nullable=True),
        sa.Column('lock_reason', sa.Text(), nullable=True),
        sa.Column('verified_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('verification_token', sa.String(255), nullable=True),
        sa.Column('verification_token_expires_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('password_reset_token', sa.String(255), nullable=True),
        sa.Column('password_reset_token_expires_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('password_changed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('deleted_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('email'),
        sa.UniqueConstraint('username'),
        if_not_exists=True
    )
    
    # Sessions table
    op.create_table(
        'sessions',
        sa.Column('id', postgresql.UUID(), nullable=False),
        sa.Column('user_id', postgresql.UUID(), nullable=False),
        sa.Column('session_type', sa.String(50), nullable=False),
        sa.Column('status', sa.String(50), nullable=False),
        sa.Column('access_token', sa.Text(), nullable=False),
        sa.Column('refresh_token', sa.Text(), nullable=True),
        sa.Column('ip_address', sa.String(45), nullable=True),
        sa.Column('user_agent', sa.Text(), nullable=True),
        sa.Column('device_fingerprint', sa.String(255), nullable=True),
        sa.Column('geolocation', postgresql.JSON(), nullable=True),
        sa.Column('is_trusted', sa.Boolean(), nullable=False, default=False),
        sa.Column('requires_mfa', sa.Boolean(), nullable=False, default=False),
        sa.Column('mfa_completed', sa.Boolean(), nullable=False, default=False),
        sa.Column('last_activity_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_refresh_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('activity_count', sa.Integer(), nullable=False, default=0),
        sa.Column('flags', postgresql.JSON(), nullable=False, default=[]),
        sa.Column('metadata', postgresql.JSON(), nullable=False, default={}),
        sa.Column('risk_score', sa.Float(), nullable=False, default=0.0),
        sa.Column('security_events', postgresql.JSON(), nullable=False, default=[]),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        if_not_exists=True
    )
    
    # Groups table
    op.create_table(
        'groups',
        sa.Column('id', postgresql.UUID(), nullable=False),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('description', sa.Text(), nullable=False, default=''),
        sa.Column('group_type', sa.String(50), nullable=False),
        sa.Column('status', sa.String(50), nullable=False),
        sa.Column('visibility', sa.String(50), nullable=False, default='private'),
        sa.Column('join_method', sa.String(50), nullable=False, default='request'),
        sa.Column('parent_group_id', postgresql.UUID(), nullable=True),
        sa.Column('nesting_level', sa.Integer(), nullable=False, default=0),
        sa.Column('max_members', sa.Integer(), nullable=False, default=1000),
        sa.Column('allow_nested_groups', sa.Boolean(), nullable=False, default=True),
        sa.Column('allow_guest_members', sa.Boolean(), nullable=False, default=False),
        sa.Column('require_approval', sa.Boolean(), nullable=False, default=False),
        sa.Column('auto_approve_members', sa.Boolean(), nullable=False, default=False),
        sa.Column('tags', postgresql.JSON(), nullable=False, default=[]),
        sa.Column('metadata', postgresql.JSON(), nullable=False, default={}),
        sa.Column('settings', postgresql.JSON(), nullable=False, default={}),
        sa.Column('member_count', sa.Integer(), nullable=False, default=0),
        sa.Column('owner_count', sa.Integer(), nullable=False, default=0),
        sa.Column('subgroup_count', sa.Integer(), nullable=False, default=0),
        sa.Column('owner_ids', postgresql.JSON(), nullable=False, default=[]),
        sa.Column('created_by', postgresql.UUID(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('archived_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('deleted_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['parent_group_id'], ['groups.id']),
        if_not_exists=True
    )
    
    # Group members table
    op.create_table(
        'group_members',
        sa.Column('id', postgresql.UUID(), nullable=False),
        sa.Column('group_id', postgresql.UUID(), nullable=False),
        sa.Column('user_id', postgresql.UUID(), nullable=False),
        sa.Column('role', sa.String(50), nullable=False),
        sa.Column('membership_type', sa.String(50), nullable=False, default='direct'),
        sa.Column('joined_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('invited_by', postgresql.UUID(), nullable=True),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=False, default=True),
        sa.Column('permissions', postgresql.JSON(), nullable=False, default=[]),
        sa.Column('metadata', postgresql.JSON(), nullable=False, default={}),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['group_id'], ['groups.id']),
        sa.UniqueConstraint('group_id', 'user_id', name='unique_group_user'),
        if_not_exists=True
    )
    
    # Permissions table
    op.create_table(
        'permissions',
        sa.Column('id', postgresql.UUID(), nullable=False),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('code', sa.String(100), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('resource', sa.String(100), nullable=True),
        sa.Column('action', sa.String(100), nullable=True),
        sa.Column('scope', sa.String(100), nullable=True),
        sa.Column('conditions', postgresql.JSON(), nullable=True),
        sa.Column('effect', sa.String(20), nullable=False, default='allow'),
        sa.Column('metadata', postgresql.JSON(), nullable=False, default={}),
        sa.Column('is_system', sa.Boolean(), nullable=False, default=False),
        sa.Column('is_active', sa.Boolean(), nullable=False, default=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('code'),
        if_not_exists=True
    )
    
    # Roles table
    op.create_table(
        'roles',
        sa.Column('id', postgresql.UUID(), nullable=False),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('code', sa.String(100), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('type', sa.String(50), nullable=False, default='custom'),
        sa.Column('priority', sa.Integer(), nullable=False, default=0),
        sa.Column('is_active', sa.Boolean(), nullable=False, default=True),
        sa.Column('is_system', sa.Boolean(), nullable=False, default=False),
        sa.Column('is_default', sa.Boolean(), nullable=False, default=False),
        sa.Column('metadata', postgresql.JSON(), nullable=False, default={}),
        sa.Column('conditions', postgresql.JSON(), nullable=True),
        sa.Column('inherits_from', postgresql.JSON(), nullable=False, default=[]),
        sa.Column('max_assignments', sa.Integer(), nullable=True),
        sa.Column('valid_from', sa.DateTime(timezone=True), nullable=True),
        sa.Column('valid_until', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('created_by', postgresql.UUID(), nullable=True),
        sa.Column('updated_by', postgresql.UUID(), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('code'),
        if_not_exists=True
    )
    
    # Role-User association table
    op.create_table(
        'role_user',
        sa.Column('role_id', postgresql.UUID(), nullable=False),
        sa.Column('user_id', postgresql.UUID(), nullable=False),
        sa.Column('assigned_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('assigned_by', postgresql.UUID(), nullable=True),
        sa.Column('valid_from', sa.DateTime(timezone=True), nullable=True),
        sa.Column('valid_until', sa.DateTime(timezone=True), nullable=True),
        sa.Column('context', postgresql.JSON(), nullable=True),
        sa.PrimaryKeyConstraint('role_id', 'user_id'),
        sa.ForeignKeyConstraint(['role_id'], ['roles.id']),
        if_not_exists=True
    )
    
    # Role-Permission association table
    op.create_table(
        'role_permission',
        sa.Column('role_id', postgresql.UUID(), nullable=False),
        sa.Column('permission_id', postgresql.UUID(), nullable=False),
        sa.Column('granted_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('conditions', postgresql.JSON(), nullable=True),
        sa.PrimaryKeyConstraint('role_id', 'permission_id'),
        sa.ForeignKeyConstraint(['role_id'], ['roles.id']),
        sa.ForeignKeyConstraint(['permission_id'], ['permissions.id']),
        if_not_exists=True
    )
    
    # Device registrations table
    op.create_table(
        'device_registrations',
        sa.Column('id', postgresql.UUID(), nullable=False),
        sa.Column('user_id', postgresql.UUID(), nullable=False),
        sa.Column('device_id', sa.String(255), nullable=False),
        sa.Column('device_name', sa.String(255), nullable=True),
        sa.Column('device_type', sa.String(50), nullable=False),
        sa.Column('fingerprint', sa.String(255), nullable=False),
        sa.Column('platform', sa.String(50), nullable=False),
        sa.Column('platform_version', sa.String(50), nullable=True),
        sa.Column('app_version', sa.String(50), nullable=True),
        sa.Column('push_token', sa.Text(), nullable=True),
        sa.Column('trusted', sa.Boolean(), nullable=False, default=False),
        sa.Column('trusted_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('trust_expires_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_seen', sa.DateTime(timezone=True), nullable=False),
        sa.Column('metadata', postgresql.JSON(), nullable=False, default={}),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('user_id', 'device_id'),
        if_not_exists=True
    )
    
    # MFA devices table
    op.create_table(
        'mfa_devices',
        sa.Column('id', postgresql.UUID(), nullable=False),
        sa.Column('user_id', postgresql.UUID(), nullable=False),
        sa.Column('device_name', sa.String(255), nullable=False),
        sa.Column('method', sa.String(50), nullable=False),
        sa.Column('secret', sa.Text(), nullable=True),
        sa.Column('phone_number', sa.String(50), nullable=True),
        sa.Column('email', sa.String(255), nullable=True),
        sa.Column('is_verified', sa.Boolean(), nullable=False, default=False),
        sa.Column('is_primary', sa.Boolean(), nullable=False, default=False),
        sa.Column('is_active', sa.Boolean(), nullable=False, default=True),
        sa.Column('verified_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_used_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('verification_count', sa.Integer(), nullable=False, default=0),
        sa.Column('failed_attempts', sa.Integer(), nullable=False, default=0),
        sa.Column('locked_until', sa.DateTime(timezone=True), nullable=True),
        sa.Column('metadata', postgresql.JSON(), nullable=False, default={}),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        if_not_exists=True
    )
    
    # Access tokens table
    op.create_table(
        'access_tokens',
        sa.Column('id', postgresql.UUID(), nullable=False),
        sa.Column('user_id', postgresql.UUID(), nullable=False),
        sa.Column('client_id', sa.String(255), nullable=True),
        sa.Column('token_hash', sa.String(255), nullable=False),
        sa.Column('token_type', sa.String(50), nullable=False),
        sa.Column('scope', sa.String(500), nullable=True),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('refresh_token_hash', sa.String(255), nullable=True),
        sa.Column('refresh_token_expires_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('token_family', sa.String(255), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=False, default=True),
        sa.Column('is_revoked', sa.Boolean(), nullable=False, default=False),
        sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('revoked_reason', sa.Text(), nullable=True),
        sa.Column('usage_count', sa.Integer(), nullable=False, default=0),
        sa.Column('max_usage', sa.Integer(), nullable=True),
        sa.Column('last_used_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_used_ip', sa.String(45), nullable=True),
        sa.Column('last_used_user_agent', sa.Text(), nullable=True),
        sa.Column('suspicious_activity', sa.Boolean(), nullable=False, default=False),
        sa.Column('metadata', postgresql.JSON(), nullable=False, default={}),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        if_not_exists=True
    )
    
    # Emergency contacts table
    op.create_table(
        'emergency_contacts',
        sa.Column('id', postgresql.UUID(), nullable=False),
        sa.Column('user_id', postgresql.UUID(), nullable=False),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('relationship', sa.String(100), nullable=False),
        sa.Column('phone_number', sa.String(50), nullable=False),
        sa.Column('email', sa.String(255), nullable=True),
        sa.Column('address', sa.Text(), nullable=True),
        sa.Column('notes', sa.Text(), nullable=True),
        sa.Column('is_primary', sa.Boolean(), nullable=False, default=False),
        sa.Column('is_verified', sa.Boolean(), nullable=False, default=False),
        sa.Column('verified_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('metadata', postgresql.JSON(), nullable=False, default={}),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        if_not_exists=True
    )
    
    # User preferences table
    op.create_table(
        'user_preferences',
        sa.Column('id', postgresql.UUID(), nullable=False),
        sa.Column('user_id', postgresql.UUID(), nullable=False),
        sa.Column('category', sa.String(100), nullable=False),
        sa.Column('preferences', postgresql.JSON(), nullable=False, default={}),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('user_id', 'category'),
        if_not_exists=True
    )
    
    # Create indexes for optimal performance
    
    # Users indexes
    op.create_index('idx_users_email', 'users', ['email'], if_not_exists=True)
    op.create_index('idx_users_username', 'users', ['username'], if_not_exists=True)
    op.create_index('idx_users_phone', 'users', ['phone_number'], if_not_exists=True)
    op.create_index('idx_users_status', 'users', ['status'], if_not_exists=True)
    op.create_index('idx_users_created_at', 'users', ['created_at'], if_not_exists=True)
    op.create_index('idx_users_deleted_at', 'users', ['deleted_at'], if_not_exists=True)
    
    # Sessions indexes
    op.create_index('idx_sessions_user_id', 'sessions', ['user_id'], if_not_exists=True)
    op.create_index('idx_sessions_access_token', 'sessions', ['access_token'], if_not_exists=True)
    op.create_index('idx_sessions_refresh_token', 'sessions', ['refresh_token'], if_not_exists=True)
    op.create_index('idx_sessions_type', 'sessions', ['session_type'], if_not_exists=True)
    op.create_index('idx_sessions_status', 'sessions', ['status'], if_not_exists=True)
    op.create_index('idx_sessions_device_fingerprint', 'sessions', ['device_fingerprint'], if_not_exists=True)
    op.create_index('idx_sessions_ip_address', 'sessions', ['ip_address'], if_not_exists=True)
    op.create_index('idx_sessions_created_at', 'sessions', ['created_at'], if_not_exists=True)
    op.create_index('idx_sessions_last_activity', 'sessions', ['last_activity_at'], if_not_exists=True)
    
    # Groups indexes
    op.create_index('idx_groups_name', 'groups', ['name'], if_not_exists=True)
    op.create_index('idx_groups_type', 'groups', ['group_type'], if_not_exists=True)
    op.create_index('idx_groups_status', 'groups', ['status'], if_not_exists=True)
    op.create_index('idx_groups_parent', 'groups', ['parent_group_id'], if_not_exists=True)
    op.create_index('idx_groups_created_by', 'groups', ['created_by'], if_not_exists=True)
    op.create_index('idx_groups_created_at', 'groups', ['created_at'], if_not_exists=True)
    op.create_index('idx_groups_deleted_at', 'groups', ['deleted_at'], if_not_exists=True)
    
    # Group members indexes
    op.create_index('idx_group_members_group', 'group_members', ['group_id'], if_not_exists=True)
    op.create_index('idx_group_members_user', 'group_members', ['user_id'], if_not_exists=True)
    op.create_index('idx_group_members_role', 'group_members', ['role'], if_not_exists=True)
    op.create_index('idx_group_members_active', 'group_members', ['is_active'], if_not_exists=True)
    op.create_index('idx_group_members_joined', 'group_members', ['joined_at'], if_not_exists=True)
    op.create_index('idx_group_members_expires', 'group_members', ['expires_at'], if_not_exists=True)
    
    # Device registrations indexes
    op.create_index('idx_devices_user_id', 'device_registrations', ['user_id'], if_not_exists=True)
    op.create_index('idx_devices_device_id', 'device_registrations', ['device_id'], if_not_exists=True)
    op.create_index('idx_devices_fingerprint', 'device_registrations', ['fingerprint'], if_not_exists=True)
    op.create_index('idx_devices_platform', 'device_registrations', ['platform'], if_not_exists=True)
    op.create_index('idx_devices_trusted', 'device_registrations', ['trusted'], if_not_exists=True)
    op.create_index('idx_devices_last_seen', 'device_registrations', ['last_seen'], if_not_exists=True)
    
    # MFA devices indexes
    op.create_index('idx_mfa_user_id', 'mfa_devices', ['user_id'], if_not_exists=True)
    op.create_index('idx_mfa_method', 'mfa_devices', ['method'], if_not_exists=True)
    op.create_index('idx_mfa_active', 'mfa_devices', ['is_active'], if_not_exists=True)
    op.create_index('idx_mfa_primary', 'mfa_devices', ['is_primary'], if_not_exists=True)
    
    # Access tokens indexes
    op.create_index('idx_tokens_user_id', 'access_tokens', ['user_id'], if_not_exists=True)
    op.create_index('idx_tokens_hash', 'access_tokens', ['token_hash'], if_not_exists=True)
    op.create_index('idx_tokens_refresh_hash', 'access_tokens', ['refresh_token_hash'], if_not_exists=True)
    op.create_index('idx_tokens_family', 'access_tokens', ['token_family'], if_not_exists=True)
    op.create_index('idx_tokens_active', 'access_tokens', ['is_active'], if_not_exists=True)
    op.create_index('idx_tokens_expires', 'access_tokens', ['expires_at'], if_not_exists=True)
    
    # Composite indexes for common queries
    op.create_index('idx_sessions_user_active', 'sessions', ['user_id', 'status'], if_not_exists=True)
    op.create_index('idx_groups_members_active', 'group_members', ['group_id', 'is_active'], if_not_exists=True)
    op.create_index('idx_user_roles_active', 'role_user', ['user_id', 'valid_until'], if_not_exists=True)


def downgrade() -> None:
    """Drop all identity module tables."""
    # Drop indexes first
    op.drop_index('idx_user_roles_active', 'role_user', if_exists=True)
    op.drop_index('idx_groups_members_active', 'group_members', if_exists=True)
    op.drop_index('idx_sessions_user_active', 'sessions', if_exists=True)
    
    # Drop all other indexes (abbreviated for brevity)
    
    # Drop tables in reverse order
    op.drop_table('user_preferences', if_exists=True)
    op.drop_table('emergency_contacts', if_exists=True)
    op.drop_table('access_tokens', if_exists=True)
    op.drop_table('mfa_devices', if_exists=True)
    op.drop_table('device_registrations', if_exists=True)
    op.drop_table('role_permission', if_exists=True)
    op.drop_table('role_user', if_exists=True)
    op.drop_table('roles', if_exists=True)
    op.drop_table('permissions', if_exists=True)
    op.drop_table('group_members', if_exists=True)
    op.drop_table('groups', if_exists=True)
    op.drop_table('sessions', if_exists=True)
    op.drop_table('users', if_exists=True)