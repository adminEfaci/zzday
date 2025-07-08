"""Identity Foundation Tables

Revision ID: 001_identity_foundation
Revises: 
Create Date: 2025-07-04 12:00:00.000000

"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '001_identity_foundation'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    """Create core identity tables."""
    
    # Create identity schema
    op.execute('CREATE SCHEMA IF NOT EXISTS identity')
    
    # Users table
    op.create_table('users',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column('email', sa.String(255), nullable=False, unique=True, index=True),
        sa.Column('username', sa.String(50), nullable=False, unique=True, index=True),
        sa.Column('password_hash', sa.Text(), nullable=False),
        sa.Column('security_stamp', sa.String(255), nullable=False),
        sa.Column('status', sa.Enum('active', 'inactive', 'suspended', 'deleted', name='user_status'), nullable=False, default='inactive'),
        sa.Column('email_verified', sa.Boolean(), nullable=False, default=False),
        sa.Column('email_verified_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('phone_number', sa.String(20), nullable=True),
        sa.Column('phone_verified', sa.Boolean(), nullable=False, default=False),
        sa.Column('phone_verified_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_login_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_login_ip', sa.String(45), nullable=True),
        sa.Column('failed_login_attempts', sa.Integer(), nullable=False, default=0),
        sa.Column('locked_until', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('CURRENT_TIMESTAMP')),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('CURRENT_TIMESTAMP')),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True), nullable=True, index=True),
        schema='identity'
    )
    
    # User profiles table
    op.create_table('user_profiles',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=False, index=True),
        sa.Column('first_name', sa.String(100), nullable=True),
        sa.Column('last_name', sa.String(100), nullable=True),
        sa.Column('display_name', sa.String(200), nullable=True),
        sa.Column('bio', sa.Text(), nullable=True),
        sa.Column('avatar_url', sa.String(500), nullable=True),
        sa.Column('date_of_birth', sa.Date(), nullable=True),
        sa.Column('gender', sa.String(20), nullable=True),
        sa.Column('timezone', sa.String(50), nullable=True, default='UTC'),
        sa.Column('language', sa.String(10), nullable=True, default='en'),
        sa.Column('country', sa.String(2), nullable=True),
        sa.Column('city', sa.String(100), nullable=True),
        sa.Column('website', sa.String(200), nullable=True),
        sa.Column('company', sa.String(100), nullable=True),
        sa.Column('job_title', sa.String(100), nullable=True),
        sa.Column('profile_visibility', sa.Enum('public', 'private', 'connections', name='profile_visibility'), nullable=False, default='private'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('CURRENT_TIMESTAMP')),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('CURRENT_TIMESTAMP')),
        sa.ForeignKeyConstraint(['user_id'], ['identity.users.id'], ondelete='CASCADE'),
        schema='identity'
    )
    
    # Roles table
    op.create_table('roles',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column('name', sa.String(50), nullable=False, unique=True, index=True),
        sa.Column('display_name', sa.String(100), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('is_system', sa.Boolean(), nullable=False, default=False),
        sa.Column('is_active', sa.Boolean(), nullable=False, default=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('CURRENT_TIMESTAMP')),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('CURRENT_TIMESTAMP')),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True), nullable=True, index=True),
        schema='identity'
    )
    
    # Permissions table
    op.create_table('permissions',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column('name', sa.String(100), nullable=False, unique=True, index=True),
        sa.Column('display_name', sa.String(200), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('resource', sa.String(50), nullable=False, index=True),
        sa.Column('action', sa.String(50), nullable=False, index=True),
        sa.Column('is_system', sa.Boolean(), nullable=False, default=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('CURRENT_TIMESTAMP')),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True), nullable=True, index=True),
        schema='identity'
    )
    
    # User roles junction table
    op.create_table('user_roles',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=False, index=True),
        sa.Column('role_id', postgresql.UUID(as_uuid=True), nullable=False, index=True),
        sa.Column('assigned_by', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('assigned_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('CURRENT_TIMESTAMP')),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=False, default=True),
        sa.ForeignKeyConstraint(['user_id'], ['identity.users.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['role_id'], ['identity.roles.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['assigned_by'], ['identity.users.id'], ondelete='SET NULL'),
        sa.UniqueConstraint('user_id', 'role_id', name='uq_user_roles'),
        schema='identity'
    )
    
    # Role permissions junction table
    op.create_table('role_permissions',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column('role_id', postgresql.UUID(as_uuid=True), nullable=False, index=True),
        sa.Column('permission_id', postgresql.UUID(as_uuid=True), nullable=False, index=True),
        sa.Column('granted_by', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('granted_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('CURRENT_TIMESTAMP')),
        sa.ForeignKeyConstraint(['role_id'], ['identity.roles.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['permission_id'], ['identity.permissions.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['granted_by'], ['identity.users.id'], ondelete='SET NULL'),
        sa.UniqueConstraint('role_id', 'permission_id', name='uq_role_permissions'),
        schema='identity'
    )
    
    # User permissions (direct permissions) junction table
    op.create_table('user_permissions',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=False, index=True),
        sa.Column('permission_id', postgresql.UUID(as_uuid=True), nullable=False, index=True),
        sa.Column('granted_by', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('granted_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('CURRENT_TIMESTAMP')),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=False, default=True),
        sa.ForeignKeyConstraint(['user_id'], ['identity.users.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['permission_id'], ['identity.permissions.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['granted_by'], ['identity.users.id'], ondelete='SET NULL'),
        sa.UniqueConstraint('user_id', 'permission_id', name='uq_user_permissions'),
        schema='identity'
    )
    
    # Create indexes for performance
    op.create_index('idx_users_email_status', 'users', ['email', 'status'], schema='identity')
    op.create_index('idx_users_username_status', 'users', ['username', 'status'], schema='identity')
    op.create_index('idx_users_tenant_status', 'users', ['tenant_id', 'status'], schema='identity')
    op.create_index('idx_users_created_at', 'users', ['created_at'], schema='identity')
    op.create_index('idx_user_profiles_user_id', 'user_profiles', ['user_id'], unique=True, schema='identity')
    op.create_index('idx_roles_tenant_active', 'roles', ['tenant_id', 'is_active'], schema='identity')
    op.create_index('idx_permissions_resource_action', 'permissions', ['resource', 'action'], schema='identity')


def downgrade():
    """Drop identity foundation tables."""
    op.drop_table('user_permissions', schema='identity')
    op.drop_table('role_permissions', schema='identity')
    op.drop_table('user_roles', schema='identity')
    op.drop_table('permissions', schema='identity')
    op.drop_table('roles', schema='identity')
    op.drop_table('user_profiles', schema='identity')
    op.drop_table('users', schema='identity')
    op.execute('DROP SCHEMA IF EXISTS identity CASCADE')