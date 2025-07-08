"""Indexes optimization: Performance indexes for all modules

Revision ID: 006_indexes_optimization
Revises: 005_integration_core
Create Date: 2024-07-04 11:15:00.000000

"""
from collections.abc import Sequence

from alembic import op

# revision identifiers, used by Alembic.
revision: str = '006_indexes_optimization'
down_revision: str | None = '005_integration_core'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade database schema."""
    # =====================================================================================
    # IDENTITY MODULE PERFORMANCE INDEXES
    # =====================================================================================
    
    # Composite indexes for user queries
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_users_status_created_composite 
        ON users (status, created_at, account_type)
    """)
    
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_users_login_tracking 
        ON users (last_login, login_count, failed_login_count) 
        WHERE status = 'ACTIVE'
    """)
    
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_users_security_flags 
        ON users (mfa_enabled, require_password_change, locked_until) 
        WHERE status IN ('ACTIVE', 'SUSPENDED')
    """)
    
    # Partial indexes for common filters
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_users_active_verified 
        ON users (created_at, last_login) 
        WHERE status = 'ACTIVE' AND email_verified = true
    """)
    
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_users_suspended_locked 
        ON users (suspended_until, locked_until) 
        WHERE status IN ('SUSPENDED', 'LOCKED')
    """)
    
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_users_pending_verification 
        ON users (created_at, email_verification_token_expires) 
        WHERE status = 'PENDING' AND email_verified = false
    """)
    
    # Session performance indexes
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_sessions_active_user_activity 
        ON sessions (user_id, last_activity, expires_at) 
        WHERE is_active = true
    """)
    
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_sessions_suspicious_activity 
        ON sessions (is_suspicious, risk_score, created_at) 
        WHERE is_active = true
    """)
    
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_sessions_geolocation 
        ON sessions (location_country, location_city, created_at)
    """)
    
    # Device and MFA indexes
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_devices_trusted_active 
        ON devices (user_id, is_trusted, last_seen) 
        WHERE is_blocked = false
    """)
    
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_mfa_devices_primary_active 
        ON mfa_devices (user_id, is_primary, method) 
        WHERE is_active = true
    """)
    
    # Login attempts performance indexes
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_login_attempts_failed_tracking 
        ON login_attempts (email, timestamp, ip_address) 
        WHERE success = false
    """)
    
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_login_attempts_risk_analysis 
        ON login_attempts (ip_address, timestamp, risk_score) 
        WHERE risk_score > 50
    """)
    
    # Role and permission indexes
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_roles_system_priority 
        ON roles (is_system, priority, is_active)
    """)
    
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_permissions_resource_action_active 
        ON permissions (resource, action, is_active)
    """)
    
    # =====================================================================================
    # AUDIT MODULE PERFORMANCE INDEXES
    # =====================================================================================
    
    # Time-series optimized indexes
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_audit_entries_time_series 
        ON audit_entries (created_at, severity, category) 
        WHERE outcome = 'failure'
    """)
    
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_audit_entries_user_activity 
        ON audit_entries (user_id, action_type, created_at) 
        WHERE user_id IS NOT NULL
    """)
    
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_audit_entries_resource_tracking 
        ON audit_entries (resource_type, resource_id, operation, created_at)
    """)
    
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_audit_entries_security_events 
        ON audit_entries (category, severity, created_at) 
        WHERE category IN ('SECURITY', 'AUTHENTICATION', 'AUTHORIZATION')
    """)
    
    # Session correlation indexes
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_audit_sessions_correlation 
        ON audit_sessions (correlation_id, user_id, session_type)
    """)
    
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_audit_sessions_activity_window 
        ON audit_sessions (started_at, ended_at, entry_count) 
        WHERE is_active = false
    """)
    
    # Report performance indexes
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_audit_reports_generation 
        ON audit_reports (report_type, period_start, period_end, status)
    """)
    
    # =====================================================================================
    # NOTIFICATION MODULE PERFORMANCE INDEXES
    # =====================================================================================
    
    # Delivery performance indexes
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_notifications_delivery_queue 
        ON notifications (current_status, scheduled_for, priority) 
        WHERE current_status IN ('PENDING', 'QUEUED', 'RETRYING')
    """)
    
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_notifications_retry_queue 
        ON notifications (next_retry_at, retry_count, max_retries) 
        WHERE current_status = 'FAILED' AND retry_count < max_retries
    """)
    
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_notifications_channel_performance 
        ON notifications (channel, current_status, created_at)
    """)
    
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_notifications_provider_tracking 
        ON notifications (provider, provider_message_id, current_status)
    """)
    
    # Template usage indexes
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_notification_templates_usage 
        ON notification_templates (template_type, category, is_active)
    """)
    
    # Batch processing indexes
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_notification_batches_processing 
        ON notification_batches (status, scheduled_for, priority)
    """)
    
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_notification_batches_progress 
        ON notification_batches (status, processed_count, total_recipients)
    """)
    
    # Recipient management indexes
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_recipients_preferences 
        ON recipients (email_enabled, sms_enabled, push_enabled, global_unsubscribe)
    """)
    
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_recipients_activity 
        ON recipients (last_notification_sent, total_notifications_sent)
    """)
    
    # Delivery log performance indexes
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_delivery_logs_analysis 
        ON delivery_logs (provider, status, request_timestamp, duration_ms)
    """)
    
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_delivery_logs_failures 
        ON delivery_logs (notification_id, status, attempt_number) 
        WHERE status IN ('FAILED', 'BOUNCED', 'SPAM')
    """)
    
    # =====================================================================================
    # INTEGRATION MODULE PERFORMANCE INDEXES
    # =====================================================================================
    
    # Integration health and status indexes
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_integrations_health_monitoring 
        ON integrations (status, last_health_check, health_check_failures)
    """)
    
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_integrations_active_by_type 
        ON integrations (integration_type, is_active, status)
    """)
    
    # Credential management indexes
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_credentials_expiration_tracking 
        ON credentials (access_token_expires_at, certificate_expires_at, is_active) 
        WHERE access_token_expires_at IS NOT NULL OR certificate_expires_at IS NOT NULL
    """)
    
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_credentials_usage_tracking 
        ON credentials (integration_id, last_used_at, usage_count)
    """)
    
    # Sync job performance indexes
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_sync_jobs_scheduling 
        ON sync_jobs (is_scheduled, next_run_at, status) 
        WHERE is_active = true
    """)
    
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_sync_jobs_execution_tracking 
        ON sync_jobs (status, started_at, completed_at, duration_seconds)
    """)
    
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_sync_jobs_retry_analysis 
        ON sync_jobs (retry_count, max_retries, status) 
        WHERE retry_count > 0
    """)
    
    # Webhook performance indexes
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_webhook_endpoints_health 
        ON webhook_endpoints (status, consecutive_failures, last_failure_at)
    """)
    
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_webhook_endpoints_performance 
        ON webhook_endpoints (total_deliveries, successful_deliveries, last_triggered_at)
    """)
    
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_webhook_events_delivery_queue 
        ON webhook_events (status, next_retry_at, attempt_number) 
        WHERE status IN ('pending', 'failed') AND next_retry_at IS NOT NULL
    """)
    
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_webhook_events_performance_analysis 
        ON webhook_events (webhook_endpoint_id, response_status_code, response_time_ms, created_at)
    """)
    
    # =====================================================================================
    # CROSS-MODULE CORRELATION INDEXES
    # =====================================================================================
    
    # User activity correlation
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_user_session_correlation 
        ON sessions (user_id, created_at, ip_address)
    """)
    
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_user_device_correlation 
        ON devices (user_id, fingerprint, last_seen)
    """)
    
    # Notification and audit correlation
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_notification_audit_correlation 
        ON notifications (recipient_id, created_at, current_status)
    """)
    
    # Integration and audit correlation  
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_integration_owner_correlation 
        ON integrations (owner_id, status, last_health_check)
    """)
    
    # =====================================================================================
    # FULL-TEXT SEARCH INDEXES (PostgreSQL specific)
    # =====================================================================================
    
    # Enable pg_trgm for trigram matching (if not already enabled)
    op.execute('CREATE EXTENSION IF NOT EXISTS "pg_trgm"')
    
    # Full-text search indexes for audit entries
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_audit_entries_fts_description 
        ON audit_entries USING gin (action_description gin_trgm_ops)
    """)
    
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_audit_entries_fts_resource 
        ON audit_entries USING gin (resource_name gin_trgm_ops)
    """)
    
    # Full-text search for notification content
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_notifications_fts_subject 
        ON notifications USING gin (subject gin_trgm_ops)
    """)
    
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_notifications_fts_body 
        ON notifications USING gin (body gin_trgm_ops)
    """)
    
    # Full-text search for integration names and descriptions
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_integrations_fts_name 
        ON integrations USING gin (name gin_trgm_ops)
    """)
    
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_integrations_fts_description 
        ON integrations USING gin (description gin_trgm_ops)
    """)
    
    # =====================================================================================
    # JSONB PERFORMANCE INDEXES
    # =====================================================================================
    
    # JSONB indexes for metadata and configuration fields
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_users_backup_codes_gin 
        ON users USING gin (backup_codes)
    """)
    
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_sessions_metadata_gin 
        ON sessions USING gin (metadata)
    """)
    
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_audit_entries_metadata_gin 
        ON audit_entries USING gin (metadata)
    """)
    
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_notifications_variables_gin 
        ON notifications USING gin (variables)
    """)
    
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_integrations_configuration_gin 
        ON integrations USING gin (configuration)
    """)
    
    # =====================================================================================
    # HASH INDEXES FOR EXACT LOOKUPS
    # =====================================================================================
    
    # Hash indexes for token lookups (faster than B-tree for equality)
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_sessions_token_hash_hash 
        ON sessions USING hash (token_hash)
    """)
    
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_sessions_refresh_token_hash_hash 
        ON sessions USING hash (refresh_token_hash)
    """)
    
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_access_tokens_token_hash_hash 
        ON access_tokens USING hash (token_hash)
    """)


def downgrade() -> None:
    """Downgrade database schema."""
    # Drop all performance indexes (order doesn't matter for indexes)
    
    # Identity module indexes
    op.execute('DROP INDEX IF EXISTS idx_users_status_created_composite')
    op.execute('DROP INDEX IF EXISTS idx_users_login_tracking')
    op.execute('DROP INDEX IF EXISTS idx_users_security_flags')
    op.execute('DROP INDEX IF EXISTS idx_users_active_verified')
    op.execute('DROP INDEX IF EXISTS idx_users_suspended_locked')
    op.execute('DROP INDEX IF EXISTS idx_users_pending_verification')
    
    op.execute('DROP INDEX IF EXISTS idx_sessions_active_user_activity')
    op.execute('DROP INDEX IF EXISTS idx_sessions_suspicious_activity')
    op.execute('DROP INDEX IF EXISTS idx_sessions_geolocation')
    
    op.execute('DROP INDEX IF EXISTS idx_devices_trusted_active')
    op.execute('DROP INDEX IF EXISTS idx_mfa_devices_primary_active')
    
    op.execute('DROP INDEX IF EXISTS idx_login_attempts_failed_tracking')
    op.execute('DROP INDEX IF EXISTS idx_login_attempts_risk_analysis')
    
    op.execute('DROP INDEX IF EXISTS idx_roles_system_priority')
    op.execute('DROP INDEX IF EXISTS idx_permissions_resource_action_active')
    
    # Audit module indexes
    op.execute('DROP INDEX IF EXISTS idx_audit_entries_time_series')
    op.execute('DROP INDEX IF EXISTS idx_audit_entries_user_activity')
    op.execute('DROP INDEX IF EXISTS idx_audit_entries_resource_tracking')
    op.execute('DROP INDEX IF EXISTS idx_audit_entries_security_events')
    
    op.execute('DROP INDEX IF EXISTS idx_audit_sessions_correlation')
    op.execute('DROP INDEX IF EXISTS idx_audit_sessions_activity_window')
    
    op.execute('DROP INDEX IF EXISTS idx_audit_reports_generation')
    
    # Notification module indexes
    op.execute('DROP INDEX IF EXISTS idx_notifications_delivery_queue')
    op.execute('DROP INDEX IF EXISTS idx_notifications_retry_queue')
    op.execute('DROP INDEX IF EXISTS idx_notifications_channel_performance')
    op.execute('DROP INDEX IF EXISTS idx_notifications_provider_tracking')
    
    op.execute('DROP INDEX IF EXISTS idx_notification_templates_usage')
    
    op.execute('DROP INDEX IF EXISTS idx_notification_batches_processing')
    op.execute('DROP INDEX IF EXISTS idx_notification_batches_progress')
    
    op.execute('DROP INDEX IF EXISTS idx_recipients_preferences')
    op.execute('DROP INDEX IF EXISTS idx_recipients_activity')
    
    op.execute('DROP INDEX IF EXISTS idx_delivery_logs_analysis')
    op.execute('DROP INDEX IF EXISTS idx_delivery_logs_failures')
    
    # Integration module indexes
    op.execute('DROP INDEX IF EXISTS idx_integrations_health_monitoring')
    op.execute('DROP INDEX IF EXISTS idx_integrations_active_by_type')
    
    op.execute('DROP INDEX IF EXISTS idx_credentials_expiration_tracking')
    op.execute('DROP INDEX IF EXISTS idx_credentials_usage_tracking')
    
    op.execute('DROP INDEX IF EXISTS idx_sync_jobs_scheduling')
    op.execute('DROP INDEX IF EXISTS idx_sync_jobs_execution_tracking')
    op.execute('DROP INDEX IF EXISTS idx_sync_jobs_retry_analysis')
    
    op.execute('DROP INDEX IF EXISTS idx_webhook_endpoints_health')
    op.execute('DROP INDEX IF EXISTS idx_webhook_endpoints_performance')
    
    op.execute('DROP INDEX IF EXISTS idx_webhook_events_delivery_queue')
    op.execute('DROP INDEX IF EXISTS idx_webhook_events_performance_analysis')
    
    # Cross-module correlation indexes
    op.execute('DROP INDEX IF EXISTS idx_user_session_correlation')
    op.execute('DROP INDEX IF EXISTS idx_user_device_correlation')
    op.execute('DROP INDEX IF EXISTS idx_notification_audit_correlation')
    op.execute('DROP INDEX IF EXISTS idx_integration_owner_correlation')
    
    # Full-text search indexes
    op.execute('DROP INDEX IF EXISTS idx_audit_entries_fts_description')
    op.execute('DROP INDEX IF EXISTS idx_audit_entries_fts_resource')
    op.execute('DROP INDEX IF EXISTS idx_notifications_fts_subject')
    op.execute('DROP INDEX IF EXISTS idx_notifications_fts_body')
    op.execute('DROP INDEX IF EXISTS idx_integrations_fts_name')
    op.execute('DROP INDEX IF EXISTS idx_integrations_fts_description')
    
    # JSONB indexes
    op.execute('DROP INDEX IF EXISTS idx_users_backup_codes_gin')
    op.execute('DROP INDEX IF EXISTS idx_sessions_metadata_gin')
    op.execute('DROP INDEX IF EXISTS idx_audit_entries_metadata_gin')
    op.execute('DROP INDEX IF EXISTS idx_notifications_variables_gin')
    op.execute('DROP INDEX IF EXISTS idx_integrations_configuration_gin')
    
    # Hash indexes
    op.execute('DROP INDEX IF EXISTS idx_sessions_token_hash_hash')
    op.execute('DROP INDEX IF EXISTS idx_sessions_refresh_token_hash_hash')
    op.execute('DROP INDEX IF EXISTS idx_access_tokens_token_hash_hash')