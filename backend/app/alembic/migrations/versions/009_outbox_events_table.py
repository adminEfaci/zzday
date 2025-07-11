"""
Add outbox_events table for outbox pattern implementation

Revision ID: 009_outbox_events
Revises: 008_identity_complete
Create Date: 2025-07-09 00:00:00.000000
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers
revision = '009_outbox_events'
down_revision = '008_identity_complete'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create outbox_events table for atomic event storage."""
    
    # Create outbox_events table
    op.create_table(
        'outbox_events',
        sa.Column('id', postgresql.UUID(), nullable=False, primary_key=True),
        sa.Column('aggregate_id', postgresql.UUID(), nullable=False),
        sa.Column('event_type', sa.String(100), nullable=False),
        sa.Column('event_data', postgresql.JSONB(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('processed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('retry_count', sa.Integer(), nullable=False, default=0),
        sa.Column('max_retries', sa.Integer(), nullable=False, default=3),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        if_not_exists=True
    )
    
    # Create indexes for optimal performance
    
    # Index for unprocessed events (most frequent query)
    op.create_index(
        'idx_outbox_unprocessed', 
        'outbox_events', 
        ['created_at'], 
        postgresql_where=sa.text('processed_at IS NULL'),
        if_not_exists=True
    )
    
    # Index for events ready for retry
    op.create_index(
        'idx_outbox_retry', 
        'outbox_events', 
        ['retry_count', 'created_at'],
        postgresql_where=sa.text('processed_at IS NULL AND retry_count < max_retries'),
        if_not_exists=True
    )
    
    # Index for aggregate events (useful for debugging)
    op.create_index(
        'idx_outbox_aggregate', 
        'outbox_events', 
        ['aggregate_id', 'created_at'],
        if_not_exists=True
    )
    
    # Index for event type analysis
    op.create_index(
        'idx_outbox_event_type', 
        'outbox_events', 
        ['event_type'],
        if_not_exists=True
    )
    
    # Index for cleanup of processed events
    op.create_index(
        'idx_outbox_processed', 
        'outbox_events', 
        ['processed_at'],
        postgresql_where=sa.text('processed_at IS NOT NULL'),
        if_not_exists=True
    )


def downgrade() -> None:
    """Drop outbox_events table and indexes."""
    
    # Drop indexes first
    op.drop_index('idx_outbox_processed', 'outbox_events', if_exists=True)
    op.drop_index('idx_outbox_event_type', 'outbox_events', if_exists=True)
    op.drop_index('idx_outbox_aggregate', 'outbox_events', if_exists=True)
    op.drop_index('idx_outbox_retry', 'outbox_events', if_exists=True)
    op.drop_index('idx_outbox_unprocessed', 'outbox_events', if_exists=True)
    
    # Drop table
    op.drop_table('outbox_events', if_exists=True)