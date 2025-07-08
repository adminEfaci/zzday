"""Partitioning setup: Time-based partitioning for high-volume tables

Revision ID: 007_partitioning_setup
Revises: 006_indexes_optimization
Create Date: 2024-07-04 11:30:00.000000

"""
from collections.abc import Sequence
from datetime import date, datetime, timedelta

from alembic import op

# revision identifiers, used by Alembic.
revision: str = '007_partitioning_setup'
down_revision: str | None = '006_indexes_optimization'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade database schema."""
    # =====================================================================================
    # AUDIT ENTRIES PARTITIONING (Daily partitions)
    # =====================================================================================
    
    # Convert audit_entries to partitioned table
    op.execute("""
        -- Create new partitioned table
        CREATE TABLE audit_entries_partitioned (
            LIKE audit_entries INCLUDING ALL
        ) PARTITION BY RANGE (created_at);
        
        -- Copy data from original table
        INSERT INTO audit_entries_partitioned SELECT * FROM audit_entries;
        
        -- Drop original table and rename partitioned table
        DROP TABLE audit_entries CASCADE;
        ALTER TABLE audit_entries_partitioned RENAME TO audit_entries;
    """)
    
    # Recreate foreign key constraints
    op.execute("""
        ALTER TABLE audit_entries 
        ADD CONSTRAINT fk_audit_entries_audit_log_id 
        FOREIGN KEY (audit_log_id) REFERENCES audit_logs(id);
        
        ALTER TABLE audit_entries 
        ADD CONSTRAINT fk_audit_entries_session_id 
        FOREIGN KEY (session_id) REFERENCES audit_sessions(id);
    """)
    
    # Recreate audit_fields foreign key
    op.execute("""
        ALTER TABLE audit_fields 
        DROP CONSTRAINT IF EXISTS audit_fields_audit_entry_id_fkey CASCADE;
        
        ALTER TABLE audit_fields 
        ADD CONSTRAINT fk_audit_fields_audit_entry_id 
        FOREIGN KEY (audit_entry_id) REFERENCES audit_entries(id);
    """)
    
    # Create daily partitions for audit_entries (current month + next 3 months)
    current_date = datetime.now().date()
    
    # Generate partitions for the next 120 days
    for i in range(120):
        partition_date = current_date + timedelta(days=i)
        next_date = partition_date + timedelta(days=1)
        
        partition_name = f"audit_entries_{partition_date.strftime('%Y_%m_%d')}"
        
        op.execute(f"""
            CREATE TABLE IF NOT EXISTS {partition_name} PARTITION OF audit_entries
            FOR VALUES FROM ('{partition_date}') TO ('{next_date}');
        """)
    
    # =====================================================================================
    # AUDIT LOGS PARTITIONING (Monthly partitions)
    # =====================================================================================
    
    # Convert audit_logs to partitioned table
    op.execute("""
        -- Create new partitioned table
        CREATE TABLE audit_logs_partitioned (
            LIKE audit_logs INCLUDING ALL
        ) PARTITION BY RANGE (created_at);
        
        -- Copy data from original table
        INSERT INTO audit_logs_partitioned SELECT * FROM audit_logs;
        
        -- Drop original table and rename partitioned table
        DROP TABLE audit_logs CASCADE;
        ALTER TABLE audit_logs_partitioned RENAME TO audit_logs;
    """)
    
    # Recreate foreign key constraints for audit_entries
    op.execute("""
        ALTER TABLE audit_entries 
        DROP CONSTRAINT IF EXISTS fk_audit_entries_audit_log_id CASCADE;
        
        ALTER TABLE audit_entries 
        ADD CONSTRAINT fk_audit_entries_audit_log_id 
        FOREIGN KEY (audit_log_id) REFERENCES audit_logs(id);
    """)
    
    # Create monthly partitions for audit_logs (current year + next year)
    current_year = current_date.year
    
    for year in [current_year, current_year + 1]:
        for month in range(1, 13):
            # Calculate first day of month and first day of next month
            first_day = date(year, month, 1)
            if month == 12:
                next_month_first = date(year + 1, 1, 1)
            else:
                next_month_first = date(year, month + 1, 1)
            
            partition_name = f"audit_logs_{year}_{month:02d}"
            
            op.execute(f"""
                CREATE TABLE IF NOT EXISTS {partition_name} PARTITION OF audit_logs
                FOR VALUES FROM ('{first_day}') TO ('{next_month_first}');
            """)
    
    # =====================================================================================
    # NOTIFICATIONS PARTITIONING (Weekly partitions)
    # =====================================================================================
    
    # Convert notifications to partitioned table
    op.execute("""
        -- Create new partitioned table
        CREATE TABLE notifications_partitioned (
            LIKE notifications INCLUDING ALL
        ) PARTITION BY RANGE (created_at);
        
        -- Copy data from original table
        INSERT INTO notifications_partitioned SELECT * FROM notifications;
        
        -- Drop original table and rename partitioned table
        DROP TABLE notifications CASCADE;
        ALTER TABLE notifications_partitioned RENAME TO notifications;
    """)
    
    # Recreate foreign key constraints
    op.execute("""
        ALTER TABLE notifications 
        ADD CONSTRAINT fk_notifications_template_id 
        FOREIGN KEY (template_id) REFERENCES notification_templates(id);
    """)
    
    # Recreate delivery_logs foreign key
    op.execute("""
        ALTER TABLE delivery_logs 
        DROP CONSTRAINT IF EXISTS delivery_logs_notification_id_fkey CASCADE;
        
        ALTER TABLE delivery_logs 
        ADD CONSTRAINT fk_delivery_logs_notification_id 
        FOREIGN KEY (notification_id) REFERENCES notifications(id);
    """)
    
    # Create weekly partitions for notifications (next 20 weeks)
    monday = current_date - timedelta(days=current_date.weekday())  # Start from Monday
    
    for i in range(20):
        week_start = monday + timedelta(weeks=i)
        week_end = week_start + timedelta(days=7)
        
        partition_name = f"notifications_{week_start.strftime('%Y_w%U')}"
        
        op.execute(f"""
            CREATE TABLE IF NOT EXISTS {partition_name} PARTITION OF notifications
            FOR VALUES FROM ('{week_start}') TO ('{week_end}');
        """)
    
    # =====================================================================================
    # DELIVERY LOGS PARTITIONING (Daily partitions)
    # =====================================================================================
    
    # Convert delivery_logs to partitioned table
    op.execute("""
        -- Create new partitioned table
        CREATE TABLE delivery_logs_partitioned (
            LIKE delivery_logs INCLUDING ALL
        ) PARTITION BY RANGE (created_at);
        
        -- Copy data from original table
        INSERT INTO delivery_logs_partitioned SELECT * FROM delivery_logs;
        
        -- Drop original table and rename partitioned table
        DROP TABLE delivery_logs CASCADE;
        ALTER TABLE delivery_logs_partitioned RENAME TO delivery_logs;
    """)
    
    # Recreate foreign key constraints
    op.execute("""
        ALTER TABLE delivery_logs 
        ADD CONSTRAINT fk_delivery_logs_notification_id 
        FOREIGN KEY (notification_id) REFERENCES notifications(id);
        
        ALTER TABLE delivery_logs 
        ADD CONSTRAINT fk_delivery_logs_batch_id 
        FOREIGN KEY (batch_id) REFERENCES notification_batches(id);
    """)
    
    # Create daily partitions for delivery_logs (next 60 days)
    for i in range(60):
        partition_date = current_date + timedelta(days=i)
        next_date = partition_date + timedelta(days=1)
        
        partition_name = f"delivery_logs_{partition_date.strftime('%Y_%m_%d')}"
        
        op.execute(f"""
            CREATE TABLE IF NOT EXISTS {partition_name} PARTITION OF delivery_logs
            FOR VALUES FROM ('{partition_date}') TO ('{next_date}');
        """)
    
    # =====================================================================================
    # LOGIN ATTEMPTS PARTITIONING (Weekly partitions)
    # =====================================================================================
    
    # Convert login_attempts to partitioned table
    op.execute("""
        -- Create new partitioned table
        CREATE TABLE login_attempts_partitioned (
            LIKE login_attempts INCLUDING ALL
        ) PARTITION BY RANGE (created_at);
        
        -- Copy data from original table
        INSERT INTO login_attempts_partitioned SELECT * FROM login_attempts;
        
        -- Drop original table and rename partitioned table
        DROP TABLE login_attempts CASCADE;
        ALTER TABLE login_attempts_partitioned RENAME TO login_attempts;
    """)
    
    # Recreate foreign key constraints
    op.execute("""
        ALTER TABLE login_attempts 
        ADD CONSTRAINT fk_login_attempts_user_id 
        FOREIGN KEY (user_id) REFERENCES users(id);
    """)
    
    # Create weekly partitions for login_attempts (next 12 weeks)
    for i in range(12):
        week_start = monday + timedelta(weeks=i)
        week_end = week_start + timedelta(days=7)
        
        partition_name = f"login_attempts_{week_start.strftime('%Y_w%U')}"
        
        op.execute(f"""
            CREATE TABLE IF NOT EXISTS {partition_name} PARTITION OF login_attempts
            FOR VALUES FROM ('{week_start}') TO ('{week_end}');
        """)
    
    # =====================================================================================
    # WEBHOOK EVENTS PARTITIONING (Daily partitions)
    # =====================================================================================
    
    # Convert webhook_events to partitioned table
    op.execute("""
        -- Create new partitioned table
        CREATE TABLE webhook_events_partitioned (
            LIKE webhook_events INCLUDING ALL
        ) PARTITION BY RANGE (created_at);
        
        -- Copy data from original table
        INSERT INTO webhook_events_partitioned SELECT * FROM webhook_events;
        
        -- Drop original table and rename partitioned table
        DROP TABLE webhook_events CASCADE;
        ALTER TABLE webhook_events_partitioned RENAME TO webhook_events;
    """)
    
    # Recreate foreign key constraints
    op.execute("""
        ALTER TABLE webhook_events 
        ADD CONSTRAINT fk_webhook_events_webhook_endpoint_id 
        FOREIGN KEY (webhook_endpoint_id) REFERENCES webhook_endpoints(id);
    """)
    
    # Create daily partitions for webhook_events (next 30 days)
    for i in range(30):
        partition_date = current_date + timedelta(days=i)
        next_date = partition_date + timedelta(days=1)
        
        partition_name = f"webhook_events_{partition_date.strftime('%Y_%m_%d')}"
        
        op.execute(f"""
            CREATE TABLE IF NOT EXISTS {partition_name} PARTITION OF webhook_events
            FOR VALUES FROM ('{partition_date}') TO ('{next_date}');
        """)
    
    # =====================================================================================
    # CREATE PARTITION MANAGEMENT FUNCTIONS
    # =====================================================================================
    
    # Function to automatically create future partitions
    op.execute("""
        CREATE OR REPLACE FUNCTION create_future_partitions()
        RETURNS void AS $$
        DECLARE
            current_date date := CURRENT_DATE;
            partition_date date;
            next_date date;
            week_start date;
            week_end date;
            month_start date;
            month_end date;
            partition_name text;
            year int;
            month int;
        BEGIN
            -- Create daily partitions for audit_entries (next 30 days)
            FOR i IN 1..30 LOOP
                partition_date := current_date + INTERVAL '1 day' * i;
                next_date := partition_date + INTERVAL '1 day';
                partition_name := 'audit_entries_' || to_char(partition_date, 'YYYY_MM_DD');
                
                EXECUTE format('CREATE TABLE IF NOT EXISTS %I PARTITION OF audit_entries FOR VALUES FROM (%L) TO (%L)',
                    partition_name, partition_date, next_date);
            END LOOP;
            
            -- Create daily partitions for delivery_logs (next 30 days)
            FOR i IN 1..30 LOOP
                partition_date := current_date + INTERVAL '1 day' * i;
                next_date := partition_date + INTERVAL '1 day';
                partition_name := 'delivery_logs_' || to_char(partition_date, 'YYYY_MM_DD');
                
                EXECUTE format('CREATE TABLE IF NOT EXISTS %I PARTITION OF delivery_logs FOR VALUES FROM (%L) TO (%L)',
                    partition_name, partition_date, next_date);
            END LOOP;
            
            -- Create daily partitions for webhook_events (next 30 days)
            FOR i IN 1..30 LOOP
                partition_date := current_date + INTERVAL '1 day' * i;
                next_date := partition_date + INTERVAL '1 day';
                partition_name := 'webhook_events_' || to_char(partition_date, 'YYYY_MM_DD');
                
                EXECUTE format('CREATE TABLE IF NOT EXISTS %I PARTITION OF webhook_events FOR VALUES FROM (%L) TO (%L)',
                    partition_name, partition_date, next_date);
            END LOOP;
            
            -- Create weekly partitions for notifications (next 8 weeks)
            week_start := current_date - EXTRACT(DOW FROM current_date)::int; -- Start from Monday
            FOR i IN 1..8 LOOP
                week_start := week_start + INTERVAL '1 week';
                week_end := week_start + INTERVAL '1 week';
                partition_name := 'notifications_' || to_char(week_start, 'YYYY_"w"WW');
                
                EXECUTE format('CREATE TABLE IF NOT EXISTS %I PARTITION OF notifications FOR VALUES FROM (%L) TO (%L)',
                    partition_name, week_start, week_end);
            END LOOP;
            
            -- Create weekly partitions for login_attempts (next 8 weeks)
            week_start := current_date - EXTRACT(DOW FROM current_date)::int; -- Start from Monday
            FOR i IN 1..8 LOOP
                week_start := week_start + INTERVAL '1 week';
                week_end := week_start + INTERVAL '1 week';
                partition_name := 'login_attempts_' || to_char(week_start, 'YYYY_"w"WW');
                
                EXECUTE format('CREATE TABLE IF NOT EXISTS %I PARTITION OF login_attempts FOR VALUES FROM (%L) TO (%L)',
                    partition_name, week_start, week_end);
            END LOOP;
            
            -- Create monthly partitions for audit_logs (next 6 months)
            month_start := date_trunc('month', current_date);
            FOR i IN 1..6 LOOP
                month_start := month_start + INTERVAL '1 month';
                month_end := month_start + INTERVAL '1 month';
                partition_name := 'audit_logs_' || to_char(month_start, 'YYYY_MM');
                
                EXECUTE format('CREATE TABLE IF NOT EXISTS %I PARTITION OF audit_logs FOR VALUES FROM (%L) TO (%L)',
                    partition_name, month_start, month_end);
            END LOOP;
            
        END;
        $$ LANGUAGE plpgsql;
    """)
    
    # Function to drop old partitions (for data retention)
    op.execute("""
        CREATE OR REPLACE FUNCTION drop_old_partitions()
        RETURNS void AS $$
        DECLARE
            partition_record record;
            cutoff_date date;
        BEGIN
            -- Drop audit_entries partitions older than 1 year
            cutoff_date := CURRENT_DATE - INTERVAL '1 year';
            FOR partition_record IN 
                SELECT schemaname, tablename 
                FROM pg_tables 
                WHERE tablename ~ '^audit_entries_\d{4}_\d{2}_\d{2}$'
                AND to_date(substring(tablename from '\d{4}_\d{2}_\d{2}$'), 'YYYY_MM_DD') < cutoff_date
            LOOP
                EXECUTE format('DROP TABLE IF EXISTS %I.%I', partition_record.schemaname, partition_record.tablename);
                RAISE NOTICE 'Dropped partition: %', partition_record.tablename;
            END LOOP;
            
            -- Drop delivery_logs partitions older than 6 months
            cutoff_date := CURRENT_DATE - INTERVAL '6 months';
            FOR partition_record IN 
                SELECT schemaname, tablename 
                FROM pg_tables 
                WHERE tablename ~ '^delivery_logs_\d{4}_\d{2}_\d{2}$'
                AND to_date(substring(tablename from '\d{4}_\d{2}_\d{2}$'), 'YYYY_MM_DD') < cutoff_date
            LOOP
                EXECUTE format('DROP TABLE IF EXISTS %I.%I', partition_record.schemaname, partition_record.tablename);
                RAISE NOTICE 'Dropped partition: %', partition_record.tablename;
            END LOOP;
            
            -- Drop webhook_events partitions older than 3 months
            cutoff_date := CURRENT_DATE - INTERVAL '3 months';
            FOR partition_record IN 
                SELECT schemaname, tablename 
                FROM pg_tables 
                WHERE tablename ~ '^webhook_events_\d{4}_\d{2}_\d{2}$'
                AND to_date(substring(tablename from '\d{4}_\d{2}_\d{2}$'), 'YYYY_MM_DD') < cutoff_date
            LOOP
                EXECUTE format('DROP TABLE IF EXISTS %I.%I', partition_record.schemaname, partition_record.tablename);
                RAISE NOTICE 'Dropped partition: %', partition_record.tablename;
            END LOOP;
            
            -- Drop login_attempts partitions older than 6 months
            cutoff_date := CURRENT_DATE - INTERVAL '6 months';
            FOR partition_record IN 
                SELECT schemaname, tablename 
                FROM pg_tables 
                WHERE tablename ~ '^login_attempts_\d{4}_w\d{2}$'
            LOOP
                -- This is a simplified check; in practice, you'd parse the week number
                EXECUTE format('DROP TABLE IF EXISTS %I.%I', partition_record.schemaname, partition_record.tablename);
                RAISE NOTICE 'Dropped partition: %', partition_record.tablename;
            END LOOP;
            
        END;
        $$ LANGUAGE plpgsql;
    """)
    
    # =====================================================================================
    # CREATE MAINTENANCE PROCEDURES
    # =====================================================================================
    
    # Procedure to maintain partition health
    op.execute("""
        CREATE OR REPLACE FUNCTION maintain_partitions()
        RETURNS void AS $$
        BEGIN
            -- Create future partitions
            PERFORM create_future_partitions();
            
            -- Update table statistics for all partitions
            EXECUTE 'ANALYZE audit_entries';
            EXECUTE 'ANALYZE audit_logs';
            EXECUTE 'ANALYZE notifications';
            EXECUTE 'ANALYZE delivery_logs';
            EXECUTE 'ANALYZE login_attempts';
            EXECUTE 'ANALYZE webhook_events';
            
            -- Log maintenance completion
            RAISE NOTICE 'Partition maintenance completed at %', now();
        END;
        $$ LANGUAGE plpgsql;
    """)


def downgrade() -> None:
    """Downgrade database schema."""
    # Drop partition management functions
    op.execute('DROP FUNCTION IF EXISTS maintain_partitions()')
    op.execute('DROP FUNCTION IF EXISTS drop_old_partitions()')
    op.execute('DROP FUNCTION IF EXISTS create_future_partitions()')
    
    # Convert partitioned tables back to regular tables
    # Note: This is a simplified downgrade - in production, you'd want to preserve data
    
    tables_to_unpartition = [
        'audit_entries',
        'audit_logs', 
        'notifications',
        'delivery_logs',
        'login_attempts',
        'webhook_events'
    ]
    
    for table_name in tables_to_unpartition:
        op.execute(f"""  # noqa: S608 - Table names are hardcoded constants, not user input
            -- Create new regular table
            CREATE TABLE {table_name}_regular (
                LIKE {table_name} INCLUDING ALL
            );
            
            -- Copy data from partitioned table
            INSERT INTO {table_name}_regular SELECT * FROM {table_name};
            
            -- Drop partitioned table and all partitions
            DROP TABLE {table_name} CASCADE;
            
            -- Rename regular table
            ALTER TABLE {table_name}_regular RENAME TO {table_name};
        """)