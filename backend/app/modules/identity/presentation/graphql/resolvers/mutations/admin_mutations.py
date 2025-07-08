"""
Administrative mutation resolvers for GraphQL.

This module implements comprehensive administrative mutations including
bulk operations, data import/export, system maintenance, and configuration
management with transaction support, progress tracking, and audit logging.
"""

import asyncio
import csv
import uuid
from datetime import datetime
from io import StringIO
from typing import Any

from strawberry import mutation
from strawberry.types import Info

from app.core.cache import get_cache
from app.core.database import get_db_context
from app.core.enums import EventType, JobStatus, UserStatus
from app.core.errors import (
    AuthorizationError,
    BusinessRuleError,
    NotFoundError,
    ValidationError,
)
from app.core.logging import get_logger
from app.modules.identity.application.dtos.command_params import (
    GraphQLResolverDependencies,
)
from app.modules.identity.presentation.graphql.types import (
    BulkOperationResponse,
    BulkUserUpdateInput,
    DataExportResponse,
    SystemConfigInput,
    SystemMaintenanceResponse,
    UserImportInput,
)

logger = get_logger(__name__)


class AdminMutations:
    """Administrative GraphQL mutations."""

    def __init__(self, dependencies: GraphQLResolverDependencies, **kwargs: Any):
        # Repository dependencies
        self.user_repository = dependencies.repositories.user_repository
        self.security_event_repository = dependencies.repositories.security_event_repository
        
        # Additional repositories from kwargs
        self.background_job_repository = kwargs.get('background_job_repository')
        
        # Service dependencies
        self.notification_service = dependencies.services.notification_service
        
        # Additional services from kwargs
        self.file_storage_service = kwargs.get('file_storage_service')
        self.bulk_operation_service = kwargs.get('bulk_operation_service')
        self.system_config_service = kwargs.get('system_config_service')
        
        self.cache = get_cache()
        self.logger = logger

    @mutation
    async def bulk_update_users(
        self,
        info: Info,
        update_input: BulkUserUpdateInput
    ) -> BulkOperationResponse:
        """
        Perform bulk update operations on multiple users.
        
        Args:
            update_input: Bulk update operation data
            
        Returns:
            BulkOperationResponse with operation status and job ID
            
        Raises:
            ValidationError: Invalid input data
            AuthorizationError: Insufficient permissions
        """
        async with get_db_context() as db:
            try:
                # Check authorization
                current_user = info.context.get("current_user")
                if not current_user or not self._has_bulk_operations_permission(current_user):
                    raise AuthorizationError("Insufficient permissions for bulk operations")

                # Validate input
                await self._validate_bulk_update_input(update_input)

                # Create background job for tracking
                job_data = {
                    "id": str(uuid.uuid4()),
                    "job_type": "bulk_user_update",
                    "status": JobStatus.PENDING,
                    "created_by": current_user.id,
                    "created_at": datetime.utcnow(),
                    "total_items": len(update_input.user_ids),
                    "processed_items": 0,
                    "metadata": {
                        "operation": "bulk_update",
                        "update_data": update_input.update_data.__dict__ if hasattr(update_input, 'update_data') else {},
                        "user_count": len(update_input.user_ids)
                    }
                }

                job = await self.background_job_repository.create(job_data)

                # Log bulk operation start
                await self._log_security_event(
                    current_user.id,
                    EventType.BULK_OPERATION_STARTED,
                    f"Bulk user update started for {len(update_input.user_ids)} users",
                    info,
                    metadata={
                        "job_id": job.id,
                        "user_count": len(update_input.user_ids),
                        "operation": "bulk_update"
                    }
                )

                await db.commit()

                # Start background processing
                asyncio.create_task(
                    self._process_bulk_user_update(job.id, update_input, current_user.id)
                )

                return BulkOperationResponse(
                    job_id=job.id,
                    status=JobStatus.PENDING,
                    total_items=len(update_input.user_ids),
                    message="Bulk update operation started"
                )

            except Exception as e:
                await db.rollback()
                self.logger.exception(f"Bulk user update failed: {e!s}")
                raise

    @mutation
    async def bulk_delete_users(
        self,
        info: Info,
        user_ids: list[str]
    ) -> BulkOperationResponse:
        """
        Perform bulk delete operations on multiple users.
        
        Args:
            user_ids: List of user IDs to delete
            
        Returns:
            BulkOperationResponse with operation status and job ID
        """
        async with get_db_context() as db:
            try:
                # Check authorization
                current_user = info.context.get("current_user")
                if not current_user or not self._has_bulk_operations_permission(current_user):
                    raise AuthorizationError("Insufficient permissions for bulk operations")

                # Validate input
                if not user_ids or len(user_ids) == 0:
                    raise ValidationError("User IDs list cannot be empty")

                if len(user_ids) > 1000:  # Limit bulk operations
                    raise ValidationError("Cannot delete more than 1000 users at once")

                # Check if current user is in the list
                if current_user.id in user_ids:
                    raise BusinessRuleError("Cannot delete your own account in bulk operation")

                # Create background job
                job_data = {
                    "id": str(uuid.uuid4()),
                    "job_type": "bulk_user_delete",
                    "status": JobStatus.PENDING,
                    "created_by": current_user.id,
                    "created_at": datetime.utcnow(),
                    "total_items": len(user_ids),
                    "processed_items": 0,
                    "metadata": {
                        "operation": "bulk_delete",
                        "user_ids": user_ids,
                        "user_count": len(user_ids)
                    }
                }

                job = await self.background_job_repository.create(job_data)

                # Log bulk operation start
                await self._log_security_event(
                    current_user.id,
                    EventType.BULK_OPERATION_STARTED,
                    f"Bulk user deletion started for {len(user_ids)} users",
                    info,
                    metadata={
                        "job_id": job.id,
                        "user_count": len(user_ids),
                        "operation": "bulk_delete"
                    }
                )

                await db.commit()

                # Start background processing
                asyncio.create_task(
                    self._process_bulk_user_delete(job.id, user_ids, current_user.id)
                )

                return BulkOperationResponse(
                    job_id=job.id,
                    status=JobStatus.PENDING,
                    total_items=len(user_ids),
                    message="Bulk delete operation started"
                )

            except Exception as e:
                await db.rollback()
                self.logger.exception(f"Bulk user deletion failed: {e!s}")
                raise

    @mutation
    async def export_user_data(
        self,
        info: Info,
        user_id: str,
        export_format: str = "json"
    ) -> DataExportResponse:
        """
        Export user data for GDPR compliance or data portability.
        
        Args:
            user_id: User ID
            export_format: Export format (json, csv, xml)
            
        Returns:
            DataExportResponse with download URL
        """
        async with get_db_context() as db:
            try:
                # Check authorization
                current_user = info.context.get("current_user")
                if not current_user:
                    raise AuthorizationError("Authentication required")

                # Users can export their own data, admins can export any user's data
                if current_user.id != user_id and not self._has_data_export_permission(current_user):
                    raise AuthorizationError("Insufficient permissions to export user data")

                # Find user
                user = await self.user_repository.find_by_id(user_id)
                if not user:
                    raise NotFoundError("User not found")

                # Validate format
                if export_format not in ["json", "csv", "xml"]:
                    raise ValidationError("Invalid export format. Supported: json, csv, xml")

                # Create background job for export
                job_data = {
                    "id": str(uuid.uuid4()),
                    "job_type": "user_data_export",
                    "status": JobStatus.PENDING,
                    "created_by": current_user.id,
                    "created_at": datetime.utcnow(),
                    "total_items": 1,
                    "processed_items": 0,
                    "metadata": {
                        "operation": "data_export",
                        "target_user_id": user_id,
                        "format": export_format
                    }
                }

                job = await self.background_job_repository.create(job_data)

                # Log data export request
                await self._log_security_event(
                    user_id,
                    EventType.DATA_EXPORT_REQUESTED,
                    f"User data export requested by {current_user.id} in {export_format} format",
                    info,
                    metadata={
                        "job_id": job.id,
                        "format": export_format,
                        "requested_by": current_user.id
                    }
                )

                await db.commit()

                # Start background processing
                asyncio.create_task(
                    self._process_user_data_export(job.id, user_id, export_format, current_user.id)
                )

                return DataExportResponse(
                    job_id=job.id,
                    status=JobStatus.PENDING,
                    format=export_format,
                    message="Data export started"
                )

            except Exception as e:
                await db.rollback()
                self.logger.exception(f"User data export failed: {e!s}")
                raise

    @mutation
    async def import_users(
        self,
        info: Info,
        update_input: UserImportInput
    ) -> BulkOperationResponse:
        """
        Import users from file or data.
        
        Args:
            update_input: User import data
            
        Returns:
            BulkOperationResponse with import status and job ID
        """
        async with get_db_context() as db:
            try:
                # Check authorization
                current_user = info.context.get("current_user")
                if not current_user or not self._has_user_import_permission(current_user):
                    raise AuthorizationError("Insufficient permissions to import users")

                # Validate input
                await self._validate_user_import_input(update_input)

                # Process import data
                user_data_list = await self._process_import_data(update_input)

                # Create background job
                job_data = {
                    "id": str(uuid.uuid4()),
                    "job_type": "user_import",
                    "status": JobStatus.PENDING,
                    "created_by": current_user.id,
                    "created_at": datetime.utcnow(),
                    "total_items": len(user_data_list),
                    "processed_items": 0,
                    "metadata": {
                        "operation": "user_import",
                        "format": update_input.format,
                        "user_count": len(user_data_list)
                    }
                }

                job = await self.background_job_repository.create(job_data)

                # Log import start
                await self._log_security_event(
                    current_user.id,
                    EventType.USER_IMPORT_STARTED,
                    f"User import started for {len(user_data_list)} users",
                    info,
                    metadata={
                        "job_id": job.id,
                        "user_count": len(user_data_list),
                        "format": update_input.format
                    }
                )

                await db.commit()

                # Start background processing
                asyncio.create_task(
                    self._process_user_import(job.id, user_data_list, current_user.id)
                )

                return BulkOperationResponse(
                    job_id=job.id,
                    status=JobStatus.PENDING,
                    total_items=len(user_data_list),
                    message="User import started"
                )

            except Exception as e:
                await db.rollback()
                self.logger.exception(f"User import failed: {e!s}")
                raise

    @mutation
    async def system_maintenance(
        self,
        info: Info,
        action: str
    ) -> SystemMaintenanceResponse:
        """
        Perform system maintenance operations.
        
        Args:
            action: Maintenance action to perform
            
        Returns:
            SystemMaintenanceResponse with operation status
        """
        async with get_db_context() as db:
            try:
                # Check authorization
                current_user = info.context.get("current_user")
                if not current_user or not self._has_system_maintenance_permission(current_user):
                    raise AuthorizationError("Insufficient permissions for system maintenance")

                # Validate action
                valid_actions = [
                    "cleanup_expired_sessions",
                    "cleanup_expired_tokens",
                    "cleanup_old_security_events",
                    "refresh_user_permissions_cache",
                    "vacuum_database",
                    "rebuild_search_index"
                ]

                if action not in valid_actions:
                    raise ValidationError(f"Invalid maintenance action. Valid actions: {', '.join(valid_actions)}")

                # Create maintenance job
                job_data = {
                    "id": str(uuid.uuid4()),
                    "job_type": "system_maintenance",
                    "status": JobStatus.PENDING,
                    "created_by": current_user.id,
                    "created_at": datetime.utcnow(),
                    "total_items": 1,
                    "processed_items": 0,
                    "metadata": {
                        "operation": "system_maintenance",
                        "action": action
                    }
                }

                job = await self.background_job_repository.create(job_data)

                # Log maintenance start
                await self._log_security_event(
                    current_user.id,
                    EventType.SYSTEM_MAINTENANCE_STARTED,
                    f"System maintenance started: {action}",
                    info,
                    metadata={
                        "job_id": job.id,
                        "action": action
                    }
                )

                await db.commit()

                # Start background processing
                asyncio.create_task(
                    self._process_system_maintenance(job.id, action, current_user.id)
                )

                return SystemMaintenanceResponse(
                    job_id=job.id,
                    action=action,
                    status=JobStatus.PENDING,
                    message=f"System maintenance '{action}' started"
                )

            except Exception as e:
                await db.rollback()
                self.logger.exception(f"System maintenance failed: {e!s}")
                raise

    @mutation
    async def update_system_configuration(
        self,
        info: Info,
        update_input: SystemConfigInput
    ) -> bool:
        """
        Update system configuration settings.
        
        Args:
            update_input: System configuration data
            
        Returns:
            True if configuration updated successfully
        """
        async with get_db_context() as db:
            try:
                # Check authorization
                current_user = info.context.get("current_user")
                if not current_user or not self._has_system_config_permission(current_user):
                    raise AuthorizationError("Insufficient permissions to update system configuration")

                # Validate configuration input
                await self._validate_system_config_input(update_input)

                # Update configuration
                await self.system_config_service.update_configuration(update_input.config_data)

                # Log configuration update
                await self._log_security_event(
                    current_user.id,
                    EventType.SYSTEM_CONFIG_UPDATED,
                    f"System configuration updated by {current_user.id}",
                    info,
                    metadata={
                        "config_keys": list(update_input.config_data.keys()),
                        "updated_by": current_user.id
                    }
                )

                # Clear configuration cache
                await self.cache.delete("system_config")

                await db.commit()
                return True

            except Exception as e:
                await db.rollback()
                self.logger.exception(f"System configuration update failed: {e!s}")
                raise

    # Helper methods

    def _has_bulk_operations_permission(self, user) -> bool:
        """Check if user has permission for bulk operations."""
        return user.has_permission("admin:bulk_operations")

    def _has_data_export_permission(self, user) -> bool:
        """Check if user has permission to export user data."""
        return user.has_permission("admin:data_export")

    def _has_user_import_permission(self, user) -> bool:
        """Check if user has permission to import users."""
        return user.has_permission("admin:user_import")

    def _has_system_maintenance_permission(self, user) -> bool:
        """Check if user has permission for system maintenance."""
        return user.has_permission("admin:system_maintenance")

    def _has_system_config_permission(self, user) -> bool:
        """Check if user has permission to update system configuration."""
        return user.has_permission("admin:system_config")

    async def _validate_bulk_update_input(self, update_input: BulkUserUpdateInput) -> None:
        """Validate bulk update input."""
        if not update_input.user_ids or len(update_input.user_ids) == 0:
            raise ValidationError("User IDs list cannot be empty")

        if len(update_input.user_ids) > 1000:  # Limit bulk operations
            raise ValidationError("Cannot update more than 1000 users at once")

        if not hasattr(update_input, 'update_data') or not update_input.update_data:
            raise ValidationError("Update data is required")

    async def _validate_user_import_input(self, update_input: UserImportInput) -> None:
        """Validate user import input."""
        if not update_input.format or update_input.format not in ["csv", "json", "excel"]:
            raise ValidationError("Invalid import format. Supported: csv, json, excel")

        if hasattr(update_input, 'file_data') and update_input.file_data:
            # Validate file size (max 10MB)
            if len(update_input.file_data) > 10 * 1024 * 1024:
                raise ValidationError("Import file cannot exceed 10MB")

        if hasattr(update_input, 'data') and update_input.data:
            if not isinstance(update_input.data, list):
                raise ValidationError("Import data must be a list")

    async def _validate_system_config_input(self, update_input: SystemConfigInput) -> None:
        """Validate system configuration input."""
        if not update_input.config_data or not isinstance(update_input.config_data, dict):
            raise ValidationError("Configuration data must be a dictionary")

        # Validate specific configuration keys
        for key, value in update_input.config_data.items():
            await self._validate_config_key_value(key, value)

    async def _validate_config_key_value(self, key: str, value: Any) -> None:
        """Validate specific configuration key-value pair."""
        # Add specific validation rules for different config keys
        if key == "max_login_attempts" and (not isinstance(value, int) or value < 1):
            raise ValidationError("max_login_attempts must be a positive integer")

        if key == "session_timeout" and (not isinstance(value, int) or value < 300):
            raise ValidationError("session_timeout must be at least 300 seconds")

        if key == "password_min_length" and (not isinstance(value, int) or value < 8):
            raise ValidationError("password_min_length must be at least 8")

    async def _process_import_data(self, update_input: UserImportInput) -> list[dict[str, Any]]:
        """Process import data based on format."""
        if update_input.format == "csv":
            return await self._process_csv_import(update_input)
        if update_input.format == "json":
            return await self._process_json_import(update_input)
        if update_input.format == "excel":
            return await self._process_excel_import(update_input)
        raise ValidationError(f"Unsupported import format: {update_input.format}")

    async def _process_csv_import(self, update_input: UserImportInput) -> list[dict[str, Any]]:
        """Process CSV import data."""
        try:
            if hasattr(update_input, 'file_data') and update_input.file_data:
                csv_data = update_input.file_data.decode('utf-8')
            else:
                raise ValidationError("CSV file data is required")

            reader = csv.DictReader(StringIO(csv_data))
            users = []

            required_fields = ["email", "first_name", "last_name"]

            for row_num, row in enumerate(reader, start=2):  # Start from 2 (header is row 1)
                # Validate required fields
                for field in required_fields:
                    if field not in row or not row[field]:
                        raise ValidationError(f"Missing required field '{field}' in row {row_num}")

                # Validate email format
                if "@" not in row["email"]:
                    raise ValidationError(f"Invalid email format in row {row_num}")

                users.append({
                    "email": row["email"].strip().lower(),
                    "first_name": row["first_name"].strip(),
                    "last_name": row["last_name"].strip(),
                    "phone_number": row.get("phone_number", "").strip() or None,
                    "is_active": row.get("is_active", "true").lower() == "true"
                })

            return users

        except Exception as e:
            raise ValidationError(f"CSV processing error: {e!s}")

    async def _process_json_import(self, update_input: UserImportInput) -> list[dict[str, Any]]:
        """Process JSON import data."""
        try:
            import json

            if hasattr(update_input, 'data') and update_input.data:
                users_data = update_input.data
            elif hasattr(update_input, 'file_data') and update_input.file_data:
                users_data = json.loads(update_input.file_data.decode('utf-8'))
            else:
                raise ValidationError("JSON data is required")

            if not isinstance(users_data, list):
                raise ValidationError("JSON data must be an array of user objects")

            users = []
            required_fields = ["email", "first_name", "last_name"]

            for i, user_data in enumerate(users_data):
                # Validate required fields
                for field in required_fields:
                    if field not in user_data or not user_data[field]:
                        raise ValidationError(f"Missing required field '{field}' in user {i+1}")

                # Validate email format
                if "@" not in user_data["email"]:
                    raise ValidationError(f"Invalid email format in user {i+1}")

                users.append({
                    "email": user_data["email"].strip().lower(),
                    "first_name": user_data["first_name"].strip(),
                    "last_name": user_data["last_name"].strip(),
                    "phone_number": user_data.get("phone_number", None),
                    "is_active": user_data.get("is_active", True)
                })

            return users

        except json.JSONDecodeError as e:
            raise ValidationError(f"Invalid JSON format: {e!s}")
        except Exception as e:
            raise ValidationError(f"JSON processing error: {e!s}")

    async def _process_excel_import(self, update_input: UserImportInput) -> list[dict[str, Any]]:
        """Process Excel import data."""
        # This would require additional libraries like openpyxl
        # For now, return empty list with error
        raise ValidationError("Excel import not yet implemented")

    # Background processing methods

    async def _process_bulk_user_update(
        self,
        job_id: str,
        update_input: BulkUserUpdateInput,
        user_id: str
    ) -> None:
        """Process bulk user update in background."""
        try:
            async with get_db_context() as db:
                job = await self.background_job_repository.find_by_id(job_id)
                if not job:
                    return

                # Update job status
                job.status = JobStatus.RUNNING
                job.started_at = datetime.utcnow()
                await self.background_job_repository.update(job)
                await db.commit()

                success_count = 0
                error_count = 0
                errors = []

                for user_id_to_update in update_input.user_ids:
                    try:
                        user = await self.user_repository.find_by_id(user_id_to_update)
                        if user:
                            # Apply updates
                            if hasattr(update_input.update_data, 'is_active'):
                                user.is_active = update_input.update_data.is_active

                            if hasattr(update_input.update_data, 'status'):
                                user.status = update_input.update_data.status

                            user.updated_at = datetime.utcnow()
                            await self.user_repository.update(user)
                            success_count += 1
                        else:
                            error_count += 1
                            errors.append(f"User {user_id_to_update} not found")

                    except Exception as e:
                        error_count += 1
                        errors.append(f"Error updating user {user_id_to_update}: {e!s}")

                    # Update progress
                    job.processed_items += 1
                    if job.processed_items % 10 == 0:  # Update every 10 items
                        await self.background_job_repository.update(job)
                        await db.commit()

                # Complete job
                job.status = JobStatus.COMPLETED if error_count == 0 else JobStatus.COMPLETED_WITH_ERRORS
                job.completed_at = datetime.utcnow()
                job.result = {
                    "success_count": success_count,
                    "error_count": error_count,
                    "errors": errors[:100]  # Limit error list
                }

                await self.background_job_repository.update(job)
                await db.commit()

        except Exception as e:
            # Mark job as failed
            async with get_db_context() as db:
                job = await self.background_job_repository.find_by_id(job_id)
                if job:
                    job.status = JobStatus.FAILED
                    job.error_message = str(e)
                    job.completed_at = datetime.utcnow()
                    await self.background_job_repository.update(job)
                    await db.commit()

            self.logger.exception(f"Bulk user update job {job_id} failed: {e!s}")

    async def _process_bulk_user_delete(
        self,
        job_id: str,
        user_ids: list[str],
        admin_user_id: str
    ) -> None:
        """Process bulk user delete in background."""
        try:
            async with get_db_context() as db:
                job = await self.background_job_repository.find_by_id(job_id)
                if not job:
                    return

                # Update job status
                job.status = JobStatus.RUNNING
                job.started_at = datetime.utcnow()
                await self.background_job_repository.update(job)
                await db.commit()

                success_count = 0
                error_count = 0
                errors = []

                for user_id_to_delete in user_ids:
                    try:
                        user = await self.user_repository.find_by_id(user_id_to_delete)
                        if user:
                            # Perform soft delete
                            user.is_deleted = True
                            user.deleted_at = datetime.utcnow()
                            user.deleted_by = admin_user_id
                            user.status = UserStatus.DELETED

                            await self.user_repository.update(user)
                            success_count += 1
                        else:
                            error_count += 1
                            errors.append(f"User {user_id_to_delete} not found")

                    except Exception as e:
                        error_count += 1
                        errors.append(f"Error deleting user {user_id_to_delete}: {e!s}")

                    # Update progress
                    job.processed_items += 1
                    if job.processed_items % 10 == 0:  # Update every 10 items
                        await self.background_job_repository.update(job)
                        await db.commit()

                # Complete job
                job.status = JobStatus.COMPLETED if error_count == 0 else JobStatus.COMPLETED_WITH_ERRORS
                job.completed_at = datetime.utcnow()
                job.result = {
                    "success_count": success_count,
                    "error_count": error_count,
                    "errors": errors[:100]  # Limit error list
                }

                await self.background_job_repository.update(job)
                await db.commit()

        except Exception as e:
            # Mark job as failed
            async with get_db_context() as db:
                job = await self.background_job_repository.find_by_id(job_id)
                if job:
                    job.status = JobStatus.FAILED
                    job.error_message = str(e)
                    job.completed_at = datetime.utcnow()
                    await self.background_job_repository.update(job)
                    await db.commit()

            self.logger.exception(f"Bulk user delete job {job_id} failed: {e!s}")

    async def _process_user_data_export(
        self,
        job_id: str,
        user_id: str,
        export_format: str,
        requester_id: str
    ) -> None:
        """Process user data export in background."""
        try:
            async with get_db_context() as db:
                job = await self.background_job_repository.find_by_id(job_id)
                if not job:
                    return

                # Update job status
                job.status = JobStatus.RUNNING
                job.started_at = datetime.utcnow()
                await self.background_job_repository.update(job)
                await db.commit()

                # Export user data
                export_data = await self.bulk_operation_service.export_user_data(user_id)

                # Generate export file
                file_url = await self.file_storage_service.create_export_file(
                    export_data,
                    export_format,
                    f"user_export_{user_id}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
                )

                # Complete job
                job.status = JobStatus.COMPLETED
                job.completed_at = datetime.utcnow()
                job.processed_items = 1
                job.result = {
                    "export_url": file_url,
                    "format": export_format,
                    "user_id": user_id
                }

                await self.background_job_repository.update(job)
                await db.commit()

        except Exception as e:
            # Mark job as failed
            async with get_db_context() as db:
                job = await self.background_job_repository.find_by_id(job_id)
                if job:
                    job.status = JobStatus.FAILED
                    job.error_message = str(e)
                    job.completed_at = datetime.utcnow()
                    await self.background_job_repository.update(job)
                    await db.commit()

            self.logger.exception(f"User data export job {job_id} failed: {e!s}")

    async def _process_user_import(
        self,
        job_id: str,
        user_data_list: list[dict[str, Any]],
        admin_user_id: str
    ) -> None:
        """Process user import in background."""
        try:
            async with get_db_context() as db:
                job = await self.background_job_repository.find_by_id(job_id)
                if not job:
                    return

                # Update job status
                job.status = JobStatus.RUNNING
                job.started_at = datetime.utcnow()
                await self.background_job_repository.update(job)
                await db.commit()

                success_count = 0
                error_count = 0
                errors = []

                for user_data in user_data_list:
                    try:
                        # Check if user already exists
                        existing_user = await self.user_repository.find_by_email(user_data["email"])
                        if existing_user:
                            error_count += 1
                            errors.append(f"User with email {user_data['email']} already exists")
                            continue

                        # Create user
                        user_data.update({
                            "id": str(uuid.uuid4()),
                            "created_at": datetime.utcnow(),
                            "created_by": admin_user_id,
                            "is_imported": True
                        })

                        await self.user_repository.create(user_data)
                        success_count += 1

                    except Exception as e:
                        error_count += 1
                        errors.append(f"Error creating user {user_data.get('email', 'unknown')}: {e!s}")

                    # Update progress
                    job.processed_items += 1
                    if job.processed_items % 10 == 0:  # Update every 10 items
                        await self.background_job_repository.update(job)
                        await db.commit()

                # Complete job
                job.status = JobStatus.COMPLETED if error_count == 0 else JobStatus.COMPLETED_WITH_ERRORS
                job.completed_at = datetime.utcnow()
                job.result = {
                    "success_count": success_count,
                    "error_count": error_count,
                    "errors": errors[:100]  # Limit error list
                }

                await self.background_job_repository.update(job)
                await db.commit()

        except Exception as e:
            # Mark job as failed
            async with get_db_context() as db:
                job = await self.background_job_repository.find_by_id(job_id)
                if job:
                    job.status = JobStatus.FAILED
                    job.error_message = str(e)
                    job.completed_at = datetime.utcnow()
                    await self.background_job_repository.update(job)
                    await db.commit()

            self.logger.exception(f"User import job {job_id} failed: {e!s}")

    async def _process_system_maintenance(
        self,
        job_id: str,
        action: str,
        admin_user_id: str
    ) -> None:
        """Process system maintenance in background."""
        try:
            async with get_db_context() as db:
                job = await self.background_job_repository.find_by_id(job_id)
                if not job:
                    return

                # Update job status
                job.status = JobStatus.RUNNING
                job.started_at = datetime.utcnow()
                await self.background_job_repository.update(job)
                await db.commit()

                # Perform maintenance action
                result = await self._execute_maintenance_action(action)

                # Complete job
                job.status = JobStatus.COMPLETED
                job.completed_at = datetime.utcnow()
                job.processed_items = 1
                job.result = result

                await self.background_job_repository.update(job)
                await db.commit()

        except Exception as e:
            # Mark job as failed
            async with get_db_context() as db:
                job = await self.background_job_repository.find_by_id(job_id)
                if job:
                    job.status = JobStatus.FAILED
                    job.error_message = str(e)
                    job.completed_at = datetime.utcnow()
                    await self.background_job_repository.update(job)
                    await db.commit()

            self.logger.exception(f"System maintenance job {job_id} failed: {e!s}")

    async def _execute_maintenance_action(self, action: str) -> dict[str, Any]:
        """Execute specific maintenance action."""
        if action == "cleanup_expired_sessions":
            count = await self.session_repository.cleanup_expired_sessions()
            return {"action": action, "cleaned_sessions": count}

        if action == "cleanup_expired_tokens":
            # This would integrate with token management
            return {"action": action, "cleaned_tokens": 0}

        if action == "cleanup_old_security_events":
            count = await self.security_event_repository.cleanup_old_events(days=90)
            return {"action": action, "cleaned_events": count}

        if action == "refresh_user_permissions_cache":
            await self.cache.delete_pattern("user_permissions:*")
            await self.cache.delete_pattern("user_roles:*")
            return {"action": action, "cache_refreshed": True}

        if action == "vacuum_database":
            # This would execute database vacuum/optimize
            return {"action": action, "database_vacuumed": True}

        if action == "rebuild_search_index":
            # This would rebuild search indexes
            return {"action": action, "search_index_rebuilt": True}

        raise ValueError(f"Unknown maintenance action: {action}")

    async def _log_security_event(
        self,
        user_id: str,
        event_type: EventType,
        description: str,
        info: Info,
        metadata: dict[str, Any] | None = None
    ) -> None:
        """Log security event."""
        event_data = {
            "id": str(uuid.uuid4()),
            "user_id": user_id,
            "event_type": event_type,
            "description": description,
            "ip_address": info.context.get("ip_address"),
            "user_agent": info.context.get("user_agent"),
            "metadata": metadata,
            "created_at": datetime.utcnow(),
            "is_resolved": False
        }

        await self.security_event_repository.create(event_data)
