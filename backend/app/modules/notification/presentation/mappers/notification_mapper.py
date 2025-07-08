"""
Notification Mapper

Maps between notification DTOs and GraphQL types, handling data transformation
between the domain layer and presentation layer.
"""

import json
from typing import Any
from uuid import UUID

from ..schemas.inputs.notification_inputs import (
    BulkNotificationCreateInput,
    NotificationCancelInput,
    NotificationCreateInput,
    NotificationFilterInput,
    NotificationPreferencesInput,
    NotificationResendInput,
    NotificationUpdateInput,
)
from ..schemas.types.notification_type import (
    NotificationAnalyticsType,
    NotificationBatchType,
    NotificationContentType,
    NotificationListType,
    NotificationSchedulingType,
    NotificationSummaryType,
    NotificationType,
    NotificationVariablesType,
)


class NotificationMapper:
    """Mapper for notification-related data transformations."""

    @staticmethod
    def to_graphql_type(dto: dict[str, Any]) -> NotificationType:
        """Convert notification DTO to GraphQL type."""
        # Map basic notification content
        content = NotificationContentType(
            subject=dto.get("subject"),
            body=dto.get("body", ""),
            html_body=dto.get("html_body"),
            short_text=dto.get("short_text"),
            rich_content=dto.get("rich_content"),
            attachments=dto.get("attachments", []),
            action_url=dto.get("action_url"),
            action_text=dto.get("action_text"),
            metadata=dto.get("content_metadata"),
        )

        # Map variables if present
        variables = None
        if dto.get("variables"):
            variables = NotificationVariablesType(
                user_variables=dto.get("user_variables"),
                system_variables=dto.get("system_variables"),
                custom_variables=dto.get("custom_variables"),
            )

        # Map scheduling if present
        scheduling = None
        if dto.get("scheduling"):
            sched_data = dto["scheduling"]
            scheduling = NotificationSchedulingType(
                send_at=sched_data.get("send_at"),
                timezone=sched_data.get("timezone"),
                batch_size=sched_data.get("batch_size"),
                batch_interval=sched_data.get("batch_interval"),
                retry_config=sched_data.get("retry_config"),
            )

        # Map analytics if present
        analytics = None
        if dto.get("analytics"):
            from .analytics_mapper import AnalyticsMapper

            analytics = AnalyticsMapper.notification_analytics_to_graphql(
                dto["analytics"]
            )

        return NotificationType(
            id=UUID(dto["id"]),
            title=dto["title"],
            category=dto["category"],
            priority=dto["priority"],
            status=dto["status"],
            content=content,
            template_id=UUID(dto["template_id"]) if dto.get("template_id") else None,
            variables=variables,
            channels=dto.get("channels", []),
            recipients=dto.get("recipients", []),  # Would be mapped separately
            recipient_count=dto.get("recipient_count", 0),
            scheduling=scheduling,
            delivery_logs=dto.get("delivery_logs", []),  # Would be mapped separately
            analytics=analytics,
            campaign_id=UUID(dto["campaign_id"]) if dto.get("campaign_id") else None,
            tags=dto.get("tags", []),
            external_id=dto.get("external_id"),
            source=dto.get("source", "system"),
            correlation_id=dto.get("correlation_id"),
            created_by=UUID(dto["created_by"]),
            created_at=dto["created_at"],
            updated_at=dto["updated_at"],
            sent_at=dto.get("sent_at"),
            completed_at=dto.get("completed_at"),
        )

    @staticmethod
    def list_result_to_graphql_type(result: dict[str, Any]) -> NotificationListType:
        """Convert paginated notification list result to GraphQL type."""
        items = [
            NotificationMapper.to_graphql_type(dto) for dto in result.get("items", [])
        ]

        return NotificationListType(
            items=items,
            total_count=result.get("total_count", 0),
            page=result.get("page", 1),
            page_size=result.get("page_size", 20),
            total_pages=result.get("total_pages", 0),
            has_next=result.get("has_next", False),
            has_previous=result.get("has_previous", False),
        )

    @staticmethod
    def summary_dto_to_graphql_type(dto: dict[str, Any]) -> NotificationSummaryType:
        """Convert summary DTO to GraphQL type."""
        return NotificationSummaryType(
            total_notifications=dto.get("total_notifications", 0),
            by_status=json.dumps(dto.get("by_status", {})),
            by_priority=json.dumps(dto.get("by_priority", {})),
            by_category=json.dumps(dto.get("by_category", {})),
            by_channel=json.dumps(dto.get("by_channel", {})),
            today_count=dto.get("today_count", 0),
            week_count=dto.get("week_count", 0),
            month_count=dto.get("month_count", 0),
            avg_delivery_time=dto.get("avg_delivery_time"),
            success_rate=dto.get("success_rate", 0.0),
        )

    @staticmethod
    def batch_dto_to_graphql_type(dto: dict[str, Any]) -> NotificationBatchType:
        """Convert batch DTO to GraphQL type."""
        notifications = [
            NotificationMapper.to_graphql_type(notif_dto)
            for notif_dto in dto.get("notifications", [])
        ]

        # Map analytics
        analytics = None
        if dto.get("analytics"):
            from .analytics_mapper import AnalyticsMapper

            analytics = AnalyticsMapper.notification_analytics_to_graphql(
                dto["analytics"]
            )

        return NotificationBatchType(
            id=UUID(dto["id"]),
            name=dto["name"],
            description=dto.get("description"),
            notifications=notifications,
            total_notifications=dto.get("total_notifications", 0),
            status=dto["status"],
            progress=dto.get("progress", 0.0),
            analytics=analytics,
            created_at=dto["created_at"],
            started_at=dto.get("started_at"),
            completed_at=dto.get("completed_at"),
        )

    @staticmethod
    def analytics_dto_to_graphql_type(dto: dict[str, Any]) -> NotificationAnalyticsType:
        """Convert analytics DTO to GraphQL type."""
        return NotificationAnalyticsType(
            total_sent=dto.get("total_sent", 0),
            total_delivered=dto.get("total_delivered", 0),
            total_failed=dto.get("total_failed", 0),
            total_bounced=dto.get("total_bounced", 0),
            total_clicked=dto.get("total_clicked", 0),
            total_opened=dto.get("total_opened", 0),
            delivery_rate=dto.get("delivery_rate", 0.0),
            open_rate=dto.get("open_rate", 0.0),
            click_rate=dto.get("click_rate", 0.0),
            bounce_rate=dto.get("bounce_rate", 0.0),
            avg_delivery_time=dto.get("avg_delivery_time"),
            channel_breakdown=json.dumps(dto.get("channel_breakdown", {})),
        )

    @staticmethod
    def create_input_to_dto(input: NotificationCreateInput) -> dict[str, Any]:
        """Convert create input to DTO."""
        dto = {
            "title": input.title,
            "category": input.category,
            "priority": input.priority,
            "channels": input.channels,
            "recipient_ids": input.recipient_ids,
            "recipient_group_ids": input.recipient_group_ids or [],
            "tags": input.tags or [],
            "external_id": input.external_id,
            "correlation_id": input.correlation_id,
            "template_id": input.template_id,
            "variables": input.variables,
            "campaign_id": input.campaign_id,
        }

        # Map content
        content = input.content
        dto.update(
            {
                "subject": content.subject,
                "body": content.body,
                "html_body": content.html_body,
                "short_text": content.short_text,
                "rich_content": content.rich_content,
                "attachments": content.attachments or [],
                "action_url": content.action_url,
                "action_text": content.action_text,
                "content_metadata": content.metadata,
            }
        )

        # Map scheduling if present
        if input.scheduling:
            scheduling = input.scheduling
            dto["scheduling"] = {
                "send_at": scheduling.send_at,
                "timezone": scheduling.timezone,
                "batch_size": scheduling.batch_size,
                "batch_interval": scheduling.batch_interval,
                "retry_config": scheduling.retry_config,
            }

        return dto

    @staticmethod
    def update_input_to_dto(input: NotificationUpdateInput) -> dict[str, Any]:
        """Convert update input to DTO."""
        dto = {}

        # Only include fields that are not None
        if input.title is not None:
            dto["title"] = input.title
        if input.category is not None:
            dto["category"] = input.category
        if input.priority is not None:
            dto["priority"] = input.priority
        if input.status is not None:
            dto["status"] = input.status
        if input.tags is not None:
            dto["tags"] = input.tags

        # Map content if present
        if input.content:
            content = input.content
            if content.subject is not None:
                dto["subject"] = content.subject
            if content.body is not None:
                dto["body"] = content.body
            if content.html_body is not None:
                dto["html_body"] = content.html_body
            if content.short_text is not None:
                dto["short_text"] = content.short_text
            if content.rich_content is not None:
                dto["rich_content"] = content.rich_content
            if content.attachments is not None:
                dto["attachments"] = content.attachments
            if content.action_url is not None:
                dto["action_url"] = content.action_url
            if content.action_text is not None:
                dto["action_text"] = content.action_text
            if content.metadata is not None:
                dto["content_metadata"] = content.metadata

        # Map scheduling if present
        if input.scheduling:
            scheduling = input.scheduling
            dto["scheduling"] = {
                "send_at": scheduling.send_at,
                "timezone": scheduling.timezone,
                "batch_size": scheduling.batch_size,
                "batch_interval": scheduling.batch_interval,
                "retry_config": scheduling.retry_config,
            }

        return dto

    @staticmethod
    def filter_input_to_dto(input: NotificationFilterInput) -> dict[str, Any]:
        """Convert filter input to DTO."""
        dto = {}

        # Direct field mappings
        if input.status:
            dto["status"] = input.status
        if input.priority:
            dto["priority"] = input.priority
        if input.category:
            dto["category"] = input.category
        if input.channels:
            dto["channels"] = input.channels
        if input.template_id:
            dto["template_id"] = input.template_id
        if input.campaign_id:
            dto["campaign_id"] = input.campaign_id
        if input.created_by:
            dto["created_by"] = input.created_by
        if input.recipient_id:
            dto["recipient_id"] = input.recipient_id
        if input.recipient_group_id:
            dto["recipient_group_id"] = input.recipient_group_id
        if input.external_id:
            dto["external_id"] = input.external_id
        if input.correlation_id:
            dto["correlation_id"] = input.correlation_id
        if input.search_query:
            dto["search_query"] = input.search_query
        if input.has_attachments is not None:
            dto["has_attachments"] = input.has_attachments

        # Date range filters
        if input.created_after:
            dto["created_after"] = input.created_after
        if input.created_before:
            dto["created_before"] = input.created_before
        if input.sent_after:
            dto["sent_after"] = input.sent_after
        if input.sent_before:
            dto["sent_before"] = input.sent_before

        # Tag filters
        if input.tags:
            dto["tags"] = input.tags
        if input.tags_all:
            dto["tags_all"] = input.tags_all

        return dto

    @staticmethod
    def bulk_create_input_to_dto(input: BulkNotificationCreateInput) -> dict[str, Any]:
        """Convert bulk create input to DTO."""
        return {
            "category": input.category,
            "priority": input.priority,
            "template_id": input.template_id,
            "channels": input.channels,
            "recipient_ids": input.recipient_ids or [],
            "recipient_group_ids": input.recipient_group_ids or [],
            "notifications_data": [
                json.loads(data) for data in input.notifications_data
            ],
            "scheduling": {
                "send_at": input.scheduling.send_at if input.scheduling else None,
                "timezone": input.scheduling.timezone if input.scheduling else None,
                "batch_size": input.scheduling.batch_size if input.scheduling else None,
                "batch_interval": input.scheduling.batch_interval
                if input.scheduling
                else None,
                "retry_config": input.scheduling.retry_config
                if input.scheduling
                else None,
            }
            if input.scheduling
            else None,
            "campaign_id": input.campaign_id,
            "tags": input.tags or [],
        }

    @staticmethod
    def resend_input_to_dto(input: NotificationResendInput) -> dict[str, Any]:
        """Convert resend input to DTO."""
        return {
            "notification_id": input.notification_id,
            "recipient_ids": input.recipient_ids or [],
            "channels": input.channels or [],
            "force_resend": input.force_resend or False,
        }

    @staticmethod
    def cancel_input_to_dto(input: NotificationCancelInput) -> dict[str, Any]:
        """Convert cancel input to DTO."""
        return {"notification_ids": input.notification_ids, "reason": input.reason}

    @staticmethod
    def preferences_input_to_dto(input: NotificationPreferencesInput) -> dict[str, Any]:
        """Convert preferences input to DTO."""
        return {
            "recipient_id": input.recipient_id,
            "channel_preferences": [
                json.loads(pref) for pref in input.channel_preferences
            ],
            "category_preferences": input.category_preferences or [],
            "frequency_preference": input.frequency_preference,
            "quiet_hours": json.loads(input.quiet_hours) if input.quiet_hours else None,
            "timezone": input.timezone,
        }

    @staticmethod
    def event_to_notification(event: dict[str, Any]) -> NotificationType:
        """Convert notification event to GraphQL type."""
        # This is a simplified mapper - would use the full notification data
        notification_data = event.get("notification_data", {})
        return NotificationMapper.to_graphql_type(notification_data)
