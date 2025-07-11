"""
Notification Module Public Contract

This module defines the public interface that other modules can use to interact
with the Notification module. This contract manages notification preferences,
templates, and scheduling while using Integration module for actual delivery.
"""

from abc import ABC, abstractmethod
from typing import List, Optional, Dict, Any
from datetime import datetime
from uuid import UUID
from enum import Enum

from pydantic import BaseModel, Field


class NotificationType(str, Enum):
    """Types of notifications."""
    
    WELCOME = "WELCOME"
    PASSWORD_RESET = "PASSWORD_RESET"
    EMAIL_VERIFICATION = "EMAIL_VERIFICATION"
    SECURITY_ALERT = "SECURITY_ALERT"
    TRANSACTION = "TRANSACTION"
    REMINDER = "REMINDER"
    ANNOUNCEMENT = "ANNOUNCEMENT"
    CUSTOM = "CUSTOM"


class NotificationPriority(str, Enum):
    """Notification priority levels."""
    
    LOW = "LOW"
    NORMAL = "NORMAL"
    HIGH = "HIGH"
    URGENT = "URGENT"


class NotificationStatus(str, Enum):
    """Notification status."""
    
    PENDING = "PENDING"
    SCHEDULED = "SCHEDULED"
    SENDING = "SENDING"
    SENT = "SENT"
    DELIVERED = "DELIVERED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class UserPreferenceDTO(BaseModel):
    """User notification preferences."""
    
    user_id: UUID
    email_enabled: bool = True
    sms_enabled: bool = False
    push_enabled: bool = False
    notification_types: Dict[str, bool] = Field(default_factory=dict)
    quiet_hours_start: Optional[str] = None  # HH:MM format
    quiet_hours_end: Optional[str] = None    # HH:MM format
    timezone: str = "UTC"
    language: str = "en"
    
    class Config:
        json_encoders = {
            UUID: str
        }


class NotificationRequestDTO(BaseModel):
    """Request to send notification."""
    
    user_id: UUID
    notification_type: NotificationType
    priority: NotificationPriority = NotificationPriority.NORMAL
    channels: Optional[List[str]] = None  # If None, use user preferences
    template_name: Optional[str] = None
    template_data: Dict[str, Any] = Field(default_factory=dict)
    subject: Optional[str] = None  # Override template subject
    message: Optional[str] = None  # Override template message
    schedule_at: Optional[datetime] = None  # Send later
    expires_at: Optional[datetime] = None  # Don't send after
    metadata: Dict[str, Any] = Field(default_factory=dict)
    
    class Config:
        json_encoders = {
            UUID: str,
            datetime: lambda v: v.isoformat()
        }


class NotificationDTO(BaseModel):
    """Notification record."""
    
    id: UUID
    user_id: UUID
    notification_type: NotificationType
    priority: NotificationPriority
    status: NotificationStatus
    channels: List[str]
    created_at: datetime
    scheduled_at: Optional[datetime] = None
    sent_at: Optional[datetime] = None
    delivered_at: Optional[datetime] = None
    failed_at: Optional[datetime] = None
    error_message: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    
    class Config:
        json_encoders = {
            UUID: str,
            datetime: lambda v: v.isoformat()
        }


class NotificationTemplateDTO(BaseModel):
    """Notification template."""
    
    id: UUID
    name: str
    notification_type: NotificationType
    channels: List[str]
    subject_template: Optional[str] = None  # For email
    body_template: str
    variables: List[str] = Field(default_factory=list)
    is_active: bool = True
    language: str = "en"
    created_at: datetime
    updated_at: datetime
    
    class Config:
        json_encoders = {
            UUID: str,
            datetime: lambda v: v.isoformat()
        }


class BulkNotificationRequestDTO(BaseModel):
    """Request to send notifications to multiple users."""
    
    user_ids: List[UUID]
    notification_type: NotificationType
    priority: NotificationPriority = NotificationPriority.NORMAL
    template_name: Optional[str] = None
    template_data: Dict[str, Any] = Field(default_factory=dict)
    subject: Optional[str] = None
    message: Optional[str] = None
    schedule_at: Optional[datetime] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class NotificationStatsDTO(BaseModel):
    """Notification statistics."""
    
    total_sent: int = 0
    total_delivered: int = 0
    total_failed: int = 0
    total_pending: int = 0
    by_type: Dict[str, int] = Field(default_factory=dict)
    by_channel: Dict[str, int] = Field(default_factory=dict)
    delivery_rate: float = 0.0
    average_delivery_time_seconds: Optional[float] = None


class INotificationContract(ABC):
    """
    Public contract for Notification module.
    
    This interface defines all operations that other modules can perform
    with the Notification module for managing and sending notifications.
    """
    
    # Notification Operations
    @abstractmethod
    async def send_notification(
        self,
        request: NotificationRequestDTO
    ) -> NotificationDTO:
        """
        Send notification to user.
        
        Args:
            request: Notification request details
            
        Returns:
            NotificationDTO with notification record
        """
        pass
    
    @abstractmethod
    async def send_bulk_notification(
        self,
        request: BulkNotificationRequestDTO
    ) -> List[NotificationDTO]:
        """
        Send notification to multiple users.
        
        Args:
            request: Bulk notification request
            
        Returns:
            List of NotificationDTO records
        """
        pass
    
    @abstractmethod
    async def cancel_notification(
        self,
        notification_id: UUID
    ) -> bool:
        """
        Cancel pending or scheduled notification.
        
        Args:
            notification_id: ID of notification to cancel
            
        Returns:
            True if cancelled, False if not found or already sent
        """
        pass
    
    @abstractmethod
    async def get_notification(
        self,
        notification_id: UUID
    ) -> Optional[NotificationDTO]:
        """
        Get notification by ID.
        
        Args:
            notification_id: Notification ID
            
        Returns:
            NotificationDTO if found, None otherwise
        """
        pass
    
    @abstractmethod
    async def get_user_notifications(
        self,
        user_id: UUID,
        status: Optional[NotificationStatus] = None,
        notification_type: Optional[NotificationType] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[NotificationDTO]:
        """
        Get notifications for user.
        
        Args:
            user_id: User ID
            status: Optional status filter
            notification_type: Optional type filter
            limit: Maximum results
            offset: Pagination offset
            
        Returns:
            List of NotificationDTO
        """
        pass
    
    # Preference Operations
    @abstractmethod
    async def get_user_preferences(
        self,
        user_id: UUID
    ) -> UserPreferenceDTO:
        """
        Get user notification preferences.
        
        Args:
            user_id: User ID
            
        Returns:
            UserPreferenceDTO with preferences
        """
        pass
    
    @abstractmethod
    async def update_user_preferences(
        self,
        user_id: UUID,
        preferences: UserPreferenceDTO
    ) -> UserPreferenceDTO:
        """
        Update user notification preferences.
        
        Args:
            user_id: User ID
            preferences: Updated preferences
            
        Returns:
            Updated UserPreferenceDTO
        """
        pass
    
    @abstractmethod
    async def opt_out_notification_type(
        self,
        user_id: UUID,
        notification_type: NotificationType
    ) -> bool:
        """
        Opt out of specific notification type.
        
        Args:
            user_id: User ID
            notification_type: Type to opt out of
            
        Returns:
            True if successful
        """
        pass
    
    # Template Operations
    @abstractmethod
    async def get_template(
        self,
        template_name: str,
        language: str = "en"
    ) -> Optional[NotificationTemplateDTO]:
        """
        Get notification template.
        
        Args:
            template_name: Template name
            language: Language code
            
        Returns:
            NotificationTemplateDTO if found
        """
        pass
    
    @abstractmethod
    async def list_templates(
        self,
        notification_type: Optional[NotificationType] = None,
        language: str = "en",
        active_only: bool = True
    ) -> List[NotificationTemplateDTO]:
        """
        List available templates.
        
        Args:
            notification_type: Optional type filter
            language: Language code
            active_only: Only return active templates
            
        Returns:
            List of NotificationTemplateDTO
        """
        pass
    
    # Statistics Operations
    @abstractmethod
    async def get_notification_stats(
        self,
        user_id: Optional[UUID] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None
    ) -> NotificationStatsDTO:
        """
        Get notification statistics.
        
        Args:
            user_id: Optional user filter
            start_date: Optional start date filter
            end_date: Optional end date filter
            
        Returns:
            NotificationStatsDTO with statistics
        """
        pass