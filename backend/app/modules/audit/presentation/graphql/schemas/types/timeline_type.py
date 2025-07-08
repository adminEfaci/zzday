"""GraphQL types for audit timeline and events."""

from datetime import datetime

import strawberry

from ..enums import AuditCategoryEnum, AuditSeverityEnum


@strawberry.type
class TimelineEventType:
    """GraphQL type for timeline events."""

    event_id: strawberry.ID
    timestamp: datetime
    event_type: str  # "audit_entry", "security_incident", "compliance_violation", "system_event"
    title: str
    description: str
    severity: AuditSeverityEnum
    category: AuditCategoryEnum

    # Actors
    user_id: strawberry.ID | None = None
    user_name: str | None = None
    system_component: str | None = None

    # Affected resources
    resource_type: str
    resource_id: str
    resource_name: str

    # Additional context
    correlation_id: str | None = None
    session_id: strawberry.ID | None = None
    ip_address: str | None = None

    # Metadata
    tags: list[str]
    related_event_ids: list[strawberry.ID]

    @strawberry.field
    def formatted_timestamp(self) -> str:
        """Return formatted timestamp."""
        return self.timestamp.isoformat()

    @strawberry.field
    def relative_time(self) -> str:
        """Return relative time description."""
        from datetime import datetime, timedelta

        now = datetime.now()
        delta = now - self.timestamp.replace(tzinfo=None)

        if delta < timedelta(minutes=1):
            return "just now"
        if delta < timedelta(hours=1):
            minutes = int(delta.total_seconds() / 60)
            return f"{minutes} minute{'s' if minutes != 1 else ''} ago"
        if delta < timedelta(days=1):
            hours = int(delta.total_seconds() / 3600)
            return f"{hours} hour{'s' if hours != 1 else ''} ago"
        if delta < timedelta(days=7):
            days = delta.days
            return f"{days} day{'s' if days != 1 else ''} ago"
        if delta < timedelta(days=30):
            weeks = delta.days // 7
            return f"{weeks} week{'s' if weeks != 1 else ''} ago"
        months = delta.days // 30
        return f"{months} month{'s' if months != 1 else ''} ago"

    @strawberry.field
    def impact_level(self) -> str:
        """Assess impact level of event."""
        if self.severity == AuditSeverityEnum.CRITICAL:
            return "critical"
        if self.severity == AuditSeverityEnum.HIGH:
            return "high"
        if self.severity == AuditSeverityEnum.MEDIUM:
            return "medium"
        return "low"

    @strawberry.field
    def is_security_related(self) -> bool:
        """Check if event is security-related."""
        security_categories = [
            AuditCategoryEnum.SECURITY,
            AuditCategoryEnum.AUTHENTICATION,
            AuditCategoryEnum.AUTHORIZATION,
        ]

        security_tags = [
            "security",
            "authentication",
            "authorization",
            "breach",
            "intrusion",
        ]

        return (
            self.category in security_categories
            or any(tag.lower() in security_tags for tag in self.tags)
            or self.event_type == "security_incident"
        )

    @strawberry.field
    def has_related_events(self) -> bool:
        """Check if event has related events."""
        return len(self.related_event_ids) > 0

    @strawberry.field
    def actor_display_name(self) -> str:
        """Return display name for actor."""
        if self.user_name:
            return self.user_name
        if self.user_id:
            return f"User {self.user_id}"
        if self.system_component:
            return f"System: {self.system_component}"
        return "Unknown"


@strawberry.type
class TimelineGroupType:
    """GraphQL type for grouped timeline events."""

    group_key: str  # Date, hour, or other grouping key
    group_label: str  # Human-readable label
    event_count: int
    events: list[TimelineEventType]

    # Summary statistics
    severity_breakdown: str  # JSON string of severity counts
    category_breakdown: str  # JSON string of category counts

    @strawberry.field
    def has_critical_events(self) -> bool:
        """Check if group has critical events."""
        return any(
            event.severity == AuditSeverityEnum.CRITICAL for event in self.events
        )

    @strawberry.field
    def has_security_events(self) -> bool:
        """Check if group has security events."""
        return any(event.is_security_related for event in self.events)

    @strawberry.field
    def most_severe_event(self) -> TimelineEventType | None:
        """Return most severe event in group."""
        if not self.events:
            return None

        severity_order = {
            AuditSeverityEnum.CRITICAL: 4,
            AuditSeverityEnum.HIGH: 3,
            AuditSeverityEnum.MEDIUM: 2,
            AuditSeverityEnum.LOW: 1,
        }

        return max(self.events, key=lambda e: severity_order.get(e.severity, 0))

    @strawberry.field
    def parsed_severity_breakdown(self) -> list["TimelineStatType"]:
        """Parse and return severity breakdown."""
        import json

        try:
            data = json.loads(self.severity_breakdown)
            return [
                TimelineStatType(
                    label=k, count=v, percentage=(v / self.event_count) * 100
                )
                for k, v in data.items()
            ]
        except json.JSONDecodeError:
            return []


@strawberry.type
class TimelineStatType:
    """GraphQL type for timeline statistics."""

    label: str
    count: int
    percentage: float


@strawberry.type
class TimelineFilterType:
    """GraphQL type for timeline filters."""

    start_time: datetime | None = None
    end_time: datetime | None = None
    severities: list[AuditSeverityEnum] = []
    categories: list[AuditCategoryEnum] = []
    event_types: list[str] = []
    user_ids: list[strawberry.ID] = []
    resource_types: list[str] = []
    tags: list[str] = []

    @strawberry.field
    def time_range_days(self) -> int | None:
        """Calculate time range in days."""
        if self.start_time and self.end_time:
            delta = self.end_time - self.start_time
            return delta.days
        return None

    @strawberry.field
    def has_filters(self) -> bool:
        """Check if any filters are applied."""
        return bool(
            self.start_time
            or self.end_time
            or self.severities
            or self.categories
            or self.event_types
            or self.user_ids
            or self.resource_types
            or self.tags
        )


@strawberry.type
class AuditTimelineType:
    """GraphQL type for audit timeline."""

    # Timeline metadata
    timeline_id: strawberry.ID
    generated_at: datetime
    time_range_start: datetime
    time_range_end: datetime

    # Grouping and presentation
    grouping_method: str  # "hour", "day", "week", "month", "none"
    groups: list[TimelineGroupType]

    # Summary statistics
    total_events: int
    unique_users: int
    unique_resources: int

    # Filters applied
    filters: TimelineFilterType

    # Navigation
    has_earlier_events: bool
    has_later_events: bool

    @strawberry.field
    def formatted_generated_at(self) -> str:
        """Return formatted generation timestamp."""
        return self.generated_at.isoformat()

    @strawberry.field
    def time_range_duration(self) -> str:
        """Return human-readable time range duration."""
        delta = self.time_range_end - self.time_range_start

        if delta.days >= 365:
            years = delta.days // 365
            return f"{years} year{'s' if years != 1 else ''}"
        if delta.days >= 30:
            months = delta.days // 30
            return f"{months} month{'s' if months != 1 else ''}"
        if delta.days >= 7:
            weeks = delta.days // 7
            return f"{weeks} week{'s' if weeks != 1 else ''}"
        if delta.days >= 1:
            return f"{delta.days} day{'s' if delta.days != 1 else ''}"
        hours = int(delta.total_seconds() / 3600)
        return f"{hours} hour{'s' if hours != 1 else ''}"

    @strawberry.field
    def activity_density(self) -> float:
        """Calculate activity density (events per day)."""
        delta = self.time_range_end - self.time_range_start
        if delta.days == 0:
            return float(self.total_events)
        return self.total_events / delta.days

    @strawberry.field
    def most_active_period(self) -> TimelineGroupType | None:
        """Return most active period."""
        if not self.groups:
            return None
        return max(self.groups, key=lambda g: g.event_count)

    @strawberry.field
    def security_event_count(self) -> int:
        """Count security-related events."""
        count = 0
        for group in self.groups:
            count += len([e for e in group.events if e.is_security_related])
        return count

    @strawberry.field
    def critical_event_count(self) -> int:
        """Count critical events."""
        count = 0
        for group in self.groups:
            count += len(
                [e for e in group.events if e.severity == AuditSeverityEnum.CRITICAL]
            )
        return count

    @strawberry.field
    def timeline_summary(self) -> str:
        """Generate timeline summary."""
        duration = self.time_range_duration
        avg_per_day = round(self.activity_density, 1)
        security_count = self.security_event_count
        critical_count = self.critical_event_count

        return f"""
        Timeline spanning {duration} with {self.total_events:,} events
        Average: {avg_per_day} events per day
        Security events: {security_count:,}
        Critical events: {critical_count:,}
        Active users: {self.unique_users:,}
        Affected resources: {self.unique_resources:,}
        """.strip()


@strawberry.type
class TimelineExportType:
    """GraphQL type for timeline export."""

    export_id: strawberry.ID
    format: str  # "json", "csv", "pdf"
    download_url: str
    file_size_bytes: int
    generated_at: datetime
    expires_at: datetime

    @strawberry.field
    def file_size_mb(self) -> float:
        """Return file size in MB."""
        return round(self.file_size_bytes / (1024 * 1024), 2)

    @strawberry.field
    def time_until_expiry(self) -> str:
        """Return time until export expires."""
        from datetime import datetime, timedelta

        now = datetime.now()
        delta = self.expires_at.replace(tzinfo=None) - now

        if delta < timedelta(0):
            return "expired"
        if delta < timedelta(hours=1):
            minutes = int(delta.total_seconds() / 60)
            return f"{minutes} minutes"
        if delta < timedelta(days=1):
            hours = int(delta.total_seconds() / 3600)
            return f"{hours} hours"
        return f"{delta.days} days"
