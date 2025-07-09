"""Resend email service types and models."""

import base64
from dataclasses import dataclass
from datetime import datetime
from typing import Any


@dataclass
class ResendAttachment:
    """Resend attachment model."""

    filename: str
    content: bytes | str
    content_type: str | None = None
    content_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to Resend API format."""
        # Ensure content is base64 encoded
        if isinstance(self.content, bytes):
            content_data = base64.b64encode(self.content).decode("utf-8")
        else:
            content_data = self.content

        data = {"filename": self.filename, "content": content_data}

        if self.content_type:
            data["content_type"] = self.content_type
        if self.content_id:
            data["content_id"] = self.content_id

        return data


@dataclass
class ResendEmailAddress:
    """Resend email address model."""

    email: str
    name: str | None = None

    def to_dict(self) -> dict[str, str]:
        """Convert to Resend API format."""
        if self.name:
            return {"email": self.email, "name": self.name}
        return {"email": self.email}


@dataclass
class ResendEmailRequest:
    """Resend email request model."""

    from_address: ResendEmailAddress
    to: list[ResendEmailAddress]
    subject: str
    html: str | None = None
    text: str | None = None
    cc: list[ResendEmailAddress] | None = None
    bcc: list[ResendEmailAddress] | None = None
    reply_to: list[ResendEmailAddress] | None = None
    attachments: list[ResendAttachment] | None = None
    tags: list[dict[str, str]] | None = None
    headers: dict[str, str] | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to Resend API format."""
        data = {
            "from": f"{self.from_address.name} <{self.from_address.email}>"
            if self.from_address.name
            else self.from_address.email,
            "to": [addr.email for addr in self.to],
            "subject": self.subject,
        }

        if self.html:
            data["html"] = self.html
        if self.text:
            data["text"] = self.text
        if self.cc:
            data["cc"] = [addr.email for addr in self.cc]
        if self.bcc:
            data["bcc"] = [addr.email for addr in self.bcc]
        if self.reply_to:
            data["reply_to"] = [addr.email for addr in self.reply_to]
        if self.attachments:
            data["attachments"] = [att.to_dict() for att in self.attachments]
        if self.tags:
            data["tags"] = self.tags
        if self.headers:
            data["headers"] = self.headers

        return data


@dataclass
class ResendEmailResponse:
    """Resend email response model."""

    id: str
    from_email: str
    to: list[str]
    created_at: datetime
    subject: str

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ResendEmailResponse":
        """Create from Resend API response."""
        return cls(
            id=data["id"],
            from_email=data["from"],
            to=data["to"] if isinstance(data["to"], list) else [data["to"]],
            created_at=datetime.fromisoformat(
                data["created_at"].replace("Z", "+00:00")
            ),
            subject=data["subject"],
        )


@dataclass
class ResendEmailStatus:
    """Resend email status model."""

    id: str
    object: str
    status: str
    created_at: datetime
    email: dict[str, Any]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ResendEmailStatus":
        """Create from Resend API response."""
        return cls(
            id=data["id"],
            object=data["object"],
            status=data["status"],
            created_at=datetime.fromisoformat(
                data["created_at"].replace("Z", "+00:00")
            ),
            email=data["email"],
        )


@dataclass
class ResendBatchRequest:
    """Resend batch email request model."""

    emails: list[ResendEmailRequest]

    def to_dict(self) -> dict[str, Any]:
        """Convert to Resend API format."""
        return {"emails": [email.to_dict() for email in self.emails]}


@dataclass
class ResendBatchResponse:
    """Resend batch email response model."""

    id: str
    emails: list[ResendEmailResponse]
    created_at: datetime

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ResendBatchResponse":
        """Create from Resend API response."""
        return cls(
            id=data["id"],
            emails=[ResendEmailResponse.from_dict(email) for email in data["emails"]],
            created_at=datetime.fromisoformat(
                data["created_at"].replace("Z", "+00:00")
            ),
        )


@dataclass
class ResendTemplateRequest:
    """Resend template email request model."""

    template_id: str
    to: list[str]
    variables: dict[str, Any]
    from_email: str
    subject: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to Resend API format."""
        data = {
            "template_id": self.template_id,
            "to": self.to,
            "variables": self.variables,
            "from": self.from_email,
        }

        if self.subject:
            data["subject"] = self.subject

        return data


@dataclass
class ResendScheduleRequest:
    """Resend scheduled email request model."""

    email: ResendEmailRequest
    send_at: datetime

    def to_dict(self) -> dict[str, Any]:
        """Convert to Resend API format."""
        return {"email": self.email.to_dict(), "send_at": self.send_at.isoformat()}


@dataclass
class ResendScheduleResponse:
    """Resend scheduled email response model."""

    id: str
    email_id: str
    send_at: datetime
    status: str
    created_at: datetime

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ResendScheduleResponse":
        """Create from Resend API response."""
        return cls(
            id=data["id"],
            email_id=data["email_id"],
            send_at=datetime.fromisoformat(data["send_at"].replace("Z", "+00:00")),
            status=data["status"],
            created_at=datetime.fromisoformat(
                data["created_at"].replace("Z", "+00:00")
            ),
        )


@dataclass
class ResendSuppressionEntry:
    """Resend suppression list entry model."""

    email: str
    reason: str
    created_at: datetime

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ResendSuppressionEntry":
        """Create from Resend API response."""
        return cls(
            email=data["email"],
            reason=data["reason"],
            created_at=datetime.fromisoformat(
                data["created_at"].replace("Z", "+00:00")
            ),
        )


@dataclass
class ResendAnalyticsRequest:
    """Resend analytics request model."""

    start_date: datetime
    end_date: datetime
    events: list[str]

    def to_params(self) -> dict[str, str]:
        """Convert to query parameters."""
        return {
            "start_date": self.start_date.strftime("%Y-%m-%d"),
            "end_date": self.end_date.strftime("%Y-%m-%d"),
            "events": ",".join(self.events),
        }


@dataclass
class ResendAnalyticsData:
    """Resend analytics data model."""

    event: str
    count: int
    date: str


@dataclass
class ResendAnalyticsResponse:
    """Resend analytics response model."""

    data: list[ResendAnalyticsData]
    total_count: int

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ResendAnalyticsResponse":
        """Create from Resend API response."""
        analytics_data = [
            ResendAnalyticsData(
                event=item["event"], count=item["count"], date=item["date"]
            )
            for item in data.get("data", [])
        ]

        return cls(data=analytics_data, total_count=data.get("total_count", 0))


@dataclass
class ResendDomainVerification:
    """Resend domain verification model."""

    domain: str
    status: str
    verified: bool
    dns_records: list[dict[str, str]]
    created_at: datetime

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ResendDomainVerification":
        """Create from Resend API response."""
        return cls(
            domain=data["domain"],
            status=data["status"],
            verified=data["verified"],
            dns_records=data.get("dns_records", []),
            created_at=datetime.fromisoformat(
                data["created_at"].replace("Z", "+00:00")
            ),
        )


@dataclass
class ResendWebhookConfig:
    """Resend webhook configuration model."""

    id: str
    endpoint: str
    events: list[str]
    secret: str | None
    active: bool
    created_at: datetime

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ResendWebhookConfig":
        """Create from Resend API response."""
        return cls(
            id=data["id"],
            endpoint=data["endpoint"],
            events=data["events"],
            secret=data.get("secret"),
            active=data.get("active", True),
            created_at=datetime.fromisoformat(
                data["created_at"].replace("Z", "+00:00")
            ),
        )


@dataclass
class ResendWebhookEvent:
    """Resend webhook event model."""

    type: str
    created_at: datetime
    data: dict[str, Any]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ResendWebhookEvent":
        """Create from webhook payload."""
        return cls(
            type=data["type"],
            created_at=datetime.fromisoformat(
                data["created_at"].replace("Z", "+00:00")
            ),
            data=data["data"],
        )


@dataclass
class ResendConfiguration:
    """Resend adapter configuration model."""

    api_key: str
    from_email: str
    from_name: str
    webhook_secret: str | None = None
    default_tags: list[dict[str, str]] | None = None
    rate_limit_per_second: int = 10
    max_retries: int = 3
    timeout_seconds: float = 30.0
    enable_analytics: bool = True
    enable_click_tracking: bool = True
    enable_open_tracking: bool = True


@dataclass
class BulkDeliveryResult:
    """Result of bulk email delivery."""

    total_count: int
    successful_count: int
    failed_count: int
    results: list[dict[str, Any]]
    batch_id: str | None = None


@dataclass
class ScheduleResult:
    """Result of email scheduling."""

    schedule_id: str
    email_id: str
    send_at: datetime
    status: str


@dataclass
class WebhookResult:
    """Result of webhook processing."""

    processed: bool
    email_id: str | None = None
    event_type: str | None = None
    delivery_result: dict[str, Any] | None = None


@dataclass
class SuppressionList:
    """Suppression list management result."""

    entries: list[ResendSuppressionEntry]
    total_count: int
    page: int = 1
    page_size: int = 100


# Resend event type constants
class ResendEventTypes:
    """Resend webhook event types."""

    EMAIL_SENT = "email.sent"
    EMAIL_DELIVERED = "email.delivered"
    EMAIL_DELIVERY_DELAYED = "email.delivery_delayed"
    EMAIL_COMPLAINED = "email.complained"
    EMAIL_BOUNCED = "email.bounced"
    EMAIL_OPENED = "email.opened"
    EMAIL_CLICKED = "email.clicked"


# Resend status constants
class ResendStatus:
    """Resend email status constants."""

    QUEUED = "queued"
    SENT = "sent"
    DELIVERED = "delivered"
    DELIVERY_DELAYED = "delivery_delayed"
    COMPLAINED = "complained"
    BOUNCED = "bounced"
    CLICKED = "clicked"
    OPENED = "opened"


# Resend domain status constants
class ResendDomainStatus:
    """Resend domain verification status constants."""

    PENDING = "pending"
    VERIFIED = "verified"
    FAILED = "failed"


# Resend schedule status constants
class ResendScheduleStatus:
    """Resend scheduled email status constants."""

    SCHEDULED = "scheduled"
    SENT = "sent"
    CANCELLED = "cancelled"
    FAILED = "failed"
