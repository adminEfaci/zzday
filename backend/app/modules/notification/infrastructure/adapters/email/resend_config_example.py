"""
Resend Email Adapter Configuration Example

This file shows how to configure the Resend email adapter for different environments.
Copy and modify these configurations as needed for your application.
"""

from typing import Any

# Development Configuration
RESEND_DEV_CONFIG = {
    "provider": "resend",
    "settings": {
        "from_email": "noreply@yourdomain.dev",
        "from_name": "EzzDay Development",
        "webhook_secret": "your-webhook-secret-dev",
        "default_tags": [
            {"name": "environment", "value": "development"},
            {"name": "service", "value": "ezzday"},
        ],
        "rate_limit_per_second": 5,
        "max_retries": 3,
        "timeout_seconds": 30.0,
        "enable_analytics": True,
        "enable_click_tracking": True,
        "enable_open_tracking": True,
        "connect_timeout": 10.0,
        "read_timeout": 30.0,
    },
    "credentials": {"api_key": "re_dev_your_api_key_here"},
    "rate_limits": {"requests_per_minute": 100, "requests_per_hour": 1000},
}

# Production Configuration
RESEND_PROD_CONFIG = {
    "provider": "resend",
    "settings": {
        "from_email": "noreply@yourdomain.com",
        "from_name": "EzzDay",
        "webhook_secret": "your-secure-webhook-secret-prod",
        "default_tags": [
            {"name": "environment", "value": "production"},
            {"name": "service", "value": "ezzday"},
        ],
        "rate_limit_per_second": 10,
        "max_retries": 5,
        "timeout_seconds": 45.0,
        "enable_analytics": True,
        "enable_click_tracking": True,
        "enable_open_tracking": True,
        "connect_timeout": 15.0,
        "read_timeout": 45.0,
    },
    "credentials": {"api_key": "re_prod_your_api_key_here"},
    "rate_limits": {"requests_per_minute": 500, "requests_per_hour": 10000},
}

# Test Configuration (for testing environments)
RESEND_TEST_CONFIG = {
    "provider": "resend",
    "settings": {
        "from_email": "test@yourdomain.test",
        "from_name": "EzzDay Test",
        "webhook_secret": None,  # Disable webhooks in test
        "default_tags": [
            {"name": "environment", "value": "test"},
            {"name": "service", "value": "ezzday"},
        ],
        "rate_limit_per_second": 1,
        "max_retries": 1,
        "timeout_seconds": 10.0,
        "enable_analytics": False,
        "enable_click_tracking": False,
        "enable_open_tracking": False,
    },
    "credentials": {"api_key": "re_test_your_api_key_here"},
    "rate_limits": {"requests_per_minute": 10, "requests_per_hour": 100},
}


def get_resend_config(environment: str = "development") -> dict[str, Any]:
    """Get Resend configuration for the specified environment.

    Args:
        environment: Environment name (development, production, test)

    Returns:
        Configuration dictionary
    """
    configs = {
        "development": RESEND_DEV_CONFIG,
        "production": RESEND_PROD_CONFIG,
        "test": RESEND_TEST_CONFIG,
    }

    return configs.get(environment, RESEND_DEV_CONFIG)


# Webhook Configuration Examples
WEBHOOK_EVENTS = [
    "email.sent",
    "email.delivered",
    "email.delivery_delayed",
    "email.complained",
    "email.bounced",
    "email.opened",
    "email.clicked",
]

WEBHOOK_ENDPOINT_CONFIG = {
    "development": "https://dev-api.yourdomain.com/webhooks/resend",
    "staging": "https://staging-api.yourdomain.com/webhooks/resend",
    "production": "https://api.yourdomain.com/webhooks/resend",
}


# Example usage in FastAPI app
"""
from app.modules.notification.domain.value_objects import ChannelConfig
from app.modules.notification.infrastructure.adapters.email import ResendEmailAdapter

# Create channel config
config = ChannelConfig(
    channel=NotificationChannel.EMAIL,
    provider="resend",
    settings=RESEND_PROD_CONFIG["settings"],
    credentials=RESEND_PROD_CONFIG["credentials"],
    rate_limits=RESEND_PROD_CONFIG["rate_limits"]
)

# Initialize adapter
adapter = ResendEmailAdapter(config)

# Send email
result = await adapter.send(notification)

# Check status
status = await adapter.check_status(result.provider_message_id)

# Handle webhook
webhook_result = await adapter.handle_webhook(webhook_data, headers)
"""

# Environment Variables Example
"""
# Add these to your .env file:

# Development
RESEND_DEV_API_KEY=re_dev_your_api_key_here
RESEND_DEV_FROM_EMAIL=noreply@yourdomain.dev
RESEND_DEV_FROM_NAME=EzzDay Development
RESEND_DEV_WEBHOOK_SECRET=your-webhook-secret-dev

# Production  
RESEND_PROD_API_KEY=re_prod_your_api_key_here
RESEND_PROD_FROM_EMAIL=noreply@yourdomain.com
RESEND_PROD_FROM_NAME=EzzDay
RESEND_PROD_WEBHOOK_SECRET=your-secure-webhook-secret-prod

# Webhook endpoint
RESEND_WEBHOOK_ENDPOINT=https://api.yourdomain.com/webhooks/resend
"""
