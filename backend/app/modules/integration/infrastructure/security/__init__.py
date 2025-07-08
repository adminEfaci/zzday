"""Integration security services.

This module provides security implementations for credentials, webhooks, and APIs.
"""

from app.modules.integration.infrastructure.security.api_key_manager import (
    APIKeyManager,
)
from app.modules.integration.infrastructure.security.certificate_validator import (
    CertificateValidator,
)
from app.modules.integration.infrastructure.security.credential_encryption import (
    CredentialEncryptionService,
)
from app.modules.integration.infrastructure.security.webhook_signature import (
    WebhookSignatureValidator,
)

# Alias for consistency with the request
CredentialEncryption = CredentialEncryptionService

__all__ = [
    "APIKeyManager",
    "CertificateValidator",
    "CredentialEncryption",
    "CredentialEncryptionService",
    "WebhookSignatureValidator",
]
