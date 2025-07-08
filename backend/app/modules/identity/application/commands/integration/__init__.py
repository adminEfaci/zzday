"""
Integration Commands Module.

Handles external system integrations and identity federation for the EzzDay platform.
"""

from .audit_integration_command import (
    AuditIntegrationCommand,
    AuditIntegrationCommandHandler,
)
from .compliance_reporting_command import (
    ComplianceReportingCommand,
    ComplianceReportingCommandHandler,
)
from .data_migration_command import DataMigrationCommand, DataMigrationCommandHandler
from .external_api_sync_command import (
    ExternalApiSyncCommand,
    ExternalApiSyncCommandHandler,
)
from .identity_federation_command import (
    IdentityFederationCommand,
    IdentityFederationCommandHandler,
)
from .ldap_sync_command import LdapSyncCommand, LdapSyncCommandHandler
from .oauth_provider_command import OauthProviderCommand, OauthProviderCommandHandler
from .saml_sso_command import SamlSsoCommand, SamlSsoCommandHandler
from .third_party_connect_command import (
    ThirdPartyConnectCommand,
    ThirdPartyConnectCommandHandler,
)
from .webhook_management_command import (
    WebhookManagementCommand,
    WebhookManagementCommandHandler,
)

__all__ = [
    # Audit Log Integration
    "AuditIntegrationCommand",
    "AuditIntegrationCommandHandler",
    # Compliance Reporting Integration
    "ComplianceReportingCommand",
    "ComplianceReportingCommandHandler",
    # Data Migration/Import
    "DataMigrationCommand",
    "DataMigrationCommandHandler",
    # External API Synchronization
    "ExternalApiSyncCommand",
    "ExternalApiSyncCommandHandler",
    # Identity Federation
    "IdentityFederationCommand",
    "IdentityFederationCommandHandler",
    # LDAP/Directory Integration
    "LdapSyncCommand",
    "LdapSyncCommandHandler",
    # OAuth Provider Integration
    "OauthProviderCommand",
    "OauthProviderCommandHandler",
    # SAML/SSO Integration  
    "SamlSsoCommand",
    "SamlSsoCommandHandler",
    # Third-party Service Connection
    "ThirdPartyConnectCommand",
    "ThirdPartyConnectCommandHandler",
    # Webhook Management
    "WebhookManagementCommand",
    "WebhookManagementCommandHandler",
]