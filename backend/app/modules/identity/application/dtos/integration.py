"""
Integration DTOs for identity domain.

Defines data structures for external system integration.
"""

from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field, HttpUrl

from app.modules.identity.domain.enums import ComplianceStatus


# OAuth/SSO Integration DTOs
class OAuthProviderConfig(BaseModel):
    """OAuth provider configuration."""
    provider: str  # google, facebook, github, etc.
    client_id: str
    client_secret: str
    authorize_url: HttpUrl
    token_url: HttpUrl
    userinfo_url: HttpUrl
    scopes: list[str]
    redirect_uri: HttpUrl
    enabled: bool = True


class OAuthTokenResponse(BaseModel):
    """OAuth token response from provider."""
    access_token: str
    token_type: str = "Bearer"
    expires_in: int | None = None
    refresh_token: str | None = None
    scope: str | None = None
    id_token: str | None = None  # For OpenID Connect


class OAuthUserInfo(BaseModel):
    """User information from OAuth provider."""
    provider: str
    provider_user_id: str
    email: str | None = None
    email_verified: bool | None = None
    name: str | None = None
    given_name: str | None = None
    family_name: str | None = None
    picture: str | None = None
    locale: str | None = None
    raw_data: dict[str, Any] = Field(default_factory=dict)


# LDAP/Active Directory Integration DTOs
class LDAPConfig(BaseModel):
    """LDAP configuration."""
    server_url: str
    bind_dn: str
    bind_password: str
    base_dn: str
    user_search_filter: str = "(uid={username})"
    group_search_filter: str = "(member={user_dn})"
    user_attributes: dict[str, str] = Field(default_factory=dict)
    group_attributes: dict[str, str] = Field(default_factory=dict)
    use_ssl: bool = True
    verify_cert: bool = True


class LDAPUser(BaseModel):
    """LDAP user information."""
    dn: str
    username: str
    email: str | None = None
    first_name: str | None = None
    last_name: str | None = None
    display_name: str | None = None
    department: str | None = None
    title: str | None = None
    phone_number: str | None = None
    groups: list[str] = Field(default_factory=list)
    attributes: dict[str, Any] = Field(default_factory=dict)


# SAML Integration DTOs
class SAMLConfig(BaseModel):
    """SAML configuration."""
    entity_id: str
    sso_url: HttpUrl
    slo_url: HttpUrl | None = None
    x509_cert: str
    private_key: str | None = None
    name_id_format: str = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
    attribute_mapping: dict[str, str] = Field(default_factory=dict)
    signed_requests: bool = True
    encrypted_assertions: bool = False


class SAMLAssertion(BaseModel):
    """SAML assertion data."""
    name_id: str
    name_id_format: str
    session_index: str | None = None
    attributes: dict[str, Any] = Field(default_factory=dict)
    authentication_instant: datetime
    not_before: datetime | None = None
    not_on_or_after: datetime | None = None


# External User Sync DTOs
class ExternalUserSync(BaseModel):
    """External user synchronization data."""
    external_id: str
    external_system: str  # ldap, azure_ad, google_workspace, etc.
    username: str
    email: str
    first_name: str | None = None
    last_name: str | None = None
    department: str | None = None
    title: str | None = None
    manager: str | None = None
    groups: list[str] = Field(default_factory=list)
    roles: list[str] = Field(default_factory=list)
    attributes: dict[str, Any] = Field(default_factory=dict)
    last_synced: datetime
    sync_status: str = "pending"  # pending, synced, failed


class BulkUserImport(BaseModel):
    """Bulk user import request."""
    source: str  # csv, ldap, api, etc.
    users: list[ExternalUserSync]
    options: dict[str, Any] = Field(default_factory=dict)
    dry_run: bool = False
    update_existing: bool = True
    create_missing: bool = True
    deactivate_removed: bool = False


# Webhook Integration DTOs
class WebhookConfig(BaseModel):
    """Webhook configuration."""
    id: UUID
    name: str
    url: HttpUrl
    events: list[str]  # Event types to send
    secret: str
    active: bool = True
    headers: dict[str, str] = Field(default_factory=dict)
    retry_config: dict[str, Any] = Field(default_factory=dict)


class WebhookPayload(BaseModel):
    """Webhook payload structure."""
    webhook_id: UUID
    event_type: str
    event_id: UUID
    timestamp: datetime
    data: dict[str, Any]
    signature: str  # HMAC signature


# API Integration DTOs
class APIKeyConfig(BaseModel):
    """API key configuration."""
    id: UUID
    name: str
    key: str
    secret: str | None = None
    scopes: list[str] = Field(default_factory=list)
    rate_limit: int | None = None
    expires_at: datetime | None = None
    allowed_ips: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ServiceAccountConfig(BaseModel):
    """Service account configuration."""
    id: UUID
    name: str
    client_id: str
    client_secret: str
    scopes: list[str]
    token_endpoint: HttpUrl | None = None
    public_key: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


# Event Streaming DTOs
class EventStreamConfig(BaseModel):
    """Event stream configuration."""
    stream_type: str  # kafka, rabbitmq, aws_eventbridge, etc.
    connection_string: str
    topic_prefix: str
    consumer_group: str | None = None
    serialization_format: str = "json"  # json, avro, protobuf
    authentication: dict[str, Any] = Field(default_factory=dict)


class StreamedEvent(BaseModel):
    """Event for streaming."""
    event_id: UUID
    event_type: str
    aggregate_id: UUID
    aggregate_type: str
    data: dict[str, Any]
    metadata: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime
    version: int = 1
    sequence_number: int | None = None


# External Service Responses
class GeolocationResponse(BaseModel):
    """Geolocation service response."""
    ip_address: str
    country_code: str
    country_name: str
    region: str | None = None
    city: str | None = None
    postal_code: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    timezone: str | None = None
    isp: str | None = None
    organization: str | None = None


class ThreatIntelligenceResponse(BaseModel):
    """Threat intelligence service response."""
    ip_address: str
    risk_score: float = Field(..., ge=0.0, le=1.0)
    is_proxy: bool = False
    is_vpn: bool = False
    is_tor: bool = False
    is_datacenter: bool = False
    is_residential: bool = True
    threat_categories: list[str] = Field(default_factory=list)
    last_seen: datetime | None = None
    report_count: int = 0


class PasswordBreachResponse(BaseModel):
    """Password breach check response."""
    breached: bool
    breach_count: int = 0
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    sources: list[str] = Field(default_factory=list)


# Notification Service DTOs
class NotificationChannel(BaseModel):
    """Notification channel configuration."""
    channel_type: str  # email, sms, push, slack, teams, etc.
    enabled: bool = True
    config: dict[str, Any] = Field(default_factory=dict)
    rate_limits: dict[str, int] = Field(default_factory=dict)


class NotificationRequest(BaseModel):
    """Notification request."""
    recipient_id: UUID
    channels: list[str]
    template: str
    data: dict[str, Any] = Field(default_factory=dict)
    priority: str = "normal"  # low, normal, high, urgent
    schedule_at: datetime | None = None
    expires_at: datetime | None = None
    deduplication_key: str | None = None


# Analytics Integration DTOs
class AnalyticsEvent(BaseModel):
    """Analytics event data."""
    event_name: str
    user_id: UUID | None = None
    session_id: UUID | None = None
    properties: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    context: dict[str, Any] = Field(default_factory=dict)


class UserSegment(BaseModel):
    """User segment for analytics."""
    segment_id: str
    segment_name: str
    user_count: int
    criteria: dict[str, Any]
    created_at: datetime
    updated_at: datetime


# Compliance Integration DTOs
class ComplianceExport(BaseModel):
    """Compliance data export."""
    export_id: UUID
    regulation: str  # GDPR, CCPA, etc.
    user_id: UUID
    data_categories: list[str]
    format: str
    status: str
    requested_at: datetime
    completed_at: datetime | None = None
    download_url: str | None = None
    expires_at: datetime | None = None


class ConsentRecord(BaseModel):
    """User consent record."""
    consent_id: UUID
    user_id: UUID
    purpose: str
    lawful_basis: str
    data_categories: list[str]
    granted: bool
    granted_at: datetime | None = None
    withdrawn_at: datetime | None = None
    expires_at: datetime | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


# ============================================================================
# Enhanced External Identity Provider DTOs
# ============================================================================

class IdentityProviderConfig(BaseModel):
    """Identity provider configuration."""
    provider_id: UUID
    provider_type: str  # oauth, saml, ldap, oidc, custom
    provider_name: str
    enabled: bool = True
    auto_provision: bool = False
    auto_update: bool = True
    sync_interval: timedelta | None = None
    attribute_mappings: dict[str, str] = Field(default_factory=dict)
    role_mappings: dict[str, str] = Field(default_factory=dict)
    group_mappings: dict[str, str] = Field(default_factory=dict)
    jit_provisioning: bool = False
    deprovisioning_enabled: bool = False
    mfa_required: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)


class FederatedIdentity(BaseModel):
    """Federated identity information."""
    user_id: UUID
    provider: str
    provider_user_id: str
    provider_username: str | None = None
    linked_at: datetime
    last_login: datetime | None = None
    attributes: dict[str, Any] = Field(default_factory=dict)
    access_token: str | None = None
    refresh_token: str | None = None
    token_expires_at: datetime | None = None
    active: bool = True


class IdentityLinkRequest(BaseModel):
    """Request to link external identity."""
    user_id: UUID
    provider: str
    provider_user_id: str
    provider_token: str
    attributes: dict[str, Any] = Field(default_factory=dict)
    force_link: bool = False


class IdentityUnlinkRequest(BaseModel):
    """Request to unlink external identity."""
    user_id: UUID
    provider: str
    reason: str | None = None
    retain_data: bool = False


# ============================================================================
# Enhanced OAuth/OpenID Connect DTOs
# ============================================================================

class OIDCProviderMetadata(BaseModel):
    """OpenID Connect provider metadata."""
    issuer: HttpUrl
    authorization_endpoint: HttpUrl
    token_endpoint: HttpUrl
    userinfo_endpoint: HttpUrl
    jwks_uri: HttpUrl
    registration_endpoint: HttpUrl | None = None
    scopes_supported: list[str]
    response_types_supported: list[str]
    grant_types_supported: list[str]
    subject_types_supported: list[str]
    id_token_signing_alg_values_supported: list[str]
    claims_supported: list[str]
    token_endpoint_auth_methods_supported: list[str]


class OAuthAuthorizationRequest(BaseModel):
    """OAuth authorization request."""
    provider: str
    response_type: str = "code"
    client_id: str
    redirect_uri: HttpUrl
    scope: str
    state: str
    nonce: str | None = None
    code_challenge: str | None = None
    code_challenge_method: str | None = None
    prompt: str | None = None
    max_age: int | None = None
    login_hint: str | None = None


class OAuthTokenExchange(BaseModel):
    """OAuth token exchange request."""
    grant_type: str
    code: str | None = None
    redirect_uri: HttpUrl | None = None
    refresh_token: str | None = None
    client_id: str
    client_secret: str | None = None
    code_verifier: str | None = None
    username: str | None = None
    password: str | None = None
    scope: str | None = None


# ============================================================================
# Enhanced SAML DTOs
# ============================================================================

class SAMLMetadata(BaseModel):
    """SAML metadata."""
    entity_id: str
    sso_service_url: HttpUrl
    slo_service_url: HttpUrl | None = None
    x509_certs: list[str]
    name_id_formats: list[str]
    single_logout_supported: bool = False
    want_authn_requests_signed: bool = True
    want_assertions_signed: bool = True
    want_assertions_encrypted: bool = False
    authn_context_class_refs: list[str] = Field(default_factory=list)


class SAMLAuthRequest(BaseModel):
    """SAML authentication request."""
    id: str
    version: str = "2.0"
    issue_instant: datetime
    destination: HttpUrl
    assertion_consumer_service_url: HttpUrl
    issuer: str
    name_id_policy_format: str | None = None
    requested_authn_context: list[str] | None = None
    relay_state: str | None = None
    force_authn: bool = False
    is_passive: bool = False


class SAMLResponse(BaseModel):
    """SAML response."""
    id: str
    in_response_to: str
    version: str = "2.0"
    issue_instant: datetime
    destination: HttpUrl
    issuer: str
    status_code: str
    assertion: SAMLAssertion | None = None
    encrypted_assertion: str | None = None
    relay_state: str | None = None


class SAMLLogoutRequest(BaseModel):
    """SAML logout request."""
    id: str
    version: str = "2.0"
    issue_instant: datetime
    destination: HttpUrl
    issuer: str
    name_id: str
    name_id_format: str
    session_index: str | None = None
    reason: str | None = None


# ============================================================================
# Enhanced LDAP/Active Directory DTOs
# ============================================================================

class LDAPConnectionPool(BaseModel):
    """LDAP connection pool configuration."""
    min_connections: int = 1
    max_connections: int = 10
    connection_timeout: int = 30
    pool_timeout: int = 60
    retry_count: int = 3
    retry_delay: int = 1
    health_check_interval: int = 300
    use_ssl: bool = True
    start_tls: bool = False
    validate_cert: bool = True


class LDAPSearchRequest(BaseModel):
    """LDAP search request."""
    base_dn: str
    scope: str = "subtree"  # base, onelevel, subtree
    filter: str
    attributes: list[str] = Field(default_factory=list)
    size_limit: int = 1000
    time_limit: int = 30
    types_only: bool = False
    deref_aliases: str = "never"  # never, search, find, always
    paged_results: bool = True
    page_size: int = 100


class LDAPModifyRequest(BaseModel):
    """LDAP modify request."""
    dn: str
    modifications: list[dict[str, Any]]  # operation, attribute, values
    controls: list[dict[str, Any]] = Field(default_factory=list)


class ADGroupSync(BaseModel):
    """Active Directory group synchronization."""
    ad_group_dn: str
    ad_group_name: str
    local_role: str
    sync_members: bool = True
    sync_nested_groups: bool = True
    remove_missing_members: bool = False
    last_sync: datetime | None = None
    member_count: int = 0
    sync_errors: list[str] = Field(default_factory=list)


# ============================================================================
# Enhanced API Gateway & Service Mesh DTOs
# ============================================================================

class APIGatewayConfig(BaseModel):
    """API gateway configuration."""
    gateway_url: HttpUrl
    service_name: str
    service_version: str
    route_prefix: str
    load_balancing: str = "round_robin"  # round_robin, least_conn, ip_hash
    health_check_path: str = "/health"
    health_check_interval: int = 30
    circuit_breaker_enabled: bool = True
    circuit_breaker_threshold: float = 0.5
    circuit_breaker_timeout: int = 60
    retry_policy: dict[str, Any] = Field(default_factory=dict)
    timeout_ms: int = 30000
    rate_limits: dict[str, int] = Field(default_factory=dict)


class ServiceMeshConfig(BaseModel):
    """Service mesh configuration."""
    mesh_name: str
    namespace: str
    service_name: str
    mtls_enabled: bool = True
    tracing_enabled: bool = True
    metrics_enabled: bool = True
    retry_policy: dict[str, Any] = Field(default_factory=dict)
    circuit_breaker: dict[str, Any] = Field(default_factory=dict)
    traffic_policy: dict[str, Any] = Field(default_factory=dict)
    security_policy: dict[str, Any] = Field(default_factory=dict)


class ServiceDiscovery(BaseModel):
    """Service discovery information."""
    service_id: UUID
    service_name: str
    service_version: str
    endpoints: list[HttpUrl]
    health_status: str = "healthy"  # healthy, unhealthy, unknown
    metadata: dict[str, Any] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)
    last_heartbeat: datetime
    registered_at: datetime


# ============================================================================
# Enhanced Event Bus & Message Queue DTOs
# ============================================================================

class EventBusConfig(BaseModel):
    """Event bus configuration."""
    bus_type: str  # kafka, rabbitmq, aws_eventbridge, azure_eventgrid, gcp_pubsub
    connection_config: dict[str, Any]
    topic_prefix: str
    consumer_group: str | None = None
    serialization: str = "json"  # json, avro, protobuf, msgpack
    compression: str | None = None  # gzip, snappy, lz4, zstd
    batch_size: int = 100
    batch_timeout_ms: int = 1000
    retry_policy: dict[str, Any] = Field(default_factory=dict)
    dead_letter_config: dict[str, Any] | None = None


class MessageQueueConfig(BaseModel):
    """Message queue configuration."""
    queue_type: str  # sqs, rabbitmq, redis, activemq
    connection_string: str
    queue_name: str
    visibility_timeout: int = 300
    message_retention: int = 345600  # 4 days
    max_receive_count: int = 3
    dead_letter_queue: str | None = None
    encryption_enabled: bool = True
    fifo_queue: bool = False


class EventSubscription(BaseModel):
    """Event subscription configuration."""
    subscription_id: UUID
    subscriber_name: str
    event_types: list[str]
    filter_expression: str | None = None
    endpoint_type: str  # webhook, queue, function, email
    endpoint_config: dict[str, Any]
    retry_policy: dict[str, Any] = Field(default_factory=dict)
    active: bool = True
    created_at: datetime
    last_delivery: datetime | None = None
    delivery_count: int = 0
    error_count: int = 0


# ============================================================================
# Enhanced Data Pipeline & ETL DTOs
# ============================================================================

class DataPipelineConfig(BaseModel):
    """Data pipeline configuration."""
    pipeline_id: UUID
    pipeline_name: str
    source_config: dict[str, Any]
    destination_config: dict[str, Any]
    transformation_steps: list[dict[str, Any]]
    schedule: str | None = None  # cron expression
    trigger_type: str = "scheduled"  # scheduled, event, manual
    parallel_processing: bool = True
    batch_size: int = 1000
    error_handling: str = "stop"  # stop, continue, dead_letter
    monitoring_config: dict[str, Any] = Field(default_factory=dict)


class ETLJob(BaseModel):
    """ETL job configuration."""
    job_id: UUID
    job_name: str
    extract_config: dict[str, Any]
    transform_config: list[dict[str, Any]]
    load_config: dict[str, Any]
    validation_rules: list[dict[str, Any]] = Field(default_factory=list)
    checkpoint_enabled: bool = True
    checkpoint_interval: int = 1000
    max_retries: int = 3
    timeout_minutes: int = 60
    resource_config: dict[str, Any] = Field(default_factory=dict)


class DataQualityCheck(BaseModel):
    """Data quality check configuration."""
    check_id: UUID
    check_name: str
    check_type: str  # completeness, accuracy, consistency, validity
    target_table: str
    check_expression: str
    severity: str = "warning"  # info, warning, error, critical
    threshold: float | None = None
    sample_size: int | None = None
    active: bool = True
    schedule: str | None = None


# ============================================================================
# Enhanced Monitoring & Observability DTOs
# ============================================================================

class TracingConfig(BaseModel):
    """Distributed tracing configuration."""
    tracer_type: str  # jaeger, zipkin, datadog, newrelic
    endpoint: HttpUrl
    service_name: str
    sample_rate: float = 0.1
    propagation_format: str = "w3c"  # w3c, b3, jaeger
    tags: dict[str, str] = Field(default_factory=dict)
    export_interval_ms: int = 5000
    max_export_batch_size: int = 512
    enabled: bool = True


class MetricsExporter(BaseModel):
    """Metrics exporter configuration."""
    exporter_type: str  # prometheus, datadog, cloudwatch, stackdriver
    endpoint: HttpUrl | None = None
    export_interval: int = 60
    metric_prefix: str = "identity"
    labels: dict[str, str] = Field(default_factory=dict)
    aggregation_temporality: str = "cumulative"  # cumulative, delta
    histogram_buckets: list[float] = Field(default_factory=list)


class LogShipper(BaseModel):
    """Log shipping configuration."""
    shipper_type: str  # elasticsearch, splunk, datadog, cloudwatch
    endpoint: HttpUrl
    index_pattern: str
    batch_size: int = 100
    flush_interval_ms: int = 1000
    compression: bool = True
    encryption: bool = True
    filter_rules: list[dict[str, Any]] = Field(default_factory=list)
    enrichment_fields: dict[str, Any] = Field(default_factory=dict)


class AlertingRule(BaseModel):
    """Alerting rule configuration."""
    rule_id: UUID
    rule_name: str
    metric_name: str
    condition: str  # expression
    threshold: float
    evaluation_interval: int = 60
    for_duration: int = 300  # seconds
    severity: str = "warning"  # info, warning, error, critical
    notification_channels: list[str]
    labels: dict[str, str] = Field(default_factory=dict)
    annotations: dict[str, str] = Field(default_factory=dict)
    active: bool = True


# ============================================================================
# Enhanced Security Integration DTOs
# ============================================================================

class WAFConfig(BaseModel):
    """Web Application Firewall configuration."""
    waf_provider: str  # cloudflare, aws_waf, akamai, f5
    rule_sets: list[str]
    custom_rules: list[dict[str, Any]] = Field(default_factory=list)
    ip_allowlist: list[str] = Field(default_factory=list)
    ip_blocklist: list[str] = Field(default_factory=list)
    geo_blocking: list[str] = Field(default_factory=list)  # country codes
    rate_limiting: dict[str, int] = Field(default_factory=dict)
    bot_protection: bool = True
    ddos_protection: bool = True
    logging_enabled: bool = True


class SIEMIntegration(BaseModel):
    """SIEM integration configuration."""
    siem_type: str  # splunk, qradar, sentinel, chronicle
    endpoint: HttpUrl
    api_key: str
    event_types: list[str]
    log_sources: list[str]
    correlation_rules: list[dict[str, Any]] = Field(default_factory=list)
    enrichment_enabled: bool = True
    real_time_sync: bool = True
    batch_interval: int = 60


class VulnerabilityScanner(BaseModel):
    """Vulnerability scanner configuration."""
    scanner_type: str  # owasp_zap, burp, nessus, qualys
    target_url: HttpUrl
    scan_profile: str = "standard"  # light, standard, deep
    authentication_config: dict[str, Any] | None = None
    excluded_paths: list[str] = Field(default_factory=list)
    scan_schedule: str | None = None
    severity_threshold: str = "medium"  # low, medium, high, critical
    auto_remediation: bool = False


class SecurityOrchestration(BaseModel):
    """Security orchestration configuration."""
    playbook_id: UUID
    playbook_name: str
    trigger_conditions: list[dict[str, Any]]
    investigation_steps: list[dict[str, Any]]
    containment_actions: list[dict[str, Any]]
    remediation_actions: list[dict[str, Any]]
    notification_config: dict[str, Any]
    approval_required: bool = False
    approvers: list[UUID] = Field(default_factory=list)
    auto_execute: bool = False
    max_execution_time: int = 3600


# ============================================================================
# Enhanced Cloud Provider Integration DTOs
# ============================================================================

class CloudProviderConfig(BaseModel):
    """Cloud provider configuration."""
    provider: str  # aws, azure, gcp, alibaba
    region: str
    account_id: str
    authentication: dict[str, Any]  # provider-specific auth
    services: list[str]  # enabled services
    vpc_config: dict[str, Any] | None = None
    security_groups: list[str] = Field(default_factory=list)
    tags: dict[str, str] = Field(default_factory=dict)


class CloudIdentityMapping(BaseModel):
    """Cloud identity mapping."""
    local_user_id: UUID
    cloud_provider: str
    cloud_user_arn: str  # AWS ARN, Azure ID, GCP identity
    role_mappings: dict[str, str] = Field(default_factory=dict)
    permission_boundaries: str | None = None
    session_duration: int = 3600
    mfa_required: bool = True
    ip_restrictions: list[str] = Field(default_factory=list)
    condition_policies: list[dict[str, Any]] = Field(default_factory=list)


class CloudResourceAccess(BaseModel):
    """Cloud resource access configuration."""
    resource_arn: str
    resource_type: str
    access_level: str  # read, write, admin
    principals: list[str]  # user/role ARNs
    conditions: dict[str, Any] = Field(default_factory=dict)
    tags_required: dict[str, str] = Field(default_factory=dict)
    encryption_required: bool = True
    audit_logging: bool = True


# ============================================================================
# Enhanced Compliance & Audit Integration DTOs
# ============================================================================

class ComplianceFramework(BaseModel):
    """Compliance framework configuration."""
    framework_id: UUID
    framework_name: str  # SOC2, ISO27001, HIPAA, PCI-DSS
    version: str
    controls: list[dict[str, Any]]
    evidence_requirements: list[dict[str, Any]]
    assessment_frequency: str  # monthly, quarterly, annually
    automated_controls: list[str]
    manual_controls: list[str]
    responsible_parties: dict[str, UUID] = Field(default_factory=dict)
    last_assessment: datetime | None = None
    next_assessment: datetime
    compliance_status: ComplianceStatus


class AuditLogExport(BaseModel):
    """Audit log export configuration."""
    export_id: UUID
    export_format: str  # json, csv, parquet, avro
    compression: str | None = None  # gzip, zip, bzip2
    encryption: bool = True
    encryption_key_id: str | None = None
    time_range: dict[str, datetime]
    filters: dict[str, Any] = Field(default_factory=dict)
    include_fields: list[str] = Field(default_factory=list)
    exclude_fields: list[str] = Field(default_factory=list)
    destination_type: str  # s3, blob, gcs, sftp
    destination_config: dict[str, Any]
    retention_days: int = 2555  # 7 years


class ComplianceReport(BaseModel):
    """Compliance report configuration."""
    report_id: UUID
    report_type: str
    framework: str
    period_start: datetime
    period_end: datetime
    executive_summary: str
    findings: list[dict[str, Any]]
    remediation_items: list[dict[str, Any]]
    evidence_links: list[HttpUrl]
    attestations: list[dict[str, Any]]
    generated_by: UUID
    reviewed_by: UUID | None = None
    approved_by: UUID | None = None
    status: str = "draft"  # draft, review, approved, submitted


# ============================================================================
# Enhanced Business Intelligence Integration DTOs
# ============================================================================

class BIConnector(BaseModel):
    """Business Intelligence connector configuration."""
    connector_id: UUID
    bi_platform: str  # tableau, powerbi, looker, qlik
    connection_type: str  # direct_query, import, hybrid
    data_sources: list[dict[str, Any]]
    refresh_schedule: str | None = None
    incremental_refresh: bool = True
    row_level_security: bool = True
    column_level_security: dict[str, list[str]] = Field(default_factory=dict)
    performance_mode: str = "balanced"  # economy, balanced, performance
    cache_config: dict[str, Any] = Field(default_factory=dict)


class DataWarehouseSync(BaseModel):
    """Data warehouse synchronization configuration."""
    sync_id: UUID
    warehouse_type: str  # snowflake, redshift, bigquery, synapse
    connection_config: dict[str, Any]
    sync_tables: list[str]
    sync_frequency: str  # real_time, hourly, daily
    transformation_sql: str | None = None
    partition_strategy: str | None = None
    clustering_keys: list[str] = Field(default_factory=list)
    retention_policy: dict[str, Any] | None = None
    cost_controls: dict[str, Any] = Field(default_factory=dict)


class AnalyticsWorkspace(BaseModel):
    """Analytics workspace configuration."""
    workspace_id: UUID
    workspace_name: str
    datasets: list[dict[str, Any]]
    reports: list[dict[str, Any]]
    dashboards: list[dict[str, Any]]
    sharing_permissions: dict[str, list[str]]
    refresh_schedules: dict[str, str]
    alert_rules: list[dict[str, Any]] = Field(default_factory=list)
    export_formats: list[str] = ["pdf", "excel", "csv"]
    branding_config: dict[str, Any] | None = None