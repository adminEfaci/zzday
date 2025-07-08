"""
Audit module bootstrap configuration.

This module handles the initialization and dependency injection setup
for the Audit bounded context.
"""

import logging

from dependency_injector import containers, providers

from app.modules.audit.application.command_handlers import (
    ArchiveAuditLogsCommandHandler,
    CreateAuditLogCommandHandler,
    CreateComplianceRuleCommandHandler,
    GenerateComplianceReportCommandHandler,
    UpdateComplianceRuleCommandHandler,
)
from app.modules.audit.application.event_handlers import (
    AuditEventHandler,
    ComplianceEventHandler,
    IdentityEventHandler,
)
from app.modules.audit.application.query_handlers import (
    GetAuditLogQueryHandler,
    GetAuditLogsQueryHandler,
    GetComplianceReportQueryHandler,
    GetComplianceReportsQueryHandler,
    GetComplianceRuleQueryHandler,
    GetComplianceRulesQueryHandler,
    GetRiskAssessmentQueryHandler,
)
from app.modules.audit.application.services import (
    AuditApplicationService,
    ComplianceApplicationService,
    ReportingApplicationService,
)
from app.modules.audit.domain.services import (
    AuditDomainService,
    ComplianceDomainService,
    RiskAssessmentService,
)
from app.modules.audit.infrastructure.caching import (
    AuditLogCacheService,
    ComplianceRuleCacheService,
    ReportCacheService,
)
from app.modules.audit.infrastructure.repositories import (
    SqlAuditLogRepository,
    SqlComplianceReportRepository,
    SqlComplianceRuleRepository,
)
from app.modules.audit.infrastructure.services import (
    ComplianceEngineService,
    ElasticsearchAuditStore,
    ReportGeneratorService,
)

logger = logging.getLogger(__name__)


class AuditContainer(containers.DeclarativeContainer):
    """Audit module dependency injection container."""

    # Core dependencies (injected from main container)
    database = providers.Dependency()
    cache_manager = providers.Dependency()
    command_bus = providers.Dependency()
    query_bus = providers.Dependency()
    event_bus = providers.Dependency()
    config = providers.Dependency()

    # Infrastructure services
    elasticsearch_store = providers.Singleton(
        ElasticsearchAuditStore,
        hosts=config.provided.audit.elasticsearch_hosts,
        index_prefix=config.provided.audit.elasticsearch_index_prefix,
        retention_days=config.provided.audit.log_retention_days,
    )

    compliance_engine = providers.Singleton(
        ComplianceEngineService,
        rules_config=config.provided.audit.compliance_rules,
        engine_type=config.provided.audit.compliance_engine_type,
    )

    report_generator = providers.Singleton(
        ReportGeneratorService,
        template_path=config.provided.audit.report_template_path,
        output_formats=config.provided.audit.supported_report_formats,
    )

    # Cache services
    audit_log_cache = providers.Singleton(
        AuditLogCacheService,
        cache_manager=cache_manager,
        ttl=config.provided.audit.cache_ttl,
    )

    compliance_rule_cache = providers.Singleton(
        ComplianceRuleCacheService,
        cache_manager=cache_manager,
        ttl=config.provided.audit.compliance_cache_ttl,
    )

    report_cache = providers.Singleton(
        ReportCacheService,
        cache_manager=cache_manager,
        ttl=config.provided.audit.report_cache_ttl,
    )

    # Repositories
    audit_log_repository = providers.Singleton(
        SqlAuditLogRepository,
        database=database,
        elasticsearch_store=elasticsearch_store,
        cache_service=audit_log_cache,
    )

    compliance_rule_repository = providers.Singleton(
        SqlComplianceRuleRepository,
        database=database,
        cache_service=compliance_rule_cache,
    )

    compliance_report_repository = providers.Singleton(
        SqlComplianceReportRepository,
        database=database,
        cache_service=report_cache,
    )

    # Domain services
    audit_domain_service = providers.Singleton(
        AuditDomainService,
        audit_log_repository=audit_log_repository,
        risk_assessment_config=config.provided.audit.risk_assessment,
    )

    compliance_domain_service = providers.Singleton(
        ComplianceDomainService,
        compliance_rule_repository=compliance_rule_repository,
        compliance_engine=compliance_engine,
    )

    risk_assessment_service = providers.Singleton(
        RiskAssessmentService,
        audit_log_repository=audit_log_repository,
        compliance_rule_repository=compliance_rule_repository,
        risk_thresholds=config.provided.audit.risk_thresholds,
    )

    # Application services
    audit_application_service = providers.Singleton(
        AuditApplicationService,
        audit_domain_service=audit_domain_service,
        audit_log_repository=audit_log_repository,
        event_bus=event_bus,
    )

    compliance_application_service = providers.Singleton(
        ComplianceApplicationService,
        compliance_domain_service=compliance_domain_service,
        compliance_rule_repository=compliance_rule_repository,
        event_bus=event_bus,
    )

    reporting_application_service = providers.Singleton(
        ReportingApplicationService,
        audit_log_repository=audit_log_repository,
        compliance_report_repository=compliance_report_repository,
        report_generator=report_generator,
        event_bus=event_bus,
    )

    # Command handlers
    create_audit_log_command_handler = providers.Singleton(
        CreateAuditLogCommandHandler,
        audit_application_service=audit_application_service,
    )

    create_compliance_rule_command_handler = providers.Singleton(
        CreateComplianceRuleCommandHandler,
        compliance_application_service=compliance_application_service,
    )

    update_compliance_rule_command_handler = providers.Singleton(
        UpdateComplianceRuleCommandHandler,
        compliance_application_service=compliance_application_service,
    )

    generate_compliance_report_command_handler = providers.Singleton(
        GenerateComplianceReportCommandHandler,
        reporting_application_service=reporting_application_service,
    )

    archive_audit_logs_command_handler = providers.Singleton(
        ArchiveAuditLogsCommandHandler,
        audit_application_service=audit_application_service,
    )

    # Query handlers
    get_audit_log_query_handler = providers.Singleton(
        GetAuditLogQueryHandler,
        audit_log_repository=audit_log_repository,
    )

    get_audit_logs_query_handler = providers.Singleton(
        GetAuditLogsQueryHandler,
        audit_log_repository=audit_log_repository,
    )

    get_compliance_rule_query_handler = providers.Singleton(
        GetComplianceRuleQueryHandler,
        compliance_rule_repository=compliance_rule_repository,
    )

    get_compliance_rules_query_handler = providers.Singleton(
        GetComplianceRulesQueryHandler,
        compliance_rule_repository=compliance_rule_repository,
    )

    get_compliance_report_query_handler = providers.Singleton(
        GetComplianceReportQueryHandler,
        compliance_report_repository=compliance_report_repository,
    )

    get_compliance_reports_query_handler = providers.Singleton(
        GetComplianceReportsQueryHandler,
        compliance_report_repository=compliance_report_repository,
    )

    get_risk_assessment_query_handler = providers.Singleton(
        GetRiskAssessmentQueryHandler,
        risk_assessment_service=risk_assessment_service,
    )

    # Event handlers
    identity_event_handler = providers.Singleton(
        IdentityEventHandler,
        audit_application_service=audit_application_service,
    )

    audit_event_handler = providers.Singleton(
        AuditEventHandler,
        audit_log_cache=audit_log_cache,
        compliance_application_service=compliance_application_service,
    )

    compliance_event_handler = providers.Singleton(
        ComplianceEventHandler,
        compliance_rule_cache=compliance_rule_cache,
        audit_application_service=audit_application_service,
    )


class AuditBootstrap:
    """Bootstrap class for Audit module."""

    def __init__(self, main_container):
        """
        Initialize Audit bootstrap.

        Args:
            main_container: Main application container
        """
        self.main_container = main_container
        self.logger = logging.getLogger(self.__class__.__name__)

    def bootstrap(self) -> AuditContainer:
        """
        Bootstrap the Audit module.

        Returns:
            AuditContainer: Configured Audit container
        """
        self.logger.info("Bootstrapping Audit module")

        try:
            # Create container with dependencies
            container = AuditContainer()
            container.database.override(self.main_container.database())
            container.cache_manager.override(self.main_container.cache_manager())
            container.command_bus.override(self.main_container.command_bus())
            container.query_bus.override(self.main_container.query_bus())
            container.event_bus.override(self.main_container.event_bus())
            container.config.override(self.main_container.config())

            # Register command handlers
            self._register_command_handlers(container)

            # Register query handlers
            self._register_query_handlers(container)

            # Register event handlers
            self._register_event_handlers(container)

            # Initialize services
            self._initialize_services(container)

            # Setup scheduled tasks
            self._setup_scheduled_tasks(container)

            self.logger.info("Audit module bootstrapped successfully")
            return container

        except Exception as e:
            self.logger.exception(f"Failed to bootstrap Audit module: {e}")
            raise

    def _register_command_handlers(self, container: AuditContainer) -> None:
        """Register command handlers with the command bus."""
        self.logger.debug("Registering Audit command handlers")

        command_bus = container.command_bus()

        # Import commands
        from app.modules.audit.application.commands import (
            ArchiveAuditLogsCommand,
            CreateAuditLogCommand,
            CreateComplianceRuleCommand,
            GenerateComplianceReportCommand,
            UpdateComplianceRuleCommand,
        )

        # Register handlers
        command_bus.register(
            CreateAuditLogCommand, container.create_audit_log_command_handler()
        )
        command_bus.register(
            CreateComplianceRuleCommand,
            container.create_compliance_rule_command_handler(),
        )
        command_bus.register(
            UpdateComplianceRuleCommand,
            container.update_compliance_rule_command_handler(),
        )
        command_bus.register(
            GenerateComplianceReportCommand,
            container.generate_compliance_report_command_handler(),
        )
        command_bus.register(
            ArchiveAuditLogsCommand, container.archive_audit_logs_command_handler()
        )

        self.logger.debug("Audit command handlers registered")

    def _register_query_handlers(self, container: AuditContainer) -> None:
        """Register query handlers with the query bus."""
        self.logger.debug("Registering Audit query handlers")

        query_bus = container.query_bus()

        # Import queries
        from app.modules.audit.application.queries import (
            GetAuditLogQuery,
            GetAuditLogsQuery,
            GetComplianceReportQuery,
            GetComplianceReportsQuery,
            GetComplianceRuleQuery,
            GetComplianceRulesQuery,
            GetRiskAssessmentQuery,
        )

        # Register handlers
        query_bus.register(GetAuditLogQuery, container.get_audit_log_query_handler())
        query_bus.register(GetAuditLogsQuery, container.get_audit_logs_query_handler())
        query_bus.register(
            GetComplianceRuleQuery, container.get_compliance_rule_query_handler()
        )
        query_bus.register(
            GetComplianceRulesQuery, container.get_compliance_rules_query_handler()
        )
        query_bus.register(
            GetComplianceReportQuery, container.get_compliance_report_query_handler()
        )
        query_bus.register(
            GetComplianceReportsQuery, container.get_compliance_reports_query_handler()
        )
        query_bus.register(
            GetRiskAssessmentQuery, container.get_risk_assessment_query_handler()
        )

        self.logger.debug("Audit query handlers registered")

    def _register_event_handlers(self, container: AuditContainer) -> None:
        """Register event handlers with the event bus."""
        self.logger.debug("Registering Audit event handlers")

        event_bus = container.event_bus()

        # Import events
        from app.modules.audit.domain.events import (
            AuditLogCreatedEvent,
            ComplianceReportGeneratedEvent,
            ComplianceViolationDetectedEvent,
            CriticalActionPerformedEvent,
            RiskThresholdExceededEvent,
        )

        # Get handlers
        audit_event_handler = container.audit_event_handler()
        compliance_event_handler = container.compliance_event_handler()

        # Register audit events
        event_bus.subscribe(
            AuditLogCreatedEvent, audit_event_handler.handle_audit_log_created
        )
        event_bus.subscribe(
            ComplianceViolationDetectedEvent,
            audit_event_handler.handle_compliance_violation,
        )
        event_bus.subscribe(
            CriticalActionPerformedEvent, audit_event_handler.handle_critical_action
        )
        event_bus.subscribe(
            RiskThresholdExceededEvent,
            audit_event_handler.handle_risk_threshold_exceeded,
        )

        # Register compliance events
        event_bus.subscribe(
            ComplianceReportGeneratedEvent,
            compliance_event_handler.handle_report_generated,
        )

        self.logger.debug("Audit event handlers registered")

    def _initialize_services(self, container: AuditContainer) -> None:
        """Initialize and configure services."""
        self.logger.debug("Initializing Audit services")

        # Initialize Elasticsearch store
        elasticsearch_store = container.elasticsearch_store()
        elasticsearch_store.initialize()

        # Initialize compliance engine
        compliance_engine = container.compliance_engine()
        compliance_engine.initialize()

        # Initialize report generator
        report_generator = container.report_generator()
        report_generator.initialize()

        # Initialize cache services
        container.audit_log_cache().initialize()
        container.compliance_rule_cache().initialize()
        container.report_cache().initialize()

        # Setup compliance rules if none exist
        self._setup_default_compliance_rules(container)

        self.logger.debug("Audit services initialized")

    def _setup_default_compliance_rules(self, container: AuditContainer) -> None:
        """Setup default compliance rules if none exist."""
        self.logger.debug("Setting up default compliance rules")

        try:
            compliance_rule_repository = container.compliance_rule_repository()
            existing_rules = compliance_rule_repository.find_all()

            if not existing_rules:
                # Create default compliance rules
                from app.modules.audit.domain.entities import ComplianceRule
                from app.modules.audit.domain.value_objects import RuleType, Severity

                default_rules = [
                    ComplianceRule(
                        name="Failed Login Attempts",
                        description="Monitor failed login attempts",
                        rule_type=RuleType.SECURITY,
                        condition="failed_login_attempts > 5",
                        severity=Severity.HIGH,
                        enabled=True,
                    ),
                    ComplianceRule(
                        name="Privileged Access Usage",
                        description="Monitor privileged access usage",
                        rule_type=RuleType.ACCESS_CONTROL,
                        condition="action_type = 'ADMIN' AND user_role != 'ADMIN'",
                        severity=Severity.CRITICAL,
                        enabled=True,
                    ),
                    ComplianceRule(
                        name="Data Modification After Hours",
                        description="Monitor data modifications outside business hours",
                        rule_type=RuleType.DATA_PROTECTION,
                        condition="hour(timestamp) NOT BETWEEN 9 AND 17 AND action_type IN ('CREATE', 'UPDATE', 'DELETE')",
                        severity=Severity.MEDIUM,
                        enabled=True,
                    ),
                ]

                for rule in default_rules:
                    compliance_rule_repository.save(rule)

                self.logger.info(
                    f"Created {len(default_rules)} default compliance rules"
                )

        except Exception as e:
            self.logger.warning(f"Failed to setup default compliance rules: {e}")

    def _setup_scheduled_tasks(self, container: AuditContainer) -> None:
        """Setup scheduled tasks for audit operations."""
        self.logger.debug("Setting up Audit scheduled tasks")

        config = container.config()

        # Setup log archival task
        if config.audit.enable_log_archival:
            from app.core.scheduler import scheduler

            scheduler.add_job(
                func=self._archive_old_logs,
                trigger="cron",
                hour=config.audit.archival_hour,
                minute=0,
                args=[container],
                id="audit_log_archival",
                replace_existing=True,
            )

            self.logger.debug("Scheduled audit log archival task")

        # Setup compliance report generation
        if config.audit.enable_scheduled_reports:
            from app.core.scheduler import scheduler

            scheduler.add_job(
                func=self._generate_scheduled_reports,
                trigger="cron",
                day_of_week="mon",
                hour=config.audit.report_generation_hour,
                minute=0,
                args=[container],
                id="compliance_report_generation",
                replace_existing=True,
            )

            self.logger.debug("Scheduled compliance report generation task")

    def _archive_old_logs(self, container: AuditContainer) -> None:
        """Archive old audit logs."""
        try:
            command_bus = container.command_bus()
            config = container.config()

            from datetime import datetime, timedelta

            from app.modules.audit.application.commands import ArchiveAuditLogsCommand

            cutoff_date = datetime.utcnow() - timedelta(
                days=config.audit.log_retention_days
            )

            command = ArchiveAuditLogsCommand(cutoff_date=cutoff_date)
            command_bus.dispatch(command)

            self.logger.info(f"Archived audit logs older than {cutoff_date}")

        except Exception as e:
            self.logger.exception(f"Failed to archive audit logs: {e}")

    def _generate_scheduled_reports(self, container: AuditContainer) -> None:
        """Generate scheduled compliance reports."""
        try:
            command_bus = container.command_bus()

            from datetime import datetime, timedelta

            from app.modules.audit.application.commands import (
                GenerateComplianceReportCommand,
            )

            # Generate weekly report
            end_date = datetime.utcnow()
            start_date = end_date - timedelta(days=7)

            command = GenerateComplianceReportCommand(
                report_type="weekly_compliance",
                start_date=start_date,
                end_date=end_date,
                format="pdf",
            )
            command_bus.dispatch(command)

            self.logger.info("Generated scheduled compliance report")

        except Exception as e:
            self.logger.exception(f"Failed to generate scheduled report: {e}")
