"""
Comprehensive Analytics Queries GraphQL Resolver

This module provides specialized audit analytics queries with enterprise-grade features:
- Real-time performance metrics and dashboards
- Advanced pattern analysis and anomaly detection
- User behavior analytics and risk scoring
- System performance monitoring
- Predictive analytics and forecasting

Features:
- Multi-dimensional analytics with drill-down capabilities
- Real-time metric collection and aggregation
- Machine learning-powered insights
- Custom dashboard configuration
- Export capabilities for business intelligence tools

Security:
- Authentication and authorization required
- Role-based access to sensitive analytics
- Data filtering based on user permissions
- Comprehensive audit logging of analytics access
"""

from typing import Any
from uuid import UUID

import strawberry

# Core imports
from app.core.errors import AuthorizationError, ValidationError
from app.core.logging import get_logger

# Audit domain imports
from app.modules.audit.application.services.audit_service import AuditService
from app.modules.audit.application.services.reporting_service import ReportingService
from app.modules.audit.presentation.graphql.schemas.inputs.report_inputs import (
    MetricsQueryInput,
    RiskAnalysisInput,
    SystemPerformanceInput,
    UserBehaviorInput,
)

# GraphQL types and inputs
from app.modules.audit.presentation.graphql.schemas.types.analytics_type import (
    AnomalyDetectionType,
    AuditMetricsType,
    PredictiveAnalyticsType,
    RiskAnalyticsType,
    SystemPerformanceType,
    UserBehaviorAnalyticsType,
)

# Mappers
from app.modules.audit.presentation.mappers.report_mapper import ReportMapper

# Identity imports for authentication
from app.modules.identity.presentation.graphql.decorators import (
    audit_log,
    cache_result,
    operation_timeout,
    rate_limit,
    require_auth,
    require_permission,
)

logger = get_logger(__name__)


@strawberry.type
class AnalyticsQueries:
    """
    Specialized analytics queries for audit data insights.

    Provides comprehensive analytics capabilities for business intelligence,
    security analysis, and performance monitoring with real-time dashboards
    and predictive insights.
    """

    @strawberry.field(description="Get real-time audit metrics dashboard")
    @require_auth()
    @require_permission("audit.analytics.metrics.read")
    @rate_limit(requests=60, window=60)
    @audit_log("audit.analytics.metrics")
    @cache_result(ttl=60)  # Cache for 1 minute for real-time data
    async def get_audit_metrics(
        self, info: strawberry.Info, input: MetricsQueryInput
    ) -> AuditMetricsType:
        """
        Get real-time audit metrics for dashboard displays.

        Features:
        - Real-time event counts and rates
        - Security incident metrics
        - Compliance status indicators
        - Performance benchmarks
        - Historical comparisons

        Args:
            input: Metrics query parameters

        Returns:
            Comprehensive metrics data for dashboards

        Raises:
            ValidationError: If input parameters are invalid
        """
        try:
            # Validate input
            validation_errors = input.validate()
            if validation_errors:
                raise ValidationError(
                    f"Invalid metrics query: {'; '.join(validation_errors)}"
                )

            # Get audit service
            audit_service: AuditService = info.context["container"].resolve(
                AuditService
            )
            current_user = info.context.get("current_user")

            logger.info(
                "Retrieving audit metrics",
                user_id=str(current_user.id),
                time_range=input.time_range,
                metrics=input.metrics,
            )

            # Apply permission-based filtering
            criteria = input.to_criteria_dict()
            if not current_user.has_permission("audit.analytics.metrics.read_all"):
                criteria["scope_to_user"] = current_user.id

            # Get metrics data
            metrics_data = await audit_service.get_real_time_metrics(
                time_range=input.time_range,
                metrics=input.metrics,
                aggregation_level=input.aggregation_level,
                include_trends=input.include_trends,
                include_comparisons=input.include_comparisons,
                criteria=criteria,
            )

            # Convert to GraphQL type
            return ReportMapper.metrics_to_graphql(metrics_data)

        except ValidationError:
            raise
        except Exception as e:
            logger.error(f"Metrics retrieval failed: {e}", exc_info=True)
            raise ValidationError("Failed to retrieve metrics")

    @strawberry.field(description="Get user behavior analytics and patterns")
    @require_auth()
    @require_permission("audit.analytics.user_behavior.read")
    @rate_limit(requests=30, window=60)
    @audit_log("audit.analytics.user_behavior")
    @cache_result(ttl=300)
    async def get_user_behavior_analytics(
        self, info: strawberry.Info, input: UserBehaviorInput
    ) -> UserBehaviorAnalyticsType:
        """
        Analyze user behavior patterns and detect anomalies.

        Features:
        - Activity pattern analysis
        - Anomaly detection algorithms
        - Risk scoring based on behavior
        - Baseline comparison
        - Peer group analysis

        Args:
            input: User behavior analysis parameters

        Returns:
            Comprehensive user behavior analytics
        """
        try:
            # Validate input
            validation_errors = input.validate()
            if validation_errors:
                raise ValidationError(
                    f"Invalid user behavior input: {'; '.join(validation_errors)}"
                )

            # Get reporting service
            reporting_service: ReportingService = info.context["container"].resolve(
                ReportingService
            )
            current_user = info.context.get("current_user")

            # Permission check for analyzing other users
            if input.user_ids:
                target_users = [UUID(uid) for uid in input.user_ids]
                if not current_user.has_permission(
                    "audit.analytics.user_behavior.read_all"
                ):
                    # Only allow analysis of own behavior
                    if len(target_users) != 1 or target_users[0] != current_user.id:
                        raise AuthorizationError("Cannot analyze other users' behavior")

            logger.info(
                "Analyzing user behavior",
                user_id=str(current_user.id),
                target_users=input.user_ids,
                analysis_period=input.analysis_period,
            )

            # Generate behavior analytics
            behavior_data = await reporting_service.analyze_user_behavior(
                user_ids=input.user_ids,
                start_date=input.date_range.start_date,
                end_date=input.date_range.end_date,
                analysis_period=input.analysis_period,
                include_anomalies=input.include_anomalies,
                include_risk_scoring=input.include_risk_scoring,
                include_peer_comparison=input.include_peer_comparison,
                requested_by=current_user.id,
            )

            # Convert to GraphQL type
            return ReportMapper.user_behavior_to_graphql(behavior_data)

        except (ValidationError, AuthorizationError):
            raise
        except Exception as e:
            logger.error(f"User behavior analysis failed: {e}", exc_info=True)
            raise ValidationError("Failed to analyze user behavior")

    @strawberry.field(description="Get system performance analytics")
    @require_auth()
    @require_permission("audit.analytics.system_performance.read")
    @rate_limit(requests=20, window=60)
    @audit_log("audit.analytics.system_performance")
    @cache_result(ttl=180)
    async def get_system_performance_analytics(
        self, info: strawberry.Info, input: SystemPerformanceInput
    ) -> SystemPerformanceType:
        """
        Analyze audit system performance and resource utilization.

        Features:
        - Query performance analysis
        - Storage utilization trends
        - Processing latency metrics
        - Throughput analysis
        - Capacity planning insights

        Args:
            input: System performance analysis parameters

        Returns:
            Comprehensive system performance analytics
        """
        try:
            # Validate input
            validation_errors = input.validate()
            if validation_errors:
                raise ValidationError(
                    f"Invalid system performance input: {'; '.join(validation_errors)}"
                )

            # Get reporting service
            reporting_service: ReportingService = info.context["container"].resolve(
                ReportingService
            )
            current_user = info.context.get("current_user")

            logger.info(
                "Analyzing system performance",
                user_id=str(current_user.id),
                metrics=input.metrics,
                time_granularity=input.time_granularity,
            )

            # Generate performance analytics
            performance_data = await reporting_service.analyze_system_performance(
                metrics=input.metrics,
                start_date=input.date_range.start_date,
                end_date=input.date_range.end_date,
                time_granularity=input.time_granularity,
                include_trends=input.include_trends,
                include_predictions=input.include_predictions,
                include_recommendations=input.include_recommendations,
                requested_by=current_user.id,
            )

            # Convert to GraphQL type
            return ReportMapper.system_performance_to_graphql(performance_data)

        except ValidationError:
            raise
        except Exception as e:
            logger.error(f"System performance analysis failed: {e}", exc_info=True)
            raise ValidationError("Failed to analyze system performance")

    @strawberry.field(description="Get risk analytics and threat detection")
    @require_auth()
    @require_permission("audit.analytics.risk.read")
    @rate_limit(requests=20, window=60)
    @audit_log("audit.analytics.risk")
    @cache_result(ttl=300)
    async def get_risk_analytics(
        self, info: strawberry.Info, input: RiskAnalysisInput
    ) -> RiskAnalyticsType:
        """
        Analyze security risks and threat patterns.

        Features:
        - Risk scoring algorithms
        - Threat pattern detection
        - Vulnerability assessment
        - Risk trend analysis
        - Mitigation recommendations

        Args:
            input: Risk analysis parameters

        Returns:
            Comprehensive risk analytics and recommendations
        """
        try:
            # Validate input
            validation_errors = input.validate()
            if validation_errors:
                raise ValidationError(
                    f"Invalid risk analysis input: {'; '.join(validation_errors)}"
                )

            # Get reporting service
            reporting_service: ReportingService = info.context["container"].resolve(
                ReportingService
            )
            current_user = info.context.get("current_user")

            logger.info(
                "Analyzing security risks",
                user_id=str(current_user.id),
                risk_categories=input.risk_categories,
                include_threats=input.include_threat_analysis,
            )

            # Generate risk analytics
            risk_data = await reporting_service.analyze_security_risks(
                risk_categories=input.risk_categories,
                start_date=input.date_range.start_date,
                end_date=input.date_range.end_date,
                include_threat_analysis=input.include_threat_analysis,
                include_vulnerability_assessment=input.include_vulnerability_assessment,
                include_mitigation_recommendations=input.include_mitigation_recommendations,
                threat_intelligence_sources=input.threat_intelligence_sources,
                requested_by=current_user.id,
            )

            # Convert to GraphQL type
            return ReportMapper.risk_analytics_to_graphql(risk_data)

        except ValidationError:
            raise
        except Exception as e:
            logger.error(f"Risk analysis failed: {e}", exc_info=True)
            raise ValidationError("Failed to analyze risks")

    @strawberry.field(description="Get anomaly detection results")
    @require_auth()
    @require_permission("audit.analytics.anomalies.read")
    @rate_limit(requests=30, window=60)
    @audit_log("audit.analytics.anomalies")
    @cache_result(ttl=120)
    async def get_anomaly_detection(
        self,
        info: strawberry.Info,
        time_range: str = "24h",
        sensitivity: float = 0.95,
        include_ml_analysis: bool = True,
        include_context: bool = True,
    ) -> AnomalyDetectionType:
        """
        Get anomaly detection results from machine learning analysis.

        Features:
        - Statistical anomaly detection
        - Machine learning pattern analysis
        - Contextual anomaly identification
        - Severity scoring
        - Root cause analysis

        Args:
            time_range: Time period for anomaly detection
            sensitivity: Detection sensitivity (0.0-1.0)
            include_ml_analysis: Include ML-based analysis
            include_context: Include contextual information

        Returns:
            Detected anomalies with analysis and context
        """
        try:
            # Validate parameters
            if not 0.0 <= sensitivity <= 1.0:
                raise ValidationError("Sensitivity must be between 0.0 and 1.0")

            # Get reporting service
            reporting_service: ReportingService = info.context["container"].resolve(
                ReportingService
            )
            current_user = info.context.get("current_user")

            logger.info(
                "Detecting anomalies",
                user_id=str(current_user.id),
                time_range=time_range,
                sensitivity=sensitivity,
                include_ml=include_ml_analysis,
            )

            # Run anomaly detection
            anomaly_data = await reporting_service.detect_anomalies(
                time_range=time_range,
                sensitivity=sensitivity,
                include_ml_analysis=include_ml_analysis,
                include_context=include_context,
                user_scope=current_user.id
                if not current_user.has_permission("audit.analytics.anomalies.read_all")
                else None,
                requested_by=current_user.id,
            )

            # Convert to GraphQL type
            return ReportMapper.anomaly_detection_to_graphql(anomaly_data)

        except ValidationError:
            raise
        except Exception as e:
            logger.error(f"Anomaly detection failed: {e}", exc_info=True)
            raise ValidationError("Failed to detect anomalies")

    @strawberry.field(description="Get predictive analytics and forecasting")
    @require_auth()
    @require_permission("audit.analytics.predictions.read")
    @rate_limit(requests=10, window=60)
    @audit_log("audit.analytics.predictions")
    @cache_result(ttl=1800)  # Cache for 30 minutes
    @operation_timeout(60)
    async def get_predictive_analytics(
        self,
        info: strawberry.Info,
        metrics: list[str],
        forecast_period: str = "30d",
        confidence_level: float = 0.95,
        include_scenarios: bool = True,
    ) -> PredictiveAnalyticsType:
        """
        Generate predictive analytics and forecasting for audit metrics.

        Features:
        - Time series forecasting
        - Scenario modeling
        - Confidence intervals
        - Trend projections
        - Capacity planning

        Args:
            metrics: List of metrics to forecast
            forecast_period: Period for forecasting (e.g., "30d", "3m")
            confidence_level: Confidence level for predictions
            include_scenarios: Include scenario analysis

        Returns:
            Predictive analytics with forecasts and scenarios
        """
        try:
            # Validate parameters
            if not 0.5 <= confidence_level <= 0.99:
                raise ValidationError("Confidence level must be between 0.5 and 0.99")

            # Get reporting service
            reporting_service: ReportingService = info.context["container"].resolve(
                ReportingService
            )
            current_user = info.context.get("current_user")

            logger.info(
                "Generating predictive analytics",
                user_id=str(current_user.id),
                metrics=metrics,
                forecast_period=forecast_period,
                confidence_level=confidence_level,
            )

            # Generate predictions
            prediction_data = await reporting_service.generate_predictions(
                metrics=metrics,
                forecast_period=forecast_period,
                confidence_level=confidence_level,
                include_scenarios=include_scenarios,
                historical_period="90d",  # Use 90 days of history for predictions
                requested_by=current_user.id,
            )

            # Convert to GraphQL type
            return ReportMapper.predictive_analytics_to_graphql(prediction_data)

        except ValidationError:
            raise
        except Exception as e:
            logger.error(f"Predictive analytics failed: {e}", exc_info=True)
            raise ValidationError("Failed to generate predictions")

    @strawberry.field(description="Get custom analytics query results")
    @require_auth()
    @require_permission("audit.analytics.custom.read")
    @rate_limit(requests=20, window=300)  # 20 custom queries per 5 minutes
    @audit_log("audit.analytics.custom")
    @operation_timeout(120)
    async def get_custom_analytics(
        self,
        info: strawberry.Info,
        query_definition: dict[str, Any],
        cache_duration: int = 300,
    ) -> dict[str, Any]:
        """
        Execute custom analytics query with flexible parameters.

        Features:
        - Flexible query definition language
        - Custom aggregations and calculations
        - Dynamic filtering and grouping
        - Configurable caching
        - Export capabilities

        Args:
            query_definition: Custom query definition
            cache_duration: Cache duration in seconds

        Returns:
            Custom analytics results
        """
        try:
            # Validate query definition
            if not query_definition or "query_type" not in query_definition:
                raise ValidationError("Query definition must include query_type")

            # Get reporting service
            reporting_service: ReportingService = info.context["container"].resolve(
                ReportingService
            )
            current_user = info.context.get("current_user")

            # Security validation for custom queries
            if not self._validate_custom_query_security(query_definition, current_user):
                raise AuthorizationError(
                    "Custom query contains unauthorized operations"
                )

            logger.info(
                "Executing custom analytics query",
                user_id=str(current_user.id),
                query_type=query_definition.get("query_type"),
                cache_duration=cache_duration,
            )

            # Execute custom query
            result = await reporting_service.execute_custom_analytics(
                query_definition=query_definition,
                requested_by=current_user.id,
                cache_duration=cache_duration,
            )

            return {
                "query_id": result.query_id,
                "execution_time_ms": result.execution_time_ms,
                "result_count": result.result_count,
                "data": result.data,
                "metadata": result.metadata,
                "cached": result.from_cache,
            }

        except (ValidationError, AuthorizationError):
            raise
        except Exception as e:
            logger.error(f"Custom analytics query failed: {e}", exc_info=True)
            raise ValidationError("Failed to execute custom query")

    @strawberry.field(description="Get analytics performance benchmarks")
    @require_auth()
    @require_permission("audit.analytics.benchmarks.read")
    @rate_limit(requests=10, window=60)
    @cache_result(ttl=3600)  # Cache for 1 hour
    async def get_analytics_benchmarks(
        self,
        info: strawberry.Info,
        benchmark_type: str = "industry",
        include_historical: bool = True,
    ) -> dict[str, Any]:
        """
        Get analytics performance benchmarks for comparison.

        Features:
        - Industry benchmark comparisons
        - Historical performance trends
        - Peer organization comparisons
        - Best practice recommendations

        Args:
            benchmark_type: Type of benchmarks to retrieve
            include_historical: Include historical benchmark data

        Returns:
            Benchmark data for performance comparison
        """
        try:
            # Get reporting service
            reporting_service: ReportingService = info.context["container"].resolve(
                ReportingService
            )
            current_user = info.context.get("current_user")

            logger.info(
                "Retrieving analytics benchmarks",
                user_id=str(current_user.id),
                benchmark_type=benchmark_type,
                include_historical=include_historical,
            )

            # Get benchmark data
            benchmarks = await reporting_service.get_analytics_benchmarks(
                benchmark_type=benchmark_type,
                include_historical=include_historical,
                organization_context=current_user.organization_id,
                requested_by=current_user.id,
            )

            return {
                "benchmark_type": benchmark_type,
                "last_updated": benchmarks.last_updated.isoformat(),
                "metrics": benchmarks.metrics,
                "comparisons": benchmarks.comparisons,
                "recommendations": benchmarks.recommendations,
                "historical_data": benchmarks.historical_data
                if include_historical
                else None,
            }

        except Exception as e:
            logger.error(f"Benchmark retrieval failed: {e}", exc_info=True)
            raise ValidationError("Failed to retrieve benchmarks")

    # Helper methods
    def _validate_custom_query_security(
        self, query_definition: dict[str, Any], user
    ) -> bool:
        """Validate custom query for security compliance."""
        # Check for dangerous operations
        dangerous_operations = ["DELETE", "DROP", "ALTER", "EXEC", "SYSTEM"]
        query_text = str(query_definition).upper()

        for operation in dangerous_operations:
            if operation in query_text:
                logger.warning(
                    "Dangerous operation detected in custom query",
                    user_id=str(user.id),
                    operation=operation,
                )
                return False

        # Check for required permissions based on query type
        query_type = query_definition.get("query_type", "").lower()

        if query_type == "user_data" and not user.has_permission(
            "audit.analytics.user_data.read"
        ):
            return False

        return not (
            query_type == "system_data"
            and not user.has_permission("audit.analytics.system_data.read")
        )
