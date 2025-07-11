"""
Identity federation command implementation.

Handles identity federation across multiple identity providers and systems.
"""

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import Any
from uuid import UUID

from app.core.cqrs import Command, CommandHandler
from app.core.events import EventBus
from app.core.infrastructure import UnitOfWork
from app.modules.identity.application.decorators import (
    audit_action,
    rate_limit,
    require_permission,
    validate_request,
)
from app.modules.identity.application.dtos.internal import (
    AuditContext,
    NotificationContext,
)
from app.modules.identity.application.dtos.request import IdentityFederationRequest
from app.modules.identity.application.dtos.response import IdentityFederationResponse
from app.modules.identity.domain.enums import (
    AuditAction,
    ConflictResolution,
    FederationStatus,
    FederationType,
    NotificationType,
)
from app.modules.identity.domain.events import IdentityFederated
from app.modules.identity.domain.exceptions import (
    FederationValidationError,
    IdentityFederationError,
    ProviderConfigurationError,
)
from app.modules.identity.domain.interfaces.repositories.user_repository import (
    IUserRepository,
)
from app.modules.identity.domain.interfaces.services.communication.notification_service import (
    IEmailService,
    INotificationService,
)
from app.modules.identity.domain.services import (
from app.modules.identity.domain.interfaces.services import (
    IAuditService,
)
    MatchingService,
    MergeService,
    SecurityService,
    ValidationService,
)


class FederationMode(Enum):
    """Mode of identity federation operation."""
    AUTOMATIC = "automatic"
    MANUAL = "manual"
    ASSISTED = "assisted"
    APPROVAL_REQUIRED = "approval_required"


class MatchingCriteria(Enum):
    """Criteria used for identity matching."""
    EMAIL = "email"
    USERNAME = "username"
    PHONE = "phone"
    EMPLOYEE_ID = "employee_id"
    SSN = "ssn"
    CUSTOM_ATTRIBUTE = "custom_attribute"
    FUZZY_NAME = "fuzzy_name"
    MULTIPLE_FACTORS = "multiple_factors"


@dataclass
class FederationRule:
    """Rule for identity federation behavior."""
    source_provider: str
    target_provider: str
    matching_criteria: list[MatchingCriteria]
    matching_threshold: float = 0.8
    conflict_resolution: ConflictResolution = ConflictResolution.MANUAL_REVIEW
    auto_approve: bool = False
    require_verification: bool = True
    merge_attributes: bool = True
    priority: int = 1


@dataclass
class IdentityMatch:
    """Result of identity matching operation."""
    source_identity_id: UUID
    target_identity_id: UUID
    confidence_score: float
    matching_attributes: list[str]
    conflicting_attributes: list[str]
    suggested_action: str


class IdentityFederationCommand(Command[IdentityFederationResponse]):
    """Command to handle identity federation operations."""
    
    def __init__(
        self,
        operation_type: str,  # "federate", "link", "unlink", "resolve_conflict", "bulk_federate"
        source_identity_id: UUID | None = None,
        target_identity_id: UUID | None = None,
        source_provider: str | None = None,
        target_provider: str | None = None,
        federation_rule_id: UUID | None = None,
        federation_mode: FederationMode = FederationMode.MANUAL,
        matching_criteria: list[MatchingCriteria] | None = None,
        matching_threshold: float = 0.8,
        conflict_resolution: ConflictResolution = ConflictResolution.MANUAL_REVIEW,
        auto_merge_attributes: bool = True,
        preserve_source_identity: bool = True,
        require_user_approval: bool = False,
        send_notifications: bool = True,
        verify_before_federation: bool = True,
        federation_metadata: dict[str, Any] | None = None,
        custom_matching_attributes: dict[str, Any] | None = None,
        batch_identities: list[UUID] | None = None,
        batch_size: int = 100,
        dry_run: bool = False,
        force_federation: bool = False,
        rollback_on_error: bool = True,
        audit_detailed: bool = True,
        initiated_by: UUID | None = None,
        metadata: dict[str, Any] | None = None
    ):
        self.operation_type = operation_type
        self.source_identity_id = source_identity_id
        self.target_identity_id = target_identity_id
        self.source_provider = source_provider
        self.target_provider = target_provider
        self.federation_rule_id = federation_rule_id
        self.federation_mode = federation_mode
        self.matching_criteria = matching_criteria or [MatchingCriteria.EMAIL]
        self.matching_threshold = matching_threshold
        self.conflict_resolution = conflict_resolution
        self.auto_merge_attributes = auto_merge_attributes
        self.preserve_source_identity = preserve_source_identity
        self.require_user_approval = require_user_approval
        self.send_notifications = send_notifications
        self.verify_before_federation = verify_before_federation
        self.federation_metadata = federation_metadata or {}
        self.custom_matching_attributes = custom_matching_attributes or {}
        self.batch_identities = batch_identities or []
        self.batch_size = batch_size
        self.dry_run = dry_run
        self.force_federation = force_federation
        self.rollback_on_error = rollback_on_error
        self.audit_detailed = audit_detailed
        self.initiated_by = initiated_by
        self.metadata = metadata or {}


class IdentityFederationCommandHandler(CommandHandler[IdentityFederationCommand, IdentityFederationResponse]):
    """Handler for identity federation operations."""
    
    def __init__(
        self,
        user_repository: IUserRepository,
        federation_repository: IFederationRepository,
        identity_repository: IIdentityRepository,
        provider_repository: IProviderRepository,
        validation_service: ValidationService,
        security_service: SecurityService,
        matching_service: MatchingService,
        merge_service: MergeService,
        notification_service: INotificationService,
        audit_service: IAuditService,
        email_service: IEmailService,
        event_bus: EventBus,
        unit_of_work: UnitOfWork
    ):
        self._user_repository = user_repository
        self._federation_repository = federation_repository
        self._identity_repository = identity_repository
        self._provider_repository = provider_repository
        self._validation_service = validation_service
        self._security_service = security_service
        self._matching_service = matching_service
        self._merge_service = merge_service
        self._notification_service = notification_service
        self._audit_service = audit_service
        self._email_service = email_service
        self._event_bus = event_bus
        self._unit_of_work = unit_of_work
    
    @audit_action(
        action=AuditAction.IDENTITY_FEDERATION,
        resource_type="identity_federation",
        include_request=True,
        include_response=True
    )
    @validate_request(IdentityFederationRequest)
    @rate_limit(
        max_requests=100,
        window_seconds=3600,
        strategy='user'
    )
    @require_permission("integrations.federation.manage")
    async def handle(self, command: IdentityFederationCommand) -> IdentityFederationResponse:
        """
        Handle identity federation operations.
        
        Supports multiple operations:
        - federate: Automatically federate identities based on rules
        - link: Manually link two specific identities
        - unlink: Remove federation between identities
        - resolve_conflict: Resolve federation conflicts
        - bulk_federate: Federate multiple identities in batch
        
        Returns:
            IdentityFederationResponse with operation results
        """
        async with self._unit_of_work:
            # Route to appropriate handler based on operation type
            if command.operation_type == "federate":
                return await self._handle_identity_federation(command)
            if command.operation_type == "link":
                return await self._handle_identity_linking(command)
            if command.operation_type == "unlink":
                return await self._handle_identity_unlinking(command)
            if command.operation_type == "resolve_conflict":
                return await self._handle_conflict_resolution(command)
            if command.operation_type == "bulk_federate":
                return await self._handle_bulk_federation(command)
            raise FederationValidationError(f"Unsupported operation type: {command.operation_type}")
    
    async def _handle_identity_federation(self, command: IdentityFederationCommand) -> IdentityFederationResponse:
        """Handle automatic identity federation based on rules."""
        # 1. Load federation rule if specified
        federation_rule = None
        if command.federation_rule_id:
            federation_rule = await self._federation_repository.get_rule_by_id(command.federation_rule_id)
            if not federation_rule:
                raise ProviderConfigurationError(f"Federation rule {command.federation_rule_id} not found")
        
        # 2. Load source identity
        source_identity = await self._identity_repository.find_by_id(command.source_identity_id)
        if not source_identity:
            raise IdentityFederationError(f"Source identity {command.source_identity_id} not found")
        
        # 3. Find potential matches using configured criteria
        potential_matches = await self._find_identity_matches(
            source_identity,
            command.matching_criteria,
            command.target_provider,
            command.matching_threshold,
            federation_rule
        )
        
        if not potential_matches:
            return IdentityFederationResponse(
                success=True,
                operation_type="federate",
                source_identity_id=command.source_identity_id,
                matches_found=0,
                federations_created=0,
                message="No matching identities found for federation"
            )
        
        # 4. Process matches based on federation mode
        federation_results = []
        
        for match in potential_matches:
            try:
                if command.federation_mode == FederationMode.AUTOMATIC and match.confidence_score >= command.matching_threshold:
                    # Automatic federation for high-confidence matches
                    result = await self._create_federation(
                        source_identity,
                        match,
                        federation_rule,
                        command
                    )
                    federation_results.append(result)
                
                elif command.federation_mode == FederationMode.MANUAL:
                    # Queue for manual review
                    await self._queue_for_manual_review(
                        source_identity,
                        match,
                        federation_rule,
                        command
                    )
                
                elif command.federation_mode == FederationMode.ASSISTED:
                    # Provide recommendations but require approval
                    await self._create_federation_recommendation(
                        source_identity,
                        match,
                        federation_rule,
                        command
                    )
                
                elif command.federation_mode == FederationMode.APPROVAL_REQUIRED:
                    # Require explicit approval even for high-confidence matches
                    await self._request_federation_approval(
                        source_identity,
                        match,
                        federation_rule,
                        command
                    )
                    
            except Exception as e:
                if command.rollback_on_error:
                    raise
                await self._audit_service.log_error(
                    f"Federation failed for match {match.target_identity_id}: {e!s}"
                )
        
        # 5. Log federation operation
        await self._log_federation_operation(source_identity, potential_matches, federation_results, command)
        
        # 6. Send notifications if enabled
        if command.send_notifications and federation_results:
            await self._send_federation_notifications(source_identity, federation_results, command)
        
        # 7. Publish domain event
        await self._event_bus.publish(
            IdentityFederated(
                aggregate_id=source_identity.id,
                source_identity_id=source_identity.id,
                target_identities=[r["target_identity_id"] for r in federation_results],
                federation_method="automatic",
                confidence_scores=[r["confidence_score"] for r in federation_results],
                federated_by=command.initiated_by
            )
        )
        
        # 8. Commit transaction
        await self._unit_of_work.commit()
        
        # 9. Generate response
        return IdentityFederationResponse(
            success=True,
            operation_type="federate",
            source_identity_id=command.source_identity_id,
            matches_found=len(potential_matches),
            federations_created=len(federation_results),
            federation_results=federation_results,
            pending_reviews=len(potential_matches) - len(federation_results),
            dry_run=command.dry_run,
            message=f"Identity federation completed: {len(federation_results)} federations created"
        )
    
    async def _find_identity_matches(
        self,
        source_identity: Any,
        matching_criteria: list[MatchingCriteria],
        target_provider: str | None,
        threshold: float,
        federation_rule: FederationRule | None
    ) -> list[IdentityMatch]:
        """Find potential identity matches using specified criteria."""
        matches = []
        
        # Build search criteria based on matching strategy
        search_criteria = {}
        
        for criterion in matching_criteria:
            if criterion == MatchingCriteria.EMAIL and source_identity.email:
                search_criteria["email"] = source_identity.email
            elif criterion == MatchingCriteria.USERNAME and source_identity.username:
                search_criteria["username"] = source_identity.username
            elif criterion == MatchingCriteria.PHONE and source_identity.phone_number:
                search_criteria["phone"] = source_identity.phone_number
            elif criterion == MatchingCriteria.EMPLOYEE_ID and hasattr(source_identity, 'employee_id'):
                search_criteria["employee_id"] = source_identity.employee_id
        
        # Find candidate identities
        candidates = await self._identity_repository.find_by_criteria(
            search_criteria,
            provider=target_provider
        )
        
        # Score and evaluate matches
        for candidate in candidates:
            if candidate.id == source_identity.id:
                continue  # Skip self-matches
            
            match_score = await self._calculate_match_score(
                source_identity,
                candidate,
                matching_criteria
            )
            
            if match_score >= threshold:
                # Identify matching and conflicting attributes
                matching_attrs, conflicting_attrs = await self._analyze_attribute_compatibility(
                    source_identity,
                    candidate
                )
                
                match = IdentityMatch(
                    source_identity_id=source_identity.id,
                    target_identity_id=candidate.id,
                    confidence_score=match_score,
                    matching_attributes=matching_attrs,
                    conflicting_attributes=conflicting_attrs,
                    suggested_action="federate" if match_score > 0.9 else "review"
                )
                
                matches.append(match)
        
        # Sort by confidence score descending
        matches.sort(key=lambda x: x.confidence_score, reverse=True)
        
        return matches
    
    async def _calculate_match_score(
        self,
        source_identity: Any,
        candidate_identity: Any,
        matching_criteria: list[MatchingCriteria]
    ) -> float:
        """Calculate match confidence score between two identities."""
        total_score = 0.0
        total_weight = 0.0
        
        # Define weights for different matching criteria
        weights = {
            MatchingCriteria.EMAIL: 0.4,
            MatchingCriteria.USERNAME: 0.2,
            MatchingCriteria.PHONE: 0.2,
            MatchingCriteria.EMPLOYEE_ID: 0.3,
            MatchingCriteria.SSN: 0.5,
            MatchingCriteria.FUZZY_NAME: 0.1
        }
        
        for criterion in matching_criteria:
            weight = weights.get(criterion, 0.1)
            total_weight += weight
            
            if criterion == MatchingCriteria.EMAIL:
                if (source_identity.email and candidate_identity.email and 
                    source_identity.email.lower() == candidate_identity.email.lower()):
                    total_score += weight
            
            elif criterion == MatchingCriteria.USERNAME:
                if (source_identity.username and candidate_identity.username and 
                    source_identity.username.lower() == candidate_identity.username.lower()):
                    total_score += weight
            
            elif criterion == MatchingCriteria.PHONE:
                if (source_identity.phone_number and candidate_identity.phone_number and 
                    self._normalize_phone(source_identity.phone_number) == 
                    self._normalize_phone(candidate_identity.phone_number)):
                    total_score += weight
            
            elif criterion == MatchingCriteria.FUZZY_NAME:
                name_score = await self._calculate_fuzzy_name_match(
                    source_identity.full_name,
                    candidate_identity.full_name
                )
                total_score += weight * name_score
        
        return total_score / total_weight if total_weight > 0 else 0.0
    
    def _normalize_phone(self, phone: str) -> str:
        """Normalize phone number for comparison."""
        if not phone:
            return ""
        
        # Remove all non-digit characters
        normalized = ''.join(c for c in phone if c.isdigit())
        
        # Handle US phone numbers
        if len(normalized) == 10:
            return f"+1{normalized}"
        if len(normalized) == 11 and normalized.startswith('1'):
            return f"+{normalized}"
        
        return normalized
    
    async def _calculate_fuzzy_name_match(self, name1: str | None, name2: str | None) -> float:
        """Calculate fuzzy match score for names."""
        if not name1 or not name2:
            return 0.0
        
        # Simple implementation - in production use libraries like fuzzywuzzy
        name1_clean = name1.lower().strip()
        name2_clean = name2.lower().strip()
        
        if name1_clean == name2_clean:
            return 1.0
        
        # Calculate Levenshtein distance ratio
        from difflib import SequenceMatcher
        return SequenceMatcher(None, name1_clean, name2_clean).ratio()
    
    async def _analyze_attribute_compatibility(
        self,
        source_identity: Any,
        candidate_identity: Any
    ) -> tuple[list[str], list[str]]:
        """Analyze which attributes match and which conflict."""
        matching_attributes = []
        conflicting_attributes = []
        
        # Define attributes to check
        attributes_to_check = [
            'email', 'username', 'phone_number', 'first_name', 'last_name',
            'date_of_birth', 'employee_id', 'department'
        ]
        
        for attr in attributes_to_check:
            source_value = getattr(source_identity, attr, None)
            candidate_value = getattr(candidate_identity, attr, None)
            
            if source_value and candidate_value:
                if source_value == candidate_value:
                    matching_attributes.append(attr)
                else:
                    conflicting_attributes.append(attr)
        
        return matching_attributes, conflicting_attributes
    
    async def _create_federation(
        self,
        source_identity: Any,
        match: IdentityMatch,
        federation_rule: FederationRule | None,
        command: IdentityFederationCommand
    ) -> dict[str, Any]:
        """Create identity federation between matched identities."""
        if command.dry_run:
            return {
                "success": True,
                "action": "federation_created",
                "source_identity_id": source_identity.id,
                "target_identity_id": match.target_identity_id,
                "confidence_score": match.confidence_score,
                "dry_run": True
            }
        
        # Load target identity
        target_identity = await self._identity_repository.find_by_id(match.target_identity_id)
        
        # Check for existing federation
        existing_federation = await self._federation_repository.find_federation(
            source_identity.id,
            target_identity.id
        )
        
        if existing_federation and not command.force_federation:
            return {
                "success": False,
                "error": "Federation already exists",
                "source_identity_id": source_identity.id,
                "target_identity_id": match.target_identity_id,
                "existing_federation_id": existing_federation.id
            }
        
        # Create federation record
        federation_data = {
            "id": UUID(),
            "source_identity_id": source_identity.id,
            "target_identity_id": target_identity.id,
            "federation_type": FederationType.IDENTITY_LINKING,
            "status": FederationStatus.ACTIVE,
            "confidence_score": match.confidence_score,
            "matching_attributes": match.matching_attributes,
            "conflicting_attributes": match.conflicting_attributes,
            "federation_rule_id": federation_rule.id if federation_rule else None,
            "created_at": datetime.now(UTC),
            "created_by": command.initiated_by,
            "metadata": {
                "federation_mode": command.federation_mode.value,
                "matching_criteria": [c.value for c in command.matching_criteria],
                "auto_merged": command.auto_merge_attributes,
                **command.federation_metadata
            }
        }
        
        federation = await self._federation_repository.create(federation_data)
        
        # Merge attributes if enabled
        merge_result = None
        if command.auto_merge_attributes:
            merge_result = await self._merge_identity_attributes(
                source_identity,
                target_identity,
                match.conflicting_attributes,
                command.conflict_resolution
            )
        
        # Verify federation if required
        if command.verify_before_federation:
            verification_result = await self._verify_federation(federation, command)
            if not verification_result["success"]:
                # Rollback federation
                await self._federation_repository.delete(federation.id)
                return {
                    "success": False,
                    "error": f"Federation verification failed: {verification_result['error']}",
                    "source_identity_id": source_identity.id,
                    "target_identity_id": match.target_identity_id
                }
        
        return {
            "success": True,
            "action": "federation_created",
            "federation_id": federation.id,
            "source_identity_id": source_identity.id,
            "target_identity_id": match.target_identity_id,
            "confidence_score": match.confidence_score,
            "merge_result": merge_result
        }
    
    async def _merge_identity_attributes(
        self,
        source_identity: Any,
        target_identity: Any,
        conflicting_attributes: list[str],
        conflict_resolution: ConflictResolution
    ) -> dict[str, Any]:
        """Merge attributes from source identity to target identity."""
        merge_decisions = {}
        
        for attr in conflicting_attributes:
            source_value = getattr(source_identity, attr, None)
            target_value = getattr(target_identity, attr, None)
            
            if conflict_resolution == ConflictResolution.SOURCE_WINS:
                merge_decisions[attr] = {
                    "chosen_value": source_value,
                    "discarded_value": target_value,
                    "reason": "source_priority"
                }
            elif conflict_resolution == ConflictResolution.TARGET_WINS:
                merge_decisions[attr] = {
                    "chosen_value": target_value,
                    "discarded_value": source_value,
                    "reason": "target_priority"
                }
            elif conflict_resolution == ConflictResolution.MOST_RECENT:
                # Use the most recently updated value
                source_updated = getattr(source_identity, 'updated_at', source_identity.created_at)
                target_updated = getattr(target_identity, 'updated_at', target_identity.created_at)
                
                if source_updated > target_updated:
                    chosen_value, discarded_value = source_value, target_value
                else:
                    chosen_value, discarded_value = target_value, source_value
                
                merge_decisions[attr] = {
                    "chosen_value": chosen_value,
                    "discarded_value": discarded_value,
                    "reason": "most_recent"
                }
            else:
                # Manual review required
                merge_decisions[attr] = {
                    "chosen_value": None,
                    "source_value": source_value,
                    "target_value": target_value,
                    "reason": "manual_review_required"
                }
        
        # Apply merge decisions
        for attr, decision in merge_decisions.items():
            if decision["chosen_value"] is not None:
                setattr(target_identity, attr, decision["chosen_value"])
        
        # Update target identity
        if any(d["chosen_value"] is not None for d in merge_decisions.values()):
            await self._identity_repository.update(target_identity)
        
        return {
            "attributes_merged": len([d for d in merge_decisions.values() if d["chosen_value"] is not None]),
            "manual_review_required": len([d for d in merge_decisions.values() if d["chosen_value"] is None]),
            "merge_decisions": merge_decisions
        }
    
    async def _verify_federation(self, federation: Any, command: IdentityFederationCommand) -> dict[str, Any]:
        """Verify that the federation is valid and secure."""
        verification_checks = []
        
        # Check for suspicious federation patterns
        recent_federations = await self._federation_repository.find_recent_federations(
            federation.source_identity_id,
            hours=24
        )
        
        if len(recent_federations) > 5:
            verification_checks.append({
                "check": "rapid_federation_rate",
                "result": "warning",
                "message": "High rate of recent federations detected"
            })
        
        # Check identity provider trust levels
        source_provider = await self._provider_repository.get_by_identity_id(federation.source_identity_id)
        target_provider = await self._provider_repository.get_by_identity_id(federation.target_identity_id)
        
        if source_provider and source_provider.trust_level == "low":
            verification_checks.append({
                "check": "source_provider_trust",
                "result": "warning",
                "message": "Source provider has low trust level"
            })
        
        if target_provider and target_provider.trust_level == "low":
            verification_checks.append({
                "check": "target_provider_trust",
                "result": "warning",
                "message": "Target provider has low trust level"
            })
        
        # Determine overall verification result
        has_failures = any(check["result"] == "failure" for check in verification_checks)
        has_warnings = any(check["result"] == "warning" for check in verification_checks)
        
        return {
            "success": not has_failures,
            "has_warnings": has_warnings,
            "checks": verification_checks,
            "recommendation": "approve" if not has_failures and not has_warnings else "review"
        }
    
    async def _queue_for_manual_review(
        self,
        source_identity: Any,
        match: IdentityMatch,
        federation_rule: FederationRule | None,
        command: IdentityFederationCommand
    ) -> None:
        """Queue identity match for manual review."""
        review_data = {
            "id": UUID(),
            "source_identity_id": source_identity.id,
            "target_identity_id": match.target_identity_id,
            "confidence_score": match.confidence_score,
            "matching_attributes": match.matching_attributes,
            "conflicting_attributes": match.conflicting_attributes,
            "suggested_action": match.suggested_action,
            "federation_rule_id": federation_rule.id if federation_rule else None,
            "review_status": "pending",
            "created_at": datetime.now(UTC),
            "created_by": command.initiated_by
        }
        
        await self._federation_repository.create_review_item(review_data)
    
    async def _create_federation_recommendation(
        self,
        source_identity: Any,
        match: IdentityMatch,
        federation_rule: FederationRule | None,
        command: IdentityFederationCommand
    ) -> None:
        """Create federation recommendation for assisted mode."""
        recommendation_data = {
            "id": UUID(),
            "source_identity_id": source_identity.id,
            "target_identity_id": match.target_identity_id,
            "confidence_score": match.confidence_score,
            "recommendation_type": "federation",
            "justification": f"High confidence match ({match.confidence_score:.2f}) based on {', '.join(match.matching_attributes)}",
            "estimated_impact": "low",
            "created_at": datetime.now(UTC),
            "created_by": command.initiated_by
        }
        
        await self._federation_repository.create_recommendation(recommendation_data)
    
    async def _request_federation_approval(
        self,
        source_identity: Any,
        match: IdentityMatch,
        federation_rule: FederationRule | None,
        command: IdentityFederationCommand
    ) -> None:
        """Request explicit approval for federation."""
        approval_data = {
            "id": UUID(),
            "source_identity_id": source_identity.id,
            "target_identity_id": match.target_identity_id,
            "confidence_score": match.confidence_score,
            "approval_status": "pending",
            "requested_at": datetime.now(UTC),
            "requested_by": command.initiated_by,
            "expires_at": datetime.now(UTC) + timedelta(days=7)
        }
        
        await self._federation_repository.create_approval_request(approval_data)
    
    async def _send_federation_notifications(
        self,
        source_identity: Any,
        federation_results: list[dict[str, Any]],
        command: IdentityFederationCommand
    ) -> None:
        """Send notifications about federation results."""
        # In-app notification
        await self._notification_service.create_notification(
            NotificationContext(
                notification_id=UUID(),
                recipient_id=command.initiated_by,
                notification_type=NotificationType.IDENTITY_FEDERATED,
                channel="in_app",
                template_id="identity_federation_complete",
                template_data={
                    "source_identity_id": str(source_identity.id),
                    "federations_created": len(federation_results),
                    "federated_at": datetime.now(UTC).isoformat()
                },
                priority="medium"
            )
        )
    
    async def _log_federation_operation(
        self,
        source_identity: Any,
        potential_matches: list[IdentityMatch],
        federation_results: list[dict[str, Any]],
        command: IdentityFederationCommand
    ) -> None:
        """Log identity federation operation."""
        await self._audit_service.log_action(
            AuditContext(
                action=AuditAction.IDENTITY_FEDERATION_COMPLETED,
                actor_id=command.initiated_by,
                resource_type="identity_federation",
                resource_id=source_identity.id,
                details={
                    "operation_type": command.operation_type,
                    "federation_mode": command.federation_mode.value,
                    "matching_criteria": [c.value for c in command.matching_criteria],
                    "potential_matches": len(potential_matches),
                    "federations_created": len(federation_results),
                    "dry_run": command.dry_run,
                    "auto_merge_enabled": command.auto_merge_attributes
                },
                risk_level="low" if len(federation_results) <= 3 else "medium"
            )
        )
    
    async def _handle_identity_linking(self, command: IdentityFederationCommand) -> IdentityFederationResponse:
        """Handle manual identity linking."""
        # Implementation for manual identity linking
        raise NotImplementedError("Manual identity linking not yet implemented")
    
    async def _handle_identity_unlinking(self, command: IdentityFederationCommand) -> IdentityFederationResponse:
        """Handle identity unlinking."""
        # Implementation for identity unlinking
        raise NotImplementedError("Identity unlinking not yet implemented")
    
    async def _handle_conflict_resolution(self, command: IdentityFederationCommand) -> IdentityFederationResponse:
        """Handle federation conflict resolution."""
        # Implementation for conflict resolution
        raise NotImplementedError("Conflict resolution not yet implemented")
    
    async def _handle_bulk_federation(self, command: IdentityFederationCommand) -> IdentityFederationResponse:
        """Handle bulk identity federation."""
        # Implementation for bulk federation
        raise NotImplementedError("Bulk federation not yet implemented")