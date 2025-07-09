"""
Check permission query implementation.

Handles permission checking for users against specific resources and actions.
"""

from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum
from typing import Any
from uuid import UUID

from app.core.cqrs import Query, QueryHandler
from app.core.infrastructure import UnitOfWork
from app.modules.identity.application.decorators import rate_limit, validate_request
from app.modules.identity.application.dtos.response import PermissionCheckResponse
from app.modules.identity.domain.enums import AccessDecision
from app.modules.identity.domain.interfaces.repositories.user_repository import (
from app.modules.identity.domain.interfaces.services import (
    IAuthorizationRepository,
    IPolicyRepository,
)
    IUserRepository,
)


class PermissionContext(Enum):
    """Context for permission evaluation."""
    DIRECT = "direct"
    ROLE_BASED = "role_based"
    POLICY_BASED = "policy_based"
    INHERITED = "inherited"


@dataclass
class CheckPermissionQuery(Query[PermissionCheckResponse]):
    """Query to check user permissions."""
    
    user_id: UUID
    permission: str
    resource: str | None = None
    action: str | None = None
    context: dict[str, Any] | None = None
    include_reasoning: bool = False
    requester_id: UUID | None = None


class CheckPermissionQueryHandler(QueryHandler[CheckPermissionQuery, PermissionCheckResponse]):
    """Handler for permission check queries."""
    
    def __init__(
        self,
        uow: UnitOfWork,
        user_repository: IUserRepository,
        authorization_repository: IAuthorizationRepository,
        policy_repository: IPolicyRepository
    ):
        self.uow = uow
        self.user_repository = user_repository
        self.authorization_repository = authorization_repository
        self.policy_repository = policy_repository
    
    @rate_limit(max_calls=1000, window_seconds=3600)
    @validate_request
    async def handle(self, query: CheckPermissionQuery) -> PermissionCheckResponse:
        """Handle permission check query."""
        
        async with self.uow:
            # Get user
            user = await self.user_repository.find_by_id(query.user_id)
            if not user:
                return PermissionCheckResponse(
                    user_id=query.user_id,
                    permission=query.permission,
                    resource=query.resource,
                    action=query.action,
                    decision=AccessDecision.DENY,
                    reason="User not found",
                    checked_at=datetime.now(UTC)
                )
            
            # Check direct permission
            direct_access = await self._check_direct_permission(user, query)
            if direct_access["granted"]:
                return self._build_response(query, AccessDecision.ALLOW, "Direct permission", direct_access)
            
            # Check role-based permission
            role_access = await self._check_role_permission(user, query)
            if role_access["granted"]:
                return self._build_response(query, AccessDecision.ALLOW, "Role-based permission", role_access)
            
            # Check policy-based permission
            policy_access = await self._check_policy_permission(user, query)
            if policy_access["granted"]:
                return self._build_response(query, AccessDecision.ALLOW, "Policy-based permission", policy_access)
            
            # Default deny
            return self._build_response(query, AccessDecision.DENY, "No matching permissions", {})
    
    async def _check_direct_permission(self, user, query: CheckPermissionQuery) -> dict[str, Any]:
        """Check direct user permissions."""
        
        user_permissions = getattr(user, 'permissions', [])
        granted = query.permission in user_permissions
        
        return {
            "granted": granted,
            "context": PermissionContext.DIRECT,
            "source": "user_permissions",
            "matched_permission": query.permission if granted else None
        }
    
    async def _check_role_permission(self, user, query: CheckPermissionQuery) -> dict[str, Any]:
        """Check role-based permissions."""
        
        for role in user.roles:
            role_permissions = await self.user_repository.find_by_role(role)
            if query.permission in role_permissions:
                return {
                    "granted": True,
                    "context": PermissionContext.ROLE_BASED,
                    "source": f"role:{role}",
                    "matched_permission": query.permission
                }
        
        return {"granted": False}
    
    async def _check_policy_permission(self, user, query: CheckPermissionQuery) -> dict[str, Any]:
        """Check policy-based permissions."""
        
        policies = await self.policy_repository.get_applicable_policies(
            user_id=query.user_id,
            resource=query.resource,
            action=query.action
        )
        
        for policy in policies:
            decision = await self._evaluate_policy(policy, user, query)
            if decision["granted"]:
                return decision
        
        return {"granted": False}
    
    async def _evaluate_policy(self, policy: dict[str, Any], user, query: CheckPermissionQuery) -> dict[str, Any]:
        """Evaluate a specific policy."""
        
        # Simplified policy evaluation - in reality this would be more complex
        policy_rules = policy.get("rules", [])
        
        for rule in policy_rules:
            if self._rule_matches(rule, query):
                if rule.get("effect") == "allow":
                    return {
                        "granted": True,
                        "context": PermissionContext.POLICY_BASED,
                        "source": f"policy:{policy.get('id')}",
                        "matched_rule": rule.get("id")
                    }
        
        return {"granted": False}
    
    def _rule_matches(self, rule: dict[str, Any], query: CheckPermissionQuery) -> bool:
        """Check if a rule matches the query."""
        
        # Check permission match
        rule_permissions = rule.get("permissions", [])
        if query.permission not in rule_permissions and "*" not in rule_permissions:
            return False
        
        # Check resource match
        if query.resource and rule.get("resources"):
            rule_resources = rule.get("resources", [])
            if query.resource not in rule_resources and "*" not in rule_resources:
                return False
        
        # Check action match
        if query.action and rule.get("actions"):
            rule_actions = rule.get("actions", [])
            if query.action not in rule_actions and "*" not in rule_actions:
                return False
        
        return True
    
    def _build_response(
        self,
        query: CheckPermissionQuery,
        decision: AccessDecision,
        reason: str,
        access_info: dict[str, Any]
    ) -> PermissionCheckResponse:
        """Build permission check response."""
        
        reasoning = None
        if query.include_reasoning:
            reasoning = {
                "decision_path": [access_info.get("context", "unknown")],
                "matched_rules": [access_info.get("matched_permission")] if access_info.get("matched_permission") else [],
                "evaluation_steps": [reason]
            }
        
        return PermissionCheckResponse(
            user_id=query.user_id,
            permission=query.permission,
            resource=query.resource,
            action=query.action,
            decision=decision,
            reason=reason,
            reasoning=reasoning,
            checked_at=datetime.now(UTC)
        )