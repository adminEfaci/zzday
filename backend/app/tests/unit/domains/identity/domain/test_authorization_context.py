"""
Test cases for AuthorizationContext value object.

Tests all aspects of authorization context including validation,
factors detection, decision making, and audit functionality.
"""

from dataclasses import FrozenInstanceError
from datetime import UTC, datetime

import pytest

from app.modules.identity.domain.value_objects.authorization_context import (
    AuthorizationContext,
    AuthorizationDecision,
    AuthorizationFactor,
)


class TestAuthorizationContextCreation:
    """Test AuthorizationContext creation and validation."""

    def test_create_valid_context(self):
        """Test creating a valid authorization context."""
        context = AuthorizationContext(
            user_id="user-123",
            action="read",
            resource_type="document",
            resource_id="doc-456",
            user_roles=["editor", "viewer"],
            user_permissions={"read_document", "write_document"},
            group_memberships=["team-alpha", "team-beta"],
            session_id="session-789",
            mfa_verified=True,
            device_trusted=True,
            ip_address="192.168.1.1",
            location_country="US",
            risk_level="low",
        )

        assert context.user_id == "user-123"
        assert context.action == "read"
        assert context.resource_type == "document"
        assert context.resource_id == "doc-456"
        assert "editor" in context.user_roles
        assert "read_document" in context.user_permissions
        assert "team-alpha" in context.group_memberships
        assert context.mfa_verified is True
        assert context.device_trusted is True
        assert context.risk_level == "low"

    def test_minimal_context(self):
        """Test creating context with minimal required fields."""
        context = AuthorizationContext(
            user_id="user-123", action="read", resource_type="document"
        )

        assert context.user_id == "user-123"
        assert context.action == "read"
        assert context.resource_type == "document"
        assert context.resource_id is None
        assert context.user_roles == []
        assert context.user_permissions == set()
        assert context.mfa_verified is False

    def test_invalid_context(self):
        """Test validation of invalid contexts."""
        # Missing user ID
        with pytest.raises(ValueError, match="User ID is required"):
            AuthorizationContext(user_id="", action="read", resource_type="document")

        # Missing action
        with pytest.raises(ValueError, match="Action is required"):
            AuthorizationContext(
                user_id="user-123", action="", resource_type="document"
            )

        # Missing resource type
        with pytest.raises(ValueError, match="Resource type is required"):
            AuthorizationContext(user_id="user-123", action="read", resource_type="")


class TestAuthorizationFactors:
    """Test authorization factor detection and analysis."""

    def test_factor_detection(self):
        """Test detection of all authorization factors."""
        context = AuthorizationContext(
            user_id="user-123",
            action="write",
            resource_type="document",
            user_roles=["editor"],
            user_permissions={"write_document"},
            group_memberships=["writers"],
            mfa_verified=True,
            device_id="device-456",
            device_trusted=True,
            ip_address="192.168.1.1",
            location_country="US",
            risk_level="low",
            request_time=datetime.now(UTC),
            delegation_from="admin-789",
            emergency_access=True,
            compliance_flags={"gdpr_compliant": True},
        )

        factors = context.get_factors()

        assert AuthorizationFactor.USER_ROLE in factors
        assert AuthorizationFactor.USER_PERMISSION in factors
        assert AuthorizationFactor.GROUP_MEMBERSHIP in factors
        assert AuthorizationFactor.MFA_STATUS in factors
        assert AuthorizationFactor.DEVICE_TRUST in factors
        assert AuthorizationFactor.LOCATION_BASED in factors
        assert AuthorizationFactor.RISK_LEVEL in factors
        assert AuthorizationFactor.TIME_BASED in factors
        assert AuthorizationFactor.DELEGATION in factors
        assert AuthorizationFactor.EMERGENCY_ACCESS in factors
        assert AuthorizationFactor.COMPLIANCE_STATUS in factors

    def test_factor_strength(self):
        """Test factor strength calculation."""
        # Strong factors
        strong_context = AuthorizationContext(
            user_id="user-123",
            action="read",
            resource_type="document",
            mfa_verified=True,
            device_trusted=True,
            risk_level="low",
        )

        assert strong_context.get_factor_strength() == "strong"

        # Medium factors
        medium_context = AuthorizationContext(
            user_id="user-123",
            action="read",
            resource_type="document",
            mfa_verified=False,
            device_trusted=True,
            risk_level="medium",
        )

        assert medium_context.get_factor_strength() == "medium"

        # Weak factors
        weak_context = AuthorizationContext(
            user_id="user-123",
            action="read",
            resource_type="document",
            mfa_verified=False,
            device_trusted=False,
            risk_level="high",
        )

        assert weak_context.get_factor_strength() == "weak"


class TestAuthorizationProperties:
    """Test authorization context properties."""

    def test_authentication_properties(self):
        """Test authentication-related properties."""
        # Authenticated context
        auth_context = AuthorizationContext(
            user_id="user-123",
            action="read",
            resource_type="document",
            session_id="session-456",
            mfa_verified=True,
        )

        assert auth_context.is_authenticated is True
        assert auth_context.is_multi_factor_authenticated is True

        # Unauthenticated context
        unauth_context = AuthorizationContext(
            user_id="anonymous", action="read", resource_type="document"
        )

        assert unauth_context.is_authenticated is False
        assert unauth_context.is_multi_factor_authenticated is False

    def test_trust_properties(self):
        """Test trust-related properties."""
        # Trusted context
        trusted = AuthorizationContext(
            user_id="user-123",
            action="read",
            resource_type="document",
            device_trusted=True,
            risk_level="low",
            location_country="US",
        )

        assert trusted.is_trusted_context is True

        # Untrusted context
        untrusted = AuthorizationContext(
            user_id="user-123",
            action="read",
            resource_type="document",
            device_trusted=False,
            risk_level="high",
            location_country="XX",  # Unknown country
        )

        assert untrusted.is_trusted_context is False

    def test_privilege_properties(self):
        """Test privilege-related properties."""
        # Admin privileges
        admin = AuthorizationContext(
            user_id="user-123",
            action="admin",
            resource_type="system",
            user_roles=["admin", "superuser"],
        )

        assert admin.has_elevated_privileges is True
        assert admin.has_role("admin") is True
        assert admin.has_role("superuser") is True
        assert admin.has_role("user") is False

        # Emergency access
        emergency = AuthorizationContext(
            user_id="user-123",
            action="read",
            resource_type="document",
            emergency_access=True,
        )

        assert emergency.is_emergency is True
        assert emergency.has_elevated_privileges is True

    def test_delegation_properties(self):
        """Test delegation properties."""
        delegated = AuthorizationContext(
            user_id="user-123",
            action="write",
            resource_type="document",
            delegation_from="admin-456",
            delegation_scope=["write", "delete"],
        )

        assert delegated.is_delegated is True
        assert delegated.delegation_from == "admin-456"
        assert "write" in delegated.delegation_scope
        assert delegated.has_delegated_permission("write") is True
        assert delegated.has_delegated_permission("admin") is False


class TestAuthorizationDecision:
    """Test authorization decision making."""

    def test_simple_permission_check(self):
        """Test simple permission-based authorization."""
        context = AuthorizationContext(
            user_id="user-123",
            action="read",
            resource_type="document",
            user_permissions={"read_document", "list_documents"},
        )

        decision = context.make_decision()
        assert decision.is_allowed is True
        assert decision.reason == "User has required permission"
        assert AuthorizationFactor.USER_PERMISSION in decision.factors_used

    def test_role_based_check(self):
        """Test role-based authorization."""
        context = AuthorizationContext(
            user_id="user-123",
            action="delete",
            resource_type="document",
            user_roles=["admin"],
        )

        decision = context.make_decision(admin_required=True)
        assert decision.is_allowed is True
        assert AuthorizationFactor.USER_ROLE in decision.factors_used

    def test_mfa_requirement(self):
        """Test MFA requirement enforcement."""
        # Without MFA
        no_mfa = AuthorizationContext(
            user_id="user-123",
            action="delete",
            resource_type="sensitive_data",
            user_permissions={"delete_sensitive_data"},
            mfa_verified=False,
        )

        decision = no_mfa.make_decision(mfa_required=True)
        assert decision.is_allowed is False
        assert decision.reason == "MFA verification required"
        assert decision.additional_requirements == ["mfa_verification"]

        # With MFA
        with_mfa = AuthorizationContext(
            user_id="user-123",
            action="delete",
            resource_type="sensitive_data",
            user_permissions={"delete_sensitive_data"},
            mfa_verified=True,
        )

        decision = with_mfa.make_decision(mfa_required=True)
        assert decision.is_allowed is True

    def test_risk_based_decision(self):
        """Test risk-based authorization decisions."""
        # High risk blocked
        high_risk = AuthorizationContext(
            user_id="user-123",
            action="transfer_funds",
            resource_type="account",
            user_permissions={"transfer_funds"},
            risk_level="high",
            risk_score=0.9,
        )

        decision = high_risk.make_decision(max_risk_level="medium")
        assert decision.is_allowed is False
        assert decision.reason == "Risk level too high"
        assert AuthorizationFactor.RISK_LEVEL in decision.factors_used

        # Low risk allowed
        low_risk = AuthorizationContext(
            user_id="user-123",
            action="transfer_funds",
            resource_type="account",
            user_permissions={"transfer_funds"},
            risk_level="low",
            risk_score=0.2,
        )

        decision = low_risk.make_decision(max_risk_level="medium")
        assert decision.is_allowed is True

    def test_time_based_decision(self):
        """Test time-based authorization."""
        # During business hours
        business_hours = datetime.now(UTC).replace(hour=14)  # 2 PM
        context = AuthorizationContext(
            user_id="user-123",
            action="access_reports",
            resource_type="financial_report",
            user_permissions={"access_reports"},
            request_time=business_hours,
        )

        decision = context.make_decision(
            time_restrictions={"start_hour": 9, "end_hour": 17}
        )
        assert decision.is_allowed is True

        # Outside business hours
        after_hours = datetime.now(UTC).replace(hour=22)  # 10 PM
        context_late = AuthorizationContext(
            user_id="user-123",
            action="access_reports",
            resource_type="financial_report",
            user_permissions={"access_reports"},
            request_time=after_hours,
        )

        decision_late = context_late.make_decision(
            time_restrictions={"start_hour": 9, "end_hour": 17}
        )
        assert decision_late.is_allowed is False
        assert decision_late.reason == "Access outside allowed time window"

    def test_location_based_decision(self):
        """Test location-based authorization."""
        # Allowed country
        allowed_location = AuthorizationContext(
            user_id="user-123",
            action="access_data",
            resource_type="customer_data",
            user_permissions={"access_data"},
            location_country="US",
            ip_address="192.168.1.1",
        )

        decision = allowed_location.make_decision(allowed_countries=["US", "CA", "UK"])
        assert decision.is_allowed is True

        # Blocked country
        blocked_location = AuthorizationContext(
            user_id="user-123",
            action="access_data",
            resource_type="customer_data",
            user_permissions={"access_data"},
            location_country="XX",
            ip_address="1.2.3.4",
        )

        decision = blocked_location.make_decision(allowed_countries=["US", "CA", "UK"])
        assert decision.is_allowed is False
        assert decision.reason == "Access from blocked location"


class TestAuthorizationContextSecurity:
    """Test security features of authorization context."""

    def test_context_immutability(self):
        """Test that context is immutable."""
        context = AuthorizationContext(
            user_id="user-123", action="read", resource_type="document"
        )

        with pytest.raises(FrozenInstanceError):
            context.user_id = "user-456"

        with pytest.raises(FrozenInstanceError):
            context.action = "write"

    def test_context_anonymization(self):
        """Test context anonymization for logging."""
        context = AuthorizationContext(
            user_id="user-123",
            action="read",
            resource_type="document",
            resource_id="doc-456",
            user_roles=["editor"],
            user_permissions={"read_document", "write_document"},
            group_memberships=["team-alpha"],
            session_id="session-789",
            device_id="device-012",
            ip_address="192.168.1.1",
        )

        anonymized = context.anonymize()

        assert anonymized.user_id == "anonymous"
        assert anonymized.action == "read"  # Action preserved
        assert anonymized.resource_type == "document"  # Type preserved
        assert anonymized.resource_id is None  # ID removed
        assert anonymized.user_roles == ["editor"]  # Roles preserved
        assert len(anonymized.user_permissions) == 0  # Permissions removed
        assert len(anonymized.group_memberships) == 0  # Groups removed
        assert anonymized.session_id is None  # Session removed
        assert anonymized.device_id is None  # Device removed
        assert anonymized.ip_address is None  # IP removed

    def test_context_audit_trail(self):
        """Test audit trail generation."""
        context = AuthorizationContext(
            user_id="user-123",
            action="delete",
            resource_type="document",
            resource_id="doc-456",
            user_roles=["admin"],
            mfa_verified=True,
            risk_level="medium",
        )

        audit = context.to_audit_log()

        assert audit["user_id"] == "user-123"
        assert audit["action"] == "delete"
        assert audit["resource_type"] == "document"
        assert audit["resource_id"] == "doc-456"
        assert audit["decision"] is not None
        assert audit["factors"] is not None
        assert audit["timestamp"] is not None
        assert "risk_level" in audit["context"]


class TestAuthorizationContextComparison:
    """Test context comparison and equality."""

    def test_context_equality(self):
        """Test context equality comparison."""
        context1 = AuthorizationContext(
            user_id="user-123",
            action="read",
            resource_type="document",
            resource_id="doc-456",
        )

        context2 = AuthorizationContext(
            user_id="user-123",
            action="read",
            resource_type="document",
            resource_id="doc-456",
        )

        context3 = AuthorizationContext(
            user_id="user-456",
            action="write",
            resource_type="document",
            resource_id="doc-789",
        )

        assert context1 == context2
        assert context1 != context3
        assert hash(context1) == hash(context2)
        assert hash(context1) != hash(context3)

    def test_context_similarity(self):
        """Test context similarity scoring."""
        base_context = AuthorizationContext(
            user_id="user-123",
            action="read",
            resource_type="document",
            user_roles=["editor"],
            mfa_verified=True,
            device_trusted=True,
        )

        # Very similar context
        similar = AuthorizationContext(
            user_id="user-123",
            action="read",
            resource_type="document",
            user_roles=["editor"],
            mfa_verified=True,
            device_trusted=False,  # Only difference
        )

        similarity_score = base_context.similarity_score(similar)
        assert similarity_score > 0.8

        # Very different context
        different = AuthorizationContext(
            user_id="user-456",
            action="delete",
            resource_type="account",
            user_roles=["user"],
            mfa_verified=False,
            device_trusted=False,
        )

        different_score = base_context.similarity_score(different)
        assert different_score < 0.3


class TestAuthorizationContextPatterns:
    """Test common authorization patterns."""

    def test_admin_override_pattern(self):
        """Test admin override authorization pattern."""
        # Regular user denied
        user_context = AuthorizationContext(
            user_id="user-123",
            action="force_delete",
            resource_type="protected_resource",
            user_roles=["user"],
        )

        user_decision = user_context.make_decision()
        assert user_decision.is_allowed is False

        # Admin allowed
        admin_context = AuthorizationContext(
            user_id="admin-456",
            action="force_delete",
            resource_type="protected_resource",
            user_roles=["admin"],
            user_permissions={"admin_override"},
        )

        admin_decision = admin_context.make_decision()
        assert admin_decision.is_allowed is True
        assert admin_decision.override_used is True

    def test_owner_access_pattern(self):
        """Test resource owner access pattern."""
        # Owner access
        owner_context = AuthorizationContext(
            user_id="user-123",
            action="edit",
            resource_type="profile",
            resource_id="profile-123",
            resource_owner="user-123",
        )

        owner_decision = owner_context.make_decision()
        assert owner_decision.is_allowed is True
        assert owner_decision.reason == "Resource owner access"

        # Non-owner denied
        non_owner_context = AuthorizationContext(
            user_id="user-456",
            action="edit",
            resource_type="profile",
            resource_id="profile-123",
            resource_owner="user-123",
        )

        non_owner_decision = non_owner_context.make_decision()
        assert non_owner_decision.is_allowed is False

    def test_progressive_authorization(self):
        """Test progressive authorization requirements."""
        base_context = AuthorizationContext(
            user_id="user-123",
            action="sensitive_operation",
            resource_type="critical_system",
            user_permissions={"basic_access"},
        )

        # Level 1: Basic access
        level1 = base_context.make_decision(security_level=1)
        assert level1.is_allowed is True

        # Level 2: Requires MFA
        level2 = base_context.make_decision(security_level=2)
        assert level2.is_allowed is False
        assert "mfa_verification" in level2.additional_requirements

        # Level 2 with MFA
        mfa_context = AuthorizationContext(
            user_id="user-123",
            action="sensitive_operation",
            resource_type="critical_system",
            user_permissions={"basic_access"},
            mfa_verified=True,
        )

        level2_mfa = mfa_context.make_decision(security_level=2)
        assert level2_mfa.is_allowed is True

        # Level 3: Requires admin approval
        level3 = mfa_context.make_decision(security_level=3)
        assert level3.is_allowed is False
        assert "admin_approval" in level3.additional_requirements

    def test_create_minimal_context(self):
        """Test creating context with minimal required fields."""
        context = AuthorizationContext(
            user_id="user_123", action="read", resource_type="document"
        )

        assert context.user_id == "user_123"
        assert context.action == "read"
        assert context.resource_type == "document"
        assert context.resource_id is None
        assert context.user_roles == ()
        assert context.user_permissions == frozenset()
        assert context.group_memberships == ()

    def test_create_full_context(self):
        """Test creating context with all fields."""
        now = datetime.now(UTC)
        context = AuthorizationContext(
            user_id="user_123",
            action="write",
            resource_type="document",
            resource_id="doc_456",
            user_roles=["admin", "editor"],
            user_permissions={"read", "write", "delete"},
            group_memberships=["group1", "group2"],
            session_id="session_789",
            session_type="web",
            authentication_method="password+mfa",
            mfa_verified=True,
            device_id="device_abc",
            device_trusted=True,
            ip_address="192.168.1.1",
            location_country="US",
            location_region="CA",
            risk_level="low",
            compliance_flags={"gdpr": True, "hipaa": False},
            request_time=now,
            delegation_from="user_999",
            emergency_access=False,
            additional_context={"app_version": "1.0.0"},
        )

        assert context.user_id == "user_123"
        assert context.action == "write"
        assert context.resource_type == "document"
        assert context.resource_id == "doc_456"
        assert "admin" in context.user_roles
        assert "editor" in context.user_roles
        assert "read" in context.user_permissions
        assert "write" in context.user_permissions
        assert "delete" in context.user_permissions
        assert "group1" in context.group_memberships
        assert "group2" in context.group_memberships
        assert context.session_id == "session_789"
        assert context.session_type == "web"
        assert context.mfa_verified is True
        assert context.device_trusted is True
        assert context.ip_address == "192.168.1.1"
        assert context.location_country == "US"
        assert context.location_region == "CA"
        assert context.risk_level == "low"
        assert context.compliance_flags["gdpr"] is True
        assert context.delegation_from == "user_999"
        assert context.emergency_access is False

    def test_empty_user_id_raises_error(self):
        """Test that empty user_id raises ValueError."""
        with pytest.raises(ValueError, match="User ID is required"):
            AuthorizationContext(user_id="", action="read", resource_type="document")

    def test_empty_action_raises_error(self):
        """Test that empty action raises ValueError."""
        with pytest.raises(ValueError, match="Action is required"):
            AuthorizationContext(
                user_id="user_123", action="", resource_type="document"
            )

    def test_empty_resource_type_raises_error(self):
        """Test that empty resource_type raises ValueError."""
        with pytest.raises(ValueError, match="Resource type is required"):
            AuthorizationContext(user_id="user_123", action="read", resource_type="")

    def test_immutable_collections(self):
        """Test that mutable collections are converted to immutable."""
        context = AuthorizationContext(
            user_id="user_123",
            action="read",
            resource_type="document",
            user_roles=["admin", "user"],
            user_permissions={"read", "write"},
            group_memberships=["group1", "group2"],
        )

        # Should be converted to immutable types
        assert isinstance(context.user_roles, tuple)
        assert isinstance(context.user_permissions, frozenset)
        assert isinstance(context.group_memberships, tuple)


class TestAuthorizationContextProperties:
    """Test authorization context properties."""

    def test_is_authenticated_with_session(self):
        """Test is_authenticated property with session."""
        context = AuthorizationContext(
            user_id="user_123",
            action="read",
            resource_type="document",
            session_id="session_789",
        )

        assert context.is_authenticated is True

    def test_is_authenticated_without_session(self):
        """Test is_authenticated property without session."""
        context = AuthorizationContext(
            user_id="user_123", action="read", resource_type="document"
        )

        assert context.is_authenticated is False

    def test_is_multi_factor_authenticated_true(self):
        """Test is_multi_factor_authenticated when MFA verified."""
        context = AuthorizationContext(
            user_id="user_123",
            action="read",
            resource_type="document",
            session_id="session_789",
            mfa_verified=True,
        )

        assert context.is_multi_factor_authenticated is True

    def test_is_multi_factor_authenticated_false_no_mfa(self):
        """Test is_multi_factor_authenticated when MFA not verified."""
        context = AuthorizationContext(
            user_id="user_123",
            action="read",
            resource_type="document",
            session_id="session_789",
            mfa_verified=False,
        )

        assert context.is_multi_factor_authenticated is False

    def test_is_multi_factor_authenticated_false_no_session(self):
        """Test is_multi_factor_authenticated when not authenticated."""
        context = AuthorizationContext(
            user_id="user_123",
            action="read",
            resource_type="document",
            mfa_verified=True,  # MFA verified but no session
        )

        assert context.is_multi_factor_authenticated is False

    def test_is_trusted_context_true(self):
        """Test is_trusted_context when all conditions met."""
        context = AuthorizationContext(
            user_id="user_123",
            action="read",
            resource_type="document",
            device_trusted=True,
            mfa_verified=True,
            risk_level="low",
        )

        assert context.is_trusted_context is True

    def test_is_trusted_context_false_device_not_trusted(self):
        """Test is_trusted_context when device not trusted."""
        context = AuthorizationContext(
            user_id="user_123",
            action="read",
            resource_type="document",
            device_trusted=False,
            mfa_verified=True,
            risk_level="low",
        )

        assert context.is_trusted_context is False

    def test_is_trusted_context_false_no_mfa(self):
        """Test is_trusted_context when MFA not verified."""
        context = AuthorizationContext(
            user_id="user_123",
            action="read",
            resource_type="document",
            device_trusted=True,
            mfa_verified=False,
            risk_level="low",
        )

        assert context.is_trusted_context is False

    def test_is_trusted_context_false_high_risk(self):
        """Test is_trusted_context when risk level is high."""
        context = AuthorizationContext(
            user_id="user_123",
            action="read",
            resource_type="document",
            device_trusted=True,
            mfa_verified=True,
            risk_level="high",
        )

        assert context.is_trusted_context is False

    def test_is_delegated_true(self):
        """Test is_delegated when delegation_from is set."""
        context = AuthorizationContext(
            user_id="user_123",
            action="read",
            resource_type="document",
            delegation_from="user_999",
        )

        assert context.is_delegated is True

    def test_is_delegated_false(self):
        """Test is_delegated when delegation_from is None."""
        context = AuthorizationContext(
            user_id="user_123", action="read", resource_type="document"
        )

        assert context.is_delegated is False

    def test_is_emergency_true(self):
        """Test is_emergency when emergency_access is True."""
        context = AuthorizationContext(
            user_id="user_123",
            action="read",
            resource_type="document",
            emergency_access=True,
        )

        assert context.is_emergency is True

    def test_is_emergency_false(self):
        """Test is_emergency when emergency_access is False."""
        context = AuthorizationContext(
            user_id="user_123",
            action="read",
            resource_type="document",
            emergency_access=False,
        )

        assert context.is_emergency is False

    def test_has_elevated_privileges_emergency(self):
        """Test has_elevated_privileges with emergency access."""
        context = AuthorizationContext(
            user_id="user_123",
            action="read",
            resource_type="document",
            emergency_access=True,
        )

        assert context.has_elevated_privileges is True

    def test_has_elevated_privileges_admin_role(self):
        """Test has_elevated_privileges with admin role."""
        context = AuthorizationContext(
            user_id="user_123",
            action="read",
            resource_type="document",
            user_roles=["admin", "user"],
        )

        assert context.has_elevated_privileges is True

    def test_has_elevated_privileges_false(self):
        """Test has_elevated_privileges when no elevated access."""
        context = AuthorizationContext(
            user_id="user_123",
            action="read",
            resource_type="document",
            user_roles=["user", "editor"],
        )

        assert context.has_elevated_privileges is False


class TestAuthorizationContextHelperMethods:
    """Test authorization context helper methods."""

    def test_has_permission_true(self):
        """Test has_permission when permission exists."""
        context = AuthorizationContext(
            user_id="user_123",
            action="read",
            resource_type="document",
            user_permissions={"read", "write", "delete"},
        )

        assert context.has_permission("read") is True
        assert context.has_permission("write") is True

    def test_has_permission_false(self):
        """Test has_permission when permission doesn't exist."""
        context = AuthorizationContext(
            user_id="user_123",
            action="read",
            resource_type="document",
            user_permissions={"read"},
        )

        assert context.has_permission("write") is False
        assert context.has_permission("delete") is False

    def test_has_role_true(self):
        """Test has_role when role exists."""
        context = AuthorizationContext(
            user_id="user_123",
            action="read",
            resource_type="document",
            user_roles=["admin", "editor", "user"],
        )

        assert context.has_role("admin") is True
        assert context.has_role("editor") is True

    def test_has_role_false(self):
        """Test has_role when role doesn't exist."""
        context = AuthorizationContext(
            user_id="user_123",
            action="read",
            resource_type="document",
            user_roles=["user"],
        )

        assert context.has_role("admin") is False
        assert context.has_role("editor") is False

    def test_is_member_of_group_true(self):
        """Test is_member_of_group when group membership exists."""
        context = AuthorizationContext(
            user_id="user_123",
            action="read",
            resource_type="document",
            group_memberships=["group1", "group2", "group3"],
        )

        assert context.is_member_of_group("group1") is True
        assert context.is_member_of_group("group2") is True

    def test_is_member_of_group_false(self):
        """Test is_member_of_group when group membership doesn't exist."""
        context = AuthorizationContext(
            user_id="user_123",
            action="read",
            resource_type="document",
            group_memberships=["group1"],
        )

        assert context.is_member_of_group("group2") is False
        assert context.is_member_of_group("group3") is False


class TestAuthorizationContextFactors:
    """Test authorization factor detection."""

    def test_get_factors_minimal_context(self):
        """Test get_factors with minimal context."""
        context = AuthorizationContext(
            user_id="user_123", action="read", resource_type="document"
        )

        factors = context.get_factors()
        assert len(factors) == 0

    def test_get_factors_user_role(self):
        """Test get_factors with user roles."""
        context = AuthorizationContext(
            user_id="user_123",
            action="read",
            resource_type="document",
            user_roles=["admin"],
        )

        factors = context.get_factors()
        assert AuthorizationFactor.USER_ROLE in factors

    def test_get_factors_user_permission(self):
        """Test get_factors with user permissions."""
        context = AuthorizationContext(
            user_id="user_123",
            action="read",
            resource_type="document",
            user_permissions={"read"},
        )

        factors = context.get_factors()
        assert AuthorizationFactor.USER_PERMISSION in factors

    def test_get_factors_group_membership(self):
        """Test get_factors with group memberships."""
        context = AuthorizationContext(
            user_id="user_123",
            action="read",
            resource_type="document",
            group_memberships=["group1"],
        )

        factors = context.get_factors()
        assert AuthorizationFactor.GROUP_MEMBERSHIP in factors

    def test_get_factors_time_based(self):
        """Test get_factors with time-based context."""
        context = AuthorizationContext(
            user_id="user_123",
            action="read",
            resource_type="document",
            request_time=datetime.now(UTC),
        )

        factors = context.get_factors()
        assert AuthorizationFactor.TIME_BASED in factors

    def test_get_factors_location_based_ip(self):
        """Test get_factors with IP address."""
        context = AuthorizationContext(
            user_id="user_123",
            action="read",
            resource_type="document",
            ip_address="192.168.1.1",
        )

        factors = context.get_factors()
        assert AuthorizationFactor.LOCATION_BASED in factors

    def test_get_factors_location_based_country(self):
        """Test get_factors with location country."""
        context = AuthorizationContext(
            user_id="user_123",
            action="read",
            resource_type="document",
            location_country="US",
        )

        factors = context.get_factors()
        assert AuthorizationFactor.LOCATION_BASED in factors

    def test_get_factors_device_trust(self):
        """Test get_factors with device ID."""
        context = AuthorizationContext(
            user_id="user_123",
            action="read",
            resource_type="document",
            device_id="device_123",
        )

        factors = context.get_factors()
        assert AuthorizationFactor.DEVICE_TRUST in factors

    def test_get_factors_mfa_status(self):
        """Test get_factors with MFA verification."""
        context = AuthorizationContext(
            user_id="user_123",
            action="read",
            resource_type="document",
            mfa_verified=True,
        )

        factors = context.get_factors()
        assert AuthorizationFactor.MFA_STATUS in factors

    def test_get_factors_session_type(self):
        """Test get_factors with session type."""
        context = AuthorizationContext(
            user_id="user_123",
            action="read",
            resource_type="document",
            session_type="web",
        )

        factors = context.get_factors()
        assert AuthorizationFactor.SESSION_TYPE in factors

    def test_get_factors_risk_level(self):
        """Test get_factors with risk level."""
        context = AuthorizationContext(
            user_id="user_123",
            action="read",
            resource_type="document",
            risk_level="medium",
        )

        factors = context.get_factors()
        assert AuthorizationFactor.RISK_LEVEL in factors

    def test_get_factors_compliance_status(self):
        """Test get_factors with compliance flags."""
        context = AuthorizationContext(
            user_id="user_123",
            action="read",
            resource_type="document",
            compliance_flags={"gdpr": True},
        )

        factors = context.get_factors()
        assert AuthorizationFactor.COMPLIANCE_STATUS in factors

    def test_get_factors_delegation(self):
        """Test get_factors with delegation."""
        context = AuthorizationContext(
            user_id="user_123",
            action="read",
            resource_type="document",
            delegation_from="user_999",
        )

        factors = context.get_factors()
        assert AuthorizationFactor.DELEGATION in factors

    def test_get_factors_emergency_access(self):
        """Test get_factors with emergency access."""
        context = AuthorizationContext(
            user_id="user_123",
            action="read",
            resource_type="document",
            emergency_access=True,
        )

        factors = context.get_factors()
        assert AuthorizationFactor.EMERGENCY_ACCESS in factors

    def test_get_factors_multiple(self):
        """Test get_factors with multiple factors."""
        context = AuthorizationContext(
            user_id="user_123",
            action="read",
            resource_type="document",
            user_roles=["admin"],
            user_permissions={"read"},
            mfa_verified=True,
            device_id="device_123",
            risk_level="low",
        )

        factors = context.get_factors()
        assert len(factors) == 5
        assert AuthorizationFactor.USER_ROLE in factors
        assert AuthorizationFactor.USER_PERMISSION in factors
        assert AuthorizationFactor.MFA_STATUS in factors
        assert AuthorizationFactor.DEVICE_TRUST in factors
        assert AuthorizationFactor.RISK_LEVEL in factors


class TestAuthorizationContextDecision:
    """Test authorization decision functionality."""

    def test_with_decision_allow(self):
        """Test creating ALLOW decision."""
        context = AuthorizationContext(
            user_id="user_123",
            action="read",
            resource_type="document",
            user_roles=["admin"],
        )

        decision = context.with_decision(
            AuthorizationDecision.ALLOW,
            reason="User has admin role",
            applied_policies=["admin_policy"],
        )

        assert decision["decision"] == AuthorizationDecision.ALLOW
        assert decision["reason"] == "User has admin role"
        assert decision["applied_policies"] == ["admin_policy"]
        assert "user_role" in decision["context_factors"]
        assert "timestamp" in decision

    def test_with_decision_deny(self):
        """Test creating DENY decision."""
        context = AuthorizationContext(
            user_id="user_123", action="delete", resource_type="document"
        )

        decision = context.with_decision(
            AuthorizationDecision.DENY, reason="Insufficient permissions"
        )

        assert decision["decision"] == AuthorizationDecision.DENY
        assert decision["reason"] == "Insufficient permissions"
        assert decision["applied_policies"] == []

    def test_with_decision_conditional(self):
        """Test creating CONDITIONAL decision."""
        context = AuthorizationContext(
            user_id="user_123",
            action="write",
            resource_type="document",
            mfa_verified=False,
        )

        decision = context.with_decision(
            AuthorizationDecision.CONDITIONAL,
            reason="MFA required for write operations",
        )

        assert decision["decision"] == AuthorizationDecision.CONDITIONAL
        assert decision["reason"] == "MFA required for write operations"


class TestAuthorizationContextAudit:
    """Test audit functionality."""

    def test_to_audit_log_minimal(self):
        """Test audit log with minimal context."""
        context = AuthorizationContext(
            user_id="user_123", action="read", resource_type="document"
        )

        audit_log = context.to_audit_log()

        assert audit_log["user_id"] == "user_123"
        assert audit_log["action"] == "read"
        assert audit_log["resource_type"] == "document"
        assert audit_log["resource_id"] is None
        assert audit_log["session_id"] is None
        assert audit_log["roles"] == []
        assert audit_log["permissions"] == []
        assert audit_log["groups"] == []
        assert audit_log["mfa_verified"] is False
        assert audit_log["device_trusted"] is False
        assert audit_log["is_delegated"] is False
        assert audit_log["is_emergency"] is False
        assert audit_log["factors"] == []

    def test_to_audit_log_full(self):
        """Test audit log with full context."""
        now = datetime.now(UTC)
        context = AuthorizationContext(
            user_id="user_123",
            action="write",
            resource_type="document",
            resource_id="doc_456",
            user_roles=["admin", "editor"],
            user_permissions={"read", "write"},
            group_memberships=["group1", "group2"],
            session_id="session_789",
            mfa_verified=True,
            device_trusted=True,
            ip_address="192.168.1.1",
            location_country="US",
            location_region="CA",
            risk_level="low",
            delegation_from="user_999",
            emergency_access=True,
            request_time=now,
        )

        audit_log = context.to_audit_log()

        assert audit_log["user_id"] == "user_123"
        assert audit_log["resource_id"] == "doc_456"
        assert "admin" in audit_log["roles"]
        assert "read" in audit_log["permissions"]
        assert "group1" in audit_log["groups"]
        assert audit_log["mfa_verified"] is True
        assert audit_log["device_trusted"] is True
        assert audit_log["ip_address"] == "192.168.1.1"
        assert audit_log["location"]["country"] == "US"
        assert audit_log["location"]["region"] == "CA"
        assert audit_log["risk_level"] == "low"
        assert audit_log["is_delegated"] is True
        assert audit_log["delegation_from"] == "user_999"
        assert audit_log["is_emergency"] is True
        assert len(audit_log["factors"]) > 0
        assert audit_log["request_time"] == now.isoformat()


class TestAuthorizationContextAnonymization:
    """Test anonymization functionality."""

    def test_anonymize_removes_sensitive_data(self):
        """Test that anonymize removes sensitive data."""
        context = AuthorizationContext(
            user_id="user_123",
            action="read",
            resource_type="document",
            resource_id="sensitive_doc",
            user_roles=["admin"],
            user_permissions={"read", "write", "delete"},
            group_memberships=["sensitive_group"],
            session_id="session_789",
            ip_address="192.168.1.1",
        )

        anonymized = context.anonymize()

        assert anonymized.user_id == "anonymous"
        assert anonymized.action == "read"  # Action preserved
        assert anonymized.resource_type == "document"  # Resource type preserved
        assert anonymized.resource_id is None  # Resource ID removed
        assert list(anonymized.user_roles) == ["admin"]  # Roles preserved
        assert len(anonymized.user_permissions) == 0  # Permissions removed
        assert len(anonymized.group_memberships) == 0  # Groups removed
        assert anonymized.session_id is None  # Session removed
        assert (
            anonymized.location_country == context.location_country
        )  # Location preserved
        assert anonymized.request_time is None  # Timestamp removed

    def test_anonymize_preserves_analytical_data(self):
        """Test that anonymize preserves data useful for analytics."""
        context = AuthorizationContext(
            user_id="user_123",
            action="write",
            resource_type="document",
            session_type="mobile",
            authentication_method="oauth",
            mfa_verified=True,
            device_trusted=False,
            location_country="US",
            risk_level="medium",
        )

        anonymized = context.anonymize()

        assert anonymized.session_type == "mobile"
        assert anonymized.authentication_method == "oauth"
        assert anonymized.mfa_verified is True
        assert anonymized.device_trusted is False
        assert anonymized.location_country == "US"
        assert anonymized.risk_level == "medium"


class TestAuthorizationContextStringRepresentation:
    """Test string representation methods."""

    def test_str_representation(self):
        """Test __str__ method."""
        context = AuthorizationContext(
            user_id="user_123", action="read", resource_type="document"
        )

        str_repr = str(context)
        assert "user=user_123" in str_repr
        assert "action=read" in str_repr
        assert "resource=document" in str_repr

    def test_repr_representation(self):
        """Test __repr__ method."""
        context = AuthorizationContext(
            user_id="user_123",
            action="read",
            resource_type="document",
            user_roles=["admin"],
            mfa_verified=True,
            device_trusted=True,
            risk_level="low",
        )

        repr_str = repr(context)
        assert "factors=" in repr_str
        assert "mfa=True" in repr_str
        assert "trusted=True" in repr_str


class TestAuthorizationContextImmutability:
    """Test that AuthorizationContext is immutable."""

    def test_immutable_user_id(self):
        """Test that user_id cannot be changed."""
        context = AuthorizationContext(
            user_id="user_123", action="read", resource_type="document"
        )

        with pytest.raises(FrozenInstanceError):
            context.user_id = "user_456"

    def test_immutable_action(self):
        """Test that action cannot be changed."""
        context = AuthorizationContext(
            user_id="user_123", action="read", resource_type="document"
        )

        with pytest.raises(FrozenInstanceError):
            context.action = "write"

    def test_immutable_collections(self):
        """Test that collections are immutable."""
        context = AuthorizationContext(
            user_id="user_123",
            action="read",
            resource_type="document",
            user_roles=["admin"],
            user_permissions={"read"},
        )

        # Should not be able to modify the collections
        with pytest.raises((TypeError, AttributeError)):
            context.user_roles.append("user")

        with pytest.raises((TypeError, AttributeError)):
            context.user_permissions.add("write")


class TestAuthorizationContextEquality:
    """Test equality and comparison behavior."""

    def test_equal_contexts(self):
        """Test that identical contexts are equal."""
        context1 = AuthorizationContext(
            user_id="user_123",
            action="read",
            resource_type="document",
            user_roles=["admin"],
            mfa_verified=True,
        )

        context2 = AuthorizationContext(
            user_id="user_123",
            action="read",
            resource_type="document",
            user_roles=["admin"],
            mfa_verified=True,
        )

        assert context1 == context2

    def test_different_contexts_not_equal(self):
        """Test that different contexts are not equal."""
        context1 = AuthorizationContext(
            user_id="user_123", action="read", resource_type="document"
        )

        context2 = AuthorizationContext(
            user_id="user_456", action="read", resource_type="document"
        )

        assert context1 != context2

    def test_different_collections_not_equal(self):
        """Test that contexts with different collections are not equal."""
        context1 = AuthorizationContext(
            user_id="user_123",
            action="read",
            resource_type="document",
            user_roles=["admin"],
        )

        context2 = AuthorizationContext(
            user_id="user_123",
            action="read",
            resource_type="document",
            user_roles=["user"],
        )

        assert context1 != context2


class TestAuthorizationContextEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_empty_collections(self):
        """Test with empty collections."""
        context = AuthorizationContext(
            user_id="user_123",
            action="read",
            resource_type="document",
            user_roles=[],
            user_permissions=set(),
            group_memberships=[],
            compliance_flags={},
            additional_context={},
        )

        assert len(context.user_roles) == 0
        assert len(context.user_permissions) == 0
        assert len(context.group_memberships) == 0
        assert len(context.get_factors()) == 0

    def test_none_risk_level_trusted_context(self):
        """Test trusted context with None risk level."""
        context = AuthorizationContext(
            user_id="user_123",
            action="read",
            resource_type="document",
            device_trusted=True,
            mfa_verified=True,
            risk_level=None,
        )

        assert context.is_trusted_context is True

    def test_all_authorization_decisions(self):
        """Test that all authorization decisions can be created."""
        context = AuthorizationContext(
            user_id="user_123", action="read", resource_type="document"
        )

        for decision in AuthorizationDecision:
            result = context.with_decision(decision)
            assert result["decision"] == decision

    def test_all_authorization_factors_coverage(self):
        """Test that all authorization factors can be detected."""
        # This is more of a documentation test to ensure we handle all factors
        all_factors = set(AuthorizationFactor)

        # Create context with all possible factors
        context = AuthorizationContext(
            user_id="user_123",
            action="read",
            resource_type="document",
            user_roles=["admin"],
            user_permissions={"read"},
            group_memberships=["group1"],
            request_time=datetime.now(UTC),
            ip_address="192.168.1.1",
            device_id="device_123",
            mfa_verified=True,
            session_type="web",
            risk_level="low",
            compliance_flags={"gdpr": True},
            delegation_from="user_999",
            emergency_access=True,
        )

        detected_factors = context.get_factors()

        # Should detect most factors (resource ownership not applicable here)
        expected_factors = all_factors - {AuthorizationFactor.RESOURCE_OWNERSHIP}
        assert detected_factors == expected_factors

    def test_large_collections(self):
        """Test with large collections."""
        large_roles = [f"role_{i}" for i in range(100)]
        large_permissions = {f"permission_{i}" for i in range(100)}
        large_groups = [f"group_{i}" for i in range(100)]

        context = AuthorizationContext(
            user_id="user_123",
            action="read",
            resource_type="document",
            user_roles=large_roles,
            user_permissions=large_permissions,
            group_memberships=large_groups,
        )

        assert len(context.user_roles) == 100
        assert len(context.user_permissions) == 100
        assert len(context.group_memberships) == 100
        assert context.has_role("role_50")
        assert context.has_permission("permission_50")
        assert context.is_member_of_group("group_50")
