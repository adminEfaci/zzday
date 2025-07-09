"""Unit tests for UserAuthenticationService integration."""

import pytest
from datetime import datetime, timedelta, UTC
from uuid import uuid4
from unittest.mock import MagicMock

# Mock the dependencies to avoid config loading issues
import sys

# Create minimal mocks
sys.modules['app.core'] = MagicMock()
sys.modules['app.core.domain'] = MagicMock()
sys.modules['app.core.domain.base'] = MagicMock()
sys.modules['app.modules.identity.shared'] = MagicMock()
sys.modules['app.modules.identity.shared.base_entity'] = MagicMock()

# Mock the base classes
class MockAggregateRoot:
    def __init__(self):
        self.events = []
        self.created_at = datetime.now(UTC)
        self.updated_at = None
        self.id = uuid4()
    
    def add_domain_event(self, event):
        self.events.append(event)
    
    def _touch(self):
        self.updated_at = datetime.now(UTC)

# Import our classes
from app.modules.identity.domain.enums import UserStatus, AccountType
from app.modules.identity.domain.value_objects import Email, Username
from app.modules.identity.domain.services.user_authentication_service import UserAuthenticationService
from app.modules.identity.domain.interfaces.services.user_authentication_service import AuthenticationContext


class TestUserAuthenticationService:
    """Test the UserAuthenticationService implementation."""
    
    def setup_method(self):
        """Set up test data."""
        # Patch the base class for User
        from app.modules.identity.domain.aggregates.user import User
        User.__bases__ = (MockAggregateRoot,)
        
        self.service = UserAuthenticationService()
        self.user = User(
            email=Email("test@example.com"),
            username=Username("testuser"),
            password_hash="hashed_password",
            status=UserStatus.ACTIVE,
            account_type=AccountType.REGULAR,
            failed_login_count=0,
            mfa_enabled=False,
            email_verified=True
        )
        
        # Set the authentication service
        self.user.set_authentication_service(self.service)
        
        self.context = AuthenticationContext(
            user_id=self.user.id,
            ip_address="192.168.1.1",
            user_agent="Mozilla/5.0",
            timestamp=datetime.now(UTC)
        )
    
    def test_password_policy_validation_strong_password(self):
        """Test password policy validation for strong password."""
        strong_password = "StrongP@ssw0rd123!"
        
        result = self.service.validate_password_policy(strong_password, self.user)
        
        assert result.is_valid is True
        assert result.meets_policy is True
        assert len(result.errors) == 0
        assert result.strength_score > 0.8
    
    def test_password_policy_validation_weak_password(self):
        """Test password policy validation for weak password."""
        weak_password = "weak"
        
        result = self.service.validate_password_policy(weak_password, self.user)
        
        assert result.is_valid is False
        assert result.meets_policy is False
        assert len(result.errors) > 0
        assert result.strength_score < 0.5
    
    def test_process_login_attempt_success(self):
        """Test successful login attempt processing."""
        result = self.service.process_login_attempt(self.user, True, self.context)
        
        assert result.success is True
        assert result.should_lock_account is False
        assert result.lock_duration is None
        assert result.remaining_attempts == 5
        assert result.risk_score == 0.1
    
    def test_process_login_attempt_failure(self):
        """Test failed login attempt processing."""
        self.user.failed_login_count = 2
        
        result = self.service.process_login_attempt(self.user, False, self.context)
        
        assert result.success is False
        assert result.remaining_attempts == 2  # 5 - 2 - 1
        assert result.risk_score > 0.1
    
    def test_process_login_attempt_lock_trigger(self):
        """Test login attempt that should trigger account lock."""
        self.user.failed_login_count = 4  # Next attempt will be 5th
        
        result = self.service.process_login_attempt(self.user, False, self.context)
        
        assert result.should_lock_account is True
        assert result.lock_duration is not None
        assert result.remaining_attempts == 0
    
    def test_assess_authentication_risk_low_risk(self):
        """Test authentication risk assessment for low-risk user."""
        # Set up a low-risk user
        self.user.failed_login_count = 0
        self.user.mfa_enabled = True
        self.user.email_verified = True
        self.user.created_at = datetime.now(UTC) - timedelta(days=30)
        
        result = self.service.assess_authentication_risk(self.user, self.context)
        
        assert result.risk_level == "low"
        assert result.risk_score < 0.4
    
    def test_assess_authentication_risk_high_risk(self):
        """Test authentication risk assessment for high-risk user."""
        # Set up a high-risk user
        self.user.failed_login_count = 3
        self.user.mfa_enabled = False
        self.user.email_verified = False
        self.user.created_at = datetime.now(UTC) - timedelta(days=1)
        
        result = self.service.assess_authentication_risk(self.user, self.context)
        
        assert result.risk_level in ["high", "critical"]
        assert result.risk_score >= 0.6
        assert result.requires_additional_verification is True
    
    def test_should_require_mfa_enabled(self):
        """Test MFA requirement when MFA is enabled."""
        self.user.mfa_enabled = True
        
        result = self.service.should_require_mfa(self.user, self.context)
        
        assert result is True
    
    def test_should_require_mfa_high_risk(self):
        """Test MFA requirement for high-risk authentication."""
        self.user.mfa_enabled = False
        self.user.failed_login_count = 3
        self.user.email_verified = False
        
        result = self.service.should_require_mfa(self.user, self.context)
        
        assert result is True  # Should require MFA due to high risk
    
    def test_calculate_lock_duration(self):
        """Test lock duration calculation."""
        # Test exponential backoff
        duration_5 = self.service.calculate_lock_duration(self.user, 5)
        duration_6 = self.service.calculate_lock_duration(self.user, 6)
        duration_10 = self.service.calculate_lock_duration(self.user, 10)
        
        assert duration_5 == timedelta(minutes=15)
        assert duration_6 == timedelta(minutes=30)
        assert duration_10 == timedelta(minutes=240)  # Capped at 4 hours
    
    def test_evaluate_password_strength(self):
        """Test password strength evaluation."""
        weak_password = "weak"
        medium_password = "MediumPass123"
        strong_password = "V3ryStr0ng!P@ssw0rd"
        
        weak_score = self.service.evaluate_password_strength(weak_password)
        medium_score = self.service.evaluate_password_strength(medium_password)
        strong_score = self.service.evaluate_password_strength(strong_password)
        
        assert weak_score < 0.5
        assert medium_score > weak_score
        assert strong_score > medium_score
    
    def test_get_security_recommendations(self):
        """Test security recommendations."""
        # User with no MFA and unverified email
        self.user.mfa_enabled = False
        self.user.email_verified = False
        
        recommendations = self.service.get_security_recommendations(self.user)
        
        assert len(recommendations) >= 2
        assert any("multi-factor authentication" in r.lower() for r in recommendations)
        assert any("verify your email" in r.lower() for r in recommendations)
    
    def test_validate_account_status_active(self):
        """Test account status validation for active account."""
        is_valid, reason = self.service.validate_account_status(self.user)
        
        assert is_valid is True
        assert reason == "Account is valid for authentication"
    
    def test_validate_account_status_suspended(self):
        """Test account status validation for suspended account."""
        self.user.status = UserStatus.SUSPENDED
        
        is_valid, reason = self.service.validate_account_status(self.user)
        
        assert is_valid is False
        assert "suspended" in reason.lower()
    
    def test_user_aggregate_integration(self):
        """Test integration with User aggregate."""
        # Test that User aggregate uses the service
        password = "TestP@ssw0rd123!"
        
        validation_result = self.user.validate_password_policy(password)
        
        assert "is_valid" in validation_result
        assert "strength_score" in validation_result
        assert validation_result["is_valid"] is True
    
    def test_user_aggregate_risk_assessment(self):
        """Test risk assessment through User aggregate."""
        context = {
            "ip_address": "192.168.1.1",
            "user_agent": "Mozilla/5.0"
        }
        
        risk_result = self.user.assess_authentication_risk(context)
        
        assert "risk_level" in risk_result
        assert "risk_score" in risk_result
        assert risk_result["risk_level"] in ["low", "medium", "high", "critical"]
    
    def test_user_aggregate_mfa_requirement(self):
        """Test MFA requirement through User aggregate."""
        context = {
            "ip_address": "192.168.1.1",
            "user_agent": "Mozilla/5.0"
        }
        
        # Test with MFA enabled
        self.user.mfa_enabled = True
        requires_mfa = self.user.requires_mfa(context)
        assert requires_mfa is True
        
        # Test with MFA disabled but low risk
        self.user.mfa_enabled = False
        requires_mfa = self.user.requires_mfa(context)
        assert requires_mfa is False
    
    def test_user_aggregate_security_recommendations(self):
        """Test security recommendations through User aggregate."""
        self.user.mfa_enabled = False
        
        recommendations = self.user.get_security_recommendations()
        
        assert len(recommendations) > 0
        assert any("multi-factor authentication" in r.lower() for r in recommendations)