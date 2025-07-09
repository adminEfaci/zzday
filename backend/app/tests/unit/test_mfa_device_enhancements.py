"""Unit tests for MFADevice aggregate enhancements."""

import pytest
from datetime import datetime, timedelta, UTC
from uuid import uuid4

# Mock the dependencies to avoid config loading issues
import sys
from unittest.mock import MagicMock

# Create minimal mocks
sys.modules['app.core'] = MagicMock()
sys.modules['app.core.domain'] = MagicMock()
sys.modules['app.core.domain.base'] = MagicMock()
sys.modules['app.modules.identity.shared'] = MagicMock()
sys.modules['app.modules.identity.shared.base_entity'] = MagicMock()
sys.modules['app.modules.identity.entities'] = MagicMock()
sys.modules['app.modules.identity.entities.user'] = MagicMock()
sys.modules['app.modules.identity.entities.user.user_events'] = MagicMock()

# Mock the base classes
class MockIdentityAggregate:
    def __init__(self):
        self.events = []
        self.created_at = datetime.now(UTC)
        self.updated_at = None
    
    def add_domain_event(self, event):
        self.events.append(event)
    
    def touch(self):
        self.updated_at = datetime.now(UTC)

class MockSecurityValidationMixin:
    def validate_token_format(self, token, field_name):
        return True

# Now we can import our enhanced MFADevice
from app.modules.identity.domain.enums import MFAMethod
from app.modules.identity.domain.aggregates.mfa_device import MFADevice, MFASecret, DeviceName, BackupCode


class TestMFADeviceEnhancements:
    """Test the enhanced business methods for MFADevice aggregate."""
    
    def setup_method(self):
        """Set up test data."""
        # Patch the base classes
        MFADevice.__bases__ = (MockIdentityAggregate, MockSecurityValidationMixin)
        
        self.user_id = uuid4()
        self.device = MFADevice(
            id=uuid4(),
            user_id=self.user_id,
            method=MFAMethod.TOTP,
            device_name=DeviceName("Test Device"),
            secret=MFASecret.generate_totp(),
            verified=True,
            created_at=datetime.now(UTC) - timedelta(days=30)
        )
    
    def test_calculate_trust_score_verified_device(self):
        """Test trust score calculation for verified device."""
        self.device.verified = True
        self.device.failed_attempts = 0
        self.device.last_used = datetime.now(UTC) - timedelta(days=5)
        self.device.is_primary = True
        
        score = self.device.calculate_trust_score()
        
        # Should have high trust score
        assert score > 0.8
        assert score <= 1.0
    
    def test_calculate_trust_score_unverified_device(self):
        """Test trust score calculation for unverified device."""
        self.device.verified = False
        self.device.failed_attempts = 3
        
        score = self.device.calculate_trust_score()
        
        # Should have low trust score
        assert score < 0.5
    
    def test_should_require_reverification_inactive(self):
        """Test reverification requirement for inactive device."""
        self.device.last_used = datetime.now(UTC) - timedelta(days=100)
        
        assert self.device.should_require_reverification() is True
    
    def test_should_require_reverification_failed_attempts(self):
        """Test reverification requirement after failed attempts."""
        self.device.failed_attempts = 3
        self.device.last_used = datetime.now(UTC)
        
        assert self.device.should_require_reverification() is True
    
    def test_should_not_require_reverification(self):
        """Test when reverification is not required."""
        self.device.failed_attempts = 0
        self.device.last_used = datetime.now(UTC)
        self.device.verified = True
        
        # Mock trust score to be high
        self.device.calculate_trust_score = lambda: 0.9
        
        assert self.device.should_require_reverification() is False
    
    def test_unlock_device(self):
        """Test unlocking a locked device."""
        self.device.locked_until = datetime.now(UTC) + timedelta(minutes=15)
        self.device.failed_attempts = 5
        
        self.device.unlock(unlocked_by=self.user_id)
        
        assert self.device.locked_until is None
        assert self.device.failed_attempts == 0
        assert len(self.device.events) > 0
    
    def test_rotate_secret(self):
        """Test rotating TOTP secret."""
        old_secret = self.device.secret.value
        
        new_secret = self.device.rotate_secret()
        
        assert new_secret != old_secret
        assert self.device.secret.value == new_secret
        assert len(self.device.events) > 0
    
    def test_rotate_secret_invalid_method(self):
        """Test rotating secret for non-TOTP method."""
        self.device.method = MFAMethod.SMS
        
        with pytest.raises(ValueError, match="Secret rotation not supported"):
            self.device.rotate_secret()
    
    def test_update_phone_number(self):
        """Test updating phone number for SMS device."""
        self.device.method = MFAMethod.SMS
        self.device.phone_number = "+1234567890"
        
        self.device.update_phone_number("+0987654321", verified_by=self.user_id)
        
        assert self.device.phone_number == "+0987654321"
        assert self.device.verified is False  # Requires reverification
        assert len(self.device.events) > 0
    
    def test_update_phone_number_invalid_method(self):
        """Test updating phone for non-SMS device."""
        self.device.method = MFAMethod.TOTP
        
        with pytest.raises(ValueError, match="Phone number can only be updated for SMS devices"):
            self.device.update_phone_number("+1234567890", verified_by=self.user_id)
    
    def test_can_be_primary(self):
        """Test checking if device can be primary."""
        self.device.verified = True
        self.device.locked_until = None
        
        assert self.device.can_be_primary() is True
    
    def test_cannot_be_primary_unverified(self):
        """Test unverified device cannot be primary."""
        self.device.verified = False
        
        assert self.device.can_be_primary() is False
    
    def test_estimate_time_until_unlock(self):
        """Test estimating time until unlock."""
        future_time = datetime.now(UTC) + timedelta(minutes=30)
        self.device.locked_until = future_time
        
        time_remaining = self.device.estimate_time_until_unlock()
        
        assert time_remaining is not None
        assert time_remaining.total_seconds() > 0
        assert time_remaining.total_seconds() <= 1800  # 30 minutes
    
    def test_regenerate_single_backup_code(self):
        """Test regenerating a used backup code."""
        # Create a used backup code
        used_code = BackupCode(value="USED123", is_used=True)
        new_code = BackupCode(value="NEW456")
        self.device.backup_codes = [used_code, new_code]
        
        regenerated = self.device.regenerate_single_backup_code("USED123")
        
        assert regenerated is not None
        assert regenerated != "USED123"
        assert len(self.device.backup_codes) == 2
        assert all(code.value != "USED123" for code in self.device.backup_codes)