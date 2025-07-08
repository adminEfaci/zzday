"""
Test cases for SecurityStamp value object.

Tests all aspects of security stamp including generation, validation,
rotation logic, and audit functionality.
"""

from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta

import pytest

from app.modules.identity.domain.value_objects.security_stamp import (
    SecurityStamp,
    SecurityStampPurpose,
)


class TestSecurityStampCreation:
    """Test SecurityStamp creation and validation."""

    def test_create_valid_security_stamp(self):
        """Test creating a valid security stamp."""
        timestamp = datetime.now(UTC)
        stamp = SecurityStamp(
            value="secure_stamp_1234567890abcdef1234567890abcdef",
            generated_at=timestamp,
            purpose=SecurityStampPurpose.INITIAL,
        )

        assert stamp.value == "secure_stamp_1234567890abcdef1234567890abcdef"
        assert stamp.generated_at == timestamp
        assert stamp.purpose == SecurityStampPurpose.INITIAL
        assert stamp.is_valid is True

    def test_create_with_different_purposes(self):
        """Test creating stamps with different purposes."""
        timestamp = datetime.now(UTC)

        # Password change stamp
        password_stamp = SecurityStamp(
            value="password_stamp_123456789012345678901234567890",
            generated_at=timestamp,
            purpose=SecurityStampPurpose.PASSWORD_CHANGE,
        )
        assert password_stamp.was_security_event is True
        assert password_stamp.was_profile_change is False

        # Email change stamp
        email_stamp = SecurityStamp(
            value="email_stamp_12345678901234567890123456789012",
            generated_at=timestamp,
            purpose=SecurityStampPurpose.EMAIL_CHANGE,
        )
        assert email_stamp.was_profile_change is True
        assert email_stamp.was_security_event is False

        # Suspicious activity stamp
        suspicious_stamp = SecurityStamp(
            value="suspicious_stamp_1234567890123456789012345678",
            generated_at=timestamp,
            purpose=SecurityStampPurpose.SUSPICIOUS_ACTIVITY,
        )
        assert suspicious_stamp.was_security_event is True
        assert suspicious_stamp.requires_immediate_action is True

    def test_invalid_security_stamp_creation(self):
        """Test validation of invalid security stamps."""
        timestamp = datetime.now(UTC)

        # Empty value
        with pytest.raises(ValueError, match="Security stamp value is required"):
            SecurityStamp(
                value="", generated_at=timestamp, purpose=SecurityStampPurpose.INITIAL
            )

        # Too short
        with pytest.raises(
            ValueError, match="Security stamp must be at least 32 characters"
        ):
            SecurityStamp(
                value="short_stamp",
                generated_at=timestamp,
                purpose=SecurityStampPurpose.INITIAL,
            )

        # Timezone naive timestamp
        with pytest.raises(ValueError, match="generated_at must be timezone-aware"):
            SecurityStamp(
                value="valid_stamp_1234567890123456789012345678901234",
                generated_at=datetime.now(),  # No timezone
                purpose=SecurityStampPurpose.INITIAL,
            )

        # Future timestamp
        future_time = datetime.now(UTC) + timedelta(hours=1)
        with pytest.raises(ValueError, match="generated_at cannot be in the future"):
            SecurityStamp(
                value="valid_stamp_1234567890123456789012345678901234",
                generated_at=future_time,
                purpose=SecurityStampPurpose.INITIAL,
            )


class TestSecurityStampGeneration:
    """Test security stamp generation."""

    def test_generate_security_stamp(self):
        """Test generating a new security stamp."""
        stamp = SecurityStamp.generate(SecurityStampPurpose.INITIAL)

        assert len(stamp.value) >= 32
        assert stamp.purpose == SecurityStampPurpose.INITIAL
        assert stamp.generated_at.tzinfo is not None
        assert stamp.generated_at <= datetime.now(UTC)
        assert stamp.is_valid is True

    def test_generate_unique_stamps(self):
        """Test that generated stamps are unique."""
        stamps = [
            SecurityStamp.generate(SecurityStampPurpose.INITIAL) for _ in range(100)
        ]
        stamp_values = [s.value for s in stamps]

        # All should be unique
        assert len(stamp_values) == len(set(stamp_values))

    def test_generate_with_metadata(self):
        """Test generating stamps with metadata."""
        metadata = {
            "ip_address": "192.168.1.1",
            "user_agent": "Mozilla/5.0",
            "reason": "Suspicious login attempt",
        }

        stamp = SecurityStamp.generate(
            purpose=SecurityStampPurpose.SUSPICIOUS_ACTIVITY, metadata=metadata
        )

        assert stamp.metadata == metadata
        assert stamp.metadata["reason"] == "Suspicious login attempt"


class TestSecurityStampPurposes:
    """Test security stamp purpose classifications."""

    def test_security_event_purposes(self):
        """Test purposes that are security events."""
        security_purposes = [
            SecurityStampPurpose.PASSWORD_CHANGE,
            SecurityStampPurpose.MFA_CHANGE,
            SecurityStampPurpose.SUSPICIOUS_ACTIVITY,
            SecurityStampPurpose.ACCOUNT_RECOVERY,
            SecurityStampPurpose.PRIVILEGE_ESCALATION,
        ]

        for purpose in security_purposes:
            stamp = SecurityStamp.generate(purpose)
            assert stamp.was_security_event is True

    def test_profile_change_purposes(self):
        """Test purposes that are profile changes."""
        profile_purposes = [
            SecurityStampPurpose.EMAIL_CHANGE,
            SecurityStampPurpose.PHONE_CHANGE,
            SecurityStampPurpose.NAME_CHANGE,
            SecurityStampPurpose.ADDRESS_CHANGE,
        ]

        for purpose in profile_purposes:
            stamp = SecurityStamp.generate(purpose)
            assert stamp.was_profile_change is True

    def test_permission_change_purposes(self):
        """Test purposes that are permission changes."""
        permission_purposes = [
            SecurityStampPurpose.ROLE_CHANGE,
            SecurityStampPurpose.GROUP_CHANGE,
            SecurityStampPurpose.PERMISSION_GRANT,
            SecurityStampPurpose.PERMISSION_REVOKE,
        ]

        for purpose in permission_purposes:
            stamp = SecurityStamp.generate(purpose)
            assert stamp.was_permission_change is True

    def test_purpose_severity(self):
        """Test purpose severity levels."""
        # High severity
        high_severity = SecurityStamp.generate(SecurityStampPurpose.SUSPICIOUS_ACTIVITY)
        assert high_severity.severity == "high"
        assert high_severity.requires_immediate_action is True

        # Medium severity
        medium_severity = SecurityStamp.generate(SecurityStampPurpose.PASSWORD_CHANGE)
        assert medium_severity.severity == "medium"

        # Low severity
        low_severity = SecurityStamp.generate(SecurityStampPurpose.NAME_CHANGE)
        assert low_severity.severity == "low"


class TestSecurityStampValidation:
    """Test security stamp validation."""

    def test_stamp_matching(self):
        """Test stamp value matching."""
        stamp = SecurityStamp.generate(SecurityStampPurpose.INITIAL)

        assert stamp.matches(stamp.value) is True
        assert stamp.matches("different_stamp_value") is False
        assert stamp.matches("") is False
        assert stamp.matches(None) is False

    def test_stamp_age_validation(self):
        """Test stamp age validation."""
        # Fresh stamp
        fresh_stamp = SecurityStamp.generate(SecurityStampPurpose.INITIAL)
        assert fresh_stamp.is_expired() is False
        assert fresh_stamp.age.total_seconds() < 1

        # Old stamp
        old_timestamp = datetime.now(UTC) - timedelta(days=365)
        old_stamp = SecurityStamp(
            value="old_stamp_12345678901234567890123456789012",
            generated_at=old_timestamp,
            purpose=SecurityStampPurpose.INITIAL,
        )
        assert old_stamp.is_expired(max_age_days=30) is True
        assert old_stamp.age.days >= 365

    def test_stamp_rotation_needed(self):
        """Test detection of stamps needing rotation."""
        # Recent stamp
        recent_stamp = SecurityStamp.generate(SecurityStampPurpose.INITIAL)
        assert recent_stamp.needs_rotation() is False

        # Month old stamp
        month_old = datetime.now(UTC) - timedelta(days=35)
        old_stamp = SecurityStamp(
            value="month_old_stamp_123456789012345678901234567",
            generated_at=month_old,
            purpose=SecurityStampPurpose.INITIAL,
        )
        assert old_stamp.needs_rotation(rotation_days=30) is True


class TestSecurityStampComparison:
    """Test security stamp comparison and ordering."""

    def test_stamp_equality(self):
        """Test stamp equality comparison."""
        timestamp = datetime.now(UTC)

        stamp1 = SecurityStamp(
            value="stamp_12345678901234567890123456789012345678",
            generated_at=timestamp,
            purpose=SecurityStampPurpose.INITIAL,
        )

        stamp2 = SecurityStamp(
            value="stamp_12345678901234567890123456789012345678",
            generated_at=timestamp,
            purpose=SecurityStampPurpose.INITIAL,
        )

        stamp3 = SecurityStamp(
            value="different_stamp_123456789012345678901234567",
            generated_at=timestamp,
            purpose=SecurityStampPurpose.INITIAL,
        )

        assert stamp1 == stamp2
        assert stamp1 != stamp3
        assert hash(stamp1) == hash(stamp2)
        assert hash(stamp1) != hash(stamp3)

    def test_stamp_ordering(self):
        """Test stamp ordering by generation time."""
        stamps = []
        base_time = datetime.now(UTC)

        for i in range(5):
            stamp = SecurityStamp(
                value=f"stamp_{i}_{'0' * 36}",
                generated_at=base_time - timedelta(hours=i),
                purpose=SecurityStampPurpose.INITIAL,
            )
            stamps.append(stamp)

        # Sort by generation time (newest first)
        sorted_stamps = sorted(stamps, key=lambda s: s.generated_at, reverse=True)

        # Verify ordering
        for i in range(1, len(sorted_stamps)):
            assert sorted_stamps[i - 1].generated_at > sorted_stamps[i].generated_at


class TestSecurityStampSecurity:
    """Test security stamp security features."""

    def test_stamp_immutability(self):
        """Test that stamps are immutable."""
        stamp = SecurityStamp.generate(SecurityStampPurpose.INITIAL)

        with pytest.raises(FrozenInstanceError):
            stamp.value = "modified"

        with pytest.raises(FrozenInstanceError):
            stamp.purpose = SecurityStampPurpose.PASSWORD_CHANGE

    def test_secure_string_representation(self):
        """Test that string representations don't expose full stamp."""
        stamp = SecurityStamp(
            value="secret_stamp_value_1234567890123456789012345",
            generated_at=datetime.now(UTC),
            purpose=SecurityStampPurpose.PASSWORD_CHANGE,
        )

        str_repr = str(stamp)
        repr_repr = repr(stamp)

        # Should not expose full stamp value
        assert "secret_stamp_value_1234567890123456789012345" not in str_repr
        assert "secret_stamp_value_1234567890123456789012345" not in repr_repr

        # Should show partial stamp and purpose
        assert "****" in str_repr or "..." in str_repr
        assert "PASSWORD_CHANGE" in str_repr

    def test_constant_time_comparison(self):
        """Test that stamp comparison is constant time."""
        import time

        stamp = SecurityStamp.generate(SecurityStampPurpose.INITIAL)

        # Time correct match
        start = time.perf_counter()
        for _ in range(1000):
            stamp.matches(stamp.value)
        correct_time = time.perf_counter() - start

        # Time incorrect match
        start = time.perf_counter()
        for _ in range(1000):
            stamp.matches("wrong_stamp_value_123456789012345678901234")
        incorrect_time = time.perf_counter() - start

        # Times should be similar (within 20%)
        ratio = correct_time / incorrect_time
        assert 0.8 < ratio < 1.2


class TestSecurityStampAudit:
    """Test security stamp audit functionality."""

    def test_audit_info_generation(self):
        """Test generating audit information."""
        metadata = {
            "ip_address": "192.168.1.1",
            "user_agent": "Mozilla/5.0",
            "session_id": "session_123",
        }

        stamp = SecurityStamp.generate(
            purpose=SecurityStampPurpose.PASSWORD_CHANGE, metadata=metadata
        )

        audit_info = stamp.to_audit_log()

        assert audit_info["purpose"] == "PASSWORD_CHANGE"
        assert audit_info["generated_at"] == stamp.generated_at.isoformat()
        assert audit_info["was_security_event"] is True
        assert audit_info["metadata"] == metadata
        assert "value" not in audit_info  # Never expose stamp value
        assert "partial_value" in audit_info  # Show partial for correlation

    def test_change_tracking(self):
        """Test tracking what changed with the stamp."""
        # Password change
        password_stamp = SecurityStamp.generate(
            purpose=SecurityStampPurpose.PASSWORD_CHANGE,
            metadata={"password_strength": "strong"},
        )

        changes = password_stamp.get_changes()
        assert "password" in changes
        assert changes["invalidates_sessions"] is True
        assert changes["requires_reauth"] is True

        # Email change
        email_stamp = SecurityStamp.generate(
            purpose=SecurityStampPurpose.EMAIL_CHANGE,
            metadata={"old_email": "old@example.com", "new_email": "new@example.com"},
        )

        changes = email_stamp.get_changes()
        assert "email" in changes
        assert changes["requires_verification"] is True


class TestSecurityStampChain:
    """Test security stamp chaining for history."""

    def test_stamp_chain_creation(self):
        """Test creating a chain of security stamps."""
        stamps = []

        # Initial stamp
        initial = SecurityStamp.generate(SecurityStampPurpose.INITIAL)
        stamps.append(initial)

        # Chain subsequent stamps
        for purpose in [
            SecurityStampPurpose.EMAIL_CHANGE,
            SecurityStampPurpose.PASSWORD_CHANGE,
            SecurityStampPurpose.MFA_CHANGE,
        ]:
            previous = stamps[-1]
            new_stamp = SecurityStamp.generate_chained(
                purpose=purpose, previous_stamp=previous
            )
            stamps.append(new_stamp)

        # Verify chain
        for i in range(1, len(stamps)):
            assert stamps[i].previous_stamp_hash is not None
            assert stamps[i].validates_chain(stamps[i - 1])

    def test_chain_validation(self):
        """Test validating stamp chains."""
        stamp1 = SecurityStamp.generate(SecurityStampPurpose.INITIAL)
        stamp2 = SecurityStamp.generate_chained(
            purpose=SecurityStampPurpose.PASSWORD_CHANGE, previous_stamp=stamp1
        )
        stamp3 = SecurityStamp.generate_chained(
            purpose=SecurityStampPurpose.EMAIL_CHANGE, previous_stamp=stamp2
        )

        # Valid chain
        assert stamp3.validates_full_chain([stamp1, stamp2, stamp3]) is True

        # Invalid chain (wrong order)
        assert stamp3.validates_full_chain([stamp2, stamp1, stamp3]) is False

        # Invalid chain (missing stamp)
        assert stamp3.validates_full_chain([stamp1, stamp3]) is False

    def test_create_valid_security_stamp(self):
        """Test creating a valid security stamp."""
        now = datetime.now(UTC)
        stamp = SecurityStamp(
            value="test_stamp_value_abcdef123456789012345678901234",
            generated_at=now,
            purpose=SecurityStampPurpose.INITIAL,
        )

        assert stamp.value == "test_stamp_value_abcdef123456789012345678901234"
        assert stamp.generated_at == now
        assert stamp.purpose == SecurityStampPurpose.INITIAL
        assert stamp.previous_stamp is None

    def test_create_with_previous_stamp(self):
        """Test creating stamp with reference to previous stamp."""
        now = datetime.now(UTC)
        stamp = SecurityStamp(
            value="new_stamp_value_abcdef123456789012345678901234",
            generated_at=now,
            purpose=SecurityStampPurpose.PASSWORD_CHANGE,
            previous_stamp="old_stamp_value_fedcba098765432109876543210987",
        )

        assert stamp.previous_stamp == "old_stamp_value_fedcba098765432109876543210987"

    def test_empty_value_raises_error(self):
        """Test that empty stamp value raises ValueError."""
        with pytest.raises(ValueError, match="Security stamp value is required"):
            SecurityStamp(
                value="",
                generated_at=datetime.now(UTC),
                purpose=SecurityStampPurpose.INITIAL,
            )

    def test_short_value_raises_error(self):
        """Test that short stamp value raises ValueError."""
        with pytest.raises(ValueError, match="Security stamp too short"):
            SecurityStamp(
                value="short",
                generated_at=datetime.now(UTC),
                purpose=SecurityStampPurpose.INITIAL,
            )

    def test_naive_datetime_raises_error(self):
        """Test that naive datetime raises ValueError."""
        with pytest.raises(ValueError, match="generated_at must be timezone-aware"):
            SecurityStamp(
                value="valid_stamp_value_abcdef123456789012345678901234",
                generated_at=datetime.now(),  # Naive datetime
                purpose=SecurityStampPurpose.INITIAL,
            )

    def test_short_previous_stamp_raises_error(self):
        """Test that short previous stamp raises ValueError."""
        with pytest.raises(ValueError, match="Previous stamp too short"):
            SecurityStamp(
                value="valid_stamp_value_abcdef123456789012345678901234",
                generated_at=datetime.now(UTC),
                purpose=SecurityStampPurpose.PASSWORD_CHANGE,
                previous_stamp="short",
            )


class TestSecurityStampGeneration:
    """Test security stamp generation methods."""

    def test_generate_stamp(self):
        """Test generating a new security stamp."""
        stamp = SecurityStamp.generate(SecurityStampPurpose.PASSWORD_CHANGE)

        assert len(stamp.value) >= 43  # URL-safe base64 of 32 bytes
        assert stamp.purpose == SecurityStampPurpose.PASSWORD_CHANGE
        assert stamp.previous_stamp is None
        assert stamp.generated_at.tzinfo is not None

    def test_generate_with_previous_stamp(self):
        """Test generating stamp with previous stamp reference."""
        previous_stamp = SecurityStamp.generate(SecurityStampPurpose.INITIAL)
        new_stamp = SecurityStamp.generate(
            SecurityStampPurpose.PASSWORD_CHANGE, previous_stamp=previous_stamp
        )

        assert new_stamp.previous_stamp == previous_stamp.value
        assert new_stamp.value != previous_stamp.value

    def test_generate_with_custom_length(self):
        """Test generating stamp with custom length."""
        stamp = SecurityStamp.generate(SecurityStampPurpose.INITIAL, length=64)

        # URL-safe base64 encoding of 64 bytes should be longer
        assert len(stamp.value) >= 85

    def test_generate_initial(self):
        """Test generating initial security stamp."""
        stamp = SecurityStamp.generate_initial()

        assert stamp.purpose == SecurityStampPurpose.INITIAL
        assert stamp.previous_stamp is None

    def test_generated_stamps_are_unique(self):
        """Test that generated stamps are unique."""
        stamps = [
            SecurityStamp.generate(SecurityStampPurpose.INITIAL) for _ in range(10)
        ]
        stamp_values = [s.value for s in stamps]

        assert len(set(stamp_values)) == 10  # All unique


class TestSecurityStampProperties:
    """Test security stamp properties and derived values."""

    def test_age_property(self):
        """Test age calculation."""
        past_time = datetime.now(UTC) - timedelta(hours=2)
        stamp = SecurityStamp(
            value="test_stamp_value_abcdef123456789012345678901234",
            generated_at=past_time,
            purpose=SecurityStampPurpose.INITIAL,
        )

        age = stamp.age
        assert age.total_seconds() >= 7200  # At least 2 hours

    def test_age_days_property(self):
        """Test age in days."""
        past_time = datetime.now(UTC) - timedelta(days=5)
        stamp = SecurityStamp(
            value="test_stamp_value_abcdef123456789012345678901234",
            generated_at=past_time,
            purpose=SecurityStampPurpose.INITIAL,
        )

        assert stamp.age_days == 5

    def test_should_rotate_default(self):
        """Test default rotation logic (90 days)."""
        old_stamp = SecurityStamp(
            value="test_stamp_value_abcdef123456789012345678901234",
            generated_at=datetime.now(UTC) - timedelta(days=95),
            purpose=SecurityStampPurpose.INITIAL,
        )

        recent_stamp = SecurityStamp(
            value="test_stamp_value_abcdef123456789012345678901234",
            generated_at=datetime.now(UTC) - timedelta(days=30),
            purpose=SecurityStampPurpose.INITIAL,
        )

        assert old_stamp.should_rotate is True
        assert recent_stamp.should_rotate is False

    def test_should_rotate_custom_threshold(self):
        """Test rotation with custom threshold."""
        stamp = SecurityStamp(
            value="test_stamp_value_abcdef123456789012345678901234",
            generated_at=datetime.now(UTC) - timedelta(days=35),
            purpose=SecurityStampPurpose.INITIAL,
        )

        assert stamp.should_rotate(max_age_days=30) is True
        assert stamp.should_rotate(max_age_days=40) is False

    def test_is_recent_default(self):
        """Test recent generation check (5 minutes)."""
        recent_stamp = SecurityStamp(
            value="test_stamp_value_abcdef123456789012345678901234",
            generated_at=datetime.now(UTC) - timedelta(minutes=2),
            purpose=SecurityStampPurpose.INITIAL,
        )

        old_stamp = SecurityStamp(
            value="test_stamp_value_abcdef123456789012345678901234",
            generated_at=datetime.now(UTC) - timedelta(minutes=10),
            purpose=SecurityStampPurpose.INITIAL,
        )

        assert recent_stamp.is_recent is True
        assert old_stamp.is_recent is False

    def test_is_recent_custom_threshold(self):
        """Test recent check with custom threshold."""
        stamp = SecurityStamp(
            value="test_stamp_value_abcdef123456789012345678901234",
            generated_at=datetime.now(UTC) - timedelta(minutes=8),
            purpose=SecurityStampPurpose.INITIAL,
        )

        assert stamp.is_recent(threshold_minutes=10) is True
        assert stamp.is_recent(threshold_minutes=5) is False


class TestSecurityStampPurposeClassification:
    """Test purpose classification methods."""

    def test_was_security_event(self):
        """Test security event classification."""
        security_purposes = [
            SecurityStampPurpose.PASSWORD_CHANGE,
            SecurityStampPurpose.SECURITY_RESET,
            SecurityStampPurpose.ACCOUNT_RECOVERY,
            SecurityStampPurpose.SUSPICIOUS_ACTIVITY,
            SecurityStampPurpose.MANUAL_INVALIDATION,
        ]

        for purpose in security_purposes:
            stamp = SecurityStamp(
                value="test_stamp_value_abcdef123456789012345678901234",
                generated_at=datetime.now(UTC),
                purpose=purpose,
            )
            assert stamp.was_security_event is True

        # Test non-security event
        normal_stamp = SecurityStamp(
            value="test_stamp_value_abcdef123456789012345678901234",
            generated_at=datetime.now(UTC),
            purpose=SecurityStampPurpose.INITIAL,
        )
        assert normal_stamp.was_security_event is False

    def test_was_profile_change(self):
        """Test profile change classification."""
        profile_purposes = [
            SecurityStampPurpose.EMAIL_CHANGE,
            SecurityStampPurpose.PHONE_CHANGE,
            SecurityStampPurpose.MFA_CHANGE,
        ]

        for purpose in profile_purposes:
            stamp = SecurityStamp(
                value="test_stamp_value_abcdef123456789012345678901234",
                generated_at=datetime.now(UTC),
                purpose=purpose,
            )
            assert stamp.was_profile_change is True

        # Test non-profile change
        other_stamp = SecurityStamp(
            value="test_stamp_value_abcdef123456789012345678901234",
            generated_at=datetime.now(UTC),
            purpose=SecurityStampPurpose.INITIAL,
        )
        assert other_stamp.was_profile_change is False

    def test_was_permission_change(self):
        """Test permission change classification."""
        permission_purposes = [
            SecurityStampPurpose.ROLE_CHANGE,
            SecurityStampPurpose.PERMISSION_CHANGE,
        ]

        for purpose in permission_purposes:
            stamp = SecurityStamp(
                value="test_stamp_value_abcdef123456789012345678901234",
                generated_at=datetime.now(UTC),
                purpose=purpose,
            )
            assert stamp.was_permission_change is True

        # Test non-permission change
        other_stamp = SecurityStamp(
            value="test_stamp_value_abcdef123456789012345678901234",
            generated_at=datetime.now(UTC),
            purpose=SecurityStampPurpose.INITIAL,
        )
        assert other_stamp.was_permission_change is False


class TestSecurityStampHashing:
    """Test hashing and comparison functionality."""

    def test_get_hash(self):
        """Test getting stamp hash."""
        stamp = SecurityStamp(
            value="test_stamp_value_abcdef123456789012345678901234",
            generated_at=datetime.now(UTC),
            purpose=SecurityStampPurpose.INITIAL,
        )

        hash_value = stamp.get_hash()
        assert len(hash_value) == 64  # SHA256 hex
        assert all(c in "0123456789abcdef" for c in hash_value)

    def test_get_short_hash(self):
        """Test getting shortened hash."""
        stamp = SecurityStamp(
            value="test_stamp_value_abcdef123456789012345678901234",
            generated_at=datetime.now(UTC),
            purpose=SecurityStampPurpose.INITIAL,
        )

        short_hash = stamp.get_short_hash()
        assert len(short_hash) == 16
        assert short_hash == stamp.get_hash()[:16]

    def test_matches_method(self):
        """Test stamp matching with timing-safe comparison."""
        stamp_value = "test_stamp_value_abcdef123456789012345678901234"
        stamp = SecurityStamp(
            value=stamp_value,
            generated_at=datetime.now(UTC),
            purpose=SecurityStampPurpose.INITIAL,
        )

        assert stamp.matches(stamp_value) is True
        assert stamp.matches("different_value") is False

    def test_different_stamps_different_hashes(self):
        """Test that different stamps produce different hashes."""
        stamp1 = SecurityStamp(
            value="stamp_value_1_abcdef123456789012345678901234",
            generated_at=datetime.now(UTC),
            purpose=SecurityStampPurpose.INITIAL,
        )

        stamp2 = SecurityStamp(
            value="stamp_value_2_fedcba098765432109876543210987",
            generated_at=datetime.now(UTC),
            purpose=SecurityStampPurpose.INITIAL,
        )

        assert stamp1.get_hash() != stamp2.get_hash()


class TestSecurityStampSuccession:
    """Test stamp succession and chaining."""

    def test_create_successor(self):
        """Test creating a successor stamp."""
        original = SecurityStamp.generate(SecurityStampPurpose.INITIAL)
        successor = original.create_successor(SecurityStampPurpose.PASSWORD_CHANGE)

        assert successor.previous_stamp == original.value
        assert successor.purpose == SecurityStampPurpose.PASSWORD_CHANGE
        assert successor.value != original.value

    def test_succession_chain(self):
        """Test creating a chain of successor stamps."""
        stamp1 = SecurityStamp.generate(SecurityStampPurpose.INITIAL)
        stamp2 = stamp1.create_successor(SecurityStampPurpose.EMAIL_CHANGE)
        stamp3 = stamp2.create_successor(SecurityStampPurpose.PASSWORD_CHANGE)

        assert stamp2.previous_stamp == stamp1.value
        assert stamp3.previous_stamp == stamp2.value
        assert len({stamp1.value, stamp2.value, stamp3.value}) == 3  # All unique


class TestSecurityStampAudit:
    """Test audit and logging functionality."""

    def test_to_audit_entry(self):
        """Test creating audit log entry."""
        stamp = SecurityStamp(
            value="test_stamp_value_abcdef123456789012345678901234",
            generated_at=datetime.now(UTC),
            purpose=SecurityStampPurpose.PASSWORD_CHANGE,
            previous_stamp="previous_stamp_value_fedcba098765432109876543",
        )

        audit_entry = stamp.to_audit_entry()

        assert audit_entry["stamp_hash"] == stamp.get_short_hash()
        assert audit_entry["purpose"] == "password_change"
        assert "generated_at" in audit_entry
        assert audit_entry["was_security_event"] is True
        assert "previous_stamp_hash" in audit_entry

    def test_audit_entry_without_previous_stamp(self):
        """Test audit entry for stamp without previous stamp."""
        stamp = SecurityStamp.generate_initial()
        audit_entry = stamp.to_audit_entry()

        assert audit_entry["previous_stamp_hash"] is None


class TestSecurityStampStringRepresentation:
    """Test string representation methods."""

    def test_str_representation_safe(self):
        """Test that __str__ doesn't expose sensitive data."""
        stamp = SecurityStamp(
            value="sensitive_stamp_value_abcdef123456789012345678901234",
            generated_at=datetime.now(UTC),
            purpose=SecurityStampPurpose.PASSWORD_CHANGE,
        )

        str_repr = str(stamp)

        assert "sensitive_stamp_value" not in str_repr
        assert "password_change" in str_repr
        assert stamp.get_short_hash() in str_repr

    def test_repr_representation_safe(self):
        """Test that __repr__ doesn't expose sensitive data."""
        stamp = SecurityStamp(
            value="sensitive_stamp_value_abcdef123456789012345678901234",
            generated_at=datetime.now(UTC) - timedelta(days=5),
            purpose=SecurityStampPurpose.PASSWORD_CHANGE,
        )

        repr_str = repr(stamp)

        assert "sensitive_stamp_value" not in repr_str
        assert "password_change" in repr_str
        assert "5d" in repr_str


class TestSecurityStampImmutability:
    """Test that SecurityStamp is immutable."""

    def test_immutable_value(self):
        """Test that value cannot be changed."""
        stamp = SecurityStamp(
            value="test_stamp_value_abcdef123456789012345678901234",
            generated_at=datetime.now(UTC),
            purpose=SecurityStampPurpose.INITIAL,
        )

        with pytest.raises(FrozenInstanceError):
            stamp.value = "new_value"

    def test_immutable_purpose(self):
        """Test that purpose cannot be changed."""
        stamp = SecurityStamp(
            value="test_stamp_value_abcdef123456789012345678901234",
            generated_at=datetime.now(UTC),
            purpose=SecurityStampPurpose.INITIAL,
        )

        with pytest.raises(FrozenInstanceError):
            stamp.purpose = SecurityStampPurpose.PASSWORD_CHANGE


class TestSecurityStampEquality:
    """Test equality and comparison behavior."""

    def test_equal_stamps(self):
        """Test that identical stamps are equal."""
        now = datetime.now(UTC)
        stamp1 = SecurityStamp(
            value="test_stamp_value_abcdef123456789012345678901234",
            generated_at=now,
            purpose=SecurityStampPurpose.INITIAL,
        )

        stamp2 = SecurityStamp(
            value="test_stamp_value_abcdef123456789012345678901234",
            generated_at=now,
            purpose=SecurityStampPurpose.INITIAL,
        )

        assert stamp1 == stamp2

    def test_different_stamps_not_equal(self):
        """Test that different stamps are not equal."""
        now = datetime.now(UTC)
        stamp1 = SecurityStamp(
            value="stamp_value_1_abcdef123456789012345678901234",
            generated_at=now,
            purpose=SecurityStampPurpose.INITIAL,
        )

        stamp2 = SecurityStamp(
            value="stamp_value_2_fedcba098765432109876543210987",
            generated_at=now,
            purpose=SecurityStampPurpose.INITIAL,
        )

        assert stamp1 != stamp2


class TestSecurityStampEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_minimum_valid_length(self):
        """Test stamp with minimum valid length."""
        stamp = SecurityStamp(
            value="a" * 32,  # Minimum length
            generated_at=datetime.now(UTC),
            purpose=SecurityStampPurpose.INITIAL,
        )

        assert len(stamp.value) == 32

    def test_very_old_stamp(self):
        """Test behavior with very old stamp."""
        very_old = datetime.now(UTC) - timedelta(days=1000)
        stamp = SecurityStamp(
            value="test_stamp_value_abcdef123456789012345678901234",
            generated_at=very_old,
            purpose=SecurityStampPurpose.INITIAL,
        )

        assert stamp.age_days >= 1000
        assert stamp.should_rotate is True
        assert stamp.is_recent is False

    def test_future_timestamp_edge_case(self):
        """Test stamp with future timestamp (edge case)."""
        future_time = datetime.now(UTC) + timedelta(minutes=1)
        stamp = SecurityStamp(
            value="test_stamp_value_abcdef123456789012345678901234",
            generated_at=future_time,
            purpose=SecurityStampPurpose.INITIAL,
        )

        # Should handle gracefully, age might be negative
        assert stamp.generated_at == future_time
