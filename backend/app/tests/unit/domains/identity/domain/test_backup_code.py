"""
Test cases for BackupCode value object.

Tests all aspects of backup codes including generation, validation,
verification, and security features.
"""

import hashlib
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta

import pytest

from app.modules.identity.domain.value_objects.backup_code import (
    BackupCode,
    BackupCodeFormat,
    BackupCodeStatus,
)


class TestBackupCodeCreation:
    """Test BackupCode creation and validation."""

    def test_create_valid_backup_code(self):
        """Test creating a valid backup code."""
        timestamp = datetime.now(UTC)
        backup_code = BackupCode(
            code_hash="a" * 64,  # SHA256 hash
            generated_at=timestamp,
            status=BackupCodeStatus.ACTIVE,
            format_type=BackupCodeFormat.ALPHANUMERIC,
        )

        assert backup_code.code_hash == "a" * 64
        assert backup_code.generated_at == timestamp
        assert backup_code.status == BackupCodeStatus.ACTIVE
        assert backup_code.format_type == BackupCodeFormat.ALPHANUMERIC
        assert backup_code.is_active is True
        assert backup_code.is_used is False

    def test_create_with_different_formats(self):
        """Test creating backup codes with different formats."""
        timestamp = datetime.now(UTC)

        # Numeric format
        numeric = BackupCode(
            code_hash="b" * 64,
            generated_at=timestamp,
            format_type=BackupCodeFormat.NUMERIC,
        )
        assert numeric.format_type == BackupCodeFormat.NUMERIC

        # Grouped format
        grouped = BackupCode(
            code_hash="c" * 64,
            generated_at=timestamp,
            format_type=BackupCodeFormat.GROUPED,
        )
        assert grouped.format_type == BackupCodeFormat.GROUPED

    def test_invalid_backup_code(self):
        """Test validation of invalid backup codes."""
        timestamp = datetime.now(UTC)

        # Missing code hash
        with pytest.raises(ValueError, match="Code hash is required"):
            BackupCode(code_hash="", generated_at=timestamp)

        # Invalid hash format
        with pytest.raises(ValueError, match="Invalid code hash format"):
            BackupCode(code_hash="invalid!@#$%", generated_at=timestamp)

        # Timezone naive timestamp
        with pytest.raises(ValueError, match="generated_at must be timezone-aware"):
            BackupCode(code_hash="a" * 64, generated_at=datetime.now())  # No timezone

        # Used status without used_at
        with pytest.raises(ValueError, match="Used codes must have used_at timestamp"):
            BackupCode(
                code_hash="a" * 64, generated_at=timestamp, status=BackupCodeStatus.USED
            )

        # used_at without used status
        with pytest.raises(
            ValueError, match="Only used codes should have used_at timestamp"
        ):
            BackupCode(
                code_hash="a" * 64,
                generated_at=timestamp,
                status=BackupCodeStatus.ACTIVE,
                used_at=timestamp,
            )


class TestBackupCodeGeneration:
    """Test backup code generation functionality."""

    def test_generate_single_code(self):
        """Test generating a single backup code."""
        code, plain = BackupCode.generate_single()

        assert code.is_active is True
        assert code.format_type == BackupCodeFormat.ALPHANUMERIC
        assert len(plain) == 8  # Default length
        assert code.verify_code(plain) is True

    def test_generate_code_set(self):
        """Test generating a set of backup codes."""
        codes, plains = BackupCode.generate_set(count=10)

        assert len(codes) == 10
        assert len(plains) == 10

        # All codes should be unique
        hashes = [code.code_hash for code in codes]
        assert len(hashes) == len(set(hashes))

        # All plain codes should be unique
        assert len(plains) == len(set(plains))

        # Each code should verify
        for code, plain in zip(codes, plains, strict=False):
            assert code.verify_code(plain) is True

    def test_generate_with_custom_format(self):
        """Test generating codes with custom formats."""
        # Numeric codes
        numeric_codes, numeric_plains = BackupCode.generate_set(
            count=5, format_type=BackupCodeFormat.NUMERIC, length=6
        )

        for code, plain in zip(numeric_codes, numeric_plains, strict=False):
            assert code.format_type == BackupCodeFormat.NUMERIC
            assert len(plain) == 6
            assert plain.isdigit()

        # Grouped codes
        grouped_codes, grouped_plains = BackupCode.generate_set(
            count=3, format_type=BackupCodeFormat.GROUPED, length=12
        )

        for code, plain in zip(grouped_codes, grouped_plains, strict=False):
            assert code.format_type == BackupCodeFormat.GROUPED
            assert "-" in plain  # Has group separators

    def test_generate_with_custom_length(self):
        """Test generating codes with custom lengths."""
        lengths = [6, 8, 10, 12, 16]

        for length in lengths:
            code, plain = BackupCode.generate_single(length=length)
            # Account for separators in grouped format
            if code.format_type == BackupCodeFormat.GROUPED:
                assert len(plain.replace("-", "")) == length
            else:
                assert len(plain) == length


class TestBackupCodeVerification:
    """Test backup code verification functionality."""

    def test_verify_correct_code(self):
        """Test verifying correct backup codes."""
        code, plain = BackupCode.generate_single()

        # Exact match
        assert code.verify_code(plain) is True

        # Case insensitive
        assert code.verify_code(plain.lower()) is True
        assert code.verify_code(plain.upper()) is True

        # With whitespace
        assert code.verify_code(f" {plain} ") is True
        assert code.verify_code(plain.replace("-", " ")) is True

    def test_verify_incorrect_code(self):
        """Test verifying incorrect backup codes."""
        code, plain = BackupCode.generate_single()

        # Wrong code
        assert code.verify_code("WRONGCODE") is False

        # Modified code
        if len(plain) > 1:
            modified = plain[:-1] + ("X" if plain[-1] != "X" else "Y")
            assert code.verify_code(modified) is False

        # Empty code
        assert code.verify_code("") is False

        # None
        assert code.verify_code(None) is False

    def test_verify_used_code(self):
        """Test that used codes cannot be verified."""
        code, plain = BackupCode.generate_single()

        # Mark as used
        used_code = code.mark_used()

        # Should not verify even with correct plain code
        assert used_code.verify_code(plain) is False

    def test_verify_revoked_code(self):
        """Test that revoked codes cannot be verified."""
        code, plain = BackupCode.generate_single()

        # Revoke code
        revoked_code = code.revoke()

        # Should not verify even with correct plain code
        assert revoked_code.verify_code(plain) is False


class TestBackupCodeUsage:
    """Test backup code usage tracking."""

    def test_mark_code_used(self):
        """Test marking a code as used."""
        code, _ = BackupCode.generate_single()

        assert code.is_active is True
        assert code.is_used is False
        assert code.used_at is None

        # Mark as used
        used_code = code.mark_used()

        assert used_code.is_active is False
        assert used_code.is_used is True
        assert used_code.status == BackupCodeStatus.USED
        assert used_code.used_at is not None
        assert used_code.used_at <= datetime.now(UTC)

        # Original should be unchanged (immutable)
        assert code.is_active is True
        assert code.is_used is False

    def test_cannot_use_already_used_code(self):
        """Test that already used codes cannot be used again."""
        code, _ = BackupCode.generate_single()
        used_code = code.mark_used()

        with pytest.raises(ValueError, match="Cannot use already used code"):
            used_code.mark_used()

    def test_cannot_use_revoked_code(self):
        """Test that revoked codes cannot be used."""
        code, _ = BackupCode.generate_single()
        revoked_code = code.revoke()

        with pytest.raises(ValueError, match="Cannot use revoked code"):
            revoked_code.mark_used()

    def test_usage_statistics(self):
        """Test backup code usage statistics."""
        codes, _ = BackupCode.generate_set(count=10)

        # Use some codes
        used_codes = [codes[0].mark_used(), codes[1].mark_used(), codes[2].mark_used()]

        # Revoke one code
        revoked_code = codes[3].revoke()

        all_codes = used_codes + [revoked_code] + codes[4:]

        stats = BackupCode.get_statistics(all_codes)

        assert stats["total"] == 10
        assert stats["active"] == 6
        assert stats["used"] == 3
        assert stats["revoked"] == 1
        assert stats["usage_percentage"] == 30.0


class TestBackupCodeRevocation:
    """Test backup code revocation functionality."""

    def test_revoke_active_code(self):
        """Test revoking an active backup code."""
        code, _ = BackupCode.generate_single()

        assert code.status == BackupCodeStatus.ACTIVE

        # Revoke code
        revoked = code.revoke(reason="Security policy update")

        assert revoked.status == BackupCodeStatus.REVOKED
        assert revoked.is_active is False
        assert revoked.is_revoked is True
        assert revoked.revoked_at is not None
        assert revoked.revocation_reason == "Security policy update"

        # Original should be unchanged
        assert code.status == BackupCodeStatus.ACTIVE

    def test_cannot_revoke_used_code(self):
        """Test that used codes cannot be revoked."""
        code, _ = BackupCode.generate_single()
        used_code = code.mark_used()

        with pytest.raises(ValueError, match="Cannot revoke used code"):
            used_code.revoke()

    def test_cannot_revoke_already_revoked(self):
        """Test that already revoked codes cannot be revoked again."""
        code, _ = BackupCode.generate_single()
        revoked_code = code.revoke()

        with pytest.raises(ValueError, match="Code is already revoked"):
            revoked_code.revoke()

    def test_bulk_revocation(self):
        """Test bulk revocation of backup codes."""
        codes, _ = BackupCode.generate_set(count=10)

        # Revoke all codes
        revoked_codes = BackupCode.revoke_all(codes, reason="User requested new set")

        assert len(revoked_codes) == 10
        for code in revoked_codes:
            assert code.is_revoked is True
            assert code.revocation_reason == "User requested new set"


class TestBackupCodeSecurity:
    """Test backup code security features."""

    def test_code_immutability(self):
        """Test that backup codes are immutable."""
        code, _ = BackupCode.generate_single()

        with pytest.raises(FrozenInstanceError):
            code.code_hash = "modified"

        with pytest.raises(FrozenInstanceError):
            code.status = BackupCodeStatus.USED

    def test_code_comparison(self):
        """Test backup code comparison."""
        timestamp = datetime.now(UTC)

        code1 = BackupCode(
            code_hash="a" * 64, generated_at=timestamp, status=BackupCodeStatus.ACTIVE
        )

        code2 = BackupCode(
            code_hash="a" * 64, generated_at=timestamp, status=BackupCodeStatus.ACTIVE
        )

        code3 = BackupCode(
            code_hash="b" * 64, generated_at=timestamp, status=BackupCodeStatus.ACTIVE
        )

        assert code1 == code2
        assert code1 != code3
        assert hash(code1) == hash(code2)
        assert hash(code1) != hash(code3)

    def test_secure_string_representation(self):
        """Test that string representations don't expose sensitive data."""
        code, plain = BackupCode.generate_single()

        str_repr = str(code)
        repr_repr = repr(code)

        # Should not expose hash
        assert code.code_hash not in str_repr
        assert code.code_hash not in repr_repr

        # Should include status for identification
        assert "ACTIVE" in str_repr or "active" in str_repr.lower()

    def test_timing_safe_verification(self):
        """Test that verification is timing-safe."""
        import time

        code, plain = BackupCode.generate_single()

        # Time correct verification
        start = time.perf_counter()
        for _ in range(100):
            code.verify_code(plain)
        correct_time = time.perf_counter() - start

        # Time incorrect verification
        start = time.perf_counter()
        for _ in range(100):
            code.verify_code("WRONGCODE")
        incorrect_time = time.perf_counter() - start

        # Times should be similar (within 20% variance)
        time_ratio = correct_time / incorrect_time
        assert 0.8 < time_ratio < 1.2


class TestBackupCodeExpiration:
    """Test backup code expiration functionality."""

    def test_code_expiration(self):
        """Test backup code expiration."""
        # Create expired code
        past_time = datetime.now(UTC) - timedelta(days=365)
        expired_code = BackupCode(
            code_hash="a" * 64,
            generated_at=past_time,
            expires_at=datetime.now(UTC) - timedelta(days=1),
        )

        assert expired_code.is_expired is True
        assert expired_code.is_active is False

        # Create valid code
        valid_code = BackupCode(
            code_hash="b" * 64,
            generated_at=datetime.now(UTC),
            expires_at=datetime.now(UTC) + timedelta(days=365),
        )

        assert valid_code.is_expired is False
        assert valid_code.is_active is True

    def test_expired_code_verification(self):
        """Test that expired codes cannot be verified."""
        # Generate code and manually set expiration
        code, plain = BackupCode.generate_single()

        expired_code = BackupCode(
            code_hash=code.code_hash,
            generated_at=code.generated_at,
            expires_at=datetime.now(UTC) - timedelta(days=1),
            salt=code.salt,
        )

        # Should not verify even with correct plain code
        assert expired_code.verify_code(plain) is False


class TestBackupCodeAudit:
    """Test backup code audit functionality."""

    def test_audit_log_generation(self):
        """Test generating audit log entries."""
        code, _ = BackupCode.generate_single()

        # Generate audit entry for usage
        audit = code.create_audit_entry(
            action="verified", ip_address="192.168.1.1", user_agent="Mozilla/5.0..."
        )

        assert audit["code_id"] == code.get_identifier()
        assert audit["action"] == "verified"
        assert audit["status"] == "ACTIVE"
        assert audit["ip_address"] == "192.168.1.1"
        assert audit["user_agent"] == "Mozilla/5.0..."
        assert "timestamp" in audit
        assert "code_hash" not in audit  # Never expose hash

    def test_usage_history(self):
        """Test tracking usage history."""
        code, plain = BackupCode.generate_single()

        # Track verification attempts
        history = []

        # Successful verification
        history.append(
            code.track_verification_attempt(success=True, ip_address="192.168.1.1")
        )

        # Failed verification
        history.append(
            code.track_verification_attempt(success=False, ip_address="10.0.0.1")
        )

        assert len(history) == 2
        assert history[0]["success"] is True
        assert history[1]["success"] is False
        assert history[0]["ip_address"] == "192.168.1.1"
        assert history[1]["ip_address"] == "10.0.0.1"

    """Test BackupCode creation and validation."""

    def test_create_valid_backup_code(self):
        """Test creating a valid backup code."""
        now = datetime.now(UTC)
        code_hash = hashlib.sha256(b"TEST12345").hexdigest()

        backup_code = BackupCode(
            code_hash=code_hash,
            generated_at=now,
            status=BackupCodeStatus.ACTIVE,
            format_type=BackupCodeFormat.ALPHANUMERIC,
        )

        assert backup_code.code_hash == code_hash
        assert backup_code.generated_at == now
        assert backup_code.status == BackupCodeStatus.ACTIVE
        assert backup_code.format_type == BackupCodeFormat.ALPHANUMERIC
        assert backup_code.used_at is None

    def test_create_used_backup_code(self):
        """Test creating a used backup code."""
        now = datetime.now(UTC)
        used_at = now + timedelta(hours=1)
        code_hash = hashlib.sha256(b"USED12345").hexdigest()

        backup_code = BackupCode(
            code_hash=code_hash,
            generated_at=now,
            status=BackupCodeStatus.USED,
            used_at=used_at,
            format_type=BackupCodeFormat.NUMERIC,
        )

        assert backup_code.status == BackupCodeStatus.USED
        assert backup_code.used_at == used_at
        assert backup_code.format_type == BackupCodeFormat.NUMERIC

    def test_empty_code_hash_raises_error(self):
        """Test that empty code hash raises ValueError."""
        with pytest.raises(ValueError, match="Code hash is required"):
            BackupCode(code_hash="", generated_at=datetime.now(UTC))

    def test_invalid_hash_format_raises_error(self):
        """Test that invalid hash format raises ValueError."""
        with pytest.raises(ValueError, match="Invalid code hash format"):
            BackupCode(code_hash="invalid@hash#format!", generated_at=datetime.now(UTC))

    def test_naive_generated_at_raises_error(self):
        """Test that naive datetime for generated_at raises ValueError."""
        code_hash = hashlib.sha256(b"TEST").hexdigest()

        with pytest.raises(ValueError, match="generated_at must be timezone-aware"):
            BackupCode(
                code_hash=code_hash, generated_at=datetime.now()  # Naive datetime
            )

    def test_naive_used_at_raises_error(self):
        """Test that naive datetime for used_at raises ValueError."""
        code_hash = hashlib.sha256(b"TEST").hexdigest()

        with pytest.raises(ValueError, match="used_at must be timezone-aware"):
            BackupCode(
                code_hash=code_hash,
                generated_at=datetime.now(UTC),
                status=BackupCodeStatus.USED,
                used_at=datetime.now(),  # Naive datetime
            )

    def test_used_status_without_timestamp_raises_error(self):
        """Test that USED status without used_at raises ValueError."""
        code_hash = hashlib.sha256(b"TEST").hexdigest()

        with pytest.raises(ValueError, match="Used codes must have used_at timestamp"):
            BackupCode(
                code_hash=code_hash,
                generated_at=datetime.now(UTC),
                status=BackupCodeStatus.USED,
                used_at=None,
            )

    def test_used_timestamp_without_used_status_raises_error(self):
        """Test that used_at without USED status raises ValueError."""
        code_hash = hashlib.sha256(b"TEST").hexdigest()

        with pytest.raises(
            ValueError, match="Only used codes should have used_at timestamp"
        ):
            BackupCode(
                code_hash=code_hash,
                generated_at=datetime.now(UTC),
                status=BackupCodeStatus.ACTIVE,
                used_at=datetime.now(UTC),
            )


class TestBackupCodeGeneration:
    """Test backup code generation methods."""

    def test_generate_set_default(self):
        """Test generating default set of backup codes."""
        codes, plain_codes = BackupCode.generate_set()

        assert len(codes) == 10
        assert len(plain_codes) == 10
        assert len(codes) == len(plain_codes)

        for code in codes:
            assert code.status == BackupCodeStatus.ACTIVE
            assert code.format_type == BackupCodeFormat.ALPHANUMERIC
            assert code.used_at is None
            assert len(code.code_hash) == 64  # SHA256 hex

        # All codes should be unique
        code_hashes = [code.code_hash for code in codes]
        assert len(set(code_hashes)) == 10

        plain_code_values = set(plain_codes)
        assert len(plain_code_values) == 10

    def test_generate_set_custom_count(self):
        """Test generating custom count of backup codes."""
        codes, plain_codes = BackupCode.generate_set(count=5)

        assert len(codes) == 5
        assert len(plain_codes) == 5

    def test_generate_numeric_codes(self):
        """Test generating numeric backup codes."""
        codes, plain_codes = BackupCode.generate_set(
            count=3, format_type=BackupCodeFormat.NUMERIC, length=10
        )

        for i, code in enumerate(codes):
            assert code.format_type == BackupCodeFormat.NUMERIC
            plain_code = plain_codes[i]
            assert len(plain_code) == 10
            assert plain_code.isdigit()

    def test_generate_alphanumeric_codes(self):
        """Test generating alphanumeric backup codes."""
        codes, plain_codes = BackupCode.generate_set(
            count=3, format_type=BackupCodeFormat.ALPHANUMERIC, length=12
        )

        for i, code in enumerate(codes):
            assert code.format_type == BackupCodeFormat.ALPHANUMERIC
            plain_code = plain_codes[i]
            assert len(plain_code) == 12
            # Should not contain ambiguous characters
            assert "O" not in plain_code
            assert "0" not in plain_code
            assert "I" not in plain_code
            assert "l" not in plain_code

    def test_generate_word_based_codes(self):
        """Test generating word-based backup codes."""
        codes, plain_codes = BackupCode.generate_set(
            count=3, format_type=BackupCodeFormat.WORDS
        )

        for i, code in enumerate(codes):
            assert code.format_type == BackupCodeFormat.WORDS
            plain_code = plain_codes[i]
            # Should have format: word-word-number
            parts = plain_code.split("-")
            assert len(parts) == 3
            assert parts[0].isalpha()
            assert parts[1].isalpha()
            assert parts[2].isdigit()

    def test_generate_grouped_codes(self):
        """Test generating grouped format backup codes."""
        codes, plain_codes = BackupCode.generate_set(
            count=3, format_type=BackupCodeFormat.GROUPED
        )

        for i, code in enumerate(codes):
            assert code.format_type == BackupCodeFormat.GROUPED
            plain_code = plain_codes[i]
            # Should have format: XXXX-XXXX-XXXX
            parts = plain_code.split("-")
            assert len(parts) == 3
            for part in parts:
                assert len(part) == 4
                assert part.isalnum()

    def test_from_plain_code(self):
        """Test creating backup code from plain text."""
        backup_code = BackupCode.from_plain_code(
            plain_code="TEST1234", format_type=BackupCodeFormat.ALPHANUMERIC
        )

        expected_hash = hashlib.sha256(b"TEST1234").hexdigest()
        assert backup_code.code_hash == expected_hash
        assert backup_code.format_type == BackupCodeFormat.ALPHANUMERIC
        assert backup_code.status == BackupCodeStatus.ACTIVE

    def test_from_plain_code_normalizes_input(self):
        """Test that plain code input is normalized."""
        backup_code = BackupCode.from_plain_code(
            plain_code="  test1234  ",  # With whitespace and lowercase
            format_type=BackupCodeFormat.ALPHANUMERIC,
        )

        expected_hash = hashlib.sha256(b"TEST1234").hexdigest()
        assert backup_code.code_hash == expected_hash

    def test_from_plain_code_grouped_removes_dashes(self):
        """Test that grouped format removes dashes during creation."""
        backup_code = BackupCode.from_plain_code(
            plain_code="ABCD-EFGH-IJKL", format_type=BackupCodeFormat.GROUPED
        )

        expected_hash = hashlib.sha256(b"ABCDEFGHIJKL").hexdigest()
        assert backup_code.code_hash == expected_hash


class TestBackupCodeVerification:
    """Test backup code verification functionality."""

    def test_verify_correct_code(self):
        """Test verifying correct plain code."""
        backup_code = BackupCode.from_plain_code("CORRECT123")

        assert backup_code.verify_code("CORRECT123") is True

    def test_verify_incorrect_code(self):
        """Test verifying incorrect plain code."""
        backup_code = BackupCode.from_plain_code("CORRECT123")

        assert backup_code.verify_code("WRONG123") is False

    def test_verify_normalizes_input(self):
        """Test that verification normalizes input."""
        backup_code = BackupCode.from_plain_code("TEST1234")

        # Should work with different formatting
        assert backup_code.verify_code("  test1234  ") is True
        assert backup_code.verify_code("Test1234") is True

    def test_verify_grouped_format_removes_dashes(self):
        """Test that verification removes dashes for grouped format."""
        backup_code = BackupCode.from_plain_code(
            "ABCD-EFGH-IJKL", format_type=BackupCodeFormat.GROUPED
        )

        # Should work with or without dashes
        assert backup_code.verify_code("ABCDEFGHIJKL") is True
        assert backup_code.verify_code("ABCD-EFGH-IJKL") is True

    def test_verify_timing_safe(self):
        """Test that verification uses timing-safe comparison."""
        backup_code = BackupCode.from_plain_code("SECRET123")

        # The verify_code method uses secrets.compare_digest
        # This test ensures it doesn't raise exceptions
        assert backup_code.verify_code("SECRET123") is True
        assert backup_code.verify_code("") is False
        assert backup_code.verify_code("DIFFERENT") is False


class TestBackupCodeStatusTransitions:
    """Test backup code status transitions."""

    def test_mark_used_active_code(self):
        """Test marking active code as used."""
        original = BackupCode.from_plain_code("ACTIVE123")
        used_code = original.mark_used()

        assert used_code.status == BackupCodeStatus.USED
        assert used_code.used_at is not None
        assert used_code.code_hash == original.code_hash
        assert original.status == BackupCodeStatus.ACTIVE  # Original unchanged

    def test_mark_used_non_active_raises_error(self):
        """Test that marking non-active code as used raises error."""
        revoked_code = BackupCode(
            code_hash=hashlib.sha256(b"TEST").hexdigest(),
            generated_at=datetime.now(UTC),
            status=BackupCodeStatus.REVOKED,
        )

        with pytest.raises(ValueError, match="Cannot use revoked code"):
            revoked_code.mark_used()

    def test_revoke_active_code(self):
        """Test revoking active code."""
        original = BackupCode.from_plain_code("ACTIVE123")
        revoked_code = original.revoke()

        assert revoked_code.status == BackupCodeStatus.REVOKED
        assert revoked_code.used_at is None
        assert revoked_code.code_hash == original.code_hash
        assert original.status == BackupCodeStatus.ACTIVE  # Original unchanged

    def test_revoke_used_code_raises_error(self):
        """Test that revoking used code raises error."""
        used_code = BackupCode(
            code_hash=hashlib.sha256(b"TEST").hexdigest(),
            generated_at=datetime.now(UTC),
            status=BackupCodeStatus.USED,
            used_at=datetime.now(UTC),
        )

        with pytest.raises(ValueError, match="Cannot revoke used code"):
            used_code.revoke()


class TestBackupCodeProperties:
    """Test backup code properties."""

    def test_is_active_property(self):
        """Test is_active property."""
        active_code = BackupCode.from_plain_code("ACTIVE123")
        used_code = active_code.mark_used()
        revoked_code = active_code.revoke()

        assert active_code.is_active is True
        assert used_code.is_active is False
        assert revoked_code.is_active is False

    def test_is_used_property(self):
        """Test is_used property."""
        active_code = BackupCode.from_plain_code("ACTIVE123")
        used_code = active_code.mark_used()
        revoked_code = active_code.revoke()

        assert active_code.is_used is False
        assert used_code.is_used is True
        assert revoked_code.is_used is False

    def test_age_days_property(self):
        """Test age_days calculation."""
        past_time = datetime.now(UTC) - timedelta(days=5)
        backup_code = BackupCode(
            code_hash=hashlib.sha256(b"TEST").hexdigest(), generated_at=past_time
        )

        assert backup_code.age_days == 5

    def test_get_fingerprint(self):
        """Test getting code fingerprint."""
        backup_code = BackupCode.from_plain_code("FINGERPRINT123")

        fingerprint = backup_code.get_fingerprint()
        assert len(fingerprint) == 8
        assert fingerprint == backup_code.code_hash[:8]
        assert all(c in "0123456789abcdef" for c in fingerprint)


class TestBackupCodeFormatting:
    """Test backup code formatting functionality."""

    def test_format_alphanumeric_for_display(self):
        """Test formatting alphanumeric code for display."""
        backup_code = BackupCode.from_plain_code(
            "ABCD1234", format_type=BackupCodeFormat.ALPHANUMERIC
        )

        formatted = backup_code.format_for_display("ABCD1234")
        assert formatted == "ABCD-1234"

    def test_format_numeric_for_display(self):
        """Test formatting numeric code for display."""
        backup_code = BackupCode.from_plain_code(
            "12345678", format_type=BackupCodeFormat.NUMERIC
        )

        formatted = backup_code.format_for_display("12345678")
        assert formatted == "1234 5678"

    def test_format_grouped_for_display(self):
        """Test formatting grouped code for display."""
        backup_code = BackupCode.from_plain_code(
            "ABCD-EFGH-IJKL", format_type=BackupCodeFormat.GROUPED
        )

        formatted = backup_code.format_for_display("ABCD-EFGH-IJKL")
        assert formatted == "ABCD-EFGH-IJKL"  # Already formatted

    def test_format_words_for_display(self):
        """Test formatting word-based code for display."""
        backup_code = BackupCode.from_plain_code(
            "swift-falcon-123", format_type=BackupCodeFormat.WORDS
        )

        formatted = backup_code.format_for_display("swift-falcon-123")
        assert formatted == "swift-falcon-123"  # No change

    def test_format_odd_length_codes(self):
        """Test formatting codes with odd lengths."""
        backup_code = BackupCode.from_plain_code(
            "ABC123", format_type=BackupCodeFormat.ALPHANUMERIC  # 6 chars, not 8
        )

        formatted = backup_code.format_for_display("ABC123")
        assert formatted == "ABC123"  # No formatting for odd length


class TestBackupCodeAudit:
    """Test audit functionality."""

    def test_to_audit_entry_active_code(self):
        """Test audit entry for active code."""
        backup_code = BackupCode.from_plain_code("AUDIT123")

        audit_entry = backup_code.to_audit_entry()

        assert audit_entry["fingerprint"] == backup_code.get_fingerprint()
        assert audit_entry["status"] == "active"
        assert audit_entry["format"] == "alphanumeric"
        assert "generated_at" in audit_entry
        assert audit_entry["age_days"] == 0
        assert "used_at" not in audit_entry

    def test_to_audit_entry_used_code(self):
        """Test audit entry for used code."""
        active_code = BackupCode.from_plain_code("AUDIT123")
        used_code = active_code.mark_used()

        audit_entry = used_code.to_audit_entry()

        assert audit_entry["status"] == "used"
        assert "used_at" in audit_entry


class TestBackupCodeStringRepresentation:
    """Test string representation methods."""

    def test_str_representation_safe(self):
        """Test that __str__ doesn't expose sensitive data."""
        backup_code = BackupCode.from_plain_code("SENSITIVE123")

        str_repr = str(backup_code)

        assert "SENSITIVE123" not in str_repr
        assert backup_code.get_fingerprint() in str_repr
        assert "active" in str_repr

    def test_repr_representation_safe(self):
        """Test that __repr__ doesn't expose sensitive data."""
        past_time = datetime.now(UTC) - timedelta(days=3)
        backup_code = BackupCode(
            code_hash=hashlib.sha256(b"SENSITIVE").hexdigest(),
            generated_at=past_time,
            format_type=BackupCodeFormat.NUMERIC,
        )

        repr_str = repr(backup_code)

        assert "SENSITIVE" not in repr_str
        assert "numeric" in repr_str
        assert "active" in repr_str
        assert "3d" in repr_str


class TestBackupCodeImmutability:
    """Test that BackupCode is immutable."""

    def test_immutable_code_hash(self):
        """Test that code_hash cannot be changed."""
        backup_code = BackupCode.from_plain_code("IMMUTABLE123")

        with pytest.raises(FrozenInstanceError):
            backup_code.code_hash = "new_hash"

    def test_immutable_status(self):
        """Test that status cannot be changed directly."""
        backup_code = BackupCode.from_plain_code("IMMUTABLE123")

        with pytest.raises(FrozenInstanceError):
            backup_code.status = BackupCodeStatus.USED

    def test_immutable_generated_at(self):
        """Test that generated_at cannot be changed."""
        backup_code = BackupCode.from_plain_code("IMMUTABLE123")

        with pytest.raises(FrozenInstanceError):
            backup_code.generated_at = datetime.now(UTC)


class TestBackupCodeEquality:
    """Test equality and comparison behavior."""

    def test_equal_codes(self):
        """Test that identical codes are equal."""
        now = datetime.now(UTC)
        code_hash = hashlib.sha256(b"EQUAL123").hexdigest()

        code1 = BackupCode(
            code_hash=code_hash,
            generated_at=now,
            status=BackupCodeStatus.ACTIVE,
            format_type=BackupCodeFormat.ALPHANUMERIC,
        )

        code2 = BackupCode(
            code_hash=code_hash,
            generated_at=now,
            status=BackupCodeStatus.ACTIVE,
            format_type=BackupCodeFormat.ALPHANUMERIC,
        )

        assert code1 == code2

    def test_different_codes_not_equal(self):
        """Test that different codes are not equal."""
        code1 = BackupCode.from_plain_code("CODE1")
        code2 = BackupCode.from_plain_code("CODE2")

        assert code1 != code2

    def test_different_status_not_equal(self):
        """Test that same code with different status are not equal."""
        original = BackupCode.from_plain_code("STATUS123")
        used = original.mark_used()

        assert original != used


class TestBackupCodeEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_empty_plain_code_verification(self):
        """Test verification with empty plain code."""
        backup_code = BackupCode.from_plain_code("NONEMPTY123")

        assert backup_code.verify_code("") is False

    def test_very_long_plain_code(self):
        """Test with very long plain code."""
        long_code = "A" * 100
        backup_code = BackupCode.from_plain_code(long_code)

        assert backup_code.verify_code(long_code) is True
        assert len(backup_code.code_hash) == 64  # SHA256 always 64 chars

    def test_unicode_in_plain_code(self):
        """Test handling of unicode characters in plain code."""
        unicode_code = "TEST123É"  # Contains accented character
        backup_code = BackupCode.from_plain_code(unicode_code)

        # Should normalize to uppercase
        assert backup_code.verify_code("TEST123É") is True

    def test_all_backup_code_formats(self):
        """Test that all format types can be created."""
        for format_type in BackupCodeFormat:
            codes, plain_codes = BackupCode.generate_set(
                count=1, format_type=format_type
            )

            assert len(codes) == 1
            assert codes[0].format_type == format_type
            assert len(plain_codes) == 1

    def test_all_backup_code_statuses(self):
        """Test that all status types are handled."""
        code_hash = hashlib.sha256(b"STATUS_TEST").hexdigest()
        now = datetime.now(UTC)

        for status in BackupCodeStatus:
            if status == BackupCodeStatus.USED:
                backup_code = BackupCode(
                    code_hash=code_hash, generated_at=now, status=status, used_at=now
                )
            else:
                backup_code = BackupCode(
                    code_hash=code_hash, generated_at=now, status=status
                )

            assert backup_code.status == status

    def test_maximum_age_calculation(self):
        """Test age calculation with maximum realistic values."""
        very_old = datetime.now(UTC) - timedelta(days=365 * 10)  # 10 years
        backup_code = BackupCode(
            code_hash=hashlib.sha256(b"OLD").hexdigest(), generated_at=very_old
        )

        assert backup_code.age_days >= 365 * 10

    def test_case_insensitive_verification(self):
        """Test that verification is case insensitive."""
        backup_code = BackupCode.from_plain_code("MixedCase123")

        assert backup_code.verify_code("mixedcase123") is True
        assert backup_code.verify_code("MIXEDCASE123") is True
        assert backup_code.verify_code("MiXeDcAsE123") is True
