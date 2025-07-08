"""
Test cases for MFASecret value object.

Tests all aspects of MFA secret including generation, validation,
provisioning URI, and security features.
"""

import base64
import hashlib
from dataclasses import FrozenInstanceError

import pytest

from app.modules.identity.domain.value_objects.mfa_secret import (
    MFAAlgorithm,
    MFASecret,
    MFAType,
)


class TestMFASecretCreation:
    """Test MFASecret creation and validation."""

    def test_create_valid_totp_secret(self):
        """Test creating a valid TOTP secret."""
        secret = MFASecret(
            secret_value="JBSWY3DPEHPK3PXP",  # Valid base32
            mfa_type=MFAType.TOTP,
            algorithm=MFAAlgorithm.SHA1,
            digits=6,
            period=30,
        )

        assert secret.secret_value == "JBSWY3DPEHPK3PXP"
        assert secret.mfa_type == MFAType.TOTP
        assert secret.algorithm == MFAAlgorithm.SHA1
        assert secret.digits == 6
        assert secret.period == 30
        assert secret.is_time_based is True
        assert secret.is_counter_based is False

    def test_create_valid_hotp_secret(self):
        """Test creating a valid HOTP secret."""
        secret = MFASecret(
            secret_value="JBSWY3DPEHPK3PXP",
            mfa_type=MFAType.HOTP,
            algorithm=MFAAlgorithm.SHA256,
            digits=8,
            counter=0,
        )

        assert secret.mfa_type == MFAType.HOTP
        assert secret.algorithm == MFAAlgorithm.SHA256
        assert secret.digits == 8
        assert secret.counter == 0
        assert secret.is_time_based is False
        assert secret.is_counter_based is True

    def test_create_backup_code_secret(self):
        """Test creating a backup code secret."""
        secret = MFASecret(
            secret_value="backup_code_hash_value",
            mfa_type=MFAType.BACKUP,
            algorithm=MFAAlgorithm.SHA256,
        )

        assert secret.mfa_type == MFAType.BACKUP
        assert secret.is_backup_code is True
        assert secret.requires_network is False

    def test_invalid_mfa_secret(self):
        """Test validation of invalid MFA secrets."""
        # Empty secret value
        with pytest.raises(ValueError, match="Secret value is required"):
            MFASecret(
                secret_value="", mfa_type=MFAType.TOTP, algorithm=MFAAlgorithm.SHA1
            )

        # Invalid base32 for TOTP
        with pytest.raises(ValueError, match="Invalid base32 secret"):
            MFASecret(
                secret_value="INVALID@BASE32!",
                mfa_type=MFAType.TOTP,
                algorithm=MFAAlgorithm.SHA1,
            )

        # Secret too short for TOTP
        with pytest.raises(
            ValueError, match="TOTP secret must be at least 16 characters"
        ):
            MFASecret(
                secret_value="JBSWY3DP",  # Less than 16 characters
                mfa_type=MFAType.TOTP,
                algorithm=MFAAlgorithm.SHA1,
            )

        # Invalid digits
        with pytest.raises(ValueError, match="Digits must be between 6 and 8"):
            MFASecret(
                secret_value="JBSWY3DPEHPK3PXP",
                mfa_type=MFAType.TOTP,
                algorithm=MFAAlgorithm.SHA1,
                digits=4,
            )

        # Invalid TOTP period
        with pytest.raises(ValueError, match="TOTP period must be 30 or 60 seconds"):
            MFASecret(
                secret_value="JBSWY3DPEHPK3PXP",
                mfa_type=MFAType.TOTP,
                algorithm=MFAAlgorithm.SHA1,
                period=45,
            )

        # Negative HOTP counter
        with pytest.raises(ValueError, match="HOTP counter must be non-negative"):
            MFASecret(
                secret_value="JBSWY3DPEHPK3PXP",
                mfa_type=MFAType.HOTP,
                algorithm=MFAAlgorithm.SHA1,
                counter=-1,
            )


class TestMFASecretGeneration:
    """Test MFA secret generation."""

    def test_generate_totp_secret(self):
        """Test TOTP secret generation."""
        # Default parameters
        secret = MFASecret.generate_totp_secret()

        assert secret.mfa_type == MFAType.TOTP
        assert secret.algorithm == MFAAlgorithm.SHA1
        assert secret.digits == 6
        assert secret.period == 30
        assert len(secret.secret_value) >= 16
        assert secret._is_valid_base32(secret.secret_value)

        # Custom parameters
        custom_secret = MFASecret.generate_totp_secret(
            algorithm=MFAAlgorithm.SHA256, digits=8, period=60
        )

        assert custom_secret.algorithm == MFAAlgorithm.SHA256
        assert custom_secret.digits == 8
        assert custom_secret.period == 60

    def test_generate_hotp_secret(self):
        """Test HOTP secret generation."""
        secret = MFASecret.generate_hotp_secret(algorithm=MFAAlgorithm.SHA512, digits=8)

        assert secret.mfa_type == MFAType.HOTP
        assert secret.algorithm == MFAAlgorithm.SHA512
        assert secret.digits == 8
        assert secret.counter == 0
        assert len(secret.secret_value) >= 16

    def test_generate_backup_codes(self):
        """Test backup code generation."""
        codes = MFASecret.generate_backup_codes(count=10)

        assert len(codes) == 10

        # All codes should be unique
        secret_values = [code.secret_value for code in codes]
        assert len(secret_values) == len(set(secret_values))

        for code in codes:
            assert code.mfa_type == MFAType.BACKUP
            assert code.algorithm == MFAAlgorithm.SHA256
            assert len(code.secret_value) > 0

    def test_secret_uniqueness(self):
        """Test that generated secrets are unique."""
        secrets = [MFASecret.generate_totp_secret() for _ in range(100)]
        secret_values = [s.secret_value for s in secrets]

        # All should be unique
        assert len(secret_values) == len(set(secret_values))


class TestMFASecretProvisioning:
    """Test MFA secret provisioning URI generation."""

    def test_totp_provisioning_uri(self):
        """Test TOTP provisioning URI generation."""
        secret = MFASecret(
            secret_value="JBSWY3DPEHPK3PXP",
            mfa_type=MFAType.TOTP,
            algorithm=MFAAlgorithm.SHA1,
            digits=6,
            period=30,
        )

        uri = secret.get_provisioning_uri(
            account_name="user@example.com", issuer="TestApp"
        )

        assert uri.startswith("otpauth://totp/")
        assert "TestApp:user@example.com" in uri
        assert "secret=JBSWY3DPEHPK3PXP" in uri
        assert "issuer=TestApp" in uri
        assert "algorithm=SHA1" in uri
        assert "digits=6" in uri
        assert "period=30" in uri

    def test_hotp_provisioning_uri(self):
        """Test HOTP provisioning URI generation."""
        secret = MFASecret(
            secret_value="JBSWY3DPEHPK3PXP",
            mfa_type=MFAType.HOTP,
            algorithm=MFAAlgorithm.SHA256,
            digits=8,
            counter=0,
        )

        uri = secret.get_provisioning_uri(
            account_name="user@example.com", issuer="TestApp"
        )

        assert uri.startswith("otpauth://hotp/")
        assert "counter=0" in uri
        assert "algorithm=SHA256" in uri
        assert "digits=8" in uri
        assert "period" not in uri  # HOTP doesn't use period

    def test_provisioning_uri_with_icon(self):
        """Test provisioning URI with icon URL."""
        secret = MFASecret.generate_totp_secret()

        uri = secret.get_provisioning_uri(
            account_name="user@example.com",
            issuer="TestApp",
            icon_url="https://example.com/icon.png",
        )

        assert "image=https://example.com/icon.png" in uri

    def test_provisioning_uri_encoding(self):
        """Test proper encoding in provisioning URI."""
        secret = MFASecret.generate_totp_secret()

        # Special characters in account name and issuer
        uri = secret.get_provisioning_uri(
            account_name="user+test@example.com", issuer="Test App & Co."
        )

        # Should be properly URL encoded
        assert "user%2Btest%40example.com" in uri or "user+test@example.com" in uri
        assert "Test%20App%20%26%20Co." in uri or "Test App & Co." in uri


class TestMFASecretOperations:
    """Test MFA secret operations."""

    def test_hotp_counter_increment(self):
        """Test HOTP counter increment."""
        secret = MFASecret(
            secret_value="JBSWY3DPEHPK3PXP",
            mfa_type=MFAType.HOTP,
            algorithm=MFAAlgorithm.SHA1,
            counter=5,
        )

        # Increment counter
        incremented = secret.increment_counter()

        assert incremented.counter == 6
        assert incremented.secret_value == secret.secret_value
        assert incremented.algorithm == secret.algorithm

        # Original should be unchanged (immutable)
        assert secret.counter == 5

    def test_cannot_increment_non_hotp(self):
        """Test that non-HOTP secrets cannot increment counter."""
        totp_secret = MFASecret.generate_totp_secret()

        with pytest.raises(ValueError, match="Only HOTP secrets can increment counter"):
            totp_secret.increment_counter()

    def test_secret_rotation(self):
        """Test secret rotation."""
        original = MFASecret.generate_totp_secret()

        # Rotate secret
        rotated = original.rotate()

        assert rotated.mfa_type == original.mfa_type
        assert rotated.algorithm == original.algorithm
        assert rotated.digits == original.digits
        assert rotated.period == original.period
        assert rotated.secret_value != original.secret_value


class TestMFASecretProperties:
    """Test MFA secret properties."""

    def test_mfa_type_properties(self):
        """Test properties based on MFA type."""
        totp = MFASecret.generate_totp_secret()
        hotp = MFASecret.generate_hotp_secret()
        backup = MFASecret.generate_backup_codes(count=1)[0]

        # TOTP properties
        assert totp.is_time_based is True
        assert totp.is_counter_based is False
        assert totp.is_backup_code is False
        assert totp.requires_network is False

        # HOTP properties
        assert hotp.is_time_based is False
        assert hotp.is_counter_based is True
        assert hotp.is_backup_code is False
        assert hotp.requires_network is False

        # Backup code properties
        assert backup.is_time_based is False
        assert backup.is_counter_based is False
        assert backup.is_backup_code is True
        assert backup.requires_network is False

    def test_algorithm_properties(self):
        """Test algorithm-specific properties."""
        sha1_secret = MFASecret.generate_totp_secret(algorithm=MFAAlgorithm.SHA1)
        sha256_secret = MFASecret.generate_totp_secret(algorithm=MFAAlgorithm.SHA256)
        sha512_secret = MFASecret.generate_totp_secret(algorithm=MFAAlgorithm.SHA512)

        assert sha1_secret.algorithm_name == "SHA1"
        assert sha256_secret.algorithm_name == "SHA256"
        assert sha512_secret.algorithm_name == "SHA512"

        assert sha1_secret.algorithm_strength == "standard"
        assert sha256_secret.algorithm_strength == "strong"
        assert sha512_secret.algorithm_strength == "very_strong"


class TestMFASecretSecurity:
    """Test MFA secret security features."""

    def test_secret_immutability(self):
        """Test that MFA secrets are immutable."""
        secret = MFASecret.generate_totp_secret()

        with pytest.raises(FrozenInstanceError):
            secret.secret_value = "modified"

        with pytest.raises(FrozenInstanceError):
            secret.counter = 10

    def test_secret_comparison(self):
        """Test MFA secret comparison."""
        secret1 = MFASecret(
            secret_value="JBSWY3DPEHPK3PXP",
            mfa_type=MFAType.TOTP,
            algorithm=MFAAlgorithm.SHA1,
        )

        secret2 = MFASecret(
            secret_value="JBSWY3DPEHPK3PXP",
            mfa_type=MFAType.TOTP,
            algorithm=MFAAlgorithm.SHA1,
        )

        secret3 = MFASecret(
            secret_value="DIFFERENTBASE32XX",
            mfa_type=MFAType.TOTP,
            algorithm=MFAAlgorithm.SHA1,
        )

        assert secret1 == secret2
        assert secret1 != secret3
        assert hash(secret1) == hash(secret2)
        assert hash(secret1) != hash(secret3)

    def test_secure_string_representation(self):
        """Test that string representations don't expose secret."""
        secret = MFASecret(
            secret_value="JBSWY3DPEHPK3PXP",
            mfa_type=MFAType.TOTP,
            algorithm=MFAAlgorithm.SHA1,
        )

        str_repr = str(secret)
        repr_repr = repr(secret)

        # Should not expose full secret
        assert "JBSWY3DPEHPK3PXP" not in str_repr
        assert "JBSWY3DPEHPK3PXP" not in repr_repr

        # Should show type and partial info
        assert "TOTP" in str_repr
        assert "SHA1" in str_repr
        assert "****" in str_repr or "[HIDDEN]" in str_repr

    def test_secret_encryption_readiness(self):
        """Test that secrets are ready for encryption."""
        secret = MFASecret.generate_totp_secret()

        # Should provide method to get encryptable value
        encryptable = secret.get_encryptable_value()
        assert isinstance(encryptable, bytes)
        assert len(encryptable) > 0

        # Should be able to reconstruct from encrypted value
        reconstructed = MFASecret.from_encrypted_value(
            encryptable,
            mfa_type=secret.mfa_type,
            algorithm=secret.algorithm,
            digits=secret.digits,
            period=secret.period,
        )

        assert reconstructed.secret_value == secret.secret_value


class TestMFASecretValidation:
    """Test MFA secret validation rules."""

    def test_base32_validation(self):
        """Test Base32 validation for TOTP/HOTP."""
        valid_base32 = ["JBSWY3DPEHPK3PXP", "ABCDEFGHIJKLMNOP", "23456789ABCDEFGH"]

        for b32 in valid_base32:
            secret = MFASecret(
                secret_value=b32, mfa_type=MFAType.TOTP, algorithm=MFAAlgorithm.SHA1
            )
            assert secret._is_valid_base32(b32)

        invalid_base32 = [
            "0123456789ABCDEF",  # Contains 0 and 1
            "JBSWY3DPEHPK3PX!",  # Special character
            "jbswy3dpehpk3pxp",  # Lowercase
            "JBSWY3DPEHPK3PX",  # Wrong length (not multiple of 8)
        ]

        for b32 in invalid_base32:
            with pytest.raises(ValueError):
                MFASecret(
                    secret_value=b32, mfa_type=MFAType.TOTP, algorithm=MFAAlgorithm.SHA1
                )

    def test_parameter_combinations(self):
        """Test valid parameter combinations."""
        # TOTP requires period, not counter
        with pytest.raises(ValueError):
            MFASecret(
                secret_value="JBSWY3DPEHPK3PXP",
                mfa_type=MFAType.TOTP,
                algorithm=MFAAlgorithm.SHA1,
                counter=0,  # Should not have counter
            )

        # HOTP requires counter, not period
        with pytest.raises(ValueError):
            MFASecret(
                secret_value="JBSWY3DPEHPK3PXP",
                mfa_type=MFAType.HOTP,
                algorithm=MFAAlgorithm.SHA1,
                period=30,  # Should not have period
            )


class TestMFASecretCompatibility:
    """Test MFA secret compatibility with authenticator apps."""

    def test_google_authenticator_compatibility(self):
        """Test compatibility with Google Authenticator."""
        # Google Authenticator defaults
        secret = MFASecret.generate_totp_secret(
            algorithm=MFAAlgorithm.SHA1, digits=6, period=30
        )

        uri = secret.get_provisioning_uri(
            account_name="user@example.com", issuer="TestApp"
        )

        # Should use compatible defaults
        assert "algorithm=SHA1" in uri
        assert "digits=6" in uri
        assert "period=30" in uri

    def test_microsoft_authenticator_compatibility(self):
        """Test compatibility with Microsoft Authenticator."""
        # Microsoft Authenticator supports SHA256
        secret = MFASecret.generate_totp_secret(
            algorithm=MFAAlgorithm.SHA256, digits=6, period=30
        )

        assert secret.is_compatible_with("microsoft_authenticator")

    def test_authy_compatibility(self):
        """Test compatibility with Authy."""
        # Authy supports 7 and 8 digit codes
        secret = MFASecret.generate_totp_secret(
            algorithm=MFAAlgorithm.SHA1, digits=7, period=30
        )

        assert secret.is_compatible_with("authy")

    """Test MFASecret creation and validation."""

    def test_create_valid_totp_secret(self):
        """Test creating a valid TOTP secret."""
        secret = MFASecret(
            secret_value="JBSWY3DPEHPK3PXP",  # Valid base32
            mfa_type=MFAType.TOTP,
            algorithm=MFAAlgorithm.SHA1,
            digits=6,
            period=30,
        )

        assert secret.secret_value == "JBSWY3DPEHPK3PXP"
        assert secret.mfa_type == MFAType.TOTP
        assert secret.algorithm == MFAAlgorithm.SHA1
        assert secret.digits == 6
        assert secret.period == 30

    def test_create_valid_hotp_secret(self):
        """Test creating a valid HOTP secret."""
        secret = MFASecret(
            secret_value="JBSWY3DPEHPK3PXP",
            mfa_type=MFAType.HOTP,
            algorithm=MFAAlgorithm.SHA256,
            digits=8,
            counter=10,
        )

        assert secret.mfa_type == MFAType.HOTP
        assert secret.algorithm == MFAAlgorithm.SHA256
        assert secret.digits == 8
        assert secret.counter == 10

    def test_create_backup_code_secret(self):
        """Test creating a backup code secret."""
        code_hash = hashlib.sha256(b"BACKUP123").hexdigest()
        secret = MFASecret(
            secret_value=code_hash,
            mfa_type=MFAType.BACKUP,
            algorithm=MFAAlgorithm.SHA256,
        )

        assert secret.mfa_type == MFAType.BACKUP
        assert secret.secret_value == code_hash

    def test_empty_secret_raises_error(self):
        """Test that empty secret value raises ValueError."""
        with pytest.raises(ValueError, match="Secret value is required"):
            MFASecret(secret_value="", mfa_type=MFAType.TOTP)

    def test_invalid_base32_for_totp_raises_error(self):
        """Test that invalid base32 for TOTP raises ValueError."""
        with pytest.raises(ValueError, match="Invalid base32 secret for TOTP/HOTP"):
            MFASecret(secret_value="invalid@base32!", mfa_type=MFAType.TOTP)

    def test_short_secret_for_totp_raises_error(self):
        """Test that too short secret for TOTP raises ValueError."""
        with pytest.raises(ValueError, match="Secret too short for TOTP/HOTP"):
            MFASecret(
                secret_value="JBSWY3DP", mfa_type=MFAType.TOTP  # Only 8 chars, need 16+
            )

    def test_invalid_digits_raises_error(self):
        """Test that invalid digits value raises ValueError."""
        with pytest.raises(ValueError, match="Digits must be 6, 7, or 8"):
            MFASecret(secret_value="JBSWY3DPEHPK3PXP", mfa_type=MFAType.TOTP, digits=4)

    def test_invalid_totp_period_raises_error(self):
        """Test that invalid TOTP period raises ValueError."""
        with pytest.raises(ValueError, match="TOTP period must be 30 or 60 seconds"):
            MFASecret(secret_value="JBSWY3DPEHPK3PXP", mfa_type=MFAType.TOTP, period=15)

    def test_negative_hotp_counter_raises_error(self):
        """Test that negative HOTP counter raises ValueError."""
        with pytest.raises(ValueError, match="HOTP counter must be non-negative"):
            MFASecret(
                secret_value="JBSWY3DPEHPK3PXP", mfa_type=MFAType.HOTP, counter=-1
            )


class TestMFASecretGeneration:
    """Test MFA secret generation methods."""

    def test_generate_totp_secret(self):
        """Test generating TOTP secret."""
        secret = MFASecret.generate_totp_secret()

        assert secret.mfa_type == MFAType.TOTP
        assert secret.algorithm == MFAAlgorithm.SHA1
        assert secret.digits == 6
        assert secret.period == 30
        assert len(secret.secret_value) >= 16

        # Should be valid base32
        base64.b32decode(secret.secret_value + "=" * (8 - len(secret.secret_value) % 8))

    def test_generate_totp_secret_with_custom_params(self):
        """Test generating TOTP secret with custom parameters."""
        secret = MFASecret.generate_totp_secret(
            algorithm=MFAAlgorithm.SHA256, digits=8, period=60
        )

        assert secret.algorithm == MFAAlgorithm.SHA256
        assert secret.digits == 8
        assert secret.period == 60

    def test_generate_hotp_secret(self):
        """Test generating HOTP secret."""
        secret = MFASecret.generate_hotp_secret()

        assert secret.mfa_type == MFAType.HOTP
        assert secret.algorithm == MFAAlgorithm.SHA1
        assert secret.digits == 6
        assert secret.counter == 0
        assert len(secret.secret_value) >= 16

    def test_generate_hotp_secret_with_custom_params(self):
        """Test generating HOTP secret with custom parameters."""
        secret = MFASecret.generate_hotp_secret(
            algorithm=MFAAlgorithm.SHA512, digits=7, initial_counter=50
        )

        assert secret.algorithm == MFAAlgorithm.SHA512
        assert secret.digits == 7
        assert secret.counter == 50

    def test_generate_backup_codes(self):
        """Test generating backup codes."""
        codes = MFASecret.generate_backup_codes(count=5, length=10)

        assert len(codes) == 5
        for code in codes:
            assert code.mfa_type == MFAType.BACKUP
            assert code.algorithm == MFAAlgorithm.SHA256
            assert len(code.secret_value) == 64  # SHA256 hex

        # All codes should be unique
        code_values = [code.secret_value for code in codes]
        assert len(set(code_values)) == 5

    def test_from_existing_secret(self):
        """Test creating from existing secret."""
        secret = MFASecret.from_existing_secret(
            secret="EXISTING_SECRET_VALUE",
            mfa_type=MFAType.SMS,
            algorithm=MFAAlgorithm.SHA256,
        )

        assert secret.secret_value == "EXISTING_SECRET_VALUE"
        assert secret.mfa_type == MFAType.SMS
        assert secret.algorithm == MFAAlgorithm.SHA256

    def test_generated_secrets_are_unique(self):
        """Test that generated secrets are unique."""
        secrets = [MFASecret.generate_totp_secret() for _ in range(10)]
        secret_values = [s.secret_value for s in secrets]

        assert len(set(secret_values)) == 10  # All unique


class TestMFASecretProperties:
    """Test MFA secret properties."""

    def test_is_time_based_totp(self):
        """Test time-based property for TOTP."""
        secret = MFASecret.generate_totp_secret()
        assert secret.is_time_based is True
        assert secret.is_counter_based is False

    def test_is_counter_based_hotp(self):
        """Test counter-based property for HOTP."""
        secret = MFASecret.generate_hotp_secret()
        assert secret.is_counter_based is True
        assert secret.is_time_based is False

    def test_requires_network_sms(self):
        """Test network requirement for SMS."""
        secret = MFASecret.from_existing_secret(
            secret="phone_hash", mfa_type=MFAType.SMS
        )
        assert secret.requires_network is True

    def test_requires_network_email(self):
        """Test network requirement for email."""
        secret = MFASecret.from_existing_secret(
            secret="email_hash", mfa_type=MFAType.EMAIL
        )
        assert secret.requires_network is True

    def test_requires_network_push(self):
        """Test network requirement for push."""
        secret = MFASecret.from_existing_secret(
            secret="device_token", mfa_type=MFAType.PUSH
        )
        assert secret.requires_network is True

    def test_no_network_required_totp(self):
        """Test no network requirement for TOTP."""
        secret = MFASecret.generate_totp_secret()
        assert secret.requires_network is False

    def test_is_backup_code(self):
        """Test backup code property."""
        secret = MFASecret.from_existing_secret(
            secret="backup_hash", mfa_type=MFAType.BACKUP
        )
        assert secret.is_backup_code is True

        totp_secret = MFASecret.generate_totp_secret()
        assert totp_secret.is_backup_code is False


class TestMFASecretProvisioningURI:
    """Test provisioning URI generation."""

    def test_totp_provisioning_uri(self):
        """Test TOTP provisioning URI generation."""
        secret = MFASecret(
            secret_value="JBSWY3DPEHPK3PXP",
            mfa_type=MFAType.TOTP,
            algorithm=MFAAlgorithm.SHA1,
            digits=6,
            period=30,
        )

        uri = secret.get_provisioning_uri(
            account_name="user@example.com", issuer="EzzDay"
        )

        expected_parts = [
            "otpauth://totp/EzzDay:user@example.com",
            "secret=JBSWY3DPEHPK3PXP",
            "issuer=EzzDay",
            "algorithm=SHA1",
            "digits=6",
            "period=30",
        ]

        for part in expected_parts:
            assert part in uri

    def test_hotp_provisioning_uri(self):
        """Test HOTP provisioning URI generation."""
        secret = MFASecret(
            secret_value="JBSWY3DPEHPK3PXP",
            mfa_type=MFAType.HOTP,
            algorithm=MFAAlgorithm.SHA256,
            digits=8,
            counter=5,
        )

        uri = secret.get_provisioning_uri(account_name="testuser", issuer="MyApp")

        expected_parts = [
            "otpauth://hotp/MyApp:testuser",
            "secret=JBSWY3DPEHPK3PXP",
            "issuer=MyApp",
            "algorithm=SHA256",
            "digits=8",
            "counter=5",
        ]

        for part in expected_parts:
            assert part in uri

    def test_provisioning_uri_with_icon(self):
        """Test provisioning URI with icon URL."""
        secret = MFASecret.generate_totp_secret()

        uri = secret.get_provisioning_uri(
            account_name="user", issuer="App", icon_url="https://example.com/icon.png"
        )

        assert "image=https://example.com/icon.png" in uri

    def test_provisioning_uri_invalid_type_raises_error(self):
        """Test that non-OTP types raise error for provisioning URI."""
        secret = MFASecret.from_existing_secret(
            secret="backup_hash", mfa_type=MFAType.BACKUP
        )

        with pytest.raises(
            ValueError, match="Provisioning URI only available for TOTP/HOTP"
        ):
            secret.get_provisioning_uri("user", "App")


class TestMFASecretCounterIncrement:
    """Test HOTP counter increment functionality."""

    def test_increment_hotp_counter(self):
        """Test incrementing HOTP counter."""
        secret = MFASecret(
            secret_value="JBSWY3DPEHPK3PXP", mfa_type=MFAType.HOTP, counter=5
        )

        new_secret = secret.increment_counter()

        assert new_secret.counter == 6
        assert new_secret.secret_value == secret.secret_value
        assert new_secret.mfa_type == secret.mfa_type
        assert secret.counter == 5  # Original unchanged

    def test_increment_counter_invalid_type_raises_error(self):
        """Test that incrementing counter on non-HOTP raises error."""
        secret = MFASecret.generate_totp_secret()

        with pytest.raises(ValueError, match="Counter increment only valid for HOTP"):
            secret.increment_counter()


class TestMFASecretSecurity:
    """Test security-related functionality."""

    def test_mask_secret_short(self):
        """Test masking short secret."""
        secret = MFASecret.from_existing_secret(secret="SHORT", mfa_type=MFAType.BACKUP)

        masked = secret.mask_secret()
        assert masked == "*****"

    def test_mask_secret_long(self):
        """Test masking long secret."""
        secret = MFASecret(
            secret_value="JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP", mfa_type=MFAType.TOTP
        )

        masked = secret.mask_secret()
        assert masked == "JBSW...3PXP"
        assert "DPEHPK3PXPJBSWY3DPEHPK" not in masked

    def test_get_fingerprint(self):
        """Test getting secret fingerprint."""
        secret = MFASecret(secret_value="JBSWY3DPEHPK3PXP", mfa_type=MFAType.TOTP)

        fingerprint = secret.get_fingerprint()
        assert len(fingerprint) == 16
        assert all(c in "0123456789abcdef" for c in fingerprint)

        # Same secret should produce same fingerprint
        secret2 = MFASecret(secret_value="JBSWY3DPEHPK3PXP", mfa_type=MFAType.HOTP)
        assert secret2.get_fingerprint() == fingerprint

    def test_different_secrets_different_fingerprints(self):
        """Test that different secrets produce different fingerprints."""
        secret1 = MFASecret.generate_totp_secret()
        secret2 = MFASecret.generate_totp_secret()

        assert secret1.get_fingerprint() != secret2.get_fingerprint()


class TestMFASecretStorageFormat:
    """Test storage format conversion."""

    def test_totp_storage_format(self):
        """Test TOTP storage format."""
        secret = MFASecret(
            secret_value="JBSWY3DPEHPK3PXP",
            mfa_type=MFAType.TOTP,
            algorithm=MFAAlgorithm.SHA256,
            digits=8,
            period=60,
        )

        storage = secret.to_storage_format()

        assert storage["type"] == "TOTP"
        assert storage["algorithm"] == "SHA256"
        assert storage["digits"] == 8
        assert storage["period"] == 60
        assert storage["counter"] is None
        assert "fingerprint" in storage
        assert "secret_value" not in storage  # Should not expose raw secret

    def test_hotp_storage_format(self):
        """Test HOTP storage format."""
        secret = MFASecret(
            secret_value="JBSWY3DPEHPK3PXP", mfa_type=MFAType.HOTP, counter=10
        )

        storage = secret.to_storage_format()

        assert storage["type"] == "HOTP"
        assert storage["counter"] == 10
        assert storage["period"] is None

    def test_backup_storage_format(self):
        """Test backup code storage format."""
        secret = MFASecret.from_existing_secret(
            secret="backup_hash", mfa_type=MFAType.BACKUP, algorithm=MFAAlgorithm.SHA256
        )

        storage = secret.to_storage_format()

        assert storage["type"] == "BACKUP"
        assert storage["algorithm"] == "SHA256"
        assert storage["period"] is None
        assert storage["counter"] is None


class TestMFASecretStringRepresentation:
    """Test string representation methods."""

    def test_str_representation_safe(self):
        """Test that __str__ doesn't expose sensitive data."""
        secret = MFASecret(secret_value="SENSITIVE_SECRET_VALUE", mfa_type=MFAType.TOTP)

        str_repr = str(secret)

        assert "SENSITIVE_SECRET_VALUE" not in str_repr
        assert "TOTP" in str_repr
        assert "fingerprint=" in str_repr

    def test_repr_representation_safe(self):
        """Test that __repr__ doesn't expose sensitive data."""
        secret = MFASecret(
            secret_value="SENSITIVE_SECRET_VALUE",
            mfa_type=MFAType.TOTP,
            algorithm=MFAAlgorithm.SHA256,
            digits=8,
            period=60,
        )

        repr_str = repr(secret)

        assert "SENSITIVE_SECRET_VALUE" not in repr_str
        assert "TOTP" in repr_str
        assert "SHA256" in repr_str
        assert "digits=8" in repr_str
        assert "period=60s" in repr_str

    def test_repr_hotp_includes_counter(self):
        """Test that HOTP repr includes counter."""
        secret = MFASecret(secret_value="SECRET", mfa_type=MFAType.HOTP, counter=15)

        repr_str = repr(secret)
        assert "counter=15" in repr_str


class TestMFASecretImmutability:
    """Test that MFASecret is immutable."""

    def test_immutable_secret_value(self):
        """Test that secret_value cannot be changed."""
        secret = MFASecret.generate_totp_secret()

        with pytest.raises(FrozenInstanceError):
            secret.secret_value = "new_secret"

    def test_immutable_mfa_type(self):
        """Test that mfa_type cannot be changed."""
        secret = MFASecret.generate_totp_secret()

        with pytest.raises(FrozenInstanceError):
            secret.mfa_type = MFAType.HOTP

    def test_immutable_counter(self):
        """Test that counter cannot be changed directly."""
        secret = MFASecret.generate_hotp_secret()

        with pytest.raises(FrozenInstanceError):
            secret.counter = 999


class TestMFASecretEquality:
    """Test equality and comparison behavior."""

    def test_equal_secrets(self):
        """Test that identical secrets are equal."""
        secret1 = MFASecret(
            secret_value="JBSWY3DPEHPK3PXP",
            mfa_type=MFAType.TOTP,
            algorithm=MFAAlgorithm.SHA1,
            digits=6,
            period=30,
        )

        secret2 = MFASecret(
            secret_value="JBSWY3DPEHPK3PXP",
            mfa_type=MFAType.TOTP,
            algorithm=MFAAlgorithm.SHA1,
            digits=6,
            period=30,
        )

        assert secret1 == secret2

    def test_different_secrets_not_equal(self):
        """Test that different secrets are not equal."""
        secret1 = MFASecret.generate_totp_secret()
        secret2 = MFASecret.generate_totp_secret()

        assert secret1 != secret2

    def test_different_types_not_equal(self):
        """Test that same secret with different types are not equal."""
        secret1 = MFASecret(secret_value="JBSWY3DPEHPK3PXP", mfa_type=MFAType.TOTP)

        secret2 = MFASecret(secret_value="JBSWY3DPEHPK3PXP", mfa_type=MFAType.HOTP)

        assert secret1 != secret2


class TestMFASecretEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_minimum_valid_base32_length(self):
        """Test secret with minimum valid base32 length."""
        secret = MFASecret(
            secret_value="JBSWY3DPEHPK3PXP", mfa_type=MFAType.TOTP  # Exactly 16 chars
        )

        assert len(secret.secret_value) == 16

    def test_all_mfa_types_supported(self):
        """Test that all MFA types can be created."""
        for mfa_type in MFAType:
            if mfa_type in [MFAType.TOTP, MFAType.HOTP]:
                secret = MFASecret(secret_value="JBSWY3DPEHPK3PXP", mfa_type=mfa_type)
            else:
                secret = MFASecret.from_existing_secret(
                    secret="test_value", mfa_type=mfa_type
                )

            assert secret.mfa_type == mfa_type

    def test_all_algorithms_supported(self):
        """Test that all algorithms are supported."""
        for algorithm in MFAAlgorithm:
            secret = MFASecret(
                secret_value="JBSWY3DPEHPK3PXP",
                mfa_type=MFAType.TOTP,
                algorithm=algorithm,
            )

            assert secret.algorithm == algorithm

    def test_extreme_counter_values(self):
        """Test HOTP with extreme counter values."""
        # Test with large counter
        secret = MFASecret(
            secret_value="JBSWY3DPEHPK3PXP", mfa_type=MFAType.HOTP, counter=999999
        )

        assert secret.counter == 999999

        # Test incrementing large counter
        new_secret = secret.increment_counter()
        assert new_secret.counter == 1000000
