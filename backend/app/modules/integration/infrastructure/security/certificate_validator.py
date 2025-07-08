"""Certificate validation service for mutual TLS.

This module provides certificate validation for secure API connections
using mutual TLS authentication.
"""

import hashlib
import logging
import ssl
from datetime import UTC, datetime
from typing import Any

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtensionOID, NameOID

logger = logging.getLogger(__name__)


class CertificateValidator:
    """Service for validating X.509 certificates."""

    def __init__(
        self,
        trusted_ca_certs: list[str] | None = None,
        check_hostname: bool = True,
        check_expiry: bool = True,
        allowed_key_usages: list[str] | None = None,
    ):
        """Initialize certificate validator.

        Args:
            trusted_ca_certs: List of trusted CA certificate paths
            check_hostname: Verify certificate hostname
            check_expiry: Check certificate expiration
            allowed_key_usages: Allowed key usage extensions
        """
        self.trusted_ca_certs = trusted_ca_certs or []
        self.check_hostname = check_hostname
        self.check_expiry = check_expiry
        self.allowed_key_usages = allowed_key_usages or [
            "digital_signature",
            "key_agreement",
            "key_encipherment",
        ]

        # Load trusted CA certificates
        self._trusted_cas = self._load_ca_certificates()

    def _load_ca_certificates(self) -> list[x509.Certificate]:
        """Load trusted CA certificates.

        Returns:
            List of CA certificates
        """
        ca_certs = []

        for cert_path in self.trusted_ca_certs:
            try:
                with open(cert_path, "rb") as f:
                    cert_data = f.read()
                    cert = x509.load_pem_x509_certificate(cert_data, default_backend())
                    ca_certs.append(cert)
            except Exception as e:
                logger.exception(f"Failed to load CA certificate {cert_path}: {e}")

        return ca_certs

    def validate_certificate(
        self, cert_data: bytes, hostname: str | None = None, purpose: str = "client"
    ) -> tuple[bool, dict[str, Any] | None]:
        """Validate X.509 certificate.

        Args:
            cert_data: Certificate data (PEM or DER format)
            hostname: Expected hostname
            purpose: Certificate purpose (client/server)

        Returns:
            Tuple of (is_valid, certificate_info)
        """
        try:
            # Load certificate
            try:
                cert = x509.load_pem_x509_certificate(cert_data, default_backend())
            except Exception:
                cert = x509.load_der_x509_certificate(cert_data, default_backend())

            # Extract certificate info
            cert_info = self._extract_certificate_info(cert)

            # Check expiry
            if self.check_expiry:
                now = datetime.now(UTC)
                if now < cert.not_valid_before or now > cert.not_valid_after:
                    logger.warning("Certificate is expired or not yet valid")
                    return False, cert_info

            # Check hostname
            if self.check_hostname and hostname:
                if not self._verify_hostname(cert, hostname):
                    logger.warning(f"Certificate hostname mismatch: {hostname}")
                    return False, cert_info

            # Check key usage
            if not self._verify_key_usage(cert, purpose):
                logger.warning("Certificate key usage not allowed")
                return False, cert_info

            # Verify certificate chain (simplified)
            if self._trusted_cas and not self._verify_chain(cert):
                logger.warning("Certificate chain verification failed")
                return False, cert_info

            return True, cert_info

        except Exception as e:
            logger.exception(f"Certificate validation error: {e}")
            return False, None

    def _extract_certificate_info(self, cert: x509.Certificate) -> dict[str, Any]:
        """Extract certificate information.

        Args:
            cert: X.509 certificate

        Returns:
            Certificate information dictionary
        """
        # Extract subject
        subject = {}
        for attr in cert.subject:
            if attr.oid in [
                NameOID.COMMON_NAME,
                NameOID.ORGANIZATION_NAME,
                NameOID.ORGANIZATIONAL_UNIT_NAME,
                NameOID.COUNTRY_NAME,
            ]:
                subject[attr.oid._name] = attr.value

        # Extract issuer
        issuer = {}
        for attr in cert.issuer:
            if attr.oid in [NameOID.COMMON_NAME, NameOID.ORGANIZATION_NAME]:
                issuer[attr.oid._name] = attr.value

        # Extract extensions
        extensions = {}
        for ext in cert.extensions:
            if ext.oid == ExtensionOID.SUBJECT_ALTERNATIVE_NAME:
                san_list = []
                for san in ext.value:
                    san_list.append(san.value)
                extensions["san"] = san_list
            elif ext.oid == ExtensionOID.KEY_USAGE:
                key_usage = []
                ku = ext.value
                if ku.digital_signature:
                    key_usage.append("digital_signature")
                if ku.key_encipherment:
                    key_usage.append("key_encipherment")
                if ku.key_agreement:
                    key_usage.append("key_agreement")
                extensions["key_usage"] = key_usage

        # Calculate fingerprints
        fingerprints = {
            "sha256": hashlib.sha256(
                cert.public_bytes(serialization.Encoding.DER)
            ).hexdigest(),
            "sha1": hashlib.sha1(  # noqa: S324 - SHA1 fingerprint included for compatibility with legacy systems
                cert.public_bytes(serialization.Encoding.DER)
            ).hexdigest(),
        }

        return {
            "subject": subject,
            "issuer": issuer,
            "serial_number": str(cert.serial_number),
            "not_valid_before": cert.not_valid_before.isoformat(),
            "not_valid_after": cert.not_valid_after.isoformat(),
            "extensions": extensions,
            "fingerprints": fingerprints,
            "signature_algorithm": cert.signature_algorithm_oid._name,
        }

    def _verify_hostname(self, cert: x509.Certificate, hostname: str) -> bool:
        """Verify certificate matches hostname.

        Args:
            cert: Certificate to check
            hostname: Expected hostname

        Returns:
            True if hostname matches
        """
        # Check Common Name
        for attr in cert.subject:
            if attr.oid == NameOID.COMMON_NAME:
                if self._match_hostname(attr.value, hostname):
                    return True

        # Check Subject Alternative Names
        try:
            san_ext = cert.extensions.get_extension_for_oid(
                ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
            for san in san_ext.value:
                if self._match_hostname(san.value, hostname):
                    return True
        except x509.ExtensionNotFound:
            pass

        return False

    def _match_hostname(self, cert_name: str, hostname: str) -> bool:
        """Match hostname with wildcard support.

        Args:
            cert_name: Certificate name (may include wildcards)
            hostname: Hostname to match

        Returns:
            True if matches
        """
        # Exact match
        if cert_name.lower() == hostname.lower():
            return True

        # Wildcard match
        if cert_name.startswith("*."):
            cert_domain = cert_name[2:]
            hostname_parts = hostname.split(".", 1)
            if (
                len(hostname_parts) == 2
                and hostname_parts[1].lower() == cert_domain.lower()
            ):
                return True

        return False

    def _verify_key_usage(self, cert: x509.Certificate, purpose: str) -> bool:
        """Verify certificate key usage.

        Args:
            cert: Certificate to check
            purpose: Intended purpose

        Returns:
            True if key usage is allowed
        """
        try:
            ku_ext = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
            key_usage = ku_ext.value

            # Check allowed usages
            has_allowed = False
            for usage in self.allowed_key_usages:
                if (
                    (usage == "digital_signature" and key_usage.digital_signature)
                    or (usage == "key_encipherment" and key_usage.key_encipherment)
                    or (usage == "key_agreement" and key_usage.key_agreement)
                ):
                    has_allowed = True

            return has_allowed

        except x509.ExtensionNotFound:
            # No key usage extension, allow by default
            return True

    def _verify_chain(self, cert: x509.Certificate) -> bool:
        """Verify certificate chain (simplified).

        Args:
            cert: Certificate to verify

        Returns:
            True if chain is valid
        """
        # This is a simplified check - in production use proper chain validation
        return any(cert.issuer == ca_cert.subject for ca_cert in self._trusted_cas)

    def create_ssl_context(
        self,
        client_cert_path: str | None = None,
        client_key_path: str | None = None,
        verify_mode: int = ssl.CERT_REQUIRED,
    ) -> ssl.SSLContext:
        """Create SSL context for mutual TLS.

        Args:
            client_cert_path: Client certificate path
            client_key_path: Client private key path
            verify_mode: SSL verification mode

        Returns:
            Configured SSL context
        """
        context = ssl.create_default_context()
        context.check_hostname = self.check_hostname
        context.verify_mode = verify_mode

        # Load trusted CA certificates
        if self.trusted_ca_certs:
            for ca_cert in self.trusted_ca_certs:
                context.load_verify_locations(ca_cert)

        # Load client certificate
        if client_cert_path and client_key_path:
            context.load_cert_chain(client_cert_path, client_key_path)

        return context

    def extract_peer_certificate(
        self, ssl_socket: ssl.SSLSocket
    ) -> dict[str, Any] | None:
        """Extract peer certificate from SSL connection.

        Args:
            ssl_socket: SSL socket connection

        Returns:
            Certificate information if available
        """
        try:
            peer_cert = ssl_socket.getpeercert(binary_form=True)
            if peer_cert:
                cert = x509.load_der_x509_certificate(peer_cert, default_backend())
                return self._extract_certificate_info(cert)
        except Exception as e:
            logger.exception(f"Failed to extract peer certificate: {e}")

        return None

    @staticmethod
    def generate_certificate_fingerprint(
        cert_data: bytes, algorithm: str = "sha256"
    ) -> str:
        """Generate certificate fingerprint.

        Args:
            cert_data: Certificate data
            algorithm: Hash algorithm

        Returns:
            Fingerprint hex string
        """
        if algorithm == "sha256":
            return hashlib.sha256(cert_data).hexdigest()
        if algorithm == "sha1":
            return hashlib.sha1(cert_data).hexdigest()  # noqa: S324 - SHA1 support needed for legacy certificate validation
        raise ValueError(f"Unsupported algorithm: {algorithm}")

    def validate_certificate_pinning(
        self,
        cert_data: bytes,
        pinned_fingerprints: list[str],
        algorithm: str = "sha256",
    ) -> bool:
        """Validate certificate against pinned fingerprints.

        Args:
            cert_data: Certificate data
            pinned_fingerprints: List of allowed fingerprints
            algorithm: Fingerprint algorithm

        Returns:
            True if certificate matches a pinned fingerprint
        """
        fingerprint = self.generate_certificate_fingerprint(cert_data, algorithm)
        return fingerprint in pinned_fingerprints
