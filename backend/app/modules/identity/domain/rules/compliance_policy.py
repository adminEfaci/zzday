"""
Compliance Policy

Business rules for regulatory compliance (GDPR, CCPA, etc.).
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any

from .base import BusinessRule, PolicyViolation


class DataCategory(Enum):
    """Categories of personal data."""
    BASIC_IDENTITY = "basic_identity"  # Name, email, username
    CONTACT_INFO = "contact_info"  # Phone, address
    AUTHENTICATION = "authentication"  # Password, MFA
    FINANCIAL = "financial"  # Payment methods, transactions
    BEHAVIORAL = "behavioral"  # Activity logs, preferences
    BIOMETRIC = "biometric"  # Fingerprints, face data
    LOCATION = "location"  # GPS, IP-based location
    DEVICE = "device"  # Device IDs, fingerprints
    SENSITIVE = "sensitive"  # Health, political views, etc.


class ConsentPurpose(Enum):
    """Purposes for data processing."""
    SERVICE_PROVISION = "service_provision"
    MARKETING = "marketing"
    ANALYTICS = "analytics"
    THIRD_PARTY_SHARING = "third_party_sharing"
    PROFILING = "profiling"
    AUTOMATED_DECISIONS = "automated_decisions"


@dataclass
class CompliancePolicy(BusinessRule):
    """Policy for regulatory compliance requirements."""
    
    # Data retention periods (in days)
    retention_periods: dict[DataCategory, int] = field(default_factory=lambda: {
        DataCategory.BASIC_IDENTITY: 365 * 7,  # 7 years
        DataCategory.CONTACT_INFO: 365 * 7,
        DataCategory.AUTHENTICATION: 365 * 2,  # 2 years
        DataCategory.FINANCIAL: 365 * 7,  # 7 years for tax
        DataCategory.BEHAVIORAL: 365 * 2,
        DataCategory.BIOMETRIC: 90,  # 90 days
        DataCategory.LOCATION: 180,  # 6 months
        DataCategory.DEVICE: 365,  # 1 year
        DataCategory.SENSITIVE: 30,  # 30 days unless explicit consent
    })
    
    # Required consents by region
    required_consents: dict[str, set[ConsentPurpose]] = field(default_factory=lambda: {
        'EU': {
            ConsentPurpose.MARKETING,
            ConsentPurpose.ANALYTICS,
            ConsentPurpose.THIRD_PARTY_SHARING,
            ConsentPurpose.PROFILING,
            ConsentPurpose.AUTOMATED_DECISIONS
        },
        'CA': {  # California
            ConsentPurpose.THIRD_PARTY_SHARING,
            ConsentPurpose.PROFILING
        },
        'DEFAULT': {
            ConsentPurpose.MARKETING,
            ConsentPurpose.THIRD_PARTY_SHARING
        }
    })
    
    # Configuration
    require_explicit_consent: bool = True
    allow_consent_withdrawal: bool = True
    data_portability_enabled: bool = True
    right_to_deletion_enabled: bool = True
    automated_data_minimization: bool = True
    
    # Age restrictions
    minimum_age: int = 13
    parental_consent_age: int = 16
    
    def validate(self, **kwargs) -> list[PolicyViolation]:
        """Validate compliance policy."""
        violations = []
        
        # Extract parameters
        action = kwargs.get('action')
        user_data = kwargs.get('user_data', {})
        data_categories = kwargs.get('data_categories', [])
        purpose = kwargs.get('purpose')
        region = kwargs.get('region', 'DEFAULT')
        
        # Validate age requirements
        if action in ['registration', 'data_collection']:
            violations.extend(self._validate_age_requirements(user_data))
        
        # Validate consent requirements
        if action == 'data_processing':
            violations.extend(
                self._validate_consent_requirements(user_data, purpose, region)
            )
        
        # Validate data retention
        if action == 'data_retention_check':
            violations.extend(
                self._validate_data_retention(data_categories, user_data)
            )
        
        # Validate data export request
        if action == 'data_export':
            violations.extend(self._validate_data_export_request(user_data))
        
        # Validate deletion request
        if action == 'data_deletion':
            violations.extend(self._validate_deletion_request(user_data))
        
        return violations
    
    def is_compliant(self, **kwargs) -> bool:
        """Check if action is compliant."""
        violations = self.validate(**kwargs)
        return not self.has_blocking_violations(violations)
    
    def _validate_age_requirements(self, user_data: dict[str, Any]) -> list[PolicyViolation]:
        """Validate age-related requirements."""
        violations = []
        
        age = user_data.get('age')
        if age is None:
            violations.append(PolicyViolation(
                rule_name="CompliancePolicy",
                description="Age verification required",
                severity="error",
                current_value="not_provided",
                expected_value="age_verified",
                context={"requirement": "age_verification"}
            ))
        elif age < self.minimum_age:
            violations.append(PolicyViolation(
                rule_name="CompliancePolicy",
                description="User does not meet minimum age requirement",
                severity="critical",
                current_value=age,
                expected_value=f">= {self.minimum_age}",
                context={"minimum_age": self.minimum_age}
            ))
        elif age < self.parental_consent_age:
            if not user_data.get('parental_consent'):
                violations.append(PolicyViolation(
                    rule_name="CompliancePolicy",
                    description="Parental consent required",
                    severity="error",
                    current_value="no_parental_consent",
                    expected_value="parental_consent_provided",
                    context={"age": age, "consent_age": self.parental_consent_age}
                ))
        
        return violations
    
    def _validate_consent_requirements(
        self,
        user_data: dict[str, Any],
        purpose: ConsentPurpose | None,
        region: str
    ) -> list[PolicyViolation]:
        """Validate consent requirements."""
        violations = []
        
        if not purpose:
            return violations
        
        required_consents = self.required_consents.get(
            region,
            self.required_consents['DEFAULT']
        )
        
        if purpose in required_consents:
            user_consents = user_data.get('consents', {})
            if not user_consents.get(purpose.value):
                violations.append(PolicyViolation(
                    rule_name="CompliancePolicy",
                    description=f"Explicit consent required for {purpose.value}",
                    severity="error",
                    current_value="no_consent",
                    expected_value="explicit_consent",
                    context={
                        "purpose": purpose.value,
                        "region": region
                    }
                ))
        
        return violations
    
    def _validate_data_retention(
        self,
        data_categories: list[DataCategory],
        user_data: dict[str, Any]
    ) -> list[PolicyViolation]:
        """Validate data retention compliance."""
        violations = []
        
        for category in data_categories:
            retention_limit = self.retention_periods.get(category)
            if not retention_limit:
                continue
            
            data_age = user_data.get(f'{category.value}_age_days', 0)
            if data_age > retention_limit:
                violations.append(PolicyViolation(
                    rule_name="CompliancePolicy",
                    description=f"Data retention limit exceeded for {category.value}",
                    severity="error",
                    current_value=f"{data_age} days",
                    expected_value=f"<= {retention_limit} days",
                    context={
                        "category": category.value,
                        "should_delete": True
                    }
                ))
        
        return violations
    
    def _validate_data_export_request(
        self,
        user_data: dict[str, Any]
    ) -> list[PolicyViolation]:
        """Validate data export request."""
        violations = []
        
        if not self.data_portability_enabled:
            violations.append(PolicyViolation(
                rule_name="CompliancePolicy",
                description="Data portability not enabled",
                severity="error",
                current_value="disabled",
                expected_value="enabled",
                context={"feature": "data_portability"}
            ))
        
        # Check request frequency
        last_export = user_data.get('last_data_export')
        if last_export:
            days_since = (datetime.utcnow() - last_export).days
            if days_since < 30:  # Limit to once per month
                violations.append(PolicyViolation(
                    rule_name="CompliancePolicy",
                    description="Data export requested too frequently",
                    severity="warning",
                    current_value=f"{days_since} days",
                    expected_value=">= 30 days",
                    context={"last_export": last_export.isoformat()}
                ))
        
        return violations
    
    def _validate_deletion_request(
        self,
        user_data: dict[str, Any]
    ) -> list[PolicyViolation]:
        """Validate deletion request."""
        violations = []
        
        if not self.right_to_deletion_enabled:
            violations.append(PolicyViolation(
                rule_name="CompliancePolicy",
                description="Right to deletion not enabled",
                severity="error",
                current_value="disabled",
                expected_value="enabled",
                context={"feature": "right_to_deletion"}
            ))
        
        # Check for legal holds
        if user_data.get('legal_hold'):
            violations.append(PolicyViolation(
                rule_name="CompliancePolicy",
                description="Cannot delete data under legal hold",
                severity="error",
                current_value="legal_hold_active",
                expected_value="no_legal_hold",
                context={"reason": user_data.get('legal_hold_reason')}
            ))
        
        # Check for active financial obligations
        if user_data.get('active_subscriptions') or user_data.get('pending_transactions'):
            violations.append(PolicyViolation(
                rule_name="CompliancePolicy",
                description="Cannot delete user with active financial obligations",
                severity="error",
                current_value="has_obligations",
                expected_value="no_obligations",
                context={
                    "subscriptions": user_data.get('active_subscriptions', 0),
                    "transactions": user_data.get('pending_transactions', 0)
                }
            ))
        
        return violations
    
    def get_required_consents(self, region: str) -> list[ConsentPurpose]:
        """Get required consents for a region."""
        return list(self.required_consents.get(region, self.required_consents['DEFAULT']))
    
    def get_data_retention_deadline(
        self,
        category: DataCategory,
        collection_date: datetime
    ) -> datetime:
        """Calculate when data should be deleted."""
        retention_days = self.retention_periods.get(category, 365)
        return collection_date + timedelta(days=retention_days)
    
    def categorize_personal_data(self, data_fields: list[str]) -> dict[DataCategory, list[str]]:
        """Categorize data fields by data category."""
        categorization = {
            DataCategory.BASIC_IDENTITY: ['name', 'email', 'username', 'user_id'],
            DataCategory.CONTACT_INFO: ['phone', 'address', 'city', 'country'],
            DataCategory.AUTHENTICATION: ['password', 'mfa_secret', 'backup_codes'],
            DataCategory.FINANCIAL: ['payment_method', 'billing_address', 'transactions'],
            DataCategory.BEHAVIORAL: ['preferences', 'activity_logs', 'search_history'],
            DataCategory.BIOMETRIC: ['fingerprint', 'face_data', 'voice_print'],
            DataCategory.LOCATION: ['ip_address', 'gps_location', 'timezone'],
            DataCategory.DEVICE: ['device_id', 'browser_fingerprint', 'user_agent'],
            DataCategory.SENSITIVE: ['health_data', 'political_views', 'religious_beliefs']
        }
        
        result = {}
        for category, fields in categorization.items():
            matched_fields = [f for f in data_fields if f in fields]
            if matched_fields:
                result[category] = matched_fields
        
        return result
    
    def generate_privacy_notice(self, region: str) -> dict[str, Any]:
        """Generate privacy notice requirements for region."""
        return {
            'required_consents': [c.value for c in self.get_required_consents(region)],
            'data_retention_periods': {
                k.value: v for k, v in self.retention_periods.items()
            },
            'user_rights': {
                'access': True,
                'rectification': True,
                'erasure': self.right_to_deletion_enabled,
                'portability': self.data_portability_enabled,
                'object': True,
                'withdraw_consent': self.allow_consent_withdrawal
            },
            'minimum_age': self.minimum_age,
            'parental_consent_age': self.parental_consent_age
        }