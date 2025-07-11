"""
Compliance Repository Interface

Repository interface for compliance data management and regulatory tracking.
"""

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

from ...services.compliance.compliance_service import (
    ComplianceAssessment,
    ComplianceRequirement,
    DataProcessingRecord,
    ComplianceFramework
)


class IComplianceRepository(ABC):
    """
    Repository interface for compliance data operations.
    
    Provides methods for storing and retrieving compliance assessments,
    data processing records, and regulatory requirements.
    """
    
    @abstractmethod
    async def get_framework_requirements(
        self,
        framework: ComplianceFramework
    ) -> List[ComplianceRequirement]:
        """
        Get compliance requirements for a specific framework.
        
        Args:
            framework: Compliance framework enum
            
        Returns:
            List of compliance requirements
        """
        ...
    
    @abstractmethod
    async def store_assessment(self, assessment: ComplianceAssessment) -> str:
        """
        Store a compliance assessment result.
        
        Args:
            assessment: Compliance assessment to store
            
        Returns:
            Assessment ID
        """
        ...
    
    @abstractmethod
    async def get_assessments(
        self,
        framework: Optional[ComplianceFramework] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None
    ) -> List[ComplianceAssessment]:
        """
        Retrieve compliance assessments with optional filtering.
        
        Args:
            framework: Filter by specific framework
            start_date: Filter assessments after this date
            end_date: Filter assessments before this date
            
        Returns:
            List of compliance assessments
        """
        ...
    
    @abstractmethod
    async def store_processing_record(self, record: DataProcessingRecord) -> str:
        """
        Store a data processing record for GDPR Article 30 compliance.
        
        Args:
            record: Data processing record to store
            
        Returns:
            Record ID
        """
        ...
    
    @abstractmethod
    async def get_processing_records(
        self,
        user_id: Optional[UUID] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        data_types: Optional[List[str]] = None
    ) -> List[DataProcessingRecord]:
        """
        Retrieve data processing records with filtering.
        
        Args:
            user_id: Filter by specific user
            start_date: Filter records after this date
            end_date: Filter records before this date
            data_types: Filter by specific data types
            
        Returns:
            List of data processing records
        """
        ...
    
    @abstractmethod
    async def get_compliance_data(
        self,
        framework: ComplianceFramework,
        start_date: datetime,
        end_date: datetime
    ) -> Dict[str, Any]:
        """
        Get aggregated compliance data for reporting.
        
        Args:
            framework: Compliance framework
            start_date: Start of reporting period
            end_date: End of reporting period
            
        Returns:
            Aggregated compliance data
        """
        ...
    
    @abstractmethod
    async def get_subject_requests(
        self,
        start_date: datetime,
        end_date: datetime,
        request_types: Optional[List[str]] = None
    ) -> List[Dict[str, Any]]:
        """
        Get data subject rights requests for reporting.
        
        Args:
            start_date: Start of reporting period
            end_date: End of reporting period
            request_types: Filter by specific request types
            
        Returns:
            List of data subject requests
        """
        ...
    
    @abstractmethod
    async def store_report(self, report: Dict[str, Any]) -> str:
        """
        Store a compliance report.
        
        Args:
            report: Compliance report data
            
        Returns:
            Report ID
        """
        ...
    
    @abstractmethod
    async def get_user_data(self, user_id: UUID) -> Dict[str, Any]:
        """
        Get all user data for data subject access requests.
        
        Args:
            user_id: User identifier
            
        Returns:
            Complete user data across all systems
        """
        ...
    
    @abstractmethod
    async def erase_user_data(self, user_id: UUID) -> Dict[str, Any]:
        """
        Erase user data for GDPR right to erasure.
        
        Args:
            user_id: User identifier
            
        Returns:
            Erasure result including count and processing time
        """
        ...
    
    @abstractmethod
    async def get_portable_user_data(self, user_id: UUID) -> Dict[str, Any]:
        """
        Get user data in portable format for data portability requests.
        
        Args:
            user_id: User identifier
            
        Returns:
            User data in portable format
        """
        ...
    
    @abstractmethod
    async def apply_data_corrections(
        self,
        user_id: UUID,
        corrections: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Apply data corrections for rectification requests.
        
        Args:
            user_id: User identifier
            corrections: Data corrections to apply
            
        Returns:
            Correction result including fields updated
        """
        ...
    
    @abstractmethod
    async def restrict_user_data_processing(self, user_id: UUID) -> Dict[str, Any]:
        """
        Restrict data processing for a user.
        
        Args:
            user_id: User identifier
            
        Returns:
            Restriction result including affected activities
        """
        ...
    
    @abstractmethod
    async def process_objection(self, user_id: UUID) -> Dict[str, Any]:
        """
        Process user objection to data processing.
        
        Args:
            user_id: User identifier
            
        Returns:
            Objection processing result
        """
        ...
    
    @abstractmethod
    async def update_processing_records(
        self,
        user_id: UUID,
        rights_exercised: List[str],
        update_date: datetime
    ) -> bool:
        """
        Update processing records with exercised rights.
        
        Args:
            user_id: User identifier
            rights_exercised: List of rights exercised
            update_date: Date of update
            
        Returns:
            True if update was successful
        """
        ...
    
    @abstractmethod
    async def get_retention_requirements(
        self,
        framework: ComplianceFramework
    ) -> Dict[str, Any]:
        """
        Get data retention requirements for framework.
        
        Args:
            framework: Compliance framework
            
        Returns:
            Retention requirements by data type
        """
        ...
    
    @abstractmethod
    async def check_active_contracts(self, user_id: UUID) -> bool:
        """
        Check if user has active contracts preventing erasure.
        
        Args:
            user_id: User identifier
            
        Returns:
            True if active contracts exist
        """
        ...
    
    @abstractmethod
    async def check_pending_disputes(self, user_id: UUID) -> bool:
        """
        Check if user has pending legal disputes.
        
        Args:
            user_id: User identifier
            
        Returns:
            True if pending disputes exist
        """
        ...
    
    @abstractmethod
    async def create_consent_record(
        self,
        user_id: UUID,
        consent_type: str,
        purpose: str,
        given: bool,
        consent_date: datetime
    ) -> str:
        """
        Create a consent record for tracking.
        
        Args:
            user_id: User identifier
            consent_type: Type of consent
            purpose: Purpose of data processing
            given: Whether consent was given
            consent_date: Date consent was given/withdrawn
            
        Returns:
            Consent record ID
        """
        ...
    
    @abstractmethod
    async def get_consent_history(
        self,
        user_id: UUID,
        consent_types: Optional[List[str]] = None
    ) -> List[Dict[str, Any]]:
        """
        Get consent history for a user.
        
        Args:
            user_id: User identifier
            consent_types: Filter by specific consent types
            
        Returns:
            List of consent records
        """
        ...
    
    @abstractmethod
    async def track_data_breach(
        self,
        breach_data: Dict[str, Any]
    ) -> str:
        """
        Track a data breach incident for compliance reporting.
        
        Args:
            breach_data: Data breach information
            
        Returns:
            Breach incident ID
        """
        ...
    
    @abstractmethod
    async def get_breach_notifications(
        self,
        start_date: datetime,
        end_date: datetime,
        severity: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Get data breach notifications for regulatory reporting.
        
        Args:
            start_date: Start of reporting period
            end_date: End of reporting period
            severity: Filter by breach severity
            
        Returns:
            List of breach notifications
        """
        ...
    
    @abstractmethod
    async def generate_privacy_impact_assessment(
        self,
        processing_activity: str,
        data_types: List[str],
        risk_factors: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Generate or retrieve privacy impact assessment.
        
        Args:
            processing_activity: Description of processing activity
            data_types: Types of data being processed
            risk_factors: Risk assessment factors
            
        Returns:
            Privacy impact assessment results
        """
        ...
    
    @abstractmethod
    async def cleanup_expired_data(
        self,
        retention_policies: Dict[str, int]
    ) -> Dict[str, int]:
        """
        Clean up data that has exceeded retention periods.
        
        Args:
            retention_policies: Data type to retention period mapping
            
        Returns:
            Cleanup results by data type
        """
        ...
