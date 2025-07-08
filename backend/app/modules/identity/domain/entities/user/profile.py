"""
User Profile Entity

Represents additional profile information for a user.
"""

from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from typing import Any
from uuid import UUID, uuid4

from app.core.domain.base import Entity
from app.shared.value_objects.address import Address

from .user_constants import ProfileLimits
from .user_enums import Department
from .user_events import ProfileCompleted


@dataclass
class UserProfile(Entity):
    """User profile entity containing extended user information."""
    
    id: UUID
    user_id: UUID
    display_name: str | None = None
    bio: str | None = None
    home_address: Address | None = None
    work_address: Address | None = None
    phone_number: str | None = None
    date_of_birth: date | None = None
    department: Department | None = None
    job_title: str | None = None
    supervisor_id: UUID | None = None
    skills: list[str] = field(default_factory=list)
    certifications: list[dict[str, Any]] = field(default_factory=list)
    preferred_language: str = "en"
    timezone: str = "UTC"
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    profile_completion: float = 0.0
    
    def __post_init__(self, is_new_profile: bool = True):
        """Initialize user profile entity with comprehensive validation."""
        super().__post_init__()
        
        # Validate profile data
        validation_issues = self.validate_data()
        if validation_issues:
            raise ValueError(f"Profile validation failed: {'; '.join(validation_issues)}")
        
        # Calculate initial completion
        self.profile_completion = self.calculate_completion()
        
        # Emit profile creation event only for new profiles
        if is_new_profile:
            from .user_events import ProfileUpdated
            self.add_domain_event(ProfileUpdated(
                user_id=self.user_id,
                updated_fields=["profile_created"],
                previous_values={},
                new_values={"completion": self.profile_completion}
            ))
    
    @classmethod
    def create(cls, user_id: UUID) -> 'UserProfile':
        """Create a new user profile."""
        profile = cls(
            id=uuid4(),
            user_id=user_id,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC)
        )
        # Manually call __post_init__ with the correct flag
        profile.__post_init__(is_new_profile=True)
        return profile
    
    def update_address(self, address_type: str, address: Address) -> None:
        """Update home or work address."""
        if address_type == "home":
            self.home_address = address
        elif address_type == "work":
            self.work_address = address
        else:
            raise ValueError("Address type must be 'home' or 'work'")
        
        self.updated_at = datetime.now(UTC)
        self._check_profile_completion()
    
    def add_skill(self, skill: str) -> None:
        """Add a skill to the profile."""
        if len(self.skills) >= ProfileLimits.MAX_SKILLS:
            raise ValueError(f"Cannot have more than {ProfileLimits.MAX_SKILLS} skills")
        
        # Check for duplicates (case-insensitive)
        skill_lower = skill.lower().strip()
        if skill and not any(existing.lower() == skill_lower for existing in self.skills):
            self.skills.append(skill.strip())
            self.updated_at = datetime.now(UTC)
            self._check_profile_completion()
    
    def remove_skill(self, skill: str) -> None:
        """Remove a skill from the profile."""
        # Case-insensitive removal
        skill_lower = skill.lower()
        original_count = len(self.skills)
        self.skills = [s for s in self.skills if s.lower() != skill_lower]
        
        if len(self.skills) < original_count:
            self.updated_at = datetime.now(UTC)
            self._check_profile_completion()
    
    def add_certification(self, certification: dict[str, Any]) -> None:
        """Add a certification to the profile."""
        if len(self.certifications) >= ProfileLimits.MAX_CERTIFICATIONS:
            raise ValueError(f"Cannot have more than {ProfileLimits.MAX_CERTIFICATIONS} certifications")
        
        # Validate certification structure
        required_fields = ['name', 'issuer', 'date_obtained']
        for field in required_fields:
            if field not in certification:
                raise ValueError(f"Certification must have {field}")
        
        certification['id'] = str(uuid4())
        self.certifications.append(certification)
        self.updated_at = datetime.now(UTC)
        self._check_profile_completion()
    
    def remove_certification(self, certification_id: str) -> None:
        """Remove a certification from the profile."""
        original_count = len(self.certifications)
        self.certifications = [
            cert for cert in self.certifications 
            if cert.get('id') != certification_id
        ]
        
        if len(self.certifications) < original_count:
            self.updated_at = datetime.now(UTC)
            self._check_profile_completion()
    
    def calculate_completion(self) -> float:
        """Calculate profile completion percentage."""
        fields = {
            'display_name': 10,
            'bio': 10,
            'phone_number': 10,
            'date_of_birth': 10,
            'home_address': 10,
            'work_address': 10,
            'department': 10,
            'job_title': 10,
            'skills': 10,  # At least one skill
            'certifications': 10  # At least one certification
        }
        
        total_weight = sum(fields.values())
        completed_weight = 0
        
        # Check each field
        if self.display_name:
            completed_weight += fields['display_name']
        if self.bio:
            completed_weight += fields['bio']
        if self.phone_number:
            completed_weight += fields['phone_number']
        if self.date_of_birth:
            completed_weight += fields['date_of_birth']
        if self.home_address:
            completed_weight += fields['home_address']
        if self.work_address:
            completed_weight += fields['work_address']
        if self.department:
            completed_weight += fields['department']
        if self.job_title:
            completed_weight += fields['job_title']
        if self.skills:
            completed_weight += fields['skills']
        if self.certifications:
            completed_weight += fields['certifications']
        
        return (completed_weight / total_weight) * 100
    
    def _check_profile_completion(self) -> None:
        """Check and update profile completion, emit event if 100%."""
        old_completion = self.profile_completion
        new_completion = self.calculate_completion()
        self.profile_completion = new_completion
        
        # Emit event if profile just reached 100% completion
        if old_completion < 100.0 and new_completion == 100.0:
            missing_fields = self._get_missing_fields()
            
            self.add_domain_event(ProfileCompleted(
                user_id=self.user_id,
                completion_percentage=new_completion,
                completed_at=datetime.now(UTC),
                missing_fields_filled=missing_fields
            ))
    
    def _get_missing_fields(self) -> list[str]:
        """Get list of missing profile fields."""
        missing = []
        
        if not self.display_name:
            missing.append('display_name')
        if not self.bio:
            missing.append('bio')
        if not self.phone_number:
            missing.append('phone_number')
        if not self.date_of_birth:
            missing.append('date_of_birth')
        if not self.home_address:
            missing.append('home_address')
        if not self.work_address:
            missing.append('work_address')
        if not self.department:
            missing.append('department')
        if not self.job_title:
            missing.append('job_title')
        if not self.skills:
            missing.append('skills')
        if not self.certifications:
            missing.append('certifications')
        
        return missing
    
    def validate_data(self) -> list[str]:
        """Validate profile data and return list of issues."""
        issues = []
        
        # Validate display name
        if self.display_name:
            if len(self.display_name) > ProfileLimits.DISPLAY_NAME_MAX_LENGTH:
                issues.append(f"Display name too long (max {ProfileLimits.DISPLAY_NAME_MAX_LENGTH} characters)")
            if len(self.display_name.strip()) == 0:
                issues.append("Display name cannot be empty")
            if any(char in self.display_name for char in '<>{}[]'):
                issues.append("Display name contains invalid characters")
        
        # Validate bio
        if self.bio:
            if len(self.bio) > ProfileLimits.BIO_MAX_LENGTH:
                issues.append(f"Bio exceeds {ProfileLimits.BIO_MAX_LENGTH} characters")
            # Check for potentially harmful content
            suspicious_patterns = ['<script', 'javascript:', 'data:', 'vbscript:']
            if any(pattern in self.bio.lower() for pattern in suspicious_patterns):
                issues.append("Bio contains potentially harmful content")
        
        # Validate phone number format
        if self.phone_number:
            cleaned_phone = self.phone_number.replace('+', '').replace('-', '').replace(' ', '').replace('(', '').replace(')', '')
            if not cleaned_phone.isdigit():
                issues.append("Invalid phone number format")
            if len(cleaned_phone) < ProfileLimits.PHONE_NUMBER_MIN_LENGTH or len(cleaned_phone) > ProfileLimits.PHONE_NUMBER_MAX_LENGTH:
                issues.append(f"Phone number must be between {ProfileLimits.PHONE_NUMBER_MIN_LENGTH} and {ProfileLimits.PHONE_NUMBER_MAX_LENGTH} digits")
        
        # Validate date of birth
        if self.date_of_birth:
            today = date.today()
            age = (today - self.date_of_birth).days // 365
            if age < 13:
                issues.append("User must be at least 13 years old")
            elif age > 150:
                issues.append("Invalid date of birth")
            if self.date_of_birth > today:
                issues.append("Date of birth cannot be in the future")
        
        # Validate skills
        if len(self.skills) > ProfileLimits.MAX_SKILLS:
            issues.append(f"Too many skills (max {ProfileLimits.MAX_SKILLS})")
        
        # Validate individual skills
        for skill in self.skills:
            if not skill or len(skill.strip()) == 0:
                issues.append("Skills cannot be empty")
            if len(skill) > 50:
                issues.append("Individual skills cannot exceed 50 characters")
        
        # Validate certifications
        if len(self.certifications) > ProfileLimits.MAX_CERTIFICATIONS:
            issues.append(f"Too many certifications (max {ProfileLimits.MAX_CERTIFICATIONS})")
        
        # Validate certification structure
        for cert in self.certifications:
            if not isinstance(cert, dict):
                issues.append("Certifications must be properly structured")
                continue
            
            required_fields = ['name', 'issuer', 'date_obtained']
            for field in required_fields:
                if field not in cert or not cert[field]:
                    issues.append(f"Certification missing required field: {field}")
        
        # Validate job title
        if self.job_title and len(self.job_title) > ProfileLimits.JOB_TITLE_MAX_LENGTH:
            issues.append(f"Job title cannot exceed {ProfileLimits.JOB_TITLE_MAX_LENGTH} characters")
        
        return issues
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "id": str(self.id),
            "user_id": str(self.user_id),
            "display_name": self.display_name,
            "bio": self.bio,
            "home_address": self.home_address.to_dict() if self.home_address else None,
            "work_address": self.work_address.to_dict() if self.work_address else None,
            "phone_number": self.phone_number,
            "date_of_birth": self.date_of_birth.isoformat() if self.date_of_birth else None,
            "department": self.department.value if self.department else None,
            "job_title": self.job_title,
            "supervisor_id": str(self.supervisor_id) if self.supervisor_id else None,
            "skills": self.skills,
            "certifications": self.certifications,
            "preferred_language": self.preferred_language,
            "timezone": self.timezone,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "profile_completion": self.profile_completion
        }