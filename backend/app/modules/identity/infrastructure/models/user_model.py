"""
User Model

SQLModel definition for user persistence.
"""

from datetime import datetime, UTC
from typing import Any
from uuid import UUID

from sqlmodel import Field, SQLModel, Column, JSON
from app.modules.identity.domain.aggregates.user import User
from app.modules.identity.domain.value_objects.email import Email
from app.modules.identity.domain.value_objects.username import Username
from app.modules.identity.domain.value_objects.phone_number import PhoneNumber
from app.modules.identity.domain.value_objects.person_name import PersonName
from app.modules.identity.domain.value_objects.date_of_birth import DateOfBirth
from app.modules.identity.domain.value_objects.password_hash import PasswordHash
from app.modules.identity.domain.value_objects.address import Address
from app.modules.identity.domain.entities.user.user_enums import UserStatus, Gender


class UserModel(SQLModel, table=True):
    """User persistence model."""
    
    __tablename__ = "users"
    
    # Identity
    id: UUID = Field(primary_key=True)
    email: str = Field(index=True, unique=True)
    username: str | None = Field(default=None, index=True, unique=True)
    phone_number: str | None = Field(default=None, index=True)
    
    # Authentication
    password_hash: str | None = Field(default=None)
    is_active: bool = Field(default=True)
    is_verified: bool = Field(default=False)
    is_locked: bool = Field(default=False)
    
    # Profile
    full_name: str | None = Field(default=None)
    display_name: str | None = Field(default=None)
    avatar_url: str | None = Field(default=None)
    bio: str | None = Field(default=None)
    date_of_birth: str | None = Field(default=None)
    gender: str | None = Field(default=None)
    
    # Address (stored as JSON)
    address: dict[str, Any] | None = Field(default=None, sa_column=Column(JSON))
    
    # Metadata
    metadata: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    preferences: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    
    # Security
    mfa_enabled: bool = Field(default=False)
    mfa_methods: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    backup_codes: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    
    # Permissions
    role_ids: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    permission_ids: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    
    # External IDs
    external_ids: dict[str, str] = Field(default_factory=dict, sa_column=Column(JSON))
    
    # Status
    status: str = Field(default=UserStatus.ACTIVE.value, index=True)
    status_reason: str | None = Field(default=None)
    status_changed_at: datetime | None = Field(default=None)
    
    # Activity tracking
    login_count: int = Field(default=0)
    failed_login_count: int = Field(default=0)
    last_login_at: datetime | None = Field(default=None)
    last_login_ip: str | None = Field(default=None)
    last_activity_at: datetime | None = Field(default=None)
    
    # Lock tracking
    locked_at: datetime | None = Field(default=None)
    locked_until: datetime | None = Field(default=None)
    lock_reason: str | None = Field(default=None)
    
    # Verification
    verified_at: datetime | None = Field(default=None)
    verification_token: str | None = Field(default=None)
    verification_token_expires_at: datetime | None = Field(default=None)
    
    # Password reset
    password_reset_token: str | None = Field(default=None)
    password_reset_token_expires_at: datetime | None = Field(default=None)
    password_changed_at: datetime | None = Field(default=None)
    
    # Timestamps
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC), index=True)
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    deleted_at: datetime | None = Field(default=None, index=True)
    
    @classmethod
    def from_domain(cls, user: User) -> "UserModel":
        """Create model from domain entity."""
        return cls(
            id=user.id,
            email=user.email.value if isinstance(user.email, Email) else user.email,
            username=user.username.value if user.username and isinstance(user.username, Username) else user.username,
            phone_number=user.phone_number.value if user.phone_number and isinstance(user.phone_number, PhoneNumber) else user.phone_number,
            password_hash=user.password_hash.value if user.password_hash and isinstance(user.password_hash, PasswordHash) else user.password_hash,
            is_active=user.is_active,
            is_verified=user.is_verified,
            is_locked=user.is_locked,
            full_name=user.full_name.full_name if user.full_name and isinstance(user.full_name, PersonName) else user.full_name,
            display_name=user.display_name,
            avatar_url=user.avatar_url,
            bio=user.bio,
            date_of_birth=user.date_of_birth.to_iso_format() if user.date_of_birth and isinstance(user.date_of_birth, DateOfBirth) else user.date_of_birth,
            gender=user.gender.value if user.gender and isinstance(user.gender, Gender) else user.gender,
            address=user.address.to_dict() if user.address and isinstance(user.address, Address) else user.address,
            metadata=user.metadata,
            preferences=user.preferences,
            mfa_enabled=user.mfa_enabled,
            mfa_methods=user.mfa_methods,
            backup_codes=user.backup_codes,
            role_ids=[str(role_id) for role_id in user.role_ids],
            permission_ids=[str(perm_id) for perm_id in user.permission_ids],
            external_ids=user.external_ids,
            status=user.status.value if isinstance(user.status, UserStatus) else user.status,
            status_reason=user.status_reason,
            status_changed_at=user.status_changed_at,
            login_count=user.login_count,
            failed_login_count=user.failed_login_count,
            last_login_at=user.last_login_at,
            last_login_ip=user.last_login_ip,
            last_activity_at=user.last_activity_at,
            locked_at=user.locked_at,
            locked_until=user.locked_until,
            lock_reason=user.lock_reason,
            verified_at=user.verified_at,
            verification_token=user.verification_token,
            verification_token_expires_at=user.verification_token_expires_at,
            password_reset_token=user.password_reset_token,
            password_reset_token_expires_at=user.password_reset_token_expires_at,
            password_changed_at=user.password_changed_at,
            created_at=user.created_at,
            updated_at=user.updated_at or datetime.now(UTC),
            deleted_at=user.deleted_at,
        )
    
    def to_domain(self) -> User:
        """Convert to domain entity."""
        # Reconstruct value objects
        email = Email(self.email) if self.email else None
        username = Username(self.username) if self.username else None
        phone_number = PhoneNumber(self.phone_number) if self.phone_number else None
        password_hash = PasswordHash(self.password_hash) if self.password_hash else None
        
        # Handle PersonName
        full_name = None
        if self.full_name:
            try:
                # Try to parse as "FirstName LastName"
                parts = self.full_name.split(' ', 1)
                if len(parts) == 2:
                    full_name = PersonName(first_name=parts[0], last_name=parts[1])
                else:
                    full_name = PersonName(first_name=self.full_name, last_name="")
            except (ValueError, TypeError, AttributeError):
                # Fallback to string
                full_name = self.full_name
        
        # Handle DateOfBirth
        date_of_birth = None
        if self.date_of_birth:
            try:
                date_of_birth = DateOfBirth.from_iso_format(self.date_of_birth)
            except (ValueError, TypeError, AttributeError):
                date_of_birth = self.date_of_birth
        
        # Handle Address
        address = None
        if self.address:
            try:
                address = Address(**self.address)
            except (ValueError, TypeError, AttributeError):
                address = self.address
        
        # Handle enums
        status = UserStatus(self.status) if self.status else UserStatus.ACTIVE
        gender = Gender(self.gender) if self.gender else None
        
        # Create user instance
        user = User(
            id=self.id,
            email=email,
            username=username,
            phone_number=phone_number,
            password_hash=password_hash,
            is_active=self.is_active,
            is_verified=self.is_verified,
            is_locked=self.is_locked,
            full_name=full_name,
            display_name=self.display_name,
            avatar_url=self.avatar_url,
            bio=self.bio,
            date_of_birth=date_of_birth,
            gender=gender,
            address=address,
            metadata=self.metadata or {},
            preferences=self.preferences or {},
            mfa_enabled=self.mfa_enabled,
            mfa_methods=self.mfa_methods or [],
            backup_codes=self.backup_codes or [],
            role_ids=[UUID(role_id) for role_id in self.role_ids] if self.role_ids else [],
            permission_ids=[UUID(perm_id) for perm_id in self.permission_ids] if self.permission_ids else [],
            external_ids=self.external_ids or {},
            status=status,
            status_reason=self.status_reason,
            status_changed_at=self.status_changed_at,
            login_count=self.login_count,
            failed_login_count=self.failed_login_count,
            last_login_at=self.last_login_at,
            last_login_ip=self.last_login_ip,
            last_activity_at=self.last_activity_at,
            locked_at=self.locked_at,
            locked_until=self.locked_until,
            lock_reason=self.lock_reason,
            verified_at=self.verified_at,
            verification_token=self.verification_token,
            verification_token_expires_at=self.verification_token_expires_at,
            password_reset_token=self.password_reset_token,
            password_reset_token_expires_at=self.password_reset_token_expires_at,
            password_changed_at=self.password_changed_at,
            created_at=self.created_at,
            updated_at=self.updated_at,
            deleted_at=self.deleted_at,
        )
        
        return user