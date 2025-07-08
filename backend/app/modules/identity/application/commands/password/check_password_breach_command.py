"""
Check password breach command implementation.

Handles checking if passwords have been exposed in data breaches.
"""

import hashlib
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from app.core.cqrs import Command, CommandHandler
from app.core.infrastructure import UnitOfWork
from app.modules.identity.domain.interfaces.services.infrastructure.cache_port import ICachePort as ICacheService
from app.modules.identity.domain.interfaces.services.communication.notification_service import INotificationService
from app.modules.identity.domain.interfaces.repositories.password_history_repository import IPasswordHistoryRepository
from app.modules.identity.domain.interfaces.repositories.user_repository import IUserRepository
from app.modules.identity.application.decorators import (
    audit_action,
    rate_limit,
    require_auth,
    validate_request,
)
from app.modules.identity.application.dtos.request import CheckPasswordBreachRequest
from app.modules.identity.application.dtos.response import PasswordBreachResponse
from app.modules.identity.domain.enums import AuditAction
from app.modules.identity.domain.exceptions import (
    ExternalServiceError,
    UserNotFoundError,
)
from app.modules.identity.domain.services import SecurityService


class CheckPasswordBreachCommand(Command[PasswordBreachResponse]):
    """Command to check password breach status."""
    
    def __init__(
        self,
        password: str | None = None,
        password_hash: str | None = None,
        user_id: UUID | None = None,
        check_history: bool = False,
        notify_if_breached: bool = True,
        check_similar: bool = False
    ):
        self.password = password
        self.password_hash = password_hash
        self.user_id = user_id
        self.check_history = check_history
        self.notify_if_breached = notify_if_breached
        self.check_similar = check_similar


class CheckPasswordBreachCommandHandler(CommandHandler[CheckPasswordBreachCommand, PasswordBreachResponse]):
    """Handler for checking password breaches."""
    
    def __init__(
        self,
        breach_detection_service: IBreachDetectionService,
        password_history_repository: IPasswordHistoryRepository,
        user_repository: IUserRepository,
        security_service: SecurityService,
        notification_service: INotificationService,
        cache_service: ICacheService,
        unit_of_work: UnitOfWork
    ):
        self._breach_detection_service = breach_detection_service
        self._password_history_repository = password_history_repository
        self._user_repository = user_repository
        self._security_service = security_service
        self._notification_service = notification_service
        self._cache_service = cache_service
        self._unit_of_work = unit_of_work
    
    @audit_action(
        action=AuditAction.PASSWORD_BREACH_CHECKED,
        resource_type="user",
        resource_id_attr="user_id",
        include_request=False  # Don't log passwords
    )
    @require_auth
    @validate_request(CheckPasswordBreachRequest)
    @rate_limit(
        max_requests=20,
        window_seconds=300,
        strategy='user'
    )
    async def handle(self, command: CheckPasswordBreachCommand) -> PasswordBreachResponse:
        """
        Check if password has been breached.
        
        Process:
        1. Validate input
        2. Check current password
        3. Check password history if requested
        4. Check similar passwords if requested
        5. Aggregate results
        6. Send notifications if breached
        7. Log security event
        
        Returns:
            PasswordBreachResponse with breach details
            
        Raises:
            ExternalServiceError: If breach service fails
        """
        async with self._unit_of_work:
            # 1. Validate input
            if not command.password and not command.password_hash:
                raise ValueError("Either password or password_hash must be provided")
            
            # 2. Load user if provided
            user = None
            if command.user_id:
                user = await self._user_repository.find_by_id(command.user_id)
                if not user:
                    raise UserNotFoundError(f"User {command.user_id} not found")
            
            # 3. Check main password
            main_result = await self._check_password_breach(
                password=command.password,
                password_hash=command.password_hash
            )
            
            breached_passwords = []
            if main_result['is_breached']:
                breached_passwords.append({
                    'type': 'current',
                    'breach_count': main_result['breach_count'],
                    'first_seen': main_result.get('first_seen'),
                    'last_seen': main_result.get('last_seen'),
                    'severity': self._calculate_severity(main_result['breach_count'])
                })
            
            # 4. Check password history if requested
            history_results = []
            if command.check_history and command.user_id:
                history_results = await self._check_password_history_breaches(
                    user_id=command.user_id
                )
                breached_passwords.extend(history_results)
            
            # 5. Check similar passwords if requested
            similar_results = []
            if command.check_similar and command.password:
                similar_results = await self._check_similar_passwords(
                    password=command.password
                )
                breached_passwords.extend(similar_results)
            
            # 6. Calculate overall risk
            risk_assessment = self._assess_breach_risk(
                breached_passwords=breached_passwords,
                user=user
            )
            
            # 7. Send notification if breached and requested
            if breached_passwords and command.notify_if_breached and user:
                await self._send_breach_notification(
                    user=user,
                    breached_passwords=breached_passwords,
                    risk_assessment=risk_assessment
                )
            
            # 8. Log security event
            if breached_passwords:
                await self._log_breach_detection(
                    user_id=command.user_id,
                    breach_count=len(breached_passwords),
                    risk_level=risk_assessment['risk_level']
                )
            
            # 9. Prepare recommendations
            recommendations = self._generate_recommendations(
                breached_passwords=breached_passwords,
                risk_assessment=risk_assessment
            )
            
            is_breached = len(breached_passwords) > 0
            
            return PasswordBreachResponse(
                is_breached=is_breached,
                breach_details=breached_passwords,
                total_breaches=len(breached_passwords),
                risk_assessment=risk_assessment,
                recommendations=recommendations,
                checked_history=command.check_history,
                checked_similar=command.check_similar,
                notification_sent=is_breached and command.notify_if_breached and user is not None,
                success=True,
                message=self._build_response_message(is_breached, breached_passwords)
            )
    
    async def _check_password_breach(
        self,
        password: str | None = None,
        password_hash: str | None = None
    ) -> dict[str, Any]:
        """Check if a specific password has been breached."""
        try:
            # Generate cache key
            if password:
                cache_key = f"breach:{hashlib.sha256(password.encode()).hexdigest()[:16]}"
            else:
                cache_key = f"breach_hash:{password_hash[:16]}"
            
            # Check cache
            cached = await self._cache_service.get(cache_key)
            if cached:
                return cached
            
            # Check with breach detection service
            if password:
                result = await self._breach_detection_service.check_password(password)
            else:
                result = await self._breach_detection_service.check_password_hash(
                    password_hash
                )
            
            breach_data = {
                'is_breached': result.get('found', False),
                'breach_count': result.get('count', 0),
                'first_seen': result.get('first_seen'),
                'last_seen': result.get('last_seen'),
                'data_sources': result.get('sources', [])
            }
            
            # Cache result
            await self._cache_service.set(cache_key, breach_data, ttl=3600)
            
            return breach_data
            
        except Exception as e:
            raise ExternalServiceError(
                f"Failed to check password breach: {e!s}"
            ) from e
    
    async def _check_password_history_breaches(
        self,
        user_id: UUID
    ) -> list[dict[str, Any]]:
        """Check if historical passwords have been breached."""
        breached_history = []
        
        # Get password history
        history = await self._password_history_repository.get_recent(
            user_id=user_id,
            count=10  # Check last 10 passwords
        )
        
        for i, hist_entry in enumerate(history):
            result = await self._check_password_breach(
                password_hash=hist_entry.password_hash
            )
            
            if result['is_breached']:
                breached_history.append({
                    'type': 'historical',
                    'position': i + 1,  # 1 = most recent
                    'breach_count': result['breach_count'],
                    'first_seen': result.get('first_seen'),
                    'last_seen': result.get('last_seen'),
                    'used_at': hist_entry.created_at.isoformat(),
                    'severity': self._calculate_severity(result['breach_count'])
                })
        
        return breached_history
    
    async def _check_similar_passwords(
        self,
        password: str
    ) -> list[dict[str, Any]]:
        """Check similar password variations for breaches."""
        similar_breaches = []
        
        # Generate common variations
        variations = self._generate_password_variations(password)
        
        for variation_type, variation in variations.items():
            if variation != password:
                result = await self._check_password_breach(password=variation)
                
                if result['is_breached']:
                    similar_breaches.append({
                        'type': 'similar',
                        'variation': variation_type,
                        'breach_count': result['breach_count'],
                        'first_seen': result.get('first_seen'),
                        'last_seen': result.get('last_seen'),
                        'severity': self._calculate_severity(result['breach_count'])
                    })
        
        return similar_breaches
    
    def _generate_password_variations(self, password: str) -> dict[str, str]:
        """Generate common password variations."""
        variations = {}
        
        # Basic variations
        variations['lowercase'] = password.lower()
        variations['uppercase'] = password.upper()
        
        # Common substitutions
        leet_map = {
            'a': '4', 'e': '3', 'i': '1', 'o': '0',
            's': '5', 't': '7', 'g': '9', 'b': '8'
        }
        
        leet_password = password.lower()
        for char, replacement in leet_map.items():
            leet_password = leet_password.replace(char, replacement)
        
        if leet_password != password:
            variations['leet_speak'] = leet_password
        
        # With common suffixes
        common_suffixes = ['123', '!', '1', '2023', '2024']
        for suffix in common_suffixes:
            if not password.endswith(suffix):
                variations[f'with_{suffix}'] = password + suffix
                break  # Only check one suffix
        
        # Without numbers
        no_numbers = ''.join(c for c in password if not c.isdigit())
        if no_numbers != password and len(no_numbers) >= 6:
            variations['no_numbers'] = no_numbers
        
        return variations
    
    def _calculate_severity(self, breach_count: int) -> str:
        """Calculate breach severity based on exposure count."""
        if breach_count > 10000:
            return 'critical'
        if breach_count > 1000:
            return 'high'
        if breach_count > 100:
            return 'medium'
        return 'low'
    
    def _assess_breach_risk(
        self,
        breached_passwords: list[dict[str, Any]],
        user: Any | None
    ) -> dict[str, Any]:
        """Assess overall breach risk."""
        if not breached_passwords:
            return {
                'risk_level': 'none',
                'risk_score': 0,
                'factors': []
            }
        
        risk_score = 0
        risk_factors = []
        
        # Current password breached is highest risk
        current_breaches = [b for b in breached_passwords if b['type'] == 'current']
        if current_breaches:
            risk_score += 50
            risk_factors.append('current_password_breached')
            
            # Additional risk based on exposure
            for breach in current_breaches:
                if breach['severity'] == 'critical':
                    risk_score += 30
                elif breach['severity'] == 'high':
                    risk_score += 20
                elif breach['severity'] == 'medium':
                    risk_score += 10
        
        # Historical breaches
        historical_breaches = [b for b in breached_passwords if b['type'] == 'historical']
        if historical_breaches:
            risk_score += min(20, len(historical_breaches) * 5)
            risk_factors.append(f'{len(historical_breaches)}_historical_passwords_breached')
        
        # Similar password breaches
        similar_breaches = [b for b in breached_passwords if b['type'] == 'similar']
        if similar_breaches:
            risk_score += min(15, len(similar_breaches) * 5)
            risk_factors.append('similar_passwords_breached')
        
        # User-specific risk factors
        if user:
            if hasattr(user, 'is_admin') and user.is_admin:
                risk_score += 20
                risk_factors.append('admin_account')
            
            if hasattr(user, 'has_sensitive_data') and user.has_sensitive_data:
                risk_score += 15
                risk_factors.append('sensitive_data_access')
        
        # Determine risk level
        if risk_score >= 80:
            risk_level = 'critical'
        elif risk_score >= 60:
            risk_level = 'high'
        elif risk_score >= 40:
            risk_level = 'medium'
        elif risk_score >= 20:
            risk_level = 'low'
        else:
            risk_level = 'minimal'
        
        return {
            'risk_level': risk_level,
            'risk_score': min(100, risk_score),
            'factors': risk_factors
        }
    
    def _generate_recommendations(
        self,
        breached_passwords: list[dict[str, Any]],
        risk_assessment: dict[str, Any]
    ) -> list[str]:
        """Generate security recommendations."""
        recommendations = []
        
        # Current password breached
        if any(b['type'] == 'current' for b in breached_passwords):
            recommendations.append(
                "Change your password immediately - it has been found in data breaches"
            )
            recommendations.append(
                "Use a unique password that you haven't used anywhere else"
            )
        
        # Historical passwords breached
        historical_count = len([b for b in breached_passwords if b['type'] == 'historical'])
        if historical_count > 0:
            recommendations.append(
                f"{historical_count} of your previous passwords have been breached - avoid reusing them"
            )
        
        # Similar passwords breached
        if any(b['type'] == 'similar' for b in breached_passwords):
            recommendations.append(
                "Avoid using variations of breached passwords"
            )
        
        # General recommendations based on risk
        if risk_assessment['risk_level'] in ['critical', 'high']:
            recommendations.append(
                "Enable two-factor authentication for additional security"
            )
            recommendations.append(
                "Review your account for any suspicious activity"
            )
        
        # Always recommend password manager
        recommendations.append(
            "Consider using a password manager to generate and store unique passwords"
        )
        
        return recommendations
    
    async def _send_breach_notification(
        self,
        user: Any,
        breached_passwords: list[dict[str, Any]],
        risk_assessment: dict[str, Any]
    ) -> None:
        """Send notification about password breach."""
        current_breached = any(b['type'] == 'current' for b in breached_passwords)
        
        title = "Security Alert: Password Breach Detected"
        if current_breached:
            message = "Your current password has been found in a data breach. Please change it immediately."
        else:
            message = "Some of your passwords have been found in data breaches."
        
        await self._notification_service.notify_user(
            user_id=user.id,
            title=title,
            message=message,
            priority='high' if current_breached else 'medium',
            details={
                'breached_count': len(breached_passwords),
                'risk_level': risk_assessment['risk_level'],
                'action_url': 'https://app.example.com/security/change-password'
            }
        )
    
    async def _log_breach_detection(
        self,
        user_id: UUID | None,
        breach_count: int,
        risk_level: str
    ) -> None:
        """Log breach detection event."""
        await self._security_service.log_security_event(
            user_id=user_id,
            event_type="password_breach_detected",
            details={
                'breaches_found': breach_count,
                'risk_level': risk_level,
                'timestamp': datetime.now(UTC).isoformat()
            }
        )
    
    def _build_response_message(
        self,
        is_breached: bool,
        breached_passwords: list[dict[str, Any]]
    ) -> str:
        """Build response message."""
        if not is_breached:
            return "No password breaches detected"
        
        current_breached = any(b['type'] == 'current' for b in breached_passwords)
        
        if current_breached:
            return "Current password has been breached - immediate action required"
        return f"{len(breached_passwords)} password breach(es) detected"