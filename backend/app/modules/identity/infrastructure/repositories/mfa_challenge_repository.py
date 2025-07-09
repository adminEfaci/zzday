"""
MFA Challenge Repository Implementation

Redis-based implementation of the MFA challenge repository interface 
for temporary challenge storage during MFA verification.
"""

import json
from datetime import datetime, UTC, timedelta
from typing import Any
from uuid import UUID

from app.modules.identity.application.contracts.ports import ICacheService, IMFAChallengeRepository
from app.core.errors import InfrastructureError
from app.core.logging import get_logger


logger = get_logger(__name__)


class CacheMFAChallengeRepository(IMFAChallengeRepository):
    """Cache-based implementation of MFA challenge repository interface."""
    
    def __init__(self, cache_service: ICacheService):
        """Initialize repository with cache service.
        
        Args:
            cache_service: Cache service for temporary storage
        """
        self._cache_service = cache_service
        self._challenge_prefix = "mfa_challenge"
        self._challenge_ttl = 300  # 5 minutes
    
    async def create_challenge(
        self,
        session_id: UUID,
        device_id: UUID,
        challenge_type: str
    ) -> str:
        """Create MFA challenge.
        
        Args:
            session_id: Session identifier
            device_id: MFA device identifier
            challenge_type: Type of challenge (totp, sms, email, etc.)
            
        Returns:
            Challenge identifier
        """
        try:
            # Generate challenge data
            challenge_id = str(session_id)  # Use session ID as challenge ID
            challenge_data = {
                'session_id': str(session_id),
                'device_id': str(device_id),
                'challenge_type': challenge_type,
                'created_at': datetime.now(UTC).isoformat(),
                'expires_at': (datetime.now(UTC) + timedelta(seconds=self._challenge_ttl)).isoformat(),
                'attempts': 0,
                'max_attempts': 5
            }
            
            # Store challenge in cache
            cache_key = f"{self._challenge_prefix}:{challenge_id}"
            await self._cache_service.set(
                key=cache_key,
                value=json.dumps(challenge_data),
                ttl=self._challenge_ttl
            )
            
            logger.info(
                "MFA challenge created",
                session_id=str(session_id),
                device_id=str(device_id),
                challenge_type=challenge_type
            )
            
            return challenge_id
            
        except Exception as e:
            logger.error(
                "Failed to create MFA challenge",
                session_id=str(session_id),
                error=str(e)
            )
            raise InfrastructureError(f"Failed to create MFA challenge: {str(e)}")
    
    async def get_challenge(self, session_id: UUID) -> dict[str, Any] | None:
        """Get active challenge for session.
        
        Args:
            session_id: Session identifier
            
        Returns:
            Challenge data if found and valid, None otherwise
        """
        try:
            cache_key = f"{self._challenge_prefix}:{session_id}"
            challenge_json = await self._cache_service.get(cache_key)
            
            if not challenge_json:
                return None
            
            challenge_data = json.loads(challenge_json)
            
            # Check if challenge is expired
            expires_at = datetime.fromisoformat(challenge_data['expires_at'])
            if expires_at < datetime.now(UTC):
                # Challenge expired, clean it up
                await self.expire_challenge(session_id)
                return None
            
            return challenge_data
            
        except Exception as e:
            logger.error(
                "Failed to get MFA challenge",
                session_id=str(session_id),
                error=str(e)
            )
            return None
    
    async def verify_challenge(
        self,
        session_id: UUID,
        code: str
    ) -> bool:
        """Verify challenge code.
        
        Args:
            session_id: Session identifier
            code: Verification code
            
        Returns:
            True if code is valid, False otherwise
        """
        try:
            # Get challenge data
            challenge_data = await self.get_challenge(session_id)
            
            if not challenge_data:
                logger.warning(
                    "No active challenge found for session",
                    session_id=str(session_id)
                )
                return False
            
            # Check attempts
            if challenge_data['attempts'] >= challenge_data['max_attempts']:
                logger.warning(
                    "Max attempts exceeded for challenge",
                    session_id=str(session_id),
                    attempts=challenge_data['attempts']
                )
                await self.expire_challenge(session_id)
                return False
            
            # Increment attempts
            challenge_data['attempts'] += 1
            
            # Update challenge in cache
            cache_key = f"{self._challenge_prefix}:{session_id}"
            await self._cache_service.set(
                key=cache_key,
                value=json.dumps(challenge_data),
                ttl=self._challenge_ttl
            )
            
            # Get verification code from cache based on challenge type
            code_cache_key = self._get_code_cache_key(
                challenge_data['challenge_type'],
                challenge_data['device_id'],
                session_id
            )
            
            stored_code = await self._cache_service.get(code_cache_key)
            
            if not stored_code:
                logger.warning(
                    "No verification code found for challenge",
                    session_id=str(session_id),
                    challenge_type=challenge_data['challenge_type']
                )
                return False
            
            # Verify code
            is_valid = stored_code == code
            
            if is_valid:
                # Clean up on successful verification
                await self.expire_challenge(session_id)
                await self._cache_service.delete(code_cache_key)
                
                logger.info(
                    "MFA challenge verified successfully",
                    session_id=str(session_id)
                )
            else:
                logger.warning(
                    "Invalid MFA code provided",
                    session_id=str(session_id),
                    attempts=challenge_data['attempts']
                )
            
            return is_valid
            
        except Exception as e:
            logger.error(
                "Failed to verify MFA challenge",
                session_id=str(session_id),
                error=str(e)
            )
            return False
    
    async def expire_challenge(self, session_id: UUID) -> None:
        """Expire MFA challenge.
        
        Args:
            session_id: Session identifier
        """
        try:
            cache_key = f"{self._challenge_prefix}:{session_id}"
            await self._cache_service.delete(cache_key)
            
            # Also clean up any associated verification codes
            # This is a pattern-based cleanup that may need adjustment based on cache implementation
            patterns = [
                f"mfa_sms:*:{session_id}",
                f"mfa_email:*:{session_id}",
                f"mfa_verify:*"  # Generic verification codes
            ]
            
            for pattern in patterns:
                try:
                    await self._cache_service.clear_pattern(pattern)
                except (AttributeError, NotImplementedError, ValueError) as e:
                    # Pattern clearing might not be supported by all cache implementations
                    pass
            
            logger.info(
                "MFA challenge expired",
                session_id=str(session_id)
            )
            
        except Exception as e:
            logger.error(
                "Failed to expire MFA challenge",
                session_id=str(session_id),
                error=str(e)
            )
    
    def _get_code_cache_key(
        self,
        challenge_type: str,
        device_id: str,
        session_id: UUID
    ) -> str:
        """Get cache key for verification code.
        
        Args:
            challenge_type: Type of challenge
            device_id: MFA device identifier
            session_id: Session identifier
            
        Returns:
            Cache key for verification code
        """
        if challenge_type == "sms":
            return f"mfa_sms:{device_id}:{session_id}"
        elif challenge_type == "email":
            return f"mfa_email:{device_id}:{session_id}"
        else:
            # Generic key for other types
            return f"mfa_verify:{device_id}"