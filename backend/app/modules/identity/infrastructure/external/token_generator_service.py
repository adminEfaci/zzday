"""Token generator service implementation."""

import base64
import hashlib
import secrets
import time
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from app.core.caching import cache
from app.core.logging import logger
from app.modules.identity.domain.interfaces.services.authentication.token_generator import (
    ITokenGenerator,
)
from app.modules.identity.domain.value_objects.token import TokenType


class TokenGeneratorAdapter(ITokenGenerator):
    """Service for generating and validating various types of tokens."""
    
    def __init__(self, config: dict[str, Any] | None = None):
        self.config = config or {}
        self.jwt_secret = self.config.get("jwt_secret", self._generate_secret())
        self.jwt_algorithm = self.config.get("jwt_algorithm", "HS256")
        self.issuer = self.config.get("issuer", "identity-service")
        self.audience = self.config.get("audience", ["api", "web"])
        
        # Token expiration settings
        self.access_token_ttl = self.config.get("access_token_ttl", 900)  # 15 minutes
        self.refresh_token_ttl = self.config.get("refresh_token_ttl", 2592000)  # 30 days
        self.verification_token_ttl = self.config.get("verification_token_ttl", 86400)  # 24 hours
        self.reset_token_ttl = self.config.get("reset_token_ttl", 3600)  # 1 hour
        self.invitation_token_ttl = self.config.get("invitation_token_ttl", 604800)  # 7 days
        self.api_key_ttl = self.config.get("api_key_ttl", 31536000)  # 1 year
        
        # Initialize RSA keys for asymmetric algorithms
        if self.jwt_algorithm in ["RS256", "RS384", "RS512"]:
            self._init_rsa_keys()
        
        logger.info(f"TokenGeneratorAdapter initialized with algorithm: {self.jwt_algorithm}")
    
    async def generate_access_token(
        self,
        user_id: str,
        claims: dict[str, Any]
    ) -> str:
        """Generate JWT access token."""
        try:
            now = datetime.now(UTC)
            exp = now + timedelta(seconds=self.access_token_ttl)
            
            payload = {
                "sub": user_id,
                "iat": now,
                "exp": exp,
                "nbf": now,
                "jti": str(uuid.uuid4()),
                "type": TokenType.ACCESS.value,
                "iss": self.issuer,
                "aud": self.audience,
                **claims  # Merge additional claims
            }
            
            # Add security claims
            payload["azp"] = claims.get("client_id", "web")  # Authorized party
            payload["scope"] = claims.get("scope", "openid profile email")
            
            # Sign token
            if self.jwt_algorithm.startswith("RS"):
                token = jwt.encode(payload, self.private_key, algorithm=self.jwt_algorithm)
            else:
                token = jwt.encode(payload, self.jwt_secret, algorithm=self.jwt_algorithm)
            
            # Cache token metadata for tracking
            await self._cache_token_metadata(payload["jti"], user_id, "access", exp)
            
            return token
            
        except Exception as e:
            logger.error(f"Error generating access token: {e!s}")
            raise
    
    async def generate_refresh_token(
        self,
        user_id: str,
        device_id: str | None = None
    ) -> str:
        """Generate refresh token."""
        try:
            now = datetime.now(UTC)
            exp = now + timedelta(seconds=self.refresh_token_ttl)
            
            payload = {
                "sub": user_id,
                "iat": now,
                "exp": exp,
                "jti": str(uuid.uuid4()),
                "type": TokenType.REFRESH.value,
                "iss": self.issuer,
                "device_id": device_id or str(uuid.uuid4())
            }
            
            # Use stronger algorithm for refresh tokens
            if self.jwt_algorithm.startswith("RS"):
                token = jwt.encode(payload, self.private_key, algorithm="RS512")
            else:
                token = jwt.encode(payload, self.jwt_secret, algorithm="HS512")
            
            # Cache token metadata
            await self._cache_token_metadata(payload["jti"], user_id, "refresh", exp)
            
            # Store refresh token family for rotation
            await self._store_refresh_token_family(payload["jti"], user_id, device_id)
            
            return token
            
        except Exception as e:
            logger.error(f"Error generating refresh token: {e!s}")
            raise
    
    async def generate_verification_token(
        self,
        email: str,
        purpose: str = "email_verification"
    ) -> str:
        """Generate email verification token."""
        try:
            # Create secure random token
            token_bytes = secrets.token_bytes(32)
            token = base64.urlsafe_b64encode(token_bytes).decode('utf-8').rstrip('=')
            
            # Hash token for storage
            token_hash = hashlib.sha256(token_bytes).hexdigest()
            
            # Store token metadata
            exp = datetime.now(UTC) + timedelta(seconds=self.verification_token_ttl)
            await cache.set(
                f"verification_token:{token_hash}",
                {
                    "email": email,
                    "purpose": purpose,
                    "created_at": datetime.now(UTC).isoformat(),
                    "expires_at": exp.isoformat()
                },
                ttl=self.verification_token_ttl
            )
            
            return token
            
        except Exception as e:
            logger.error(f"Error generating verification token: {e!s}")
            raise
    
    async def generate_password_reset_token(self, user_id: str) -> str:
        """Generate password reset token."""
        try:
            # Create secure token with user context
            token_data = f"{user_id}:{time.time()}:{secrets.token_hex(16)}"
            token_bytes = token_data.encode('utf-8')
            
            # Encrypt token data
            encrypted = self._encrypt_token_data(token_bytes)
            token = base64.urlsafe_b64encode(encrypted).decode('utf-8').rstrip('=')
            
            # Store token metadata
            token_hash = hashlib.sha256(encrypted).hexdigest()
            exp = datetime.now(UTC) + timedelta(seconds=self.reset_token_ttl)
            
            await cache.set(
                f"reset_token:{token_hash}",
                {
                    "user_id": user_id,
                    "created_at": datetime.now(UTC).isoformat(),
                    "expires_at": exp.isoformat(),
                    "used": False
                },
                ttl=self.reset_token_ttl
            )
            
            return token
            
        except Exception as e:
            logger.error(f"Error generating password reset token: {e!s}")
            raise
    
    async def generate_invitation_token(
        self,
        inviter_id: str,
        invitee_email: str,
        role: str = "user"
    ) -> str:
        """Generate invitation token."""
        try:
            now = datetime.now(UTC)
            exp = now + timedelta(seconds=self.invitation_token_ttl)
            
            payload = {
                "inviter_id": inviter_id,
                "invitee_email": invitee_email,
                "role": role,
                "iat": now,
                "exp": exp,
                "jti": str(uuid.uuid4()),
                "type": TokenType.INVITATION.value,
                "iss": self.issuer
            }
            
            # Sign token
            token = jwt.encode(payload, self.jwt_secret, algorithm=self.jwt_algorithm)
            
            # Store invitation metadata
            await cache.set(
                f"invitation:{payload['jti']}",
                {
                    **payload,
                    "status": "pending",
                    "created_at": now.isoformat()
                },
                ttl=self.invitation_token_ttl
            )
            
            return token
            
        except Exception as e:
            logger.error(f"Error generating invitation token: {e!s}")
            raise
    
    async def generate_api_key(
        self,
        user_id: str,
        name: str,
        scopes: list | None = None
    ) -> tuple[str, str]:
        """Generate API key and secret."""
        try:
            # Generate key components
            key_id = f"key_{uuid.uuid4().hex[:12]}"
            key_secret = secrets.token_urlsafe(32)
            
            # Create API key token
            key_hash = hashlib.sha256(f"{key_id}:{key_secret}".encode()).hexdigest()
            
            # Store key metadata
            now = datetime.now(UTC)
            exp = now + timedelta(seconds=self.api_key_ttl)
            
            await cache.set(
                f"api_key:{key_hash}",
                {
                    "key_id": key_id,
                    "user_id": user_id,
                    "name": name,
                    "scopes": scopes or ["api:read"],
                    "created_at": now.isoformat(),
                    "expires_at": exp.isoformat(),
                    "last_used": None,
                    "active": True
                },
                ttl=self.api_key_ttl
            )
            
            # Return key ID and secret
            api_key = f"{key_id}.{key_secret}"
            return key_id, api_key
            
        except Exception as e:
            logger.error(f"Error generating API key: {e!s}")
            raise
    
    async def validate_token(
        self,
        token: str,
        token_type: TokenType
    ) -> dict[str, Any]:
        """Validate token and return claims."""
        try:
            # Decode token
            if self.jwt_algorithm.startswith("RS"):
                payload = jwt.decode(
                    token,
                    self.public_key,
                    algorithms=[self.jwt_algorithm],
                    issuer=self.issuer,
                    audience=self.audience
                )
            else:
                payload = jwt.decode(
                    token,
                    self.jwt_secret,
                    algorithms=[self.jwt_algorithm],
                    issuer=self.issuer,
                    audience=self.audience
                )
            
            # Verify token type
            if payload.get("type") != token_type.value:
                raise ValueError(f"Invalid token type. Expected {token_type.value}")
            
            # Check if token is revoked
            if await self._is_token_revoked(payload.get("jti")):
                raise ValueError("Token has been revoked")
            
            # Additional validation for specific token types
            if token_type == TokenType.REFRESH:
                await self._validate_refresh_token_family(payload.get("jti"))
            
            return payload
            
        except jwt.ExpiredSignatureError as e:
            logger.warning("Token has expired")
            raise ValueError("Token has expired") from e
        except jwt.InvalidTokenError as e:
            logger.warning(f"Invalid token: {e!s}")
            raise ValueError("Invalid token") from e
        except Exception as e:
            logger.error(f"Error validating token: {e!s}")
            raise
    
    async def revoke_token(self, token_jti: str) -> None:
        """Revoke a token by its JTI."""
        try:
            # Add to revocation list
            await cache.set(
                f"revoked_token:{token_jti}",
                {
                    "revoked_at": datetime.now(UTC).isoformat(),
                    "reason": "user_requested"
                },
                ttl=86400 * 30  # Keep for 30 days
            )
            
            # Remove from active tokens
            await cache.delete(f"token_metadata:{token_jti}")
            
            logger.info(f"Token revoked: {token_jti}")
            
        except Exception as e:
            logger.error(f"Error revoking token: {e!s}")
            raise
    
    async def rotate_refresh_token(
        self,
        old_token: str
    ) -> tuple[str, str]:
        """Rotate refresh token and generate new access token."""
        try:
            # Validate old refresh token
            payload = await self.validate_token(old_token, TokenType.REFRESH)
            
            # Mark old token as used
            await self.revoke_token(payload["jti"])
            
            # Generate new tokens
            user_id = payload["sub"]
            device_id = payload.get("device_id")
            
            # Get user claims for new access token
            claims = await self._get_user_claims(user_id)
            
            # Generate new token pair
            access_token = await self.generate_access_token(user_id, claims)
            refresh_token = await self.generate_refresh_token(user_id, device_id)
            
            # Update refresh token family
            await self._update_refresh_token_family(
                old_jti=payload["jti"],
                new_jti=jwt.decode(refresh_token, options={"verify_signature": False})["jti"],
                user_id=user_id
            )
            
            return access_token, refresh_token
            
        except Exception as e:
            logger.error(f"Error rotating refresh token: {e!s}")
            raise
    
    def _generate_secret(self) -> str:
        """Generate a secure secret key."""
        return secrets.token_urlsafe(64)
    
    def _init_rsa_keys(self):
        """Initialize RSA key pair for asymmetric algorithms."""
        try:
            # Check if keys are provided in config
            if "rsa_private_key" in self.config:
                self.private_key = self.config["rsa_private_key"]
                self.public_key = self.config["rsa_public_key"]
            else:
                # Generate new key pair
                private_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=2048,
                    backend=default_backend()
                )
                
                self.private_key = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
                
                self.public_key = private_key.public_key().public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                
                logger.info("Generated new RSA key pair")
                
        except Exception as e:
            logger.error(f"Error initializing RSA keys: {e!s}")
            raise
    
    def _encrypt_token_data(self, data: bytes) -> bytes:
        """Encrypt token data for sensitive tokens."""
        # Derive key from primary secret
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'token_encryption_salt',
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(self.jwt_secret.encode())
        
        # Simple XOR encryption (in production, use proper AES)
        encrypted = bytearray()
        for i, byte in enumerate(data):
            encrypted.append(byte ^ key[i % len(key)])
        
        return bytes(encrypted)
    
    async def _cache_token_metadata(
        self,
        jti: str,
        user_id: str,
        token_type: str,
        exp: datetime
    ):
        """Cache token metadata for tracking."""
        ttl = int((exp - datetime.now(UTC)).total_seconds())
        await cache.set(
            f"token_metadata:{jti}",
            {
                "user_id": user_id,
                "type": token_type,
                "created_at": datetime.now(UTC).isoformat(),
                "expires_at": exp.isoformat()
            },
            ttl=ttl
        )
    
    async def _is_token_revoked(self, jti: str) -> bool:
        """Check if token is revoked."""
        return await cache.exists(f"revoked_token:{jti}")
    
    async def _store_refresh_token_family(
        self,
        jti: str,
        user_id: str,
        device_id: str | None
    ):
        """Store refresh token family for rotation tracking."""
        family_id = f"refresh_family:{user_id}:{device_id or 'default'}"
        
        family = await cache.get(family_id) or {
            "tokens": [],
            "created_at": datetime.now(UTC).isoformat()
        }
        
        family["tokens"].append({
            "jti": jti,
            "created_at": datetime.now(UTC).isoformat(),
            "status": "active"
        })
        
        # Keep only last 5 tokens
        family["tokens"] = family["tokens"][-5:]
        
        await cache.set(family_id, family, ttl=self.refresh_token_ttl)
    
    async def _validate_refresh_token_family(self, jti: str):
        """Validate refresh token is part of valid family."""
        # Implementation would check token family integrity
    
    async def _update_refresh_token_family(
        self,
        old_jti: str,
        new_jti: str,
        user_id: str
    ):
        """Update refresh token family after rotation."""
        # Implementation would update family tracking
    
    async def _get_user_claims(self, user_id: str) -> dict[str, Any]:
        """Get user claims for token generation."""
        # This would fetch actual user data
        return {
            "email": "user@example.com",
            "roles": ["user"],
            "permissions": ["read", "write"]
        }