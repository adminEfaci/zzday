"""
Shared Entity Components

Base classes and mixins for identity domain entities.
"""

from .base_entity import (
    AuditableEntity,
    ExpirableEntity,
    IdentityEntity,
    RiskAssessmentMixin,
    SecurityValidationMixin,
)

__all__ = [
    # === BASE ENTITIES ===
    "IdentityEntity",
    "AuditableEntity", 
    "ExpirableEntity",
    
    # === MIXINS ===
    "SecurityValidationMixin",
    "RiskAssessmentMixin",
]

# Metadata
__version__ = "1.0.0"
__domain__ = "identity"