"""Audit field entity.

This module re-exports AuditField from audit_entry module
for better organization and imports.
"""

from app.modules.audit.domain.entities.audit_entry import AuditField

__all__ = ["AuditField"]
