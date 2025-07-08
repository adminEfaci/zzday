"""
Emergency contact commands module.

This module contains all commands for managing emergency contacts
and emergency notification workflows.
"""

from .add_emergency_contact_command import (
    AddEmergencyContactCommand,
    AddEmergencyContactCommandHandler,
)
from .escalate_to_emergency_contacts_command import (
    EscalateToEmergencyContactsCommand,
    EscalateToEmergencyContactsCommandHandler,
)
from .notify_emergency_contacts_command import (
    NotifyEmergencyContactsCommand,
    NotifyEmergencyContactsCommandHandler,
)
from .remove_emergency_contact_command import (
    RemoveEmergencyContactCommand,
    RemoveEmergencyContactCommandHandler,
)
from .test_emergency_contact_command import (
    TestEmergencyContactCommand,
    TestEmergencyContactCommandHandler,
)
from .update_emergency_contact_command import (
    UpdateEmergencyContactCommand,
    UpdateEmergencyContactCommandHandler,
)
from .verify_emergency_contact_command import (
    VerifyEmergencyContactCommand,
    VerifyEmergencyContactCommandHandler,
)

__all__ = [
    # Add Emergency Contact
    "AddEmergencyContactCommand",
    "AddEmergencyContactCommandHandler",
    # Escalate to Emergency Contacts
    "EscalateToEmergencyContactsCommand",
    "EscalateToEmergencyContactsCommandHandler",
    # Notify Emergency Contacts
    "NotifyEmergencyContactsCommand",
    "NotifyEmergencyContactsCommandHandler",
    # Remove Emergency Contact
    "RemoveEmergencyContactCommand",
    "RemoveEmergencyContactCommandHandler",
    # Test Emergency Contact
    "TestEmergencyContactCommand",
    "TestEmergencyContactCommandHandler",
    # Update Emergency Contact
    "UpdateEmergencyContactCommand",
    "UpdateEmergencyContactCommandHandler",
    # Verify Emergency Contact
    "VerifyEmergencyContactCommand",
    "VerifyEmergencyContactCommandHandler",
]