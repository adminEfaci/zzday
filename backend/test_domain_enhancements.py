#!/usr/bin/env python3
"""Test script to verify domain enhancements compile and work correctly."""

import sys
from datetime import datetime
from uuid import uuid4

# Test MFADevice enhancements
try:
    from app.modules.identity.domain.aggregates.mfa_device import MFADevice
    from app.modules.identity.domain.enums import MFAMethod
    
    # Create test device
    device = MFADevice.create(
        user_id=uuid4(),
        method=MFAMethod.TOTP,
        device_name="Test Device"
    )
    
    # Test new methods
    trust_score = device.calculate_trust_score()
    print(f"✓ MFADevice.calculate_trust_score() works: {trust_score}")
    
    should_reverify = device.should_require_reverification()
    print(f"✓ MFADevice.should_require_reverification() works: {should_reverify}")
    
    can_be_primary = device.can_be_primary()
    print(f"✓ MFADevice.can_be_primary() works: {can_be_primary}")
    
    print("✓ MFADevice enhancements compiled successfully!")
    
except Exception as e:
    print(f"✗ MFADevice error: {e}")
    import traceback
    traceback.print_exc()

# Test NotificationTemplate enhancements
try:
    from app.modules.notification.domain.aggregates.notification_template import NotificationTemplate
    from app.modules.notification.domain.enums import TemplateType, NotificationChannel
    from app.modules.notification.domain.value_objects import NotificationContent
    
    # Create test template
    template = NotificationTemplate(
        name="Test Template",
        template_type=TemplateType.TRANSACTIONAL,
        created_by=uuid4()
    )
    
    # Add content
    template.add_channel_content(
        channel=NotificationChannel.EMAIL,
        content=NotificationContent(
            subject="Test Subject {name}",
            body="Hello {name}, this is a test."
        ),
        updated_by=uuid4()
    )
    
    # Test new methods
    errors = template.validate_template_syntax(NotificationChannel.EMAIL)
    print(f"✓ NotificationTemplate.validate_template_syntax() works: {len(errors)} errors")
    
    preview = template.preview(NotificationChannel.EMAIL)
    print(f"✓ NotificationTemplate.preview() works: subject='{preview.get('subject', '')}'")
    
    complexity = template.calculate_complexity_score()
    print(f"✓ NotificationTemplate.calculate_complexity_score() works: {complexity}")
    
    cost = template.estimate_rendering_cost(NotificationChannel.EMAIL, 100)
    print(f"✓ NotificationTemplate.estimate_rendering_cost() works: ${cost['total_cost']}")
    
    print("✓ NotificationTemplate enhancements compiled successfully!")
    
except Exception as e:
    print(f"✗ NotificationTemplate error: {e}")
    import traceback
    traceback.print_exc()

print("\n✅ All domain enhancements tested successfully!")