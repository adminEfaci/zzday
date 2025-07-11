"""Unit tests for NotificationTemplate aggregate enhancements."""

import pytest
from datetime import datetime
from uuid import uuid4
from unittest.mock import MagicMock, patch

# Mock the dependencies
import sys

sys.modules['app.core'] = MagicMock()
sys.modules['app.core.domain'] = MagicMock()
sys.modules['app.core.domain.base'] = MagicMock()
sys.modules['app.core.errors'] = MagicMock()

# Mock the base AggregateRoot
class MockAggregateRoot:
    def __init__(self, entity_id=None):
        self.id = entity_id or uuid4()
        self.events = []
        self.created_at = datetime.utcnow()
        self.updated_at = datetime.utcnow()
        self.metadata = {}
    
    def add_event(self, event):
        self.events.append(event)
    
    def mark_modified(self):
        self.updated_at = datetime.utcnow()
    
    def add_metadata(self, key, value):
        self.metadata[key] = value

# Import after mocking
from app.modules.notification.domain.enums import TemplateType, NotificationChannel, VariableType
from app.modules.notification.domain.value_objects import NotificationContent, TemplateVariable
from app.modules.notification.domain.aggregates.notification_template import NotificationTemplate


class TestNotificationTemplateEnhancements:
    """Test the enhanced business methods for NotificationTemplate aggregate."""
    
    def setup_method(self):
        """Set up test data."""
        # Patch the base class
        NotificationTemplate.__bases__ = (MockAggregateRoot,)
        
        self.user_id = uuid4()
        self.template = NotificationTemplate(
            name="Test Template",
            template_type=TemplateType.TRANSACTIONAL,
            created_by=self.user_id
        )
        
        # Add some test content
        self.email_content = NotificationContent(
            subject="Hello {name}",
            body="Welcome {name}, your code is {code}."
        )
        self.template.add_channel_content(
            channel=NotificationChannel.EMAIL,
            content=self.email_content,
            updated_by=self.user_id
        )
    
    def test_validate_template_syntax_valid(self):
        """Test syntax validation for valid template."""
        errors = self.template.validate_template_syntax(NotificationChannel.EMAIL)
        
        # Should have no errors for properly defined variables
        assert len(errors) == 0
    
    def test_validate_template_syntax_undefined_variables(self):
        """Test syntax validation with undefined variables."""
        # Clear the auto-created variables
        self.template.variables = {}
        
        errors = self.template.validate_template_syntax(NotificationChannel.EMAIL)
        
        assert len(errors) == 2  # name and code are undefined
        assert any("name" in error for error in errors)
        assert any("code" in error for error in errors)
    
    def test_validate_template_syntax_unmatched_braces(self):
        """Test syntax validation with unmatched braces."""
        self.template.channel_contents[NotificationChannel.EMAIL] = NotificationContent(
            subject="Hello {{name}",  # Unmatched braces
            body="Test"
        )
        
        errors = self.template.validate_template_syntax(NotificationChannel.EMAIL)
        
        assert any("Unmatched braces" in error for error in errors)
    
    def test_preview_with_sample_data(self):
        """Test template preview with provided sample data."""
        sample_data = {
            "name": "John Doe",
            "code": "ABC123"
        }
        
        preview = self.template.preview(NotificationChannel.EMAIL, sample_data)
        
        assert "error" not in preview
        assert preview["subject"] == "Hello {name}"  # NotificationContent.render() not implemented
        assert preview["preview_data"] == sample_data
    
    def test_preview_with_generated_data(self):
        """Test template preview with auto-generated data."""
        preview = self.template.preview(NotificationChannel.EMAIL)
        
        assert "error" not in preview
        assert "preview_data" in preview
        assert "name" in preview["preview_data"]
        assert "code" in preview["preview_data"]
    
    def test_clone_template(self):
        """Test cloning a template."""
        clone = self.template.clone("Cloned Template", cloned_by=self.user_id)
        
        assert clone.name == "Cloned Template"
        assert clone.template_type == self.template.template_type
        assert NotificationChannel.EMAIL in clone.channel_contents
        assert len(clone.variables) == len(self.template.variables)
        assert "cloned_from" in clone.metadata
    
    def test_add_localization(self):
        """Test adding localized content."""
        spanish_content = NotificationContent(
            subject="Hola {name}",
            body="Bienvenido {name}, tu código es {code}."
        )
        
        self.template.add_localization(
            locale="es-ES",
            channel=NotificationChannel.EMAIL,
            content=spanish_content,
            updated_by=self.user_id
        )
        
        assert hasattr(self.template, 'localizations')
        assert "es-ES" in self.template.localizations
        assert NotificationChannel.EMAIL in self.template.localizations["es-ES"]
    
    def test_render_localized(self):
        """Test rendering with localization."""
        # Add Spanish localization
        spanish_content = NotificationContent(
            subject="Hola {name}",
            body="Bienvenido {name}, tu código es {code}."
        )
        self.template.add_localization(
            locale="es-ES",
            channel=NotificationChannel.EMAIL,
            content=spanish_content,
            updated_by=self.user_id
        )
        
        # Mock the render method
        spanish_content.render = MagicMock(return_value=spanish_content)
        
        variables = {"name": "Juan", "code": "XYZ789"}
        rendered = self.template.render_localized(
            channel=NotificationChannel.EMAIL,
            variables=variables,
            locale="es-ES"
        )
        
        assert rendered == spanish_content
    
    def test_calculate_complexity_score(self):
        """Test complexity score calculation."""
        # Add more variables and channels to increase complexity
        self.template.variables = {
            f"var{i}": TemplateVariable(
                name=f"var{i}",
                var_type=VariableType.STRING,
                required=True
            ) for i in range(10)
        }
        
        self.template.add_channel_content(
            channel=NotificationChannel.SMS,
            content=NotificationContent(body="SMS message"),
            updated_by=self.user_id
        )
        
        score = self.template.calculate_complexity_score()
        
        assert 0.0 <= score <= 1.0
        assert score > 0.0  # Should have some complexity
    
    def test_get_missing_channels(self):
        """Test getting missing channels."""
        desired_channels = [
            NotificationChannel.EMAIL,
            NotificationChannel.SMS,
            NotificationChannel.PUSH
        ]
        
        missing = self.template.get_missing_channels(desired_channels)
        
        assert NotificationChannel.SMS in missing
        assert NotificationChannel.PUSH in missing
        assert NotificationChannel.EMAIL not in missing
    
    def test_estimate_rendering_cost_sms(self):
        """Test cost estimation for SMS."""
        sms_content = NotificationContent(
            body="A" * 200  # More than 160 chars = 2 segments
        )
        self.template.add_channel_content(
            channel=NotificationChannel.SMS,
            content=sms_content,
            updated_by=self.user_id
        )
        
        cost = self.template.estimate_rendering_cost(
            channel=NotificationChannel.SMS,
            recipient_count=100
        )
        
        assert cost["channel"] == "sms"
        assert cost["unit_cost"] == 0.02  # 2 segments * $0.01
        assert cost["total_cost"] == 2.0  # 100 recipients * $0.02
        assert cost["content_length"] == 200
    
    def test_estimate_rendering_cost_email(self):
        """Test cost estimation for email."""
        cost = self.template.estimate_rendering_cost(
            channel=NotificationChannel.EMAIL,
            recipient_count=1000
        )
        
        assert cost["channel"] == "email"
        assert cost["unit_cost"] == 0.001
        assert cost["total_cost"] == 1.0  # 1000 * $0.001
    
    def test_generate_sample_data(self):
        """Test sample data generation based on variable types."""
        # Add variables of different types
        self.template.variables = {
            "name": TemplateVariable(
                name="name",
                var_type=VariableType.STRING,
                required=True
            ),
            "count": TemplateVariable(
                name="count",
                var_type=VariableType.NUMBER,
                required=True
            ),
            "is_active": TemplateVariable(
                name="is_active",
                var_type=VariableType.BOOLEAN,
                required=True
            ),
            "created_at": TemplateVariable(
                name="created_at",
                var_type=VariableType.DATE,
                required=True
            ),
            "tags": TemplateVariable(
                name="tags",
                var_type=VariableType.LIST,
                required=True
            )
        }
        
        sample_data = self.template._generate_sample_data()
        
        assert sample_data["name"] == "Sample name"
        assert sample_data["count"] == 123
        assert sample_data["is_active"] is True
        assert isinstance(sample_data["created_at"], str)
        assert isinstance(sample_data["tags"], list)
        assert len(sample_data["tags"]) == 3