"""Unit tests for WebhookEndpoint aggregate enhancements."""

import pytest
from datetime import datetime, UTC, timedelta
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
        self.created_at = datetime.now(UTC)
        self.updated_at = datetime.now(UTC)
        self.metadata = {}
    
    def add_event(self, event):
        self.events.append(event)
    
    def mark_modified(self):
        self.updated_at = datetime.now(UTC)

# Import after mocking
from app.modules.integration.domain.enums import WebhookMethod, WebhookStatus
from app.modules.integration.domain.value_objects import WebhookSignature
from app.modules.integration.domain.aggregates.webhook_endpoint import WebhookEndpoint


class TestWebhookEndpointEnhancements:
    """Test the enhanced business methods for WebhookEndpoint aggregate."""
    
    def setup_method(self):
        """Set up test data."""
        # Patch the base class
        WebhookEndpoint.__bases__ = (MockAggregateRoot,)
        
        self.integration_id = uuid4()
        self.endpoint = WebhookEndpoint(
            integration_id=self.integration_id,
            name="Test Endpoint",
            path="/test",
            allowed_methods=[WebhookMethod.POST],
            is_active=True,
            retry_policy={
                "max_retries": 3,
                "initial_delay_seconds": 60,
                "backoff_factor": 2,
                "max_delay_seconds": 3600
            }
        )
    
    def test_calculate_retry_delay_exponential_backoff(self):
        """Test retry delay calculation with exponential backoff."""
        # First retry (retry_count=0)
        delay_0 = self.endpoint.calculate_retry_delay(0)
        assert delay_0 == 60  # initial_delay_seconds
        
        # Second retry (retry_count=1)
        delay_1 = self.endpoint.calculate_retry_delay(1)
        assert delay_1 == 120  # 60 * 2^1
        
        # Third retry (retry_count=2)
        delay_2 = self.endpoint.calculate_retry_delay(2)
        assert delay_2 == 240  # 60 * 2^2
        
        # Very high retry count should be capped at max_delay
        delay_high = self.endpoint.calculate_retry_delay(10)
        assert delay_high == 3600  # max_delay_seconds
    
    def test_should_retry_webhook_within_limit(self):
        """Test retry decision within retry limit."""
        # Should retry for retryable errors
        assert self.endpoint.should_retry_webhook(0, "timeout") is True
        assert self.endpoint.should_retry_webhook(1, "connection_error") is True
        assert self.endpoint.should_retry_webhook(2, "server_error") is True
    
    def test_should_retry_webhook_exceeded_limit(self):
        """Test retry decision when limit exceeded."""
        # Should not retry when max retries exceeded
        assert self.endpoint.should_retry_webhook(3, "timeout") is False
        assert self.endpoint.should_retry_webhook(5, "server_error") is False
    
    def test_should_retry_webhook_non_retryable_errors(self):
        """Test retry decision for non-retryable errors."""
        non_retryable_errors = [
            "validation_error",
            "authentication_error",
            "permission_denied",
            "bad_request",
            "not_found"
        ]
        
        for error_type in non_retryable_errors:
            assert self.endpoint.should_retry_webhook(0, error_type) is False
    
    def test_validate_signature_advanced_no_config(self):
        """Test signature validation when no config is set."""
        is_valid, reason = self.endpoint.validate_signature_advanced(
            payload=b"test payload",
            signature="test_signature"
        )
        
        assert is_valid is True
        assert reason == "No signature validation configured"
    
    def test_validate_signature_advanced_with_timestamp(self):
        """Test signature validation with timestamp tolerance."""
        # Mock signature config
        mock_config = MagicMock()
        mock_config.validate_signature.return_value = True
        self.endpoint.signature_config = mock_config
        
        # Current timestamp
        current_time = datetime.now(UTC)
        timestamp = current_time.isoformat()
        
        is_valid, reason = self.endpoint.validate_signature_advanced(
            payload=b"test payload",
            signature="test_signature",
            timestamp=timestamp
        )
        
        assert is_valid is True
        assert reason == "Valid signature"
    
    def test_validate_signature_advanced_old_timestamp(self):
        """Test signature validation with old timestamp."""
        # Mock signature config
        mock_config = MagicMock()
        self.endpoint.signature_config = mock_config
        
        # Old timestamp (10 minutes ago)
        old_time = datetime.now(UTC) - timedelta(minutes=10)
        timestamp = old_time.isoformat()
        
        is_valid, reason = self.endpoint.validate_signature_advanced(
            payload=b"test payload",
            signature="test_signature",
            timestamp=timestamp,
            tolerance_seconds=300  # 5 minutes
        )
        
        assert is_valid is False
        assert "Timestamp too old" in reason
    
    def test_get_health_metrics_healthy(self):
        """Test health metrics for healthy endpoint."""
        self.endpoint.is_active = True
        self.endpoint.total_received = 100
        self.endpoint.total_processed = 90
        self.endpoint.total_failed = 10
        self.endpoint.last_received_at = datetime.now(UTC)
        
        metrics = self.endpoint.get_health_metrics()
        
        assert metrics["is_healthy"] is True
        assert metrics["success_rate"] == 0.9
        assert metrics["total_requests"] == 100
        assert metrics["total_processed"] == 90
        assert metrics["total_failed"] == 10
        assert metrics["last_activity"] is not None
    
    def test_get_health_metrics_unhealthy(self):
        """Test health metrics for unhealthy endpoint."""
        self.endpoint.is_active = True
        self.endpoint.total_received = 100
        self.endpoint.total_processed = 60
        self.endpoint.total_failed = 40
        
        metrics = self.endpoint.get_health_metrics()
        
        assert metrics["is_healthy"] is False  # Success rate < 0.8
        assert metrics["success_rate"] == 0.6
    
    def test_update_retry_policy_valid(self):
        """Test updating retry policy with valid configuration."""
        new_policy = {
            "max_retries": 5,
            "initial_delay_seconds": 30,
            "backoff_factor": 1.5,
            "max_delay_seconds": 1800
        }
        
        self.endpoint.update_retry_policy(new_policy)
        
        assert self.endpoint.retry_policy == new_policy
    
    def test_update_retry_policy_invalid_missing_key(self):
        """Test updating retry policy with missing required key."""
        from app.core.errors import ValidationError
        
        # Mock ValidationError
        ValidationError = type('ValidationError', (Exception,), {})
        
        with pytest.raises(ValidationError):
            self.endpoint.update_retry_policy({
                "max_retries": 5,
                "initial_delay_seconds": 30
                # Missing backoff_factor
            })
    
    def test_update_retry_policy_invalid_values(self):
        """Test updating retry policy with invalid values."""
        from app.core.errors import ValidationError
        
        # Mock ValidationError
        ValidationError = type('ValidationError', (Exception,), {})
        
        with pytest.raises(ValidationError):
            self.endpoint.update_retry_policy({
                "max_retries": 15,  # > 10
                "initial_delay_seconds": 30,
                "backoff_factor": 2
            })
    
    def test_get_webhook_analytics(self):
        """Test getting webhook analytics."""
        self.endpoint.total_received = 200
        self.endpoint.total_processed = 180
        self.endpoint.total_failed = 20
        
        analytics = self.endpoint.get_webhook_analytics(days=30)
        
        assert analytics["period_days"] == 30
        assert analytics["total_webhooks"] == 200
        assert analytics["success_rate"] == 0.9
        assert "recommendation" in analytics
        assert "most_common_errors" in analytics
    
    def test_simulate_webhook_load_normal(self):
        """Test webhook load simulation for normal load."""
        result = self.endpoint.simulate_webhook_load(
            requests_per_second=5,
            duration_seconds=60
        )
        
        assert result["load_scenario"]["total_requests"] == 300
        assert result["estimated_results"]["success_rate"] > 0.8
        assert "recommendation" in result["estimated_results"]
    
    def test_simulate_webhook_load_high(self):
        """Test webhook load simulation for high load."""
        result = self.endpoint.simulate_webhook_load(
            requests_per_second=150,
            duration_seconds=60
        )
        
        assert result["load_scenario"]["total_requests"] == 9000
        # Success rate should be degraded for high load
        assert result["estimated_results"]["success_rate"] < 0.95
        assert "Very high load" in result["estimated_results"]["recommendation"]
    
    def test_calculate_avg_requests_per_day(self):
        """Test average requests per day calculation."""
        # Set created_at to 10 days ago
        self.endpoint.created_at = datetime.now(UTC) - timedelta(days=10)
        self.endpoint.total_received = 100
        
        avg = self.endpoint._calculate_avg_requests_per_day()
        
        assert avg == 10.0  # 100 requests / 10 days
    
    def test_days_since_last_activity(self):
        """Test days since last activity calculation."""
        # Set last activity to 5 days ago
        self.endpoint.last_received_at = datetime.now(UTC) - timedelta(days=5)
        
        days = self.endpoint._days_since_last_activity()
        
        assert days == 5
    
    def test_days_since_last_activity_no_activity(self):
        """Test days since last activity when no activity."""
        self.endpoint.last_received_at = None
        
        days = self.endpoint._days_since_last_activity()
        
        assert days == -1
    
    def test_detect_rate_limiting(self):
        """Test rate limiting detection."""
        # High failure rate should indicate rate limiting
        self.endpoint.total_received = 100
        self.endpoint.total_failed = 60
        
        is_rate_limited = self.endpoint._detect_rate_limiting()
        
        assert is_rate_limited is True
    
    def test_estimate_recovery_time_healthy(self):
        """Test recovery time estimation for healthy endpoint."""
        self.endpoint.is_active = True
        self.endpoint.total_processed = 90
        self.endpoint.total_failed = 10
        
        recovery_time = self.endpoint._estimate_recovery_time()
        
        assert recovery_time == 0  # No recovery needed
    
    def test_estimate_recovery_time_rate_limited(self):
        """Test recovery time estimation for rate limited endpoint."""
        self.endpoint.total_received = 100
        self.endpoint.total_failed = 60  # High failure rate
        
        recovery_time = self.endpoint._estimate_recovery_time()
        
        assert recovery_time == 3600  # 1 hour for rate limit
    
    def test_get_health_recommendation_inactive(self):
        """Test health recommendation for inactive endpoint."""
        self.endpoint.is_active = False
        
        recommendation = self.endpoint._get_health_recommendation()
        
        assert "Activate endpoint" in recommendation
    
    def test_get_health_recommendation_high_failure(self):
        """Test health recommendation for high failure rate."""
        self.endpoint.is_active = True
        self.endpoint.total_processed = 30
        self.endpoint.total_failed = 70
        
        recommendation = self.endpoint._get_health_recommendation()
        
        assert "High failure rate" in recommendation
    
    def test_get_load_recommendation(self):
        """Test load recommendations for different RPS."""
        # Low load
        low_rec = self.endpoint._get_load_recommendation(5)
        assert "should handle this load well" in low_rec
        
        # Medium load  
        med_rec = self.endpoint._get_load_recommendation(25)
        assert "monitoring closely" in med_rec
        
        # High load
        high_rec = self.endpoint._get_load_recommendation(75)
        assert "High load" in high_rec
        
        # Very high load
        very_high_rec = self.endpoint._get_load_recommendation(200)
        assert "Very high load" in very_high_rec