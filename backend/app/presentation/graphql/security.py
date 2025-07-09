"""
Advanced GraphQL Security Features

Provides comprehensive security features including query whitelisting, 
threat detection, intrusion prevention, and advanced rate limiting.
"""

import hashlib
import logging
import re
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple
from uuid import uuid4

from strawberry import GraphQLError
from strawberry.extensions import Extension
from strawberry.types import ExecutionContext, ExecutionResult

logger = logging.getLogger(__name__)


class ThreatLevel(Enum):
    """Security threat levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SecurityEventType(Enum):
    """Types of security events."""
    QUERY_INJECTION = "query_injection"
    SUSPICIOUS_QUERY = "suspicious_query"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    INTRUSION_ATTEMPT = "intrusion_attempt"
    QUERY_FLOODING = "query_flooding"
    MALICIOUS_PAYLOAD = "malicious_payload"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DATA_EXTRACTION = "data_extraction"
    BRUTE_FORCE = "brute_force"


@dataclass
class SecurityEvent:
    """Security event data."""
    id: str
    event_type: SecurityEventType
    threat_level: ThreatLevel
    user_id: Optional[str]
    ip_address: Optional[str]
    user_agent: Optional[str]
    query: str
    variables: Dict[str, Any]
    timestamp: datetime
    description: str
    metadata: Dict[str, Any]
    blocked: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for logging/storage."""
        return {
            'id': self.id,
            'event_type': self.event_type.value,
            'threat_level': self.threat_level.value,
            'user_id': self.user_id,
            'ip_address': self.ip_address,
            'user_agent': self.user_agent,
            'query': self.query,
            'variables': self.variables,
            'timestamp': self.timestamp.isoformat(),
            'description': self.description,
            'metadata': self.metadata,
            'blocked': self.blocked
        }


class QueryWhitelist:
    """
    Query whitelisting system for production GraphQL endpoints.
    
    Maintains a whitelist of approved queries and blocks all others.
    """
    
    def __init__(self):
        self.whitelisted_queries: Set[str] = set()
        self.query_hashes: Dict[str, str] = {}
        self.whitelist_enabled = False
    
    def enable_whitelist(self):
        """Enable query whitelisting."""
        self.whitelist_enabled = True
        logger.info("Query whitelist enabled")
    
    def disable_whitelist(self):
        """Disable query whitelisting."""
        self.whitelist_enabled = False
        logger.info("Query whitelist disabled")
    
    def add_query(self, query: str, operation_name: Optional[str] = None) -> str:
        """
        Add a query to the whitelist.
        
        Returns the query hash for reference.
        """
        normalized_query = self._normalize_query(query)
        query_hash = self._hash_query(normalized_query)
        
        self.whitelisted_queries.add(query_hash)
        self.query_hashes[query_hash] = normalized_query
        
        logger.info(f"Added query to whitelist: {operation_name or 'unnamed'} [{query_hash[:8]}]")
        return query_hash
    
    def remove_query(self, query_hash: str):
        """Remove a query from the whitelist."""
        if query_hash in self.whitelisted_queries:
            self.whitelisted_queries.remove(query_hash)
            self.query_hashes.pop(query_hash, None)
            logger.info(f"Removed query from whitelist: {query_hash[:8]}")
    
    def is_query_allowed(self, query: str) -> Tuple[bool, str]:
        """
        Check if a query is whitelisted.
        
        Returns (is_allowed, query_hash).
        """
        if not self.whitelist_enabled:
            return True, ""
        
        normalized_query = self._normalize_query(query)
        query_hash = self._hash_query(normalized_query)
        
        is_allowed = query_hash in self.whitelisted_queries
        return is_allowed, query_hash
    
    def get_whitelist_stats(self) -> Dict[str, Any]:
        """Get whitelist statistics."""
        return {
            'enabled': self.whitelist_enabled,
            'total_queries': len(self.whitelisted_queries),
            'queries': [
                {
                    'hash': hash_val[:8],
                    'query': query[:100] + '...' if len(query) > 100 else query
                }
                for hash_val, query in self.query_hashes.items()
            ]
        }
    
    def load_from_file(self, file_path: str):
        """Load whitelist from file."""
        try:
            with open(file_path, 'r') as f:
                queries = f.read().strip().split('\n---\n')
                for query in queries:
                    if query.strip():
                        self.add_query(query.strip())
            logger.info(f"Loaded {len(queries)} queries from whitelist file")
        except Exception as e:
            logger.error(f"Failed to load whitelist from file: {e}")
    
    def save_to_file(self, file_path: str):
        """Save whitelist to file."""
        try:
            with open(file_path, 'w') as f:
                queries = list(self.query_hashes.values())
                f.write('\n---\n'.join(queries))
            logger.info(f"Saved {len(queries)} queries to whitelist file")
        except Exception as e:
            logger.error(f"Failed to save whitelist to file: {e}")
    
    def _normalize_query(self, query: str) -> str:
        """Normalize query for consistent hashing."""
        # Remove comments
        query = re.sub(r'#.*$', '', query, flags=re.MULTILINE)
        
        # Remove extra whitespace
        query = re.sub(r'\s+', ' ', query)
        
        # Remove variable names (replace with placeholders)
        query = re.sub(r'\$\w+', '$VAR', query)
        
        return query.strip()
    
    def _hash_query(self, query: str) -> str:
        """Generate hash for query."""
        return hashlib.sha256(query.encode()).hexdigest()


class ThreatDetector:
    """
    Advanced threat detection for GraphQL queries.
    
    Detects various types of security threats and suspicious patterns.
    """
    
    def __init__(self):
        self.suspicious_patterns = [
            # SQL injection patterns
            r'(?i)(union|select|insert|update|delete|drop|create|alter)\s+',
            r'(?i)(or|and)\s+\d+\s*=\s*\d+',
            r'(?i)(\'|\");\s*(select|insert|update|delete)',
            
            # NoSQL injection patterns
            r'(?i)\$where|\$regex|\$ne|\$gt|\$lt',
            r'(?i){\s*\$.*:.*}',
            
            # Script injection patterns
            r'(?i)<script[^>]*>.*</script>',
            r'(?i)javascript:',
            r'(?i)eval\s*\(',
            
            # Path traversal patterns
            r'\.\./',
            r'\.\.\\',
            r'/etc/passwd',
            r'/proc/self/environ',
            
            # Command injection patterns
            r'(?i);\s*(cat|ls|pwd|id|whoami|uname)',
            r'(?i)\|\s*(cat|ls|pwd|id|whoami|uname)',
            r'(?i)`.*`',
            
            # Information disclosure patterns
            r'(?i)version\(\)',
            r'(?i)@@version',
            r'(?i)information_schema',
            r'(?i)sys\.tables',
        ]
        
        self.compiled_patterns = [re.compile(pattern) for pattern in self.suspicious_patterns]
        
        # Anomaly detection
        self.user_query_patterns: Dict[str, List[str]] = defaultdict(list)
        self.query_frequency: Dict[str, int] = defaultdict(int)
        self.user_request_times: Dict[str, deque] = defaultdict(lambda: deque(maxlen=100))
        
        # Threat scoring
        self.threat_scores = {
            'suspicious_pattern': 25,
            'high_complexity': 15,
            'high_frequency': 20,
            'unusual_timing': 10,
            'privilege_escalation': 30,
            'data_enumeration': 25,
            'admin_operation': 20,
            'bulk_operation': 15,
            'sensitive_field_access': 20,
        }
    
    def analyze_query(
        self,
        query: str,
        variables: Dict[str, Any],
        user_id: Optional[str],
        ip_address: Optional[str],
        user_agent: Optional[str],
        context: Dict[str, Any]
    ) -> List[SecurityEvent]:
        """
        Analyze a query for security threats.
        
        Returns a list of security events found.
        """
        events = []
        threat_score = 0
        
        # Check for suspicious patterns
        pattern_events = self._check_suspicious_patterns(query, variables, user_id, ip_address, user_agent)
        events.extend(pattern_events)
        threat_score += sum(25 for _ in pattern_events)
        
        # Check for query injection
        injection_events = self._check_query_injection(query, variables, user_id, ip_address, user_agent)
        events.extend(injection_events)
        threat_score += sum(30 for _ in injection_events)
        
        # Check for privilege escalation
        privilege_events = self._check_privilege_escalation(query, context, user_id, ip_address, user_agent)
        events.extend(privilege_events)
        threat_score += sum(30 for _ in privilege_events)
        
        # Check for data enumeration
        enumeration_events = self._check_data_enumeration(query, variables, user_id, ip_address, user_agent)
        events.extend(enumeration_events)
        threat_score += sum(25 for _ in enumeration_events)
        
        # Check for abnormal query frequency
        frequency_events = self._check_query_frequency(query, user_id, ip_address, user_agent)
        events.extend(frequency_events)
        threat_score += sum(20 for _ in frequency_events)
        
        # Check for unusual timing patterns
        timing_events = self._check_timing_patterns(user_id, ip_address, user_agent)
        events.extend(timing_events)
        threat_score += sum(15 for _ in timing_events)
        
        # Update user patterns
        if user_id:
            self.user_query_patterns[user_id].append(query)
            self.user_request_times[user_id].append(time.time())
            
            # Keep only recent patterns
            if len(self.user_query_patterns[user_id]) > 50:
                self.user_query_patterns[user_id] = self.user_query_patterns[user_id][-50:]
        
        # Generate aggregate threat event if score is high
        if threat_score >= 50:
            events.append(SecurityEvent(
                id=str(uuid4()),
                event_type=SecurityEventType.INTRUSION_ATTEMPT,
                threat_level=ThreatLevel.HIGH if threat_score >= 75 else ThreatLevel.MEDIUM,
                user_id=user_id,
                ip_address=ip_address,
                user_agent=user_agent,
                query=query,
                variables=variables,
                timestamp=datetime.utcnow(),
                description=f"High threat score detected: {threat_score}",
                metadata={'threat_score': threat_score, 'individual_events': len(events)}
            ))
        
        return events
    
    def _check_suspicious_patterns(
        self,
        query: str,
        variables: Dict[str, Any],
        user_id: Optional[str],
        ip_address: Optional[str],
        user_agent: Optional[str]
    ) -> List[SecurityEvent]:
        """Check for suspicious patterns in query."""
        events = []
        
        # Check query text
        for pattern in self.compiled_patterns:
            matches = pattern.findall(query)
            if matches:
                events.append(SecurityEvent(
                    id=str(uuid4()),
                    event_type=SecurityEventType.SUSPICIOUS_QUERY,
                    threat_level=ThreatLevel.HIGH,
                    user_id=user_id,
                    ip_address=ip_address,
                    user_agent=user_agent,
                    query=query,
                    variables=variables,
                    timestamp=datetime.utcnow(),
                    description=f"Suspicious pattern detected: {matches[0]}",
                    metadata={'pattern': pattern.pattern, 'matches': matches}
                ))
        
        # Check variables
        for var_name, var_value in variables.items():
            if isinstance(var_value, str):
                for pattern in self.compiled_patterns:
                    matches = pattern.findall(var_value)
                    if matches:
                        events.append(SecurityEvent(
                            id=str(uuid4()),
                            event_type=SecurityEventType.MALICIOUS_PAYLOAD,
                            threat_level=ThreatLevel.HIGH,
                            user_id=user_id,
                            ip_address=ip_address,
                            user_agent=user_agent,
                            query=query,
                            variables=variables,
                            timestamp=datetime.utcnow(),
                            description=f"Malicious payload in variable '{var_name}': {matches[0]}",
                            metadata={'variable': var_name, 'pattern': pattern.pattern, 'matches': matches}
                        ))
        
        return events
    
    def _check_query_injection(
        self,
        query: str,
        variables: Dict[str, Any],
        user_id: Optional[str],
        ip_address: Optional[str],
        user_agent: Optional[str]
    ) -> List[SecurityEvent]:
        """Check for query injection attempts."""
        events = []
        
        # Check for dynamic query construction patterns
        injection_indicators = [
            r'(?i)query\s*\+\s*',
            r'(?i)"\s*\+\s*"',
            r'(?i)concat\s*\(',
            r'(?i)format\s*\(',
            r'(?i)string\s*\(',
        ]
        
        for pattern in injection_indicators:
            if re.search(pattern, query):
                events.append(SecurityEvent(
                    id=str(uuid4()),
                    event_type=SecurityEventType.QUERY_INJECTION,
                    threat_level=ThreatLevel.CRITICAL,
                    user_id=user_id,
                    ip_address=ip_address,
                    user_agent=user_agent,
                    query=query,
                    variables=variables,
                    timestamp=datetime.utcnow(),
                    description=f"Query injection pattern detected: {pattern}",
                    metadata={'injection_pattern': pattern}
                ))
        
        return events
    
    def _check_privilege_escalation(
        self,
        query: str,
        context: Dict[str, Any],
        user_id: Optional[str],
        ip_address: Optional[str],
        user_agent: Optional[str]
    ) -> List[SecurityEvent]:
        """Check for privilege escalation attempts."""
        events = []
        
        # Check for admin operations by non-admin users
        admin_operations = [
            r'(?i)createUser',
            r'(?i)deleteUser',
            r'(?i)updateUserRole',
            r'(?i)adminQuery',
            r'(?i)systemSettings',
            r'(?i)bulkOperation',
        ]
        
        user = context.get('user', {})
        user_permissions = user.get('permissions', [])
        is_admin = any('admin' in perm for perm in user_permissions)
        
        if not is_admin:
            for pattern in admin_operations:
                if re.search(pattern, query):
                    events.append(SecurityEvent(
                        id=str(uuid4()),
                        event_type=SecurityEventType.PRIVILEGE_ESCALATION,
                        threat_level=ThreatLevel.HIGH,
                        user_id=user_id,
                        ip_address=ip_address,
                        user_agent=user_agent,
                        query=query,
                        variables={},
                        timestamp=datetime.utcnow(),
                        description=f"Non-admin user attempting admin operation: {pattern}",
                        metadata={'user_permissions': user_permissions, 'attempted_operation': pattern}
                    ))
        
        return events
    
    def _check_data_enumeration(
        self,
        query: str,
        variables: Dict[str, Any],
        user_id: Optional[str],
        ip_address: Optional[str],
        user_agent: Optional[str]
    ) -> List[SecurityEvent]:
        """Check for data enumeration attempts."""
        events = []
        
        # Check for large data requests
        large_limits = []
        for var_name, var_value in variables.items():
            if var_name in ['first', 'last', 'limit'] and isinstance(var_value, int):
                if var_value > 1000:
                    large_limits.append((var_name, var_value))
        
        if large_limits:
            events.append(SecurityEvent(
                id=str(uuid4()),
                event_type=SecurityEventType.DATA_EXTRACTION,
                threat_level=ThreatLevel.MEDIUM,
                user_id=user_id,
                ip_address=ip_address,
                user_agent=user_agent,
                query=query,
                variables=variables,
                timestamp=datetime.utcnow(),
                description=f"Large data request detected: {large_limits}",
                metadata={'large_limits': large_limits}
            ))
        
        # Check for sensitive field access patterns
        sensitive_fields = [
            r'(?i)password',
            r'(?i)secret',
            r'(?i)token',
            r'(?i)apiKey',
            r'(?i)privateKey',
            r'(?i)ssn',
            r'(?i)creditCard',
            r'(?i)bankAccount',
        ]
        
        for pattern in sensitive_fields:
            if re.search(pattern, query):
                events.append(SecurityEvent(
                    id=str(uuid4()),
                    event_type=SecurityEventType.DATA_EXTRACTION,
                    threat_level=ThreatLevel.HIGH,
                    user_id=user_id,
                    ip_address=ip_address,
                    user_agent=user_agent,
                    query=query,
                    variables=variables,
                    timestamp=datetime.utcnow(),
                    description=f"Sensitive field access detected: {pattern}",
                    metadata={'sensitive_field': pattern}
                ))
        
        return events
    
    def _check_query_frequency(
        self,
        query: str,
        user_id: Optional[str],
        ip_address: Optional[str],
        user_agent: Optional[str]
    ) -> List[SecurityEvent]:
        """Check for abnormal query frequency."""
        events = []
        
        # Track query frequency per user
        if user_id:
            self.query_frequency[f"user:{user_id}"] += 1
            
            # Check if user is flooding with queries
            if self.query_frequency[f"user:{user_id}"] > 1000:  # 1000 queries in window
                events.append(SecurityEvent(
                    id=str(uuid4()),
                    event_type=SecurityEventType.QUERY_FLOODING,
                    threat_level=ThreatLevel.HIGH,
                    user_id=user_id,
                    ip_address=ip_address,
                    user_agent=user_agent,
                    query=query,
                    variables={},
                    timestamp=datetime.utcnow(),
                    description=f"Query flooding detected: {self.query_frequency[f'user:{user_id}']} queries",
                    metadata={'query_count': self.query_frequency[f"user:{user_id}"]}
                ))
        
        # Track query frequency per IP
        if ip_address:
            self.query_frequency[f"ip:{ip_address}"] += 1
            
            if self.query_frequency[f"ip:{ip_address}"] > 5000:  # 5000 queries in window
                events.append(SecurityEvent(
                    id=str(uuid4()),
                    event_type=SecurityEventType.QUERY_FLOODING,
                    threat_level=ThreatLevel.CRITICAL,
                    user_id=user_id,
                    ip_address=ip_address,
                    user_agent=user_agent,
                    query=query,
                    variables={},
                    timestamp=datetime.utcnow(),
                    description=f"IP-based query flooding detected: {self.query_frequency[f'ip:{ip_address}']} queries",
                    metadata={'query_count': self.query_frequency[f"ip:{ip_address}"]}
                ))
        
        return events
    
    def _check_timing_patterns(
        self,
        user_id: Optional[str],
        ip_address: Optional[str],
        user_agent: Optional[str]
    ) -> List[SecurityEvent]:
        """Check for suspicious timing patterns."""
        events = []
        
        if not user_id:
            return events
        
        current_time = time.time()
        user_times = self.user_request_times[user_id]
        
        if len(user_times) >= 10:
            # Check for rapid-fire requests (potential bot)
            recent_times = [t for t in user_times if current_time - t < 60]  # Last minute
            
            if len(recent_times) >= 50:  # 50 requests in 1 minute
                events.append(SecurityEvent(
                    id=str(uuid4()),
                    event_type=SecurityEventType.BRUTE_FORCE,
                    threat_level=ThreatLevel.HIGH,
                    user_id=user_id,
                    ip_address=ip_address,
                    user_agent=user_agent,
                    query="",
                    variables={},
                    timestamp=datetime.utcnow(),
                    description=f"Rapid-fire requests detected: {len(recent_times)} requests in 1 minute",
                    metadata={'requests_per_minute': len(recent_times)}
                ))
        
        return events
    
    def get_threat_stats(self) -> Dict[str, Any]:
        """Get threat detection statistics."""
        return {
            'patterns_checked': len(self.compiled_patterns),
            'users_monitored': len(self.user_query_patterns),
            'query_frequency_entries': len(self.query_frequency),
            'threat_scores': self.threat_scores,
        }


class GraphQLSecurityExtension(Extension):
    """
    Comprehensive GraphQL security extension.
    
    Integrates query whitelisting, threat detection, and security monitoring.
    """
    
    def __init__(
        self,
        whitelist: Optional[QueryWhitelist] = None,
        threat_detector: Optional[ThreatDetector] = None,
        enable_whitelist: bool = False,
        enable_threat_detection: bool = True,
        block_threats: bool = True,
        security_event_handler: Optional[callable] = None
    ):
        self.whitelist = whitelist or QueryWhitelist()
        self.threat_detector = threat_detector or ThreatDetector()
        self.enable_whitelist = enable_whitelist
        self.enable_threat_detection = enable_threat_detection
        self.block_threats = block_threats
        self.security_event_handler = security_event_handler
        
        self.security_events: List[SecurityEvent] = []
        
        if enable_whitelist:
            self.whitelist.enable_whitelist()
    
    def on_validation_start(self):
        """Perform security validation before query execution."""
        query = getattr(self.execution_context, 'query', '')
        variables = getattr(self.execution_context, 'variable_values', {}) or {}
        context = getattr(self.execution_context, 'context', {})
        
        user_id = context.get('user', {}).get('id')
        ip_address = context.get('ip_address')
        user_agent = context.get('user_agent')
        
        # Check query whitelist
        if self.whitelist.whitelist_enabled:
            is_allowed, query_hash = self.whitelist.is_query_allowed(query)
            
            if not is_allowed:
                security_event = SecurityEvent(
                    id=str(uuid4()),
                    event_type=SecurityEventType.UNAUTHORIZED_ACCESS,
                    threat_level=ThreatLevel.HIGH,
                    user_id=user_id,
                    ip_address=ip_address,
                    user_agent=user_agent,
                    query=query,
                    variables=variables,
                    timestamp=datetime.utcnow(),
                    description=f"Query not in whitelist: {query_hash[:8]}",
                    metadata={'query_hash': query_hash},
                    blocked=True
                )
                
                self._handle_security_event(security_event)
                
                raise GraphQLError(
                    "Query not authorized",
                    extensions={
                        'code': 'QUERY_NOT_WHITELISTED',
                        'query_hash': query_hash[:8]
                    }
                )
        
        # Run threat detection
        if self.enable_threat_detection:
            threats = self.threat_detector.analyze_query(
                query, variables, user_id, ip_address, user_agent, context
            )
            
            # Handle detected threats
            for threat in threats:
                self._handle_security_event(threat)
                
                # Block critical threats
                if self.block_threats and threat.threat_level == ThreatLevel.CRITICAL:
                    raise GraphQLError(
                        "Security threat detected",
                        extensions={
                            'code': 'SECURITY_THREAT_DETECTED',
                            'threat_type': threat.event_type.value,
                            'threat_level': threat.threat_level.value
                        }
                    )
    
    def _handle_security_event(self, event: SecurityEvent):
        """Handle a security event."""
        self.security_events.append(event)
        
        # Log security event
        logger.warning(
            f"Security event detected: {event.event_type.value} "
            f"(Level: {event.threat_level.value}) - {event.description}",
            extra={
                'security_event': event.to_dict(),
                'user_id': event.user_id,
                'ip_address': event.ip_address,
                'threat_level': event.threat_level.value
            }
        )
        
        # Call custom security event handler
        if self.security_event_handler:
            try:
                self.security_event_handler(event)
            except Exception as e:
                logger.error(f"Error in security event handler: {e}")
    
    def get_security_stats(self) -> Dict[str, Any]:
        """Get security statistics."""
        event_counts = defaultdict(int)
        threat_level_counts = defaultdict(int)
        
        for event in self.security_events:
            event_counts[event.event_type.value] += 1
            threat_level_counts[event.threat_level.value] += 1
        
        return {
            'total_events': len(self.security_events),
            'events_by_type': dict(event_counts),
            'events_by_threat_level': dict(threat_level_counts),
            'whitelist_enabled': self.whitelist.whitelist_enabled,
            'threat_detection_enabled': self.enable_threat_detection,
            'threats_blocked': self.block_threats,
            'whitelist_stats': self.whitelist.get_whitelist_stats(),
            'threat_detector_stats': self.threat_detector.get_threat_stats()
        }


# Global security instances
query_whitelist = QueryWhitelist()
threat_detector = ThreatDetector()


def create_security_extension(
    enable_whitelist: bool = False,
    enable_threat_detection: bool = True,
    block_threats: bool = True,
    security_event_handler: Optional[callable] = None
) -> GraphQLSecurityExtension:
    """Create a configured security extension."""
    return GraphQLSecurityExtension(
        whitelist=query_whitelist,
        threat_detector=threat_detector,
        enable_whitelist=enable_whitelist,
        enable_threat_detection=enable_threat_detection,
        block_threats=block_threats,
        security_event_handler=security_event_handler
    )


def default_security_event_handler(event: SecurityEvent):
    """Default security event handler."""
    # This could integrate with external security systems
    # For now, just log critical events
    if event.threat_level == ThreatLevel.CRITICAL:
        logger.critical(
            f"CRITICAL SECURITY THREAT: {event.description}",
            extra={'security_event': event.to_dict()}
        )


__all__ = [
    'QueryWhitelist',
    'ThreatDetector',
    'GraphQLSecurityExtension',
    'SecurityEvent',
    'SecurityEventType',
    'ThreatLevel',
    'query_whitelist',
    'threat_detector',
    'create_security_extension',
    'default_security_event_handler',
]