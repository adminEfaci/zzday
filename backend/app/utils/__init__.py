"""Utility functions following DDD principles and hexagonal architecture.

This module provides framework-agnostic utility classes and functions that follow Domain-Driven Design
principles. All utilities are pure Python classes that can be used across different layers
of the application without tight coupling to any specific framework.

Enhanced Modules:
- validation: Comprehensive validation classes with rich functionality
- text: Text processing classes for sanitization, truncation, and manipulation
- crypto: Cryptographic utilities for hashing, encryption, and key generation
- date: Date/time processing classes for parsing, formatting, and calculations
- serialization: JSON and dictionary processing with extended type support
- testing: Test utilities for data generation and mocking

Design Principles:
- Framework-agnostic (no FastAPI/Pydantic dependencies in domain layer)
- Pure Python classes with clean __init__ validation
- Rich functionality with utility methods and properties
- Comprehensive error handling with clear ValidationError messages
- Static utility methods for convenience
- Proper class behavior (__eq__, __hash__, __repr__, __str__)
"""

# Cryptography utilities
from app.utils.crypto import (  # Enhanced cryptographic classes; Backward compatibility functions
    APIKeyGenerator,
    DataEncryptor,
    DataHasher,
    HMACSignature,
    RandomStringGenerator,
    SensitiveDataMasker,
    create_signature,
    generate_api_key,
    generate_random_string,
    hash_data,
    mask_sensitive_data,
    verify_signature,
)

# Date utilities
from app.utils.date import (  # Enhanced date/time classes; Backward compatibility functions
    AgeCalculator,
    BusinessDaysCalculator,
    DateParser,
    DateRangeGenerator,
    RelativeTimeFormatter,
    TimezoneConverter,
    convert_timezone,
    format_relative_time,
    get_age,
    get_business_days,
    get_date_range,
    parse_date,
)

# Serialization utilities
from app.utils.serialization import (  # Enhanced serialization classes; Backward compatibility functions
    CacheSerializer,
    DictProcessor,
    ExtendedJSONEncoder,
    JSONSerializer,
    deep_merge,
    deserialize_from_cache,
    deserialize_json,
    flatten_dict,
    serialize_for_cache,
    serialize_json,
    unflatten_dict,
)

# Testing utilities
from app.utils.testing import (  # Enhanced testing classes; Utility functions
    AsyncTestCase,
    MockRepository,
    ModelAssertion,
    TestDataFactory,
    assert_called_with_subset,
    assert_model_equals,
    create_mock_service,
    create_test_db_session,
    mock_datetime,
)

# Text utilities
from app.utils.text import (  # Enhanced text processing classes; Backward compatibility functions  # Enhanced text processing classes; Backward compatibility functions
    KeywordExtractor,
    SlugGenerator,
    TextNormalizer,
    TextSanitizer,
    TextTruncator,
    extract_keywords,
    generate_slug,
    is_valid_url,
    normalize_whitespace,
    remove_emojis,
    sanitize_text,
    truncate_text,
)
from app.utils.text import URLValidator as URLTextValidator
from app.utils.validation import (  # Enhanced validation classes; Backward compatibility functions
    ConfigValidationUtils,
    EmailValidator,
    FilenameValidator,
    PasswordValidator,
    PhoneValidator,
    URLValidator,
    UUIDValidator,
    ValidationRule,
    validate_boolean,
    validate_email,
    validate_enum,
    validate_float,
    validate_integer,
    validate_json_schema,
    validate_list,
    validate_string,
    validate_url,
)

__all__ = [
    # ===== CRYPTOGRAPHY =====
    "APIKeyGenerator",
    # ===== DATE/TIME =====
    "AgeCalculator",
    # ===== TESTING =====
    "AsyncTestCase",
    "BusinessDaysCalculator",
    # ===== SERIALIZATION =====
    "CacheSerializer",
    # ===== VALIDATION =====
    "ConfigValidationUtils",
    "DataEncryptor",
    "DataHasher",
    "DateParser",
    "DateRangeGenerator",
    "DictProcessor",
    "EmailValidator",
    "ExtendedJSONEncoder",
    "FilenameValidator",
    "HMACSignature",
    "JSONSerializer",
    # ===== TEXT PROCESSING =====
    "KeywordExtractor",
    "MockRepository",
    "ModelAssertion",
    "PasswordValidator",
    "PhoneValidator",
    "RandomStringGenerator",
    "RelativeTimeFormatter",
    "SensitiveDataMasker",
    "SlugGenerator",
    "TestDataFactory",
    "TextNormalizer",
    "TextSanitizer",
    "TextTruncator",
    "TimezoneConverter",
    "URLTextValidator",
    "URLValidator",
    "UUIDValidator",
    "ValidationRule",
    "assert_called_with_subset",
    "assert_model_equals",
    "convert_timezone",
    "create_mock_service",
    "create_signature",
    "create_test_db_session",
    "deep_merge",
    "deserialize_from_cache",
    "deserialize_json",
    "extract_keywords",
    "flatten_dict",
    "format_relative_time",
    "generate_api_key",
    "generate_random_string",
    "generate_slug",
    "get_age",
    "get_business_days",
    "get_date_range",
    "hash_data",
    "is_valid_url",
    "mask_sensitive_data",
    "mock_datetime",
    "normalize_whitespace",
    "parse_date",
    "remove_emojis",
    "sanitize_text",
    "serialize_for_cache",
    "serialize_json",
    "truncate_text",
    "unflatten_dict",
    "validate_boolean",
    "validate_email",
    "validate_enum",
    "validate_float",
    "validate_integer",
    "validate_json_schema",
    "validate_list",
    "validate_string",
    "validate_url",
    "verify_signature",
]
