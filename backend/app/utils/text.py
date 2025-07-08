"""Text processing utilities following DDD principles and hexagonal architecture.

This module provides framework-agnostic text processing utilities that follow Domain-Driven Design
principles. All text processors are pure Python classes that can be used across different layers
of the application without tight coupling to any specific framework.

Design Principles:
- Framework-agnostic (no FastAPI/Pydantic dependencies)
- Pure Python classes with clean __init__ validation
- Rich functionality with utility methods and properties
- Comprehensive error handling with clear ValidationError messages
- Static processing methods for convenience
- Proper class behavior (__eq__, __hash__, __repr__, __str__)
"""

import html
import re
import unicodedata
from collections import Counter

from app.core.errors import ValidationError
from app.core.security import sanitize_input

# =====================================================================================
# TEXT PROCESSING CLASSES
# =====================================================================================


class TextSanitizer:
    """Text sanitization with comprehensive cleaning and rich functionality."""

    def __init__(
        self, text: str, allow_html: bool = False, max_length: int | None = None
    ):
        """
        Initialize and sanitize text input.

        Args:
            text: Text to sanitize
            allow_html: Whether to allow HTML content
            max_length: Maximum length for text

        Raises:
            ValidationError: If text cannot be sanitized
        """
        if text is None:
            raise ValidationError("Text cannot be None")

        self.original_text = text
        self.allow_html = allow_html
        self.max_length = max_length
        self.value = self._sanitize_text(text)

    def _sanitize_text(self, text: str) -> str:
        """Sanitize text input."""
        if not isinstance(text, str):
            text = str(text)

        # Basic sanitization using core security module
        text = sanitize_input(text)

        if not self.allow_html:
            # Escape HTML entities
            text = html.escape(text)
        else:
            # More sophisticated HTML sanitization could go here
            # For now, just escape potentially dangerous characters
            text = html.escape(text)

        # Apply length limit if specified
        if self.max_length and len(text) > self.max_length:
            text = text[: self.max_length]

        return text

    @staticmethod
    def sanitize_text(
        text: str, allow_html: bool = False, max_length: int | None = None
    ) -> str:
        """
        Static method to sanitize text.

        Args:
            text: Text to sanitize
            allow_html: Whether to allow HTML content
            max_length: Maximum length for text

        Returns:
            str: Sanitized text
        """
        try:
            sanitizer = TextSanitizer(text, allow_html, max_length)
            return sanitizer.value
        except ValidationError:
            return ""

    @property
    def is_html_content(self) -> bool:
        """Check if original text contains HTML."""
        html_pattern = re.compile(r"<[^>]+>")
        return bool(html_pattern.search(self.original_text))

    @property
    def character_count(self) -> int:
        """Get character count of sanitized text."""
        return len(self.value)

    @property
    def word_count(self) -> int:
        """Get word count of sanitized text."""
        return len(self.value.split())

    def strip_html(self) -> str:
        """Remove all HTML tags from text."""
        html_pattern = re.compile(r"<[^>]+>")
        return html_pattern.sub("", self.value)

    def __str__(self) -> str:
        """String representation."""
        return self.value

    def __eq__(self, other) -> bool:
        """Check equality."""
        if not isinstance(other, TextSanitizer):
            return False
        return self.value == other.value

    def __hash__(self) -> int:
        """Return hash for use in sets/dicts."""
        return hash(self.value)

    def __repr__(self) -> str:
        """Detailed string representation for debugging."""
        preview = self.value[:50] + "..." if len(self.value) > 50 else self.value
        return f"TextSanitizer('{preview}', allow_html={self.allow_html})"


class TextTruncator:
    """Text truncation with smart word boundaries and rich functionality."""

    def __init__(
        self, text: str, max_length: int, suffix: str = "...", whole_words: bool = True
    ):
        """
        Initialize and truncate text.

        Args:
            text: Text to truncate
            max_length: Maximum length
            suffix: Suffix to add when truncating
            whole_words: Whether to preserve whole words

        Raises:
            ValidationError: If parameters are invalid
        """
        if not isinstance(text, str):
            raise ValidationError("Text must be a string")

        if max_length < 1:
            raise ValidationError("Maximum length must be positive")

        self.original_text = text
        self.max_length = max_length
        self.suffix = suffix
        self.whole_words = whole_words
        self.value = self._truncate_text()

    def _truncate_text(self) -> str:
        """Truncate text to specified length."""
        if len(self.original_text) <= self.max_length:
            return self.original_text

        truncate_at = self.max_length - len(self.suffix)

        if truncate_at <= 0:
            return self.suffix[: self.max_length]

        if not self.whole_words:
            return self.original_text[:truncate_at] + self.suffix

        # Find last space before truncate point
        last_space = self.original_text.rfind(" ", 0, truncate_at)

        if last_space == -1:
            # No space found, truncate at exact position
            return self.original_text[:truncate_at] + self.suffix

        return self.original_text[:last_space] + self.suffix

    @property
    def was_truncated(self) -> bool:
        """Check if text was actually truncated."""
        return len(self.original_text) > self.max_length

    @property
    def characters_removed(self) -> int:
        """Get number of characters removed."""
        if not self.was_truncated:
            return 0
        return len(self.original_text) - len(self.value) + len(self.suffix)

    def __str__(self) -> str:
        """String representation."""
        return self.value

    def __eq__(self, other) -> bool:
        """Check equality."""
        if not isinstance(other, TextTruncator):
            return False
        return self.value == other.value

    def __hash__(self) -> int:
        """Return hash for use in sets/dicts."""
        return hash(self.value)

    def __repr__(self) -> str:
        """Detailed string representation for debugging."""
        return f"TextTruncator('{self.value}', was_truncated={self.was_truncated})"


class SlugGenerator:
    """URL-friendly slug generation with comprehensive normalization and rich functionality."""

    def __init__(self, text: str, max_length: int | None = None, separator: str = "-"):
        """
        Initialize and generate slug.

        Args:
            text: Text to convert to slug
            max_length: Maximum slug length
            separator: Character to use as separator

        Raises:
            ValidationError: If text is invalid
        """
        if not text or not isinstance(text, str):
            raise ValidationError("Text cannot be empty")

        self.original_text = text
        self.max_length = max_length
        self.separator = separator
        self.value = self._generate_slug()

    def _generate_slug(self) -> str:
        """Generate URL-friendly slug from text."""
        text = self.original_text

        # Normalize unicode
        text = unicodedata.normalize("NFKD", text)

        # Convert to ASCII
        text = text.encode("ascii", "ignore").decode("ascii")

        # Convert to lowercase
        text = text.lower()

        # Replace spaces and special characters with separator
        text = re.sub(r"[^a-z0-9]+", self.separator, text)

        # Remove leading/trailing separators
        text = text.strip(self.separator)

        # Remove consecutive separators
        text = re.sub(f"{re.escape(self.separator)}+", self.separator, text)

        # Truncate if needed
        if self.max_length:
            text = text[: self.max_length].rstrip(self.separator)

        return text

    @property
    def word_count(self) -> int:
        """Get number of words in slug."""
        return len(self.value.split(self.separator)) if self.value else 0

    @property
    def is_single_word(self) -> bool:
        """Check if slug is a single word."""
        return self.separator not in self.value

    def __str__(self) -> str:
        """String representation."""
        return self.value

    def __eq__(self, other) -> bool:
        """Check equality."""
        if not isinstance(other, SlugGenerator):
            return False
        return self.value == other.value

    def __hash__(self) -> int:
        """Return hash for use in sets/dicts."""
        return hash(self.value)

    def __repr__(self) -> str:
        """Detailed string representation for debugging."""
        return f"SlugGenerator('{self.value}', separator='{self.separator}')"


class KeywordExtractor:
    """Keyword extraction with frequency analysis and rich functionality."""

    def __init__(self, text: str, min_length: int = 3, max_keywords: int = 10):
        """
        Initialize and extract keywords.

        Args:
            text: Text to extract keywords from
            min_length: Minimum keyword length
            max_keywords: Maximum number of keywords to extract

        Raises:
            ValidationError: If parameters are invalid
        """
        if not isinstance(text, str):
            raise ValidationError("Text must be a string")

        if min_length < 1:
            raise ValidationError("Minimum length must be positive")

        if max_keywords < 1:
            raise ValidationError("Maximum keywords must be positive")

        self.original_text = text
        self.min_length = min_length
        self.max_keywords = max_keywords
        self.keywords = self._extract_keywords()

    def _extract_keywords(self) -> list[str]:
        """Extract keywords from text."""
        if not self.original_text:
            return []

        # Convert to lowercase
        text = self.original_text.lower()

        # Remove punctuation and split
        words = re.findall(r"\b\w+\b", text)

        # Filter by length
        words = [w for w in words if len(w) >= self.min_length]

        # Remove common stop words
        stop_words = {
            "the",
            "and",
            "or",
            "but",
            "in",
            "on",
            "at",
            "to",
            "for",
            "of",
            "with",
            "by",
            "from",
            "as",
            "is",
            "was",
            "are",
            "were",
            "been",
            "be",
            "being",
            "have",
            "has",
            "had",
            "do",
            "does",
            "did",
            "will",
            "would",
            "could",
            "should",
            "may",
            "might",
            "must",
            "shall",
            "can",
            "a",
            "an",
            "this",
            "that",
            "these",
            "those",
            "i",
            "you",
            "he",
            "she",
            "it",
            "we",
            "they",
            "them",
            "their",
            "what",
            "which",
            "who",
            "when",
            "where",
            "why",
            "how",
        }

        keywords = [w for w in words if w not in stop_words]

        # Count frequency
        word_counts = Counter(keywords)

        # Get most common
        most_common = word_counts.most_common(self.max_keywords)

        return [word for word, count in most_common]

    @property
    def total_word_count(self) -> int:
        """Get total word count in original text."""
        return len(re.findall(r"\b\w+\b", self.original_text))

    def __str__(self) -> str:
        """String representation."""
        return ", ".join(self.keywords)

    def __eq__(self, other) -> bool:
        """Check equality."""
        if not isinstance(other, KeywordExtractor):
            return False
        return self.keywords == other.keywords

    def __hash__(self) -> int:
        """Return hash for use in sets/dicts."""
        return hash(tuple(self.keywords))

    def __repr__(self) -> str:
        """Detailed string representation for debugging."""
        preview = self.keywords[:3] if len(self.keywords) > 3 else self.keywords
        return f"KeywordExtractor({len(self.keywords)} keywords: {preview})"


class TextNormalizer:
    """Text normalization with comprehensive whitespace and character handling."""

    def __init__(self, text: str):
        """
        Initialize and normalize text.

        Args:
            text: Text to normalize

        Raises:
            ValidationError: If text is invalid
        """
        if text is None:
            raise ValidationError("Text cannot be None")

        if not isinstance(text, str):
            text = str(text)

        self.original_text = text
        self.value = self._normalize_text()

    def _normalize_text(self) -> str:
        """Normalize text whitespace."""
        text = self.original_text

        # Replace multiple spaces with single space
        text = re.sub(r"\s+", " ", text)

        # Strip leading/trailing whitespace
        return text.strip()

    def remove_emojis(self) -> str:
        """Remove emoji characters from normalized text."""
        emoji_pattern = re.compile(
            "["
            "\U0001F600-\U0001F64F"  # emoticons
            "\U0001F300-\U0001F5FF"  # symbols & pictographs
            "\U0001F680-\U0001F6FF"  # transport & map symbols
            "\U0001F1E0-\U0001F1FF"  # flags (iOS)
            "\U00002500-\U00002BEF"  # chinese char
            "\U00002702-\U000027B0"
            "\U00002702-\U000027B0"
            "\U000024C2-\U0001F251"
            "\U0001f926-\U0001f937"
            "\U00010000-\U0010ffff"
            "\u2640-\u2642"
            "\u2600-\u2B55"
            "\u200d"
            "\u23cf"
            "\u23e9"
            "\u231a"
            "\ufe0f"  # dingbats
            "\u3030"
            "]+",
            re.UNICODE,
        )

        return emoji_pattern.sub("", self.value)

    def __str__(self) -> str:
        """String representation."""
        return self.value

    def __eq__(self, other) -> bool:
        """Check equality."""
        if not isinstance(other, TextNormalizer):
            return False
        return self.value == other.value

    def __hash__(self) -> int:
        """Return hash for use in sets/dicts."""
        return hash(self.value)

    def __repr__(self) -> str:
        """Detailed string representation for debugging."""
        preview = self.value[:30] + "..." if len(self.value) > 30 else self.value
        return f"TextNormalizer('{preview}')"


# DUPLICATE REMOVED: URLValidator moved to app.utils.validation
# 
# This duplicate URLValidator class has been removed to eliminate overlap.
# Use app.utils.validation.URLValidator instead for consistent URL validation.
#
# Migration:
#   # Old usage (this file)
#   from app.utils.text import URLValidator
#   
#   # New usage (consolidated)
#   from app.utils.validation import URLValidator

import warnings

def URLValidator(*args, **kwargs):
    """
    DEPRECATED: Duplicate URLValidator removed.
    
    Use app.utils.validation.URLValidator instead.
    This function provides temporary compatibility.
    """
    warnings.warn(
        "URLValidator in text.py is removed. Use app.utils.validation.URLValidator instead.",
        DeprecationWarning,
        stacklevel=2
    )
    
    from app.utils.validation import URLValidator as ValidationURLValidator
    return ValidationURLValidator(*args, **kwargs)


# =====================================================================================
# BACKWARD COMPATIBILITY FUNCTIONS (Legacy API)
# =====================================================================================


def sanitize_text(text: str, allow_html: bool = False) -> str:
    """Sanitize text input."""
    return TextSanitizer.sanitize_text(text, allow_html)


def truncate_text(
    text: str,
    max_length: int,
    suffix: str = "...",
    whole_words: bool = True,
) -> str:
    """Truncate text to specified length."""
    if not text or len(text) <= max_length:
        return text

    truncate_at = max_length - len(suffix)

    if not whole_words:
        return text[:truncate_at] + suffix

    # Find last space before truncate point
    last_space = text.rfind(" ", 0, truncate_at)

    if last_space == -1:
        # No space found, truncate at exact position
        return text[:truncate_at] + suffix

    return text[:last_space] + suffix


def generate_slug(
    text: str,
    max_length: int | None = None,
    separator: str = "-",
) -> str:
    """Generate URL-friendly slug from text."""
    if not text:
        return ""

    try:
        generator = SlugGenerator(text, max_length, separator)
        return generator.value
    except ValidationError:
        return ""


def extract_keywords(
    text: str,
    min_length: int = 3,
    max_keywords: int = 10,
) -> list[str]:
    """Extract keywords from text."""
    if not text:
        return []

    try:
        extractor = KeywordExtractor(text, min_length, max_keywords)
        return extractor.keywords
    except ValidationError:
        return []


def normalize_whitespace(text: str) -> str:
    """Normalize whitespace in text."""
    if not text:
        return ""

    try:
        normalizer = TextNormalizer(text)
        return normalizer.value
    except ValidationError:
        return text


def remove_emojis(text: str) -> str:
    """Remove emoji characters from text."""
    if not text:
        return ""

    try:
        normalizer = TextNormalizer(text)
        return normalizer.remove_emojis()
    except ValidationError:
        return text


def is_valid_url(url: str) -> bool:
    """Check if string is a valid URL."""
    warnings.warn(
        "is_valid_url in text.py is deprecated. Use app.utils.validation.URLValidator instead.",
        DeprecationWarning,
        stacklevel=2
    )
    
    from app.utils.validation import URLValidator as ValidationURLValidator
    try:
        ValidationURLValidator(url)
        return True
    except Exception:
        return False
