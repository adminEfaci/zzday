"""
Comprehensive unit tests for UserId value object.

Tests cover:
- UUID generation and validation
- String conversion
- Equality and hashing
- Immutability
"""

from uuid import UUID, uuid4

import pytest

from app.modules.identity.domain.errors import DomainError
from app.modules.identity.domain.value_objects.user_id import UserId


class TestUserId:
    """Test suite for UserId value object."""

    def test_generate_creates_valid_uuid(self):
        """Test generating a new UserId."""
        user_id = UserId.generate()
        
        assert user_id is not None
        assert isinstance(user_id.value, UUID)
        assert user_id.value.version == 4  # Should be UUID v4

    def test_generate_creates_unique_ids(self):
        """Test that generated IDs are unique."""
        ids = [UserId.generate() for _ in range(100)]
        
        # All IDs should be unique
        unique_ids = set(id.value for id in ids)
        assert len(unique_ids) == 100

    def test_create_from_string_uuid(self):
        """Test creating UserId from string UUID."""
        uuid_string = "550e8400-e29b-41d4-a716-446655440000"
        
        user_id = UserId(uuid_string)
        
        assert user_id.value == UUID(uuid_string)
        assert str(user_id.value) == uuid_string

    def test_create_from_uuid_object(self):
        """Test creating UserId from UUID object."""
        uuid_obj = uuid4()
        
        user_id = UserId(uuid_obj)
        
        assert user_id.value == uuid_obj

    def test_invalid_uuid_string_raises_error(self):
        """Test that invalid UUID string raises error."""
        invalid_uuids = [
            "not-a-uuid",
            "12345",
            "550e8400-e29b-41d4-a716",  # Too short
            "550e8400-e29b-41d4-a716-446655440000-extra",  # Too long
            "",
            "g50e8400-e29b-41d4-a716-446655440000",  # Invalid character
        ]
        
        for invalid in invalid_uuids:
            with pytest.raises(DomainError) as exc_info:
                UserId(invalid)
            
            assert "Invalid UUID format" in str(exc_info.value)

    def test_none_value_raises_error(self):
        """Test that None value raises error."""
        with pytest.raises(DomainError) as exc_info:
            UserId(None)
        
        assert "UserId cannot be None" in str(exc_info.value)

    def test_user_id_is_immutable(self):
        """Test that UserId is immutable."""
        user_id = UserId.generate()
        
        with pytest.raises(AttributeError):
            user_id.value = uuid4()

    def test_equality_comparison(self):
        """Test equality comparison of UserId objects."""
        uuid_string = "550e8400-e29b-41d4-a716-446655440000"
        
        id1 = UserId(uuid_string)
        id2 = UserId(uuid_string)
        id3 = UserId.generate()
        
        assert id1 == id2
        assert id1 != id3
        assert id2 != id3

    def test_hash_consistency(self):
        """Test that equal UserIds have same hash."""
        uuid_string = "550e8400-e29b-41d4-a716-446655440000"
        
        id1 = UserId(uuid_string)
        id2 = UserId(uuid_string)
        
        assert hash(id1) == hash(id2)
        
        # Can be used in sets and dicts
        id_set = {id1, id2}
        assert len(id_set) == 1

    def test_string_representation(self):
        """Test string representation of UserId."""
        uuid_string = "550e8400-e29b-41d4-a716-446655440000"
        user_id = UserId(uuid_string)
        
        assert str(user_id) == uuid_string
        assert repr(user_id) == f"UserId('{uuid_string}')"

    def test_case_insensitive_uuid_parsing(self):
        """Test that UUID parsing is case-insensitive."""
        upper_uuid = "550E8400-E29B-41D4-A716-446655440000"
        lower_uuid = "550e8400-e29b-41d4-a716-446655440000"
        
        id1 = UserId(upper_uuid)
        id2 = UserId(lower_uuid)
        
        assert id1 == id2

    def test_uuid_with_hyphens_and_without(self):
        """Test UUID parsing with and without hyphens."""
        with_hyphens = "550e8400-e29b-41d4-a716-446655440000"
        without_hyphens = "550e8400e29b41d4a716446655440000"
        
        id1 = UserId(with_hyphens)
        id2 = UserId(without_hyphens)
        
        assert id1 == id2

    def test_comparison_with_non_userid(self):
        """Test comparison with non-UserId objects."""
        user_id = UserId.generate()
        
        assert user_id != "not-a-userid"
        assert user_id != 123
        assert user_id != None
        assert user_id != uuid4()  # Even UUID objects

    def test_to_dict_serialization(self):
        """Test serialization to dictionary."""
        uuid_string = "550e8400-e29b-41d4-a716-446655440000"
        user_id = UserId(uuid_string)
        
        # Should be serializable
        assert user_id.to_dict() == uuid_string
        assert user_id.to_string() == uuid_string

    def test_from_dict_deserialization(self):
        """Test deserialization from dictionary."""
        uuid_string = "550e8400-e29b-41d4-a716-446655440000"
        
        user_id = UserId.from_string(uuid_string)
        
        assert user_id.value == UUID(uuid_string)

    def test_json_serialization(self):
        """Test JSON serialization compatibility."""
        import json
        
        user_id = UserId.generate()
        
        # Should be JSON serializable
        json_str = json.dumps({"user_id": str(user_id)})
        data = json.loads(json_str)
        
        # Can recreate from JSON
        recreated = UserId(data["user_id"])
        assert recreated == user_id

    def test_database_storage_format(self):
        """Test format suitable for database storage."""
        user_id = UserId.generate()
        
        # For database storage
        db_value = user_id.value  # UUID object
        db_string = str(user_id)  # String representation
        
        # Can recreate from either
        from_uuid = UserId(db_value)
        from_string = UserId(db_string)
        
        assert from_uuid == user_id
        assert from_string == user_id

    def test_nil_uuid_handling(self):
        """Test handling of nil UUID."""
        nil_uuid = "00000000-0000-0000-0000-000000000000"
        
        # Should allow nil UUID but might want to validate in domain
        user_id = UserId(nil_uuid)
        
        assert str(user_id) == nil_uuid
        assert user_id.is_nil()

    def test_special_uuid_versions(self):
        """Test handling different UUID versions."""
        # UUID v1 (time-based)
        uuid_v1 = "550e8400-e29b-11ea-87d0-0242ac130003"
        
        # UUID v4 (random) - most common
        uuid_v4 = "550e8400-e29b-41d4-a716-446655440000"
        
        # UUID v5 (namespace)
        uuid_v5 = "550e8400-e29b-51d4-a716-446655440000"
        
        # All should be accepted
        for uuid_str in [uuid_v1, uuid_v4, uuid_v5]:
            user_id = UserId(uuid_str)
            assert str(user_id) == uuid_str

    def test_performance_of_generation(self):
        """Test performance of ID generation."""
        import time
        
        start = time.time()
        ids = [UserId.generate() for _ in range(1000)]
        duration = time.time() - start
        
        # Should be fast
        assert duration < 0.1  # Less than 100ms for 1000 IDs
        assert len(set(ids)) == 1000  # All unique

    def test_sorting_capability(self):
        """Test that UserIds can be sorted."""
        ids = [UserId.generate() for _ in range(10)]
        
        # Should be sortable by UUID value
        sorted_ids = sorted(ids, key=lambda x: x.value)
        
        # Verify sorted
        for i in range(len(sorted_ids) - 1):
            assert sorted_ids[i].value < sorted_ids[i + 1].value

    def test_copy_and_deepcopy(self):
        """Test copying UserId objects."""
        import copy
        
        original = UserId.generate()
        
        # Both should work and produce equal objects
        shallow_copy = copy.copy(original)
        deep_copy = copy.deepcopy(original)
        
        assert shallow_copy == original
        assert deep_copy == original
        assert shallow_copy is not original
        assert deep_copy is not original