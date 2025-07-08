"""
User Search Specifications

Specifications for user search and filtering operations.
"""

from ..aggregates.user import User
from .base import ParameterizedSpecification


class UserSearchSpecification(ParameterizedSpecification[User]):
    """Specification for user search operations."""
    
    def __init__(self, search_term: str, search_fields: set[str] | None = None):
        search_fields = search_fields or {'username', 'email', 'display_name'}
        super().__init__(search_term=search_term, search_fields=search_fields)
    
    def _validate_parameters(self) -> None:
        """Validate search parameters."""
        search_term = self.parameters.get('search_term', '')
        search_fields = self.parameters.get('search_fields', set())
        
        if not isinstance(search_term, str):
            raise ValueError("Search term must be a string")
        if len(search_term.strip()) < 2:
            raise ValueError("Search term must be at least 2 characters")
        if not isinstance(search_fields, set):
            raise ValueError("Search fields must be a set")
        if not search_fields:
            raise ValueError("At least one search field must be specified")
    
    def is_satisfied_by(self, user: User) -> bool:
        """Check if user matches search criteria."""
        self.validate_candidate(user)
        
        search_term = self.parameters['search_term'].lower().strip()
        search_fields = self.parameters['search_fields']
        
        for field in search_fields:
            field_value = self._get_field_value(user, field)
            if field_value and search_term in field_value.lower():
                return True
        
        return False
    
    def _get_field_value(self, user: User, field: str) -> str:
        """Get field value from user for searching."""
        if field == 'username':
            return user.username.value if user.username else ''
        if field == 'email':
            return user.email.value if user.email else ''
        if field == 'display_name':
            return user._profile.display_name if user._profile and user._profile.display_name else ''
        if field == 'first_name':
            return user._profile.first_name if user._profile and user._profile.first_name else ''
        if field == 'last_name':
            return user._profile.last_name if user._profile and user._profile.last_name else ''
        return ''


__all__ = ["UserSearchSpecification"]
