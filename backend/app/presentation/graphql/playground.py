"""
GraphQL Playground and Documentation Configuration

Provides GraphQL Playground setup, documentation generation, and developer tools.
"""

import json
from pathlib import Path
from typing import Any

from graphql import get_introspection_query
from graphql.utilities import print_schema
from strawberry import Schema


class PlaygroundConfig:
    """Configuration for GraphQL Playground."""
    
    def __init__(self, 
                 endpoint: str = "/graphql",
                 subscription_endpoint: str = "/graphql/ws",
                 title: str = "EzzDay GraphQL API",
                 enable_tabs: bool = True,
                 enable_request_credentials: bool = True,
                 theme: str = "dark"):
        self.endpoint = endpoint
        self.subscription_endpoint = subscription_endpoint
        self.title = title
        self.enable_tabs = enable_tabs
        self.enable_request_credentials = enable_request_credentials
        self.theme = theme
    
    def to_dict(self) -> dict[str, Any]:
        """Convert config to dictionary."""
        return {
            "endpoint": self.endpoint,
            "subscriptionEndpoint": self.subscription_endpoint,
            "title": self.title,
            "settings": {
                "general.betaUpdates": False,
                "editor.theme": self.theme,
                "editor.cursorShape": "line",
                "editor.fontFamily": "Consolas, Monaco, 'Courier New', monospace",
                "editor.fontSize": 14,
                "editor.reuseHeaders": True,
                "tracing.hideTracingResponse": True,
                "queryPlan.hideQueryPlanResponse": True,
                "request.credentials": "include" if self.enable_request_credentials else "omit",
            },
            "tabs": self.get_default_tabs() if self.enable_tabs else []
        }
    
    def get_default_tabs(self) -> list[dict[str, Any]]:
        """Get default playground tabs with example queries."""
        return [
            {
                "name": "Welcome",
                "query": self._get_welcome_query(),
                "variables": {},
                "headers": {},
                "responses": []
            },
            {
                "name": "Authentication",
                "query": self._get_auth_query(),
                "variables": {"email": "user@example.com", "password": "password"},
                "headers": {},
                "responses": []
            },
            {
                "name": "User Profile",
                "query": self._get_user_query(),
                "variables": {},
                "headers": {"Authorization": "Bearer YOUR_TOKEN_HERE"},
                "responses": []
            },
            {
                "name": "Subscriptions",
                "query": self._get_subscription_query(),
                "variables": {},
                "headers": {"Authorization": "Bearer YOUR_TOKEN_HERE"},
                "responses": []
            }
        ]
    
    def _get_welcome_query(self) -> str:
        """Get welcome query with schema info."""
        return """
# Welcome to EzzDay GraphQL API!
# 
# This is a production-ready identity and access management system
# with comprehensive GraphQL API for all operations.
#
# Features:
# - Authentication & Authorization
# - User Management
# - Audit Logging
# - Real-time Notifications
# - Third-party Integrations
#
# Use the tabs above to explore different API features.
# Don't forget to set your authorization header!

query WelcomeQuery {
  __schema {
    queryType {
      name
      description
    }
    mutationType {
      name
      description
    }
    subscriptionType {
      name
      description
    }
  }
}
"""
    
    def _get_auth_query(self) -> str:
        """Get authentication example query."""
        return """
# Authentication Examples
# 
# Use these mutations to authenticate and manage user sessions

mutation LoginUser($email: String!, $password: String!) {
  identity {
    login(input: {
      email: $email
      password: $password
    }) {
      success
      data {
        token
        user {
          id
          email
          profile {
            firstName
            lastName
          }
        }
      }
      errors {
        field
        message
        code
      }
    }
  }
}

mutation RegisterUser($input: UserRegistrationInput!) {
  identity {
    register(input: $input) {
      success
      data {
        user {
          id
          email
          profile {
            firstName
            lastName
          }
        }
      }
      errors {
        field
        message
        code
      }
    }
  }
}

mutation LogoutUser {
  identity {
    logout {
      success
      message
    }
  }
}
"""
    
    def _get_user_query(self) -> str:
        """Get user profile example query."""
        return """
# User Profile Queries
# 
# Examples of querying user data with proper authorization

query GetCurrentUser {
  identity {
    me {
      id
      email
      profile {
        firstName
        lastName
        avatar
        dateOfBirth
        phoneNumber
      }
      roles {
        name
        permissions {
          name
          resource
        }
      }
      sessions(first: 5) {
        edges {
          node {
            id
            deviceName
            lastActivity
            isActive
          }
        }
      }
    }
  }
}

query GetUsers($first: Int, $after: String, $filter: UserFilterInput) {
  identity {
    users(first: $first, after: $after, filter: $filter) {
      edges {
        node {
          id
          email
          profile {
            firstName
            lastName
          }
          createdAt
        }
        cursor
      }
      pageInfo {
        hasNextPage
        hasPreviousPage
        startCursor
        endCursor
      }
      totalCount
    }
  }
}

mutation UpdateUserProfile($input: UpdateProfileInput!) {
  identity {
    updateProfile(input: $input) {
      success
      data {
        profile {
          firstName
          lastName
          avatar
        }
      }
      errors {
        field
        message
        code
      }
    }
  }
}
"""
    
    def _get_subscription_query(self) -> str:
        """Get subscription example query."""
        return """
# Real-time Subscriptions
# 
# Examples of subscribing to real-time events

subscription UserStatusChanges {
  identity {
    userStatusChanged {
      userId
      status
      metadata
      timestamp
    }
  }
}

subscription NotificationReceived {
  notifications {
    notificationReceived {
      id
      title
      message
      type
      createdAt
      readAt
    }
  }
}

subscription SecurityEvents {
  audit {
    securityEvents {
      eventType
      userId
      timestamp
      severity
      details
    }
  }
}
"""


class DocumentationGenerator:
    """Generates GraphQL API documentation."""
    
    def __init__(self, schema: Schema):
        self.schema = schema
    
    def generate_schema_documentation(self) -> dict[str, Any]:
        """Generate comprehensive schema documentation."""
        introspection_result = self.schema.execute_sync(get_introspection_query())
        
        if introspection_result.errors:
            raise RuntimeError(f"Schema introspection failed: {introspection_result.errors}")
        
        schema_data = introspection_result.data["__schema"]
        
        return {
            "schema_info": {
                "query_type": schema_data["queryType"]["name"],
                "mutation_type": schema_data["mutationType"]["name"] if schema_data["mutationType"] else None,
                "subscription_type": schema_data["subscriptionType"]["name"] if schema_data["subscriptionType"] else None,
                "types_count": len(schema_data["types"]),
                "directives_count": len(schema_data["directives"]),
            },
            "types": self._document_types(schema_data["types"]),
            "queries": self._document_operations(schema_data["queryType"]),
            "mutations": self._document_operations(schema_data["mutationType"]) if schema_data["mutationType"] else {},
            "subscriptions": self._document_operations(schema_data["subscriptionType"]) if schema_data["subscriptionType"] else {},
            "directives": self._document_directives(schema_data["directives"]),
        }
    
    def _document_types(self, types: list[dict[str, Any]]) -> dict[str, Any]:
        """Document GraphQL types."""
        documented_types = {}
        
        for type_def in types:
            if type_def["name"].startswith("__"):
                continue  # Skip introspection types
            
            documented_types[type_def["name"]] = {
                "kind": type_def["kind"],
                "description": type_def.get("description"),
                "fields": self._document_fields(type_def.get("fields", [])),
                "input_fields": self._document_fields(type_def.get("inputFields", [])),
                "enum_values": self._document_enum_values(type_def.get("enumValues", [])),
                "interfaces": [iface["name"] for iface in type_def.get("interfaces", [])],
                "possible_types": [ptype["name"] for ptype in type_def.get("possibleTypes", [])],
            }
        
        return documented_types
    
    def _document_fields(self, fields: list[dict[str, Any]]) -> dict[str, Any]:
        """Document type fields."""
        documented_fields = {}
        
        for field in fields:
            documented_fields[field["name"]] = {
                "type": self._format_type(field["type"]),
                "description": field.get("description"),
                "args": {
                    arg["name"]: {
                        "type": self._format_type(arg["type"]),
                        "description": arg.get("description"),
                        "default_value": arg.get("defaultValue"),
                    }
                    for arg in field.get("args", [])
                },
                "deprecated": field.get("isDeprecated", False),
                "deprecation_reason": field.get("deprecationReason"),
            }
        
        return documented_fields
    
    def _document_enum_values(self, enum_values: list[dict[str, Any]]) -> dict[str, Any]:
        """Document enum values."""
        documented_values = {}
        
        for value in enum_values:
            documented_values[value["name"]] = {
                "description": value.get("description"),
                "deprecated": value.get("isDeprecated", False),
                "deprecation_reason": value.get("deprecationReason"),
            }
        
        return documented_values
    
    def _document_operations(self, operation_type: dict[str, Any] | None) -> dict[str, Any]:
        """Document GraphQL operations."""
        if not operation_type:
            return {}
        
        return self._document_fields(operation_type.get("fields", []))
    
    def _document_directives(self, directives: list[dict[str, Any]]) -> dict[str, Any]:
        """Document GraphQL directives."""
        documented_directives = {}
        
        for directive in directives:
            documented_directives[directive["name"]] = {
                "description": directive.get("description"),
                "locations": directive.get("locations", []),
                "args": {
                    arg["name"]: {
                        "type": self._format_type(arg["type"]),
                        "description": arg.get("description"),
                        "default_value": arg.get("defaultValue"),
                    }
                    for arg in directive.get("args", [])
                },
            }
        
        return documented_directives
    
    def _format_type(self, type_def: dict[str, Any]) -> str:
        """Format GraphQL type for documentation."""
        if type_def["kind"] == "NON_NULL":
            return f"{self._format_type(type_def['ofType'])}!"
        if type_def["kind"] == "LIST":
            return f"[{self._format_type(type_def['ofType'])}]"
        return type_def["name"]
    
    def export_schema_sdl(self) -> str:
        """Export schema as SDL string."""
        return print_schema(self.schema.schema)
    
    def save_documentation(self, output_dir: str = "docs/graphql"):
        """Save documentation to files."""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Save schema documentation
        docs = self.generate_schema_documentation()
        with open(output_path / "schema_documentation.json", "w") as f:
            json.dump(docs, f, indent=2)
        
        # Save SDL
        sdl = self.export_schema_sdl()
        with open(output_path / "schema.graphql", "w") as f:
            f.write(sdl)
        
        # Save playground config
        playground_config = PlaygroundConfig()
        with open(output_path / "playground_config.json", "w") as f:
            json.dump(playground_config.to_dict(), f, indent=2)
        
        print(f"Documentation saved to {output_path}")


def create_playground_html(config: PlaygroundConfig) -> str:
    """Create HTML page for GraphQL Playground."""
    config_json = json.dumps(config.to_dict(), indent=2)
    
    return f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{config.title}</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/graphql-playground-react@1.7.26/build/static/css/index.css">
</head>
<body>
    <div id="root">
        <style>
            body {{ margin: 0; }}
            #root {{ height: 100vh; }}
        </style>
    </div>
    <script src="https://cdn.jsdelivr.net/npm/graphql-playground-react@1.7.26/build/static/js/middleware.js"></script>
    <script>
        window.addEventListener('load', function (event) {{
            GraphQLPlayground.init(document.getElementById('root'), {config_json});
        }});
    </script>
</body>
</html>
"""


__all__ = [
    "DocumentationGenerator",
    "PlaygroundConfig",
    "create_playground_html",
]