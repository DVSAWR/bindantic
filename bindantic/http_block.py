from __future__ import annotations

from typing import ClassVar

from pydantic import Field, field_validator

from ._base_model import BindBaseModel
from ._base_types import (
    integer_BIND,
    quoted_string_BIND,
    string_BIND,
)


class HttpBlock(BindBaseModel):
    """
    HTTP configuration block for DNS-over-HTTPS (DoH) in BIND.

    Grammar:
    ```
    http <string> {
        endpoints { <quoted_string>; ... };
        listener-clients <integer>;
        streams-per-connection <integer>;
    }; // may occur multiple times
    ```
    """

    name: string_BIND = Field(..., description="Name of the HTTP configuration")
    endpoints: list[quoted_string_BIND] | None = Field(
        default=None, description="HTTP query paths to listen on"
    )
    listener_clients: integer_BIND | None = Field(
        default=None, ge=0, description="Per-listener quota for active connections"
    )
    streams_per_connection: integer_BIND | None = Field(
        default=None, ge=0, description="Maximum concurrent HTTP/2 streams per connection"
    )

    _exclude_from_syntax: ClassVar[set[str]] = {"name"}

    @property
    def comparison_attr(self) -> str:
        return self.name

    @field_validator("endpoints")
    @classmethod
    def validate_endpoints(cls, endpoints: list[str] | None) -> list[str] | None:
        """Validate HTTP endpoints format."""
        if not endpoints:
            return endpoints

        validated = []
        for endpoint in endpoints:
            endpoint_clean = endpoint.strip().strip("'\"")

            checks = [
                (endpoint_clean.startswith("/"), f"must start with '/': {endpoint}"),
                (
                    not endpoint_clean.startswith(("http://", "https://")),
                    f"must be a path, not URL: {endpoint}",
                ),
                ("//" not in endpoint_clean, f"contains double slashes: {endpoint}"),
                (
                    endpoint_clean == "/" or not endpoint_clean.endswith("/"),
                    f"should not end with '/': {endpoint}",
                ),
            ]
            for condition, error_msg in checks:
                if not condition:
                    raise ValueError(f"HTTP endpoint {error_msg}")

            validated.append(endpoint)

        return validated

    def model_bind_syntax(self, indent_level: int = 0) -> str:
        lines: list[str] = []
        self._add_comment(lines, indent_level)

        indent = self._indent(indent_level)
        lines.append(f"{indent}http {self.name} {{")
        lines.extend(self.auto_format_fields(indent_level + 1))
        lines.append(f"{indent}}};")
        return "\n".join(lines)
