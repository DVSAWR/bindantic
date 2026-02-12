from __future__ import annotations

from typing import ClassVar, Literal

from pydantic import Field, model_validator

from ._base_model import BindBaseModel
from ._base_types import (
    address_match_list_BIND,
    ip_v4_address_BIND,
    ip_v6_address_BIND,
    port_BIND,
)


class InetChannel(BindBaseModel):
    """
    Single inet channel configuration for statistics-channels.

    Grammar:
    ```
    inet ( <ipv4_address> | <ipv6_address> | * )
          [ port ( <integer> | * ) ]
          [ allow { <address_match_element>; ... } ];
    ```
    """

    address: ip_v4_address_BIND | ip_v6_address_BIND | Literal["*", "::"] = Field(
        ..., description="IP address to listen on (* for IPv4 wildcard, :: for IPv6 wildcard)"
    )

    port: port_BIND | None = Field(default=None, description="Port to listen on (default: 80)")

    allow: address_match_list_BIND | None = Field(
        default=None, description="Access control list for this channel"
    )

    _exclude_from_syntax: ClassVar[set[str]] = {"address", "port", "allow"}

    @property
    def comparison_attr(self) -> str:
        return str(self.address)

    def model_bind_syntax(self, indent_level: int = 0) -> str:
        lines: list[str] = []
        self._add_comment(lines, indent_level)

        indent = self._indent(indent_level)
        inner_indent = self._indent(indent_level)

        parts = [f"inet {self.address}"]
        if self.port is not None:
            parts.append(f"port {self.port}")

        if self.allow:
            allow_lines = []
            allow_lines.append("allow {")
            for item in sorted(self.allow) if isinstance(self.allow, list) else [self.allow]:
                allow_lines.append(f"    {item};")
            allow_lines.append("}")

            lines.append(f"{indent}{' '.join(parts)} {allow_lines[0]}")
            for line in allow_lines[1:]:
                lines.append(f"{inner_indent}{line}")
            lines[-1] = f"{inner_indent}{allow_lines[-1]};"
        else:
            lines.append(f"{indent}{' '.join(parts)};")

        return "\n".join(lines)


class StatisticsChannelsBlock(BindBaseModel):
    """
    Statistics channels configuration block for BIND.

    Grammar:
    ```
    statistics-channels {
        inet ( <ipv4_address> | <ipv6_address> | * )
              [ port ( <integer> | * ) ]
              [ allow { <address_match_element>; ... } ]; // may occur multiple times
    }; // may occur multiple times
    ```
    """

    channels: list[InetChannel] = Field(default_factory=list, description="List of inet channels")

    @model_validator(mode="after")
    def validate_channels(self) -> StatisticsChannelsBlock:
        """Validate that at least one channel is specified."""
        if not self.channels:
            raise ValueError("At least one inet channel must be specified")
        return self

    def model_bind_syntax(self, indent_level: int = 0) -> str:
        lines: list[str] = []
        self._add_comment(lines, indent_level)

        indent = self._indent(indent_level)
        inner_indent = self._indent(indent_level + 1)

        lines.append(f"{indent}statistics-channels {{")

        for channel in sorted(self.channels):
            channel_str = channel.model_bind_syntax(0)
            channel_lines = channel_str.split("\n")
            for line in channel_lines:
                lines.append(f"{inner_indent}{line}")

        lines.append(f"{indent}}};")
        return "\n".join(lines)
