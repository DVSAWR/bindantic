from __future__ import annotations

from typing import ClassVar, Literal

from pydantic import Field, field_validator

from ._base_model import BindBaseModel
from ._base_types import (
    address_match_list_BIND,
    boolean_BIND,
    ip_v4_address_BIND,
    ip_v6_address_BIND,
    port_BIND,
    server_key_BIND,
)


class InetControl(BindBaseModel):
    """
    Inet control channel specification for BIND9.

    Specifies a TCP socket as a control channel for rndc.

    NOTE: Unix control channel has been removed in BIND9.

    Grammar:
    ```
    inet ( <ipv4_address> | <ipv6_address> | * )
         [ port ( <integer> | * ) ]
         allow { <address_match_element>; ... }
         [ keys { <string>; ... } ]
         [ read-only <boolean> ];
    ```
    """

    ip_address: ip_v4_address_BIND | ip_v6_address_BIND | Literal["*", "::"] = Field(
        ...,
        description=(
            "IP address to listen on. Can be:\n"
            "- IPv4 address (e.g., 127.0.0.1)\n"
            "- IPv6 address (e.g., ::1)\n"
            "- '*' for all IPv4 interfaces\n"
            "- '::' for all IPv6 interfaces"
        ),
    )
    port: port_BIND = Field(
        default=953,
        description=(
            "Port number or '*'. Default is 953.\n"
            "NOTE: '*' cannot be used for port in BIND9 controls."
        ),
    )
    allow: address_match_list_BIND = Field(
        ...,
        description=(
            "Address match list for IP-based access control.\n"
            "Any server_key elements in this list are ignored."
        ),
    )
    keys: list[server_key_BIND] | None = Field(
        default=None,
        description=(
            "List of authorized server keys.\n"
            "Each listed key is authorized to execute commands over the control channel."
        ),
    )
    read_only: boolean_BIND | None = Field(
        default=None,
        description=(
            "If enabled (yes), limits to read-only commands:\n"
            "nta -dump, null, status, showzone, testgen, zonestatus.\n"
            "Default is read-write access."
        ),
    )

    _exclude_from_syntax: ClassVar[set[str]] = {"ip_address", "port"}

    @property
    def comparison_attr(self) -> tuple:
        return (self.ip_address, self.port)

    def model_bind_syntax(self, indent_level: int = 0) -> str:
        lines: list[str] = []
        self._add_comment(lines, indent_level)

        indent = self._indent(indent_level)
        inner_indent = self._indent(indent_level + 1)

        inet_line = f"inet {self.ip_address}"
        if self.port != 953:
            inet_line += f" port {self.port}"

        lines.append(f"{indent}{inet_line}")

        lines.append(f"{inner_indent}allow {{")
        if self.allow:
            for item in sorted(self.allow):
                lines.append(f"{inner_indent}    {item};")
        lines.append(f"{inner_indent}}}")

        if self.keys:
            lines.append(f"{inner_indent}keys {{")
            for key in sorted(self.keys):
                lines.append(f"{inner_indent}    {key};")
            lines.append(f"{inner_indent}}}")

        if self.read_only is not None:
            lines.append(f"{inner_indent}read-only {self.read_only}")

        lines.append(f"{indent};")

        return "\n".join(lines)


class ControlsBlock(BindBaseModel):
    """
    Controls block for BIND9 configuration.

    Specifies control channels to be used to manage the name server via rndc.

    NOTE: If no controls statement is present, BIND9 sets up default control channels
    on loopback addresses (127.0.0.1 and ::1) with port 953.

    Grammar:
    ```
    controls {
        inet ( <ipv4_address> | <ipv6_address> | * )
                [ port ( <integer> | * ) ]
                allow { <address_match_element>; ... }
                [ keys { <string>; ... } ]
                [ read-only <boolean> ];
    };
    ```
    """

    controls: list[InetControl] = Field(
        default_factory=list,
        description=(
            "List of control channel specifications.\n"
            "Empty list disables control channels.\n"
            "Multiple inet statements can be used."
        ),
    )

    @field_validator("controls")
    def validate_controls_configuration(cls, v: list[InetControl]) -> list[InetControl]:
        seen = set()
        for control in v:
            key = (control.ip_address, control.port)
            if key in seen:
                raise ValueError(
                    f"Duplicate control channel configuration for "
                    f"ip_address={control.ip_address}, port={control.port}"
                )
            seen.add(key)

        return v

    def model_bind_syntax(self, indent_level: int = 0) -> str:
        lines: list[str] = []
        self._add_comment(lines, indent_level)

        indent = self._indent(indent_level)

        if not self.controls:
            lines.append(f"{indent}controls {{ }};")
            return "\n".join(lines)

        lines.append(f"{indent}controls {{")

        for control in self.controls:
            control_str = control.model_bind_syntax(1)
            control_lines = control_str.split("\n")
            for line in control_lines:
                lines.append(f"{indent}{line}")

        lines.append(f"{indent}}};")

        return "\n".join(lines)
