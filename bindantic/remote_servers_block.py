from __future__ import annotations

from ipaddress import IPv4Address, IPv6Address
from typing import ClassVar, Literal

from pydantic import Field, model_validator

from ._base_model import BindBaseModel
from ._base_types import (
    ip_v4_address_BIND,
    ip_v6_address_BIND,
    port_BIND,
    server_key_BIND,
    string_BIND,
    tls_id_BIND,
)


class RemoteServerEntry(BindBaseModel):
    """
    Single server entry in a remote-servers block.

    Can be one of:
    1. Server list reference (string)
    2. IPv4 address with optional port
    3. IPv6 address with optional port

    Grammar:
    ```
    ( <server-list> | <ipv4_address> [ port <integer> ] | <ipv6_address> [ port <integer> ] )
    [ key <string> ] [ tls <string> ];
    ```
    """

    server: string_BIND | ip_v4_address_BIND | ip_v6_address_BIND = Field(
        ...,
        description=(
            "Server specification. Can be:\n"
            "- Server list name (string)\n"
            "- IPv4 address (e.g., 192.0.2.1)\n"
            "- IPv6 address (e.g., 2001:db8::1)"
        ),
    )
    port: port_BIND | None = Field(
        default=None,
        description=(
            "Port number for this specific server.\nOverrides the block-level port if specified."
        ),
    )
    key: server_key_BIND | None = Field(
        default=None, description="TSIG key for authentication with this server"
    )
    tls: tls_id_BIND | None = Field(
        default=None,
        description=(
            "TLS configuration name for encrypted zone transfers.\n"
            "Warning: Without remote-hostname or ca-file in tls configuration,\n"
            "TLS is not authenticated (Opportunistic TLS)."
        ),
    )

    @property
    def comparison_attr(self) -> str:
        return str(self.server)

    @model_validator(mode="after")
    def validate_server_type(self) -> RemoteServerEntry:
        """Validate server type and port compatibility."""
        server_str = str(self.server)

        is_ip_address = False
        try:
            IPv4Address(server_str)
            is_ip_address = True
        except ValueError:
            try:
                IPv6Address(server_str)
                is_ip_address = True
            except ValueError:
                pass

        if not is_ip_address and self.port is not None:
            raise ValueError(
                f"Server list reference '{server_str}' cannot have a port specification. "
                "Port can only be specified for IP addresses."
            )

        return self

    def model_bind_syntax(self, indent_level: int = 0) -> str:
        lines: list[str] = []
        self._add_comment(lines, indent_level)
        indent = self._indent(indent_level)

        parts = [str(self.server)]
        if self.port is not None:
            parts.append(f"port {self.port}")
        if self.key is not None:
            parts.append(f"key {self.key}")
        if self.tls is not None:
            parts.append(f"tls {self.tls}")

        lines.append(f"{indent}{' '.join(parts)};")
        return "\n".join(lines)


class RemoteServersBlock(BindBaseModel):
    """
    Remote servers block for BIND9 configuration.

    Defines a list of servers to be used by primary and secondary zones.
    This list can be referenced by parental-agents, primaries, and also-notify.

    Grammar:
    ```
    remote-servers <string> [ port <integer> ]
                   [ source ( <ipv4_address> | * ) ]
                   [ source-v6 ( <ipv6_address> | * ) ]
                   {
                       ( <server-list> | <ipv4_address> [ port <integer> ] | <ipv6_address> [ port <integer> ] )
                       [ key <string> ] [ tls <string> ];
                       ...
                   };
    ```
    """

    name: string_BIND = Field(..., description="Name of this remote servers list for reference")
    port: port_BIND | None = Field(
        default=None,
        description=(
            "Default port for all servers in this list.\n"
            "Can be overridden by individual server port."
        ),
    )
    source: ip_v4_address_BIND | Literal["*"] | None = Field(
        default=None,
        description=(
            "Source IPv4 address for outgoing connections.\n"
            "* means use any IPv4 interface address."
        ),
    )
    source_v6: ip_v6_address_BIND | Literal["*"] | None = Field(
        default=None,
        description=(
            "Source IPv6 address for outgoing connections.\n"
            "* means use any IPv6 interface address."
        ),
    )
    servers: list[RemoteServerEntry] = Field(
        default_factory=list, description="List of servers in this remote servers list"
    )

    _exclude_from_syntax: ClassVar[set[str]] = {"name"}

    @property
    def comparison_attr(self) -> str:
        return str(self.name)

    @model_validator(mode="after")
    def validate_block(self) -> RemoteServersBlock:
        if not self.servers:
            raise ValueError("Remote servers list must contain at least one server")

        server_strings = []
        for server in self.servers:
            server_str = str(server.server)
            if server.port:
                server_str = f"{server_str}:{server.port}"
            if server_str in server_strings:
                raise ValueError(f"Duplicate server entry: {server_str}")
            server_strings.append(server_str)

        return self

    def model_bind_syntax(self, indent_level: int = 0) -> str:
        lines: list[str] = []
        self._add_comment(lines, indent_level)

        indent = self._indent(indent_level)

        header = f"remote-servers {self.name}"
        options = []
        if self.port is not None:
            options.append(f"port {self.port}")
        if self.source is not None:
            options.append(f"source {self.source}")
        if self.source_v6 is not None:
            options.append(f"source-v6 {self.source_v6}")
        if options:
            header += " " + " ".join(options)

        lines.append(f"{indent}{header} {{")

        for server in sorted(self.servers):
            server_line = server.model_bind_syntax(indent_level + 1)
            lines.append(server_line)

        lines.append(f"{indent}}};")
        return "\n".join(lines)
