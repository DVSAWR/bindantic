from __future__ import annotations

from typing import ClassVar, Literal

from pydantic import Field, model_validator

from ._base_model import BindBaseModel
from ._base_types import (
    boolean_BIND,
    integer_BIND,
    ip_v4_address_BIND,
    ip_v6_address_BIND,
    net_prefix_BIND,
    server_key_BIND,
)


class ServerBlock(BindBaseModel):
    """
    Server configuration block for BIND.

    Grammar:
    ```
    server <netprefix> {
        bogus <boolean>;
        edns <boolean>;
        edns-udp-size <integer>;
        edns-version <integer>;
        keys <server_key>;
        max-udp-size <integer>;
        notify-source ( <ipv4_address> | * );
        notify-source-v6 ( <ipv6_address> | * );
        padding <integer>;
        provide-ixfr <boolean>;
        query-source [ address ] ( <ipv4_address> | * );
        query-source-v6 [ address ] ( <ipv6_address> | * );
        request-expire <boolean>;
        request-ixfr <boolean>;
        request-nsid <boolean>;
        require-cookie <boolean>;
        send-cookie <boolean>;
        tcp-keepalive <boolean>;
        tcp-only <boolean>;
        transfer-format ( many-answers | one-answer );
        transfer-source ( <ipv4_address> | * );
        transfer-source-v6 ( <ipv6_address> | * );
        transfers <integer>;
    };
    ```
    """

    netprefix: net_prefix_BIND = Field(..., description="Network prefix for the remote server")
    bogus: boolean_BIND | None = Field(default=None, description="Mark remote server as bogus")
    edns: boolean_BIND | None = Field(
        default=None, description="Use EDNS0 when communicating with remote server"
    )
    provide_ixfr: boolean_BIND | None = Field(
        default=None, description="Provide IXFR to this server"
    )
    request_expire: boolean_BIND | None = Field(
        default=None, description="Request EDNS EXPIRE value"
    )
    request_ixfr: boolean_BIND | None = Field(
        default=None, description="Request IXFR from this server"
    )
    request_nsid: boolean_BIND | None = Field(
        default=None, description="Send NSID option in queries to this server"
    )
    require_cookie: boolean_BIND | None = Field(
        default=None, description="Require valid server cookie from this server"
    )
    send_cookie: boolean_BIND | None = Field(
        default=None, description="Send COOKIE EDNS option to this server"
    )
    tcp_keepalive: boolean_BIND | None = Field(
        default=None, description="Add EDNS TCP keepalive to messages over TCP"
    )
    tcp_only: boolean_BIND | None = Field(default=None, description="Use TCP transport only")
    edns_udp_size: integer_BIND | None = Field(
        default=None, ge=0, le=512, description="EDNS UDP buffer size for this server"
    )
    edns_version: integer_BIND | None = Field(
        default=None, ge=0, le=255, description="Maximum EDNS version to send to this server"
    )
    max_udp_size: integer_BIND | None = Field(
        default=None, ge=0, le=512, description="Maximum UDP message size for this server"
    )
    padding: integer_BIND | None = Field(
        default=None, ge=0, le=512, description="EDNS Padding block size"
    )
    transfers: integer_BIND | None = Field(
        default=None, description="Maximum concurrent inbound transfers from this server"
    )
    transfer_format: Literal["many-answers", "one-answer"] | None = Field(
        default=None, description="Zone transfer format for this server"
    )
    keys: server_key_BIND | None = Field(
        default=None, description="TSIG key for transaction security"
    )
    notify_source: ip_v4_address_BIND | Literal["*"] | None = Field(
        default=None, description="IPv4 source address for NOTIFY messages"
    )
    notify_source_v6: ip_v6_address_BIND | Literal["*"] | None = Field(
        default=None, description="IPv6 source address for NOTIFY messages"
    )
    query_source: ip_v4_address_BIND | Literal["*"] | None = Field(
        default=None, description="IPv4 source address for queries"
    )
    query_source_v6: ip_v6_address_BIND | Literal["*"] | None = Field(
        default=None, description="IPv6 source address for queries"
    )
    transfer_source: ip_v4_address_BIND | Literal["*"] | None = Field(
        default=None, description="IPv4 source address for zone transfers"
    )
    transfer_source_v6: ip_v6_address_BIND | Literal["*"] | None = Field(
        default=None, description="IPv6 source address for zone transfers"
    )
    comment: str | None = Field(default=None, description="Optional comment for the server block")

    _exclude_from_syntax: ClassVar[set[str]] = {"netprefix"}

    @property
    def comparison_attr(self) -> str:
        return str(self.netprefix)

    @model_validator(mode="after")
    def validate_tcp_only_usage(self) -> ServerBlock:
        """Validate TCP-only related options."""
        if self.tcp_only == "yes":
            if self.edns_udp_size is not None:
                raise ValueError("edns-udp-size cannot be set when tcp-only is yes")
            if self.max_udp_size is not None:
                raise ValueError("max-udp-size cannot be set when tcp-only is yes")
            if self.padding is not None:
                raise ValueError("padding cannot be set when tcp-only is yes")
        return self

    @model_validator(mode="after")
    def validate_tcp_keepalive_usage(self) -> ServerBlock:
        """Validate TCP keepalive usage."""
        if self.tcp_keepalive == "yes" and self.tcp_only != "yes":
            raise ValueError("tcp-keepalive requires tcp-only to be yes")
        return self

    def model_bind_syntax(self, indent_level: int = 0) -> str:
        lines: list[str] = []
        self._add_comment(lines, indent_level)

        indent = self._indent(indent_level)
        lines.append(f"{indent}server {self.netprefix} {{")
        lines.extend(self.auto_format_fields(indent_level + 1))
        lines.append(f"{indent}}};")
        return "\n".join(lines)
