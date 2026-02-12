from __future__ import annotations

from typing import ClassVar, Literal

from pydantic import BaseModel, Field, field_validator, model_validator

from ._base_model import BindBaseModel
from ._base_types import (
    address_match_list_BIND,
    boolean_BIND,
    domain_name_BIND,
    duration_BIND,
    fixed_point_BIND,
    integer_BIND,
    ip_address_BIND,
    ip_v4_address_BIND,
    ip_v6_address_BIND,
    net_prefix_BIND,
    percentage_BIND,
    port_BIND,
    quoted_string_BIND,
    server_key_BIND,
    sizeval_BIND,
    string_BIND,
    tls_id_BIND,
)


# NOTE: SUB-BLOCKS
class ServerSpecifier(BindBaseModel):
    """
    Specificator for server type fields.

    Grammar:
    ```
    ( <ip_address> [ port <integer> ] ) [ key <server_key> ] [ tls <tls_id> ]
    ```
    """

    address: ip_address_BIND = Field(..., description="Server IP-address")
    port: port_BIND | None = Field(default=None, description="Server port")
    key: server_key_BIND | None = Field(default=None, description="Auth key")
    tls: tls_id_BIND | None = Field(default=None, description="TLS configuration")

    @property
    def comparison_attr(self) -> tuple[ip_address_BIND, port_BIND | None]:
        return (self.address, self.port)

    def model_bind_syntax(self, indent_level: int = 0) -> str:
        lines: list[str] = []
        self._add_comment(lines, indent_level)

        indent = self._indent(indent_level)

        parts = [str(self.address)]
        if self.port is not None:
            parts.append(f"port {self.port}")
        if self.key is not None:
            parts.append(f"key {self.key}")
        if self.tls is not None:
            parts.append(f"tls {self.tls}")

        lines.append(f"{indent}{' '.join(parts)};")
        return "\n".join(lines)


class AlsoNotifyBlock(BindBaseModel):
    """Options block also-notify with structure."""

    global_port: integer_BIND | None = Field(
        default=None, description="Global port for all servers"
    )
    source: ip_v4_address_BIND | Literal["*"] | None = Field(
        default=None, description="IPv4 source for notifications"
    )
    source_v6: ip_v6_address_BIND | Literal["*"] | None = Field(
        default=None, description="IPv6 source for notifications"
    )
    servers: list[ServerSpecifier] = Field(
        default_factory=list, description="Server list for notifications"
    )

    def model_bind_syntax(self, indent_level: int = 0) -> str:
        lines: list[str] = []
        self._add_comment(lines, indent_level)

        indent = self._indent(indent_level)
        inner_indent = self._indent(indent_level + 1)

        parts = ["also-notify"]
        if self.global_port is not None:
            parts.append(f"port {self.global_port}")
        if self.source is not None:
            parts.append(f"source {self.source}")
        if self.source_v6 is not None:
            parts.append(f"source-v6 {self.source_v6}")

        lines.append(f"{indent}{' '.join(parts)} {{")

        for server in self.servers:
            server_parts = [str(server.address)]
            if server.port is not None:
                server_parts.append(f"port {server.port}")
            if server.key is not None:
                server_parts.append(f"key {server.key}")
            if server.tls is not None:
                server_parts.append(f"tls {server.tls}")

            lines.append(f"{inner_indent}{' '.join(server_parts)};")

        lines.append(f"{indent}}};")
        return "\n".join(lines)


class ForwardersBlock(BindBaseModel):
    """Options block forwarders with structure."""

    global_port: integer_BIND | None = Field(
        default=None, description="Global port for all servers"
    )
    source: ip_v4_address_BIND | Literal["*"] | None = Field(
        default=None, description="IPv4 source for notifications"
    )
    source_v6: ip_v6_address_BIND | Literal["*"] | None = Field(
        default=None, description="IPv6 source for notifications"
    )
    servers: list[ServerSpecifier] = Field(
        default_factory=list, description="List of forwarding servers"
    )

    def model_bind_syntax(self, indent_level: int = 0) -> str:
        lines: list[str] = []
        self._add_comment(lines, indent_level)

        indent = self._indent(indent_level)

        parts = ["forwarders"]

        if self.global_port is not None:
            parts.append(f"port {self.global_port}")

        if self.source is not None:
            parts.append(f"source {self.source}")

        if self.source_v6 is not None:
            parts.append(f"source-v6 {self.source_v6}")

        lines.append(f"{indent}{' '.join(parts)} {{")

        for server in self.servers:
            server_line = server.model_bind_syntax(indent_level + 1)
            lines.append(server_line)

        lines.append(f"{indent}}};")
        return "\n".join(lines)


class Dns64Block(BindBaseModel):
    """DNS64 configuration block."""

    prefix: net_prefix_BIND = Field(..., description="DNS64 prefix")
    break_dnssec: boolean_BIND | None = Field(
        default=None, description="Enable DNS64 synthesis even if DNSSEC validation fails"
    )
    clients: address_match_list_BIND | None = Field(
        default=None, description="Clients affected by this DNS64 prefix"
    )
    exclude: address_match_list_BIND | None = Field(
        default=None, description="IPv6 addresses to exclude from DNS64"
    )
    mapped: address_match_list_BIND | None = Field(
        default=None, description="IPv4 addresses to map in DNS64"
    )
    recursive_only: boolean_BIND | None = Field(
        default=None, description="Apply DNS64 only to recursive queries"
    )
    suffix: ip_v6_address_BIND | None = Field(
        default=None, description="Suffix for mapped IPv4 addresses"
    )

    _exclude_from_syntax: ClassVar[set[str]] = {"prefix"}

    @property
    def comparison_attr(self) -> net_prefix_BIND:
        return self.prefix

    def model_bind_syntax(self, indent_level: int = 0) -> str:
        lines: list[str] = []
        self._add_comment(lines, indent_level)

        indent = self._indent(indent_level)
        lines.append(f"{indent}dns64 {self.prefix} {{")
        lines.extend(self.auto_format_fields(indent_level + 1))
        lines.append(f"{indent}}};")
        return "\n".join(lines)


class RateLimitBlock(BindBaseModel):
    """Response rate limiting configuration block."""

    responses_per_second: integer_BIND | None = Field(
        default=None, description="Limit for non-empty responses per second"
    )
    errors_per_second: integer_BIND | None = Field(
        default=None, description="Limit for error responses per second"
    )
    nxdomains_per_second: integer_BIND | None = Field(
        default=None, description="Limit for NXDOMAIN responses per second"
    )
    nodata_per_second: integer_BIND | None = Field(
        default=None, description="Limit for NODATA responses per second"
    )
    referrals_per_second: integer_BIND | None = Field(
        default=None, description="Limit for referral responses per second"
    )
    all_per_second: integer_BIND | None = Field(
        default=None, description="Limit for all UDP responses per second"
    )
    slip: integer_BIND | None = Field(
        default=None, description="Rate at which to send truncated responses"
    )
    window: integer_BIND | None = Field(
        default=None, description="Time window for rate limiting in seconds"
    )
    qps_scale: integer_BIND | None = Field(
        default=None, description="Query rate at which to scale back limits"
    )
    ipv4_prefix_length: integer_BIND | None = Field(
        default=None, description="IPv4 prefix length for client grouping"
    )
    ipv6_prefix_length: integer_BIND | None = Field(
        default=None, description="IPv6 prefix length for client grouping"
    )
    exempt_clients: address_match_list_BIND | None = Field(
        default=None, description="Clients exempt from rate limiting"
    )
    max_table_size: integer_BIND | None = Field(
        default=None, description="Maximum size of rate limit table"
    )
    min_table_size: integer_BIND | None = Field(
        default=None, description="Minimum size of rate limit table"
    )
    log_only: boolean_BIND | None = Field(
        default=None, description="Log rate limiting without actually dropping"
    )

    @field_validator("slip")
    def validate_slip(cls, v: integer_BIND | None) -> integer_BIND | None:
        if v is not None and (v < 0 or v > 10):
            raise ValueError("slip must be between 0 and 10")
        return v

    @field_validator("ipv4_prefix_length")
    def validate_ipv4_prefix_length(cls, v: integer_BIND | None) -> integer_BIND | None:
        if v is not None and (v < 0 or v > 32):
            raise ValueError("IPv4 prefix length must be between 0 and 32")
        return v

    @field_validator("ipv6_prefix_length")
    def validate_ipv6_prefix_length(cls, v: integer_BIND | None) -> integer_BIND | None:
        if v is not None and (v < 0 or v > 128):
            raise ValueError("IPv6 prefix length must be between 0 and 128")
        return v

    def model_bind_syntax(self, indent_level: int = 0) -> str:
        lines: list[str] = []
        self._add_comment(lines, indent_level)

        indent = self._indent(indent_level)
        lines.append(f"{indent}rate-limit {{")
        lines.extend(self.auto_format_fields(indent_level + 1))
        lines.append(f"{indent}}};")
        return "\n".join(lines)


class ResponsePolicyZone(BindBaseModel):
    """Response Policy Zone configuration."""

    zone: domain_name_BIND = Field(..., description="RPZ zone name")
    add_soa: boolean_BIND | None = Field(default=None, description="Add SOA record to responses")
    log: boolean_BIND | None = Field(default=None, description="Enable logging for this zone")
    max_policy_ttl: duration_BIND | None = Field(
        default=None, description="Maximum TTL for policy responses"
    )
    min_update_interval: duration_BIND | None = Field(
        default=None, description="Minimum interval between updates"
    )
    policy: str | None = Field(
        default=None, description="Policy action (cname, disabled, drop, given, etc.)"
    )
    recursive_only: boolean_BIND | None = Field(
        default=None, description="Apply only to recursive queries"
    )
    nsip_enable: boolean_BIND | None = Field(default=None, description="Enable NSIP triggers")
    nsdname_enable: boolean_BIND | None = Field(
        default=None, description="Enable NSDNAME triggers"
    )
    ede: str | None = Field(default=None, description="Extended DNS Error code")

    _exclude_from_syntax: ClassVar[set[str]] = {"zone"}

    @property
    def comparison_attr(self) -> domain_name_BIND:
        return self.zone

    @field_validator("policy")
    def validate_policy(cls, v: str | None) -> str | None:
        if v is None:
            return v
        valid_policies = [
            "cname",
            "disabled",
            "drop",
            "given",
            "no-op",
            "nodata",
            "nxdomain",
            "passthru",
            "tcp-only",
        ]
        if v not in valid_policies and not v.startswith("tcp-only "):
            raise ValueError(
                f"Invalid policy. Must be one of: {', '.join(valid_policies)} or 'tcp-only <domain>'"
            )
        return v

    @field_validator("ede")
    def validate_ede(cls, v: str | None) -> str | None:
        if v is None:
            return v
        valid_ede = ["none", "forged", "blocked", "censored", "filtered", "prohibited"]
        if v not in valid_ede:
            raise ValueError(f"Invalid EDE value. Must be one of: {', '.join(valid_ede)}")
        return v

    def model_bind_syntax(self, indent_level: int = 0) -> str:
        lines: list[str] = []
        self._add_comment(lines, indent_level)

        indent = self._indent(indent_level)
        lines.append(f"{indent}zone {self.zone} {{")
        lines.extend(self.auto_format_fields(indent_level + 1))
        lines.append(f"{indent}}};")
        return "\n".join(lines)


class ResponsePolicyBlock(BindBaseModel):
    """Response Policy configuration block."""

    zones: list[ResponsePolicyZone] = Field(
        default_factory=list, description="Response policy zones"
    )
    add_soa: boolean_BIND | None = Field(
        default=None, description="Add SOA record to responses (global)"
    )
    break_dnssec: boolean_BIND | None = Field(
        default=None, description="Apply RPZ even when DNSSEC records exist"
    )
    max_policy_ttl: duration_BIND | None = Field(
        default=None, description="Maximum TTL for policy responses (global)"
    )
    min_update_interval: duration_BIND | None = Field(
        default=None, description="Minimum interval between updates (global)"
    )
    min_ns_dots: integer_BIND | None = Field(
        default=None, description="Minimum dots in nameserver names"
    )
    nsip_wait_recurse: boolean_BIND | None = Field(
        default=None, description="Wait for recursion before applying NSIP rules"
    )
    nsdname_wait_recurse: boolean_BIND | None = Field(
        default=None, description="Wait for recursion before applying NSDNAME rules"
    )
    qname_wait_recurse: boolean_BIND | None = Field(
        default=None, description="Wait for recursion before applying QNAME rules"
    )
    recursive_only: boolean_BIND | None = Field(
        default=None, description="Apply only to recursive queries (global)"
    )
    servfail_until_ready: boolean_BIND | None = Field(
        default=None, description="Return SERVFAIL until RPZ zones are loaded"
    )
    nsip_enable: boolean_BIND | None = Field(
        default=None, description="Enable NSIP triggers (global)"
    )
    nsdname_enable: boolean_BIND | None = Field(
        default=None, description="Enable NSDNAME triggers (global)"
    )

    _exclude_from_syntax: ClassVar[set[str]] = {"zones"}

    def model_bind_syntax(self, indent_level: int = 0) -> str:
        lines: list[str] = []
        self._add_comment(lines, indent_level)

        indent = self._indent(indent_level)
        lines.append(f"{indent}response-policy {{")

        for zone in self.zones:
            lines.append(zone.model_bind_syntax(indent_level + 1))

        lines.extend(self.auto_format_fields(indent_level + 1))

        lines.append(f"{indent}}};")
        return "\n".join(lines)


class CatalogZoneBlock(BindBaseModel):
    """Catalog zone configuration."""

    zone: domain_name_BIND = Field(..., description="Catalog zone name")
    default_primaries: address_match_list_BIND | None = Field(
        default=None, description="Default primary servers for member zones"
    )
    zone_directory: quoted_string_BIND | None = Field(
        default=None, description="Directory for zone files"
    )
    in_memory: boolean_BIND | None = Field(default=None, description="Keep catalog in memory")
    min_update_interval: duration_BIND | None = Field(
        default=None, description="Minimum interval between updates"
    )

    _exclude_from_syntax: ClassVar[set[str]] = {"zone"}

    @property
    def comparison_attr(self) -> domain_name_BIND:
        return self.zone

    def model_bind_syntax(self, indent_level: int = 0) -> str:
        lines: list[str] = []
        self._add_comment(lines, indent_level)

        indent = self._indent(indent_level)
        lines.append(f"{indent}zone {self.zone} {{")
        lines.extend(self.auto_format_fields(indent_level + 1))
        lines.append(f"{indent}}};")
        return "\n".join(lines)


class RrsetOrderRule(BindBaseModel):
    """RRset ordering rule."""

    order_class: string_BIND | None = Field(default=None, description="Class to match")
    order_type: string_BIND | None = Field(default=None, description="Type to match")
    order_name: quoted_string_BIND | None = Field(default=None, description="Name to match")
    order: str = Field(..., description="Ordering method (fixed, random, cyclic, none)")

    @property
    def comparison_attr(self) -> str:
        return f"{self.order_class} {self.order_type} {self.order_name}"

    @field_validator("order")
    def validate_order(cls, v: str) -> str:
        valid_orders = ["fixed", "random", "cyclic", "none"]
        if v not in valid_orders:
            raise ValueError(f"Invalid order. Must be one of: {', '.join(valid_orders)}")
        return v

    def model_bind_syntax(self, indent_level: int = 0) -> str:
        lines: list[str] = []
        self._add_comment(lines, indent_level)

        indent = self._indent(indent_level)
        parts = []
        if self.order_class is not None:
            parts.append(f"class {self.order_class}")
        if self.order_type is not None:
            parts.append(f"type {self.order_type}")
        if self.order_name is not None:
            parts.append(f"name {self.order_name}")
        parts.append(f"order {self.order}")

        lines.append(f"{indent}{' '.join(parts)};")
        return "\n".join(lines)


# NOTE: MIXINS
class BasicAccessControlMixin(BaseModel):
    allow_query: address_match_list_BIND | None = Field(
        default=None, description="Hosts allowed to send queries"
    )
    allow_query_on: address_match_list_BIND | None = Field(
        default=None, description="Local addresses allowed to receive queries"
    )
    allow_transfer: address_match_list_BIND | None = Field(
        default=None, description="Hosts allowed to receive zone transfers"
    )
    allow_update: address_match_list_BIND | None = Field(
        default=None, description="Hosts allowed to submit dynamic updates"
    )
    allow_notify: address_match_list_BIND | None = Field(
        default=None, description="Hosts allowed to send NOTIFY messages"
    )
    allow_update_forwarding: address_match_list_BIND | None = Field(
        default=None, description="Hosts allowed to forward dynamic updates"
    )


class AccessControlMixin(BasicAccessControlMixin):
    allow_query_cache: address_match_list_BIND | None = Field(
        default=None, description="Hosts allowed to access cache"
    )
    allow_query_cache_on: address_match_list_BIND | None = Field(
        default=None, description="Local addresses allowed to send cache responses"
    )
    allow_recursion: address_match_list_BIND | None = Field(
        default=None, description="Hosts allowed to perform recursive queries"
    )
    allow_recursion_on: address_match_list_BIND | None = Field(
        default=None, description="Local addresses allowed to receive recursive queries"
    )
    blackhole: address_match_list_BIND | None = Field(
        default=None, description="Hosts to ignore completely"
    )
    no_case_compress: address_match_list_BIND | None = Field(
        default=None, description="Clients requiring case-insensitive compression"
    )


class BasicBooleanOptionsMixin(BaseModel):
    check_dup_records: Literal["fail", "warn", "ignore"] | None = Field(
        default=None, description="Check for duplicate records in primary zones"
    )
    check_integrity: boolean_BIND | None = Field(
        default=None, description="Perform zone integrity checks"
    )
    check_mx: Literal["fail", "warn", "ignore"] | None = Field(
        default=None, description="Check MX records"
    )
    check_mx_cname: Literal["fail", "warn", "ignore"] | None = Field(
        default=None, description="Check MX records referring to CNAMEs"
    )
    check_sibling: boolean_BIND | None = Field(default=None, description="Check for sibling glue")
    check_spf: Literal["warn", "ignore"] | None = Field(
        default=None, description="Check for TXT SPF records"
    )
    check_srv_cname: Literal["fail", "warn", "ignore"] | None = Field(
        default=None, description="Check SRV records referring to CNAMEs"
    )
    check_svcb: boolean_BIND | None = Field(default=None, description="Check SVCB records")
    check_wildcard: boolean_BIND | None = Field(
        default=None, description="Check for non-terminal wildcards"
    )
    checkds: boolean_BIND | Literal["explicit"] | None = Field(
        default=None, description="Check DS records"
    )
    inline_signing: boolean_BIND | None = Field(
        default=None, description="Maintain separate signed version"
    )
    ixfr_from_differences: boolean_BIND | None = Field(
        default=None, description="Generate IXFR from differences"
    )
    multi_master: boolean_BIND | None = Field(
        default=None, description="Multiple primary servers for a zone"
    )
    notify: boolean_BIND | Literal["explicit", "master-only", "primary-only"] | None = Field(
        default=None, description="Send NOTIFY messages on zone changes"
    )
    notify_to_soa: boolean_BIND | None = Field(
        default=None, description="Send NOTIFY to SOA MNAME"
    )
    request_expire: boolean_BIND | None = Field(
        default=None, description="Request EDNS EXPIRE value"
    )
    request_ixfr: boolean_BIND | None = Field(
        default=None, description="Request IXFR from primaries"
    )
    try_tcp_refresh: boolean_BIND | None = Field(
        default=None, description="Try TCP if UDP refresh fails"
    )
    zero_no_soa_ttl: boolean_BIND | None = Field(
        default=None, description="Set TTL to 0 for negative SOA responses"
    )

    def _format_notify(self, value: bool | str, indent_level: int) -> str:
        indent = self._indent(indent_level)  # type: ignore[attr-defined]
        if isinstance(value, bool):
            return f"{indent}notify {'yes' if value else 'no'};"
        return f"{indent}notify {value};"

    def _format_checkds(self, value: bool | str, indent_level: int) -> str:
        indent = self._indent(indent_level)  # type: ignore[attr-defined]
        if isinstance(value, bool):
            return f"{indent}checkds {'yes' if value else 'no'};"
        return f"{indent}checkds {value};"


class BooleanOptionsMixin(BasicBooleanOptionsMixin):
    allow_new_zones: boolean_BIND | None = Field(
        default=None, description="Allow runtime zone addition via rndc addzone"
    )
    auth_nxdomain: boolean_BIND | None = Field(
        default=None, description="Always set AA bit on NXDOMAIN responses"
    )
    flush_zones_on_shutdown: boolean_BIND | None = Field(
        default=None, description="Flush pending zone writes on shutdown"
    )
    root_key_sentinel: boolean_BIND | None = Field(
        default=None, description="Respond to root key sentinel probes"
    )
    reuseport: boolean_BIND | None = Field(
        default=None, description="Enable kernel socket load-balancing"
    )
    message_compression: boolean_BIND | None = Field(
        default=None, description="Use DNS name compression in responses"
    )
    minimal_responses: boolean_BIND | Literal["no-auth", "no-auth-recursive"] | None = Field(
        default=None, description="Minimize authority and additional sections"
    )
    minimal_any: boolean_BIND | None = Field(
        default=None, description="Return only one RRset for ANY queries over UDP"
    )
    recursion: boolean_BIND | None = Field(default=None, description="Allow recursion")
    request_nsid: boolean_BIND | None = Field(
        default=None, description="Send NSID option in queries"
    )
    require_server_cookie: boolean_BIND | None = Field(
        default=None, description="Require valid server cookie for UDP responses"
    )
    answer_cookie: boolean_BIND | None = Field(
        default=None, description="Send COOKIE EDNS option in replies"
    )
    send_cookie: boolean_BIND | None = Field(
        default=None, description="Send COOKIE EDNS option in queries"
    )
    stale_answer_enable: boolean_BIND | None = Field(
        default=None, description="Return stale cached answers when servers are down"
    )
    stale_cache_enable: boolean_BIND | None = Field(
        default=None, description="Retain stale cached answers"
    )
    dnssec_validation: Literal["yes", "no", "auto"] | None = Field(
        default=None, description="Enable DNSSEC validation"
    )
    dnssec_accept_expired: boolean_BIND | None = Field(
        default=None, description="Accept expired DNSSEC signatures"
    )
    querylog: boolean_BIND | None = Field(
        default=None, description="Enable query logging at startup"
    )
    zero_no_soa_ttl_cache: boolean_BIND | None = Field(
        default=None, description="Set TTL to 0 when caching negative SOA responses"
    )
    synth_from_dnssec: boolean_BIND | None = Field(
        default=None, description="Enable aggressive use of DNSSEC-validated cache"
    )

    def _format_minimal_responses(self, value: bool | str, indent_level: int) -> str:
        indent = self._indent(indent_level)  # type: ignore[attr-defined]
        if isinstance(value, bool):
            return f"{indent}minimal-responses {'yes' if value else 'no'};"
        return f"{indent}minimal-responses {value};"


class BasicForwardingMixin(BaseModel):
    forward: Literal["first", "only"] | None = Field(
        default=None, description="Forwarding behavior"
    )


class ForwardingMixin(BasicForwardingMixin):
    forwarders: ForwardersBlock | None = Field(default=None, description="Forwarding servers")
    dual_stack_servers: list[ServerSpecifier] | None = Field(
        default=None, description="Dual-stack servers for last resort"
    )

    def _format_dual_stack_servers(self, value: list[ServerSpecifier], indent_level: int) -> str:
        indent = self._indent(indent_level)  # type: ignore[attr-defined]
        inner_indent = self._indent(indent_level + 1)  # type: ignore[attr-defined]
        lines = [f"{indent}dual-stack-servers {{"]
        for server in sorted(value):
            server_line = server.model_bind_syntax().rstrip(";")
            lines.append(f"{inner_indent}{server_line};")
        lines.append(f"{indent}}};")
        return "\n".join(lines)


class BasicServerResourceMixin(BaseModel):
    max_journal_size: sizeval_BIND | Literal["default", "unlimited"] | None = Field(
        default=None, description="Maximum journal file size"
    )
    max_records: integer_BIND | None = Field(default=None, description="Maximum records per zone")
    max_records_per_type: integer_BIND | None = Field(
        default=None, description="Maximum records per RRset"
    )
    max_types_per_name: integer_BIND | None = Field(
        default=None, description="Maximum RR types per owner name"
    )

    def _format_max_journal_size(self, value: str | str, indent_level: int) -> str:
        indent = self._indent(indent_level)  # type: ignore[attr-defined]
        return f"{indent}max-journal-size {value};"


class ServerResourceMixin(BasicServerResourceMixin):
    recursive_clients: integer_BIND | None = Field(
        default=None, description="Maximum concurrent recursive clients"
    )
    tcp_clients: integer_BIND | None = Field(
        default=None, description="Maximum simultaneous TCP connections"
    )
    clients_per_query: integer_BIND | None = Field(
        default=None, description="Initial simultaneous clients per query"
    )
    max_clients_per_query: integer_BIND | None = Field(
        default=None, description="Maximum simultaneous clients per query"
    )
    fetches_per_zone: integer_BIND | None = Field(
        default=None, description="Maximum fetches per zone"
    )
    fetches_per_server: integer_BIND | None = Field(
        default=None, description="Maximum fetches per server"
    )
    fetch_quota_params: list[integer_BIND | fixed_point_BIND] | None = Field(
        default=None, description="Parameters for dynamic fetch quota adjustment"
    )
    max_cache_size: sizeval_BIND | percentage_BIND | Literal["default", "unlimited"] | None = (
        Field(default=None, description="Maximum cache size")
    )
    update_quota: integer_BIND | None = Field(
        default=None, description="Maximum concurrent UPDATE messages"
    )
    sig0key_checks_limit: integer_BIND | None = Field(
        default=None, description="Maximum SIG(0) keys to consider"
    )
    sig0message_checks_limit: integer_BIND | None = Field(
        default=None, description="Maximum SIG(0) keys to try"
    )

    def _format_max_cache_size(self, value: str | str, indent_level: int) -> str:
        indent = self._indent(indent_level)  # type: ignore[attr-defined]
        return f"{indent}max-cache-size {value};"

    def _format_fetch_quota_params(
        self, value: list[integer_BIND | fixed_point_BIND], indent_level: int
    ) -> str:
        indent = self._indent(indent_level)  # type: ignore[attr-defined]
        params = " ".join(str(p) for p in sorted(value))
        return f"{indent}fetch-quota-params {params};"


class BasicTuningMixin(BaseModel):
    zone_statistics: boolean_BIND | Literal["full", "terse", "none"] | None = Field(
        default=None, description="Level of zone statistics gathering"
    )

    def _format_zone_statistics(self, value: bool | str, indent_level: int) -> str:
        indent = self._indent(indent_level)  # type: ignore[attr-defined]
        if isinstance(value, bool):
            return f"{indent}zone-statistics {'yes' if value else 'no'};"
        return f"{indent}zone-statistics {value};"


class TuningMixin(BasicTuningMixin):
    lame_ttl: duration_BIND | None = Field(default=None, description="TTL for lame server caching")
    servfail_ttl: duration_BIND | None = Field(
        default=None, description="TTL for SERVFAIL caching"
    )
    min_ncache_ttl: duration_BIND | None = Field(
        default=None, description="Minimum negative cache TTL"
    )
    min_cache_ttl: duration_BIND | None = Field(
        default=None, description="Minimum positive cache TTL"
    )
    max_ncache_ttl: duration_BIND | None = Field(
        default=None, description="Maximum negative cache TTL"
    )
    max_cache_ttl: duration_BIND | None = Field(
        default=None, description="Maximum positive cache TTL"
    )
    max_stale_ttl: duration_BIND | None = Field(
        default=None, description="Maximum stale record TTL"
    )
    dnssec_loadkeys_interval: integer_BIND | None = Field(
        default=None, description="DNSSEC key repository check interval in minutes"
    )
    nta_lifetime: duration_BIND | None = Field(
        default=None, description="Negative trust anchor lifetime"
    )
    nta_recheck: duration_BIND | None = Field(
        default=None, description="Negative trust anchor recheck interval"
    )
    stale_answer_ttl: duration_BIND | None = Field(
        default=None, description="TTL for stale answers"
    )
    stale_answer_client_timeout: integer_BIND | Literal["disabled", "off"] | None = Field(
        default=None, description="Timeout before returning stale answers"
    )
    stale_refresh_time: duration_BIND | None = Field(
        default=None, description="Time window for returning stale answers"
    )
    nocookie_udp_size: integer_BIND | None = Field(
        default=None, description="Maximum UDP response size without valid cookie"
    )
    cookie_algorithm: Literal["siphash24"] | None = Field(
        default=None, description="Cookie generation algorithm"
    )
    cookie_secret: list[string_BIND] | None = Field(
        default=None, description="Shared secrets for EDNS COOKIE generation"
    )
    serial_update_method: Literal["date", "increment", "unixtime"] | None = Field(
        default=None, description="Dynamic DNS serial number update method"
    )

    def _format_cookie_secret(self, value: list[string_BIND], indent_level: int) -> str:
        indent = self._indent(indent_level)  # type: ignore[attr-defined]
        lines = []
        for secret in sorted(value):
            lines.append(f"{indent}cookie-secret {secret};")
        return "\n".join(lines)


class EDNSMixin(BaseModel):
    edns_udp_size: integer_BIND | None = Field(
        default=None, description="Maximum advertised EDNS UDP buffer size"
    )
    max_udp_size: integer_BIND | None = Field(
        default=None, description="Maximum EDNS UDP message size to send"
    )
    response_padding: tuple[address_match_list_BIND, integer_BIND] | None = Field(
        default=None, description="EDNS Padding configuration"
    )

    def _format_response_padding(
        self, value: tuple[address_match_list_BIND, integer_BIND], indent_level: int
    ) -> str:
        acl, block_size = value
        indent = self._indent(indent_level)  # type: ignore[attr-defined]
        inner_indent = self._indent(indent_level + 1)  # type: ignore[attr-defined]
        lines = [f"{indent}response-padding {{"]
        for item in acl:
            lines.append(f"{inner_indent}{item};")
        lines.append(f"{indent}}} block-size {block_size};")
        return "\n".join(lines)


class ZoneFileMixin(BaseModel):
    masterfile_format: Literal["raw", "text"] | None = Field(
        default=None, description="Zone file format"
    )
    masterfile_style: Literal["full", "relative"] | None = Field(
        default=None, description="Zone file dump style"
    )


class QueryProcessingMixin(BaseModel):
    max_query_count: integer_BIND | None = Field(
        default=None, description="Maximum iterative queries per recursive query"
    )
    max_recursion_depth: integer_BIND | None = Field(
        default=None, description="Maximum recursion depth"
    )
    max_recursion_queries: integer_BIND | None = Field(
        default=None, description="Maximum iterative queries per recursive query"
    )
    max_query_restarts: integer_BIND | None = Field(
        default=None, description="Maximum CNAME chain length"
    )
    notify_defer: integer_BIND | None = Field(
        default=None, description="Delay before sending NOTIFY messages"
    )
    notify_delay: integer_BIND | None = Field(
        default=None, description="Delay between NOTIFY message sets"
    )
    max_rsa_exponent_size: integer_BIND | None = Field(
        default=None, description="Maximum RSA exponent size in bits"
    )
    prefetch: tuple[integer_BIND, integer_BIND] | None = Field(
        default=None, description="Prefetch trigger and eligibility TTLs"
    )
    v6_bias: integer_BIND | None = Field(
        default=None, description="IPv6 server preference bias in milliseconds"
    )

    @field_validator("max_rsa_exponent_size")
    def validate_max_rsa_exponent_size(cls, v: integer_BIND | None) -> integer_BIND | None:
        if v is not None and v > 4096:
            raise ValueError("max-rsa-exponent-size cannot exceed 4096")
        return v

    @field_validator("prefetch")
    def validate_prefetch(
        cls, v: tuple[integer_BIND, integer_BIND] | None
    ) -> tuple[integer_BIND, integer_BIND] | None:
        if v is not None:
            trigger, eligibility = v
            if trigger > 10:
                raise ValueError("prefetch trigger TTL cannot exceed 10 seconds")
            if eligibility <= trigger + 6:
                raise ValueError(
                    "prefetch eligibility TTL must be at least 6 seconds longer than trigger"
                )
        return v

    def _format_prefetch(self, value: tuple[integer_BIND, integer_BIND], indent_level: int) -> str:
        trigger, eligibility = value
        indent = self._indent(indent_level)  # type: ignore[attr-defined]
        return f"{indent}prefetch {trigger} {eligibility};"


class ServerInfoMixin(BaseModel):
    version: quoted_string_BIND | Literal["none"] | None = Field(
        default=None, description="Server version string"
    )
    hostname: quoted_string_BIND | Literal["none"] | None = Field(
        default=None, description="Server hostname string"
    )
    server_id: quoted_string_BIND | Literal["none", "hostname"] | None = Field(
        default=None, description="Server identifier"
    )


class EmptyZonesMixin(BaseModel):
    empty_server: string_BIND | None = Field(
        default=None, description="Server name for empty zones"
    )
    empty_contact: string_BIND | None = Field(default=None, description="Contact for empty zones")
    empty_zones_enable: boolean_BIND | None = Field(
        default=None, description="Enable built-in empty zones"
    )
    disable_empty_zone: list[string_BIND] | None = Field(
        default=None, description="Disable specific empty zones"
    )


class ContentFilteringMixin(BaseModel):
    deny_answer_addresses: tuple[address_match_list_BIND, list[string_BIND]] | None = Field(
        default=None, description="Filter answers containing specific addresses"
    )
    deny_answer_aliases: tuple[list[string_BIND], list[string_BIND]] | None = Field(
        default=None, description="Filter answers containing specific aliases"
    )

    def _format_deny_answer_addresses(
        self, value: tuple[address_match_list_BIND, list[string_BIND]], indent_level: int
    ) -> str:
        acl, except_list = value
        indent = self._indent(indent_level)  # type: ignore[attr-defined]
        inner_indent = self._indent(indent_level + 1)  # type: ignore[attr-defined]
        lines = [f"{indent}deny-answer-addresses {{"]
        for item in acl:
            lines.append(f"{inner_indent}{item};")
        lines.append(f"{indent}}} except-from {{")
        for domain in except_list:
            lines.append(f"{inner_indent}{domain};")
        lines.append(f"{indent}}};")
        return "\n".join(lines)

    def _format_deny_answer_aliases(
        self, value: tuple[list[string_BIND], list[string_BIND]], indent_level: int
    ) -> str:
        domains, except_list = value
        indent = self._indent(indent_level)  # type: ignore[attr-defined]
        inner_indent = self._indent(indent_level + 1)  # type: ignore[attr-defined]
        lines = [f"{indent}deny-answer-aliases {{"]
        for domain in domains:
            lines.append(f"{inner_indent}{domain};")
        lines.append(f"{indent}}} except-from {{")
        for domain in except_list:
            lines.append(f"{inner_indent}{domain};")
        lines.append(f"{indent}}};")
        return "\n".join(lines)


class NXDomainMixin(BaseModel):
    nxdomain_redirect: string_BIND | None = Field(
        default=None, description="Suffix for NXDOMAIN redirection"
    )


class BasicDirectoriesMixin(BaseModel):
    key_directory: quoted_string_BIND | None = Field(
        default=None, description="DNSSEC key directory"
    )


class DirectoriesMixin(BasicDirectoriesMixin):
    managed_keys_directory: quoted_string_BIND | None = Field(
        default=None, description="Managed keys directory"
    )
    new_zones_directory: quoted_string_BIND | None = Field(
        default=None, description="New zones configuration directory"
    )


class BasicDnssecMixin(BaseModel):
    dnssec_policy: string_BIND | None = Field(
        default=None, description="DNSSEC key and signing policy"
    )


class DnssecMixin(BasicDnssecMixin):
    trust_anchor_telemetry: boolean_BIND | None = Field(
        default=None, description="Send trust anchor telemetry queries"
    )
    validate_except: list[string_BIND] | None = Field(
        default=None, description="Domains to exclude from DNSSEC validation"
    )


class BasicIXFRAXFDMixin(BaseModel):
    max_ixfr_ratio: percentage_BIND | Literal["unlimited"] | None = Field(
        default=None, description="Maximum IXFR size as percentage of zone"
    )

    def _format_max_ixfr_ratio(self, value: str | str, indent_level: int) -> str:
        indent = self._indent(indent_level)  # type: ignore[attr-defined]
        return f"{indent}max-ixfr-ratio {value};"


class IXFRAXFDMixin(BasicIXFRAXFDMixin):
    ixfr_from_differences: (
        boolean_BIND | Literal["primary", "master", "secondary", "slave"] | None
    ) = Field(default=None, description="Generate IXFR from differences")
    provide_ixfr: boolean_BIND | None = Field(
        default=None, description="Provide IXFR to secondaries"
    )
    request_ixfr: boolean_BIND | None = Field(
        default=None, description="Request IXFR from primaries"
    )
    request_expire: boolean_BIND | None = Field(
        default=None, description="Request EDNS EXPIRE value"
    )


class QNameMinimizationMixin(BaseModel):
    qname_minimization: Literal["strict", "relaxed", "disabled", "off"] | None = Field(
        default=None, description="QNAME minimization behavior"
    )


class CheckNamesMixin(BaseModel):
    check_names: list[tuple[str, Literal["fail", "warn", "ignore"]]] | None = Field(
        default=None, description="Domain name checking rules"
    )

    def _format_check_names(
        self, value: list[tuple[str, Literal["fail", "warn", "ignore"]]], indent_level: int
    ) -> str:
        indent = self._indent(indent_level)  # type: ignore[attr-defined]
        lines = []
        for scope, action in sorted(value):
            lines.append(f"{indent}check-names {scope} {action};")
        return "\n".join(lines)


class ResolverMixin(BaseModel):
    resolver_query_timeout: integer_BIND | None = Field(
        default=None, description="Resolver query timeout in milliseconds"
    )
    resolver_use_dns64: boolean_BIND | None = Field(
        default=None, description="Apply DNS64 to recursive queries"
    )


class IPv4OnlyMixin(BaseModel):
    ipv4only_enable: boolean_BIND | None = Field(
        default=None, description="Enable automatic IPv4-only zones"
    )
    ipv4only_server: string_BIND | None = Field(
        default=None, description="Server name for IPV4ONLY.ARPA zone"
    )
    ipv4only_contact: string_BIND | None = Field(
        default=None, description="Contact for IPV4ONLY.ARPA zone"
    )


class DNS64Mixin(BaseModel):
    dns64_server: string_BIND | None = Field(
        default=None, description="Server name for DNS64 zones"
    )
    dns64_contact: string_BIND | None = Field(default=None, description="Contact for DNS64 zones")
    dns64_blocks: list[Dns64Block] | None = Field(
        default=None, description="DNS64 configuration blocks"
    )

    def _format_dns64_blocks(self, value: list[Dns64Block], indent_level: int) -> str:
        lines = []
        for dns64_block in sorted(value):
            lines.append(dns64_block.model_bind_syntax(indent_level))
        return "\n".join(lines)


class AlgorithmsMixin(BaseModel):
    disable_algorithms: list[tuple[string_BIND, list[string_BIND]]] | None = Field(
        default=None, description="Disable DNSSEC algorithms for specific zones"
    )
    disable_ds_digests: list[tuple[string_BIND, list[string_BIND]]] | None = Field(
        default=None, description="Disable DS digest types for specific zones"
    )

    def _format_disable_algorithms(
        self, value: list[tuple[string_BIND, list[string_BIND]]], indent_level: int
    ) -> str:
        indent = self._indent(indent_level)  # type: ignore[attr-defined]
        inner_indent = self._indent(indent_level + 1)  # type: ignore[attr-defined]
        lines = []
        for zone, algorithms in sorted(value):
            lines.append(f"{indent}disable-algorithms {zone} {{")
            for alg in algorithms:
                lines.append(f"{inner_indent}{alg};")
            lines.append(f"{indent}}};")
        return "\n".join(lines)

    def _format_disable_ds_digests(
        self, value: list[tuple[string_BIND, list[string_BIND]]], indent_level: int
    ) -> str:
        indent = self._indent(indent_level)  # type: ignore[attr-defined]
        inner_indent = self._indent(indent_level + 1)  # type: ignore[attr-defined]
        lines = []
        for zone, digests in sorted(value):
            lines.append(f"{indent}disable-ds-digests {zone} {{")
            for digest in digests:
                lines.append(f"{inner_indent}{digest};")
            lines.append(f"{indent}}};")
        return "\n".join(lines)


class AddressMatchingMixin(BaseModel):
    match_mapped_addresses: boolean_BIND | None = Field(
        default=None, description="Match IPv4-mapped IPv6 addresses"
    )


class CacheMixin(BaseModel):
    attach_cache: string_BIND | None = Field(
        default=None, description="Cache to attach to for shared caching"
    )


class LMDBMixin(BaseModel):
    lmdb_mapsize: sizeval_BIND | None = Field(
        default=None, description="Maximum size for LMDB memory map"
    )


class RrsetOrderingMixin(BaseModel):
    rrset_order: list[RrsetOrderRule] | None = Field(
        default=None, description="RRset ordering rules"
    )

    def _format_rrset_order(self, value: list[RrsetOrderRule], indent_level: int) -> str:
        indent = self._indent(indent_level)  # type: ignore[attr-defined]
        lines = [f"{indent}rrset-order {{"]
        for rule in sorted(value):
            rule_lines = rule.model_bind_syntax(indent_level + 1).split("\n")
            for line in rule_lines:
                lines.append(line)
        lines.append(f"{indent}}};")
        return "\n".join(lines)


class BasicTransferRateMixin(BaseModel):
    min_transfer_rate_in: tuple[integer_BIND, integer_BIND] | None = Field(
        default=None, description="Minimum inbound transfer rate"
    )

    @field_validator("min_transfer_rate_in")
    def validate_min_transfer_rate_in(
        cls, v: tuple[integer_BIND, integer_BIND] | None
    ) -> tuple[integer_BIND, integer_BIND] | None:
        """Validate min-transfer-rate-in."""
        if v is not None:
            bytes_val, minutes_val = v
            if bytes_val < 0:
                raise ValueError("Bytes value in min-transfer-rate-in must be non-negative")
            if minutes_val < 0:
                raise ValueError("Minutes value in min-transfer-rate-in must be non-negative")
        return v

    def _format_min_transfer_rate_in(self, value: tuple[int, int], indent_level: int) -> str:
        bytes_val, minutes_val = value
        indent = self._indent(indent_level)  # type: ignore[attr-defined]
        return f"{indent}min-transfer-rate-in {bytes_val} {minutes_val};"


class TransferRateMixin(BasicTransferRateMixin):
    min_refresh_time: integer_BIND | None = Field(
        default=None, description="Minimum refresh time for secondary zones"
    )
    max_refresh_time: integer_BIND | None = Field(
        default=None, description="Maximum refresh time for secondary zones"
    )
    min_retry_time: integer_BIND | None = Field(
        default=None, description="Minimum retry time for secondary zones"
    )
    max_retry_time: integer_BIND | None = Field(
        default=None, description="Maximum retry time for secondary zones"
    )


class PreferredGlueMixin(BaseModel):
    preferred_glue: Literal["A", "AAAA"] | None = Field(
        default=None, description="Preferred glue record type"
    )


class BasicDNSSECSigningMixin(BaseModel):
    sig_signing_nodes: integer_BIND | None = Field(
        default=None, description="Maximum nodes to examine per quantum when signing"
    )
    sig_signing_signatures: integer_BIND | None = Field(
        default=None, description="Signature threshold per quantum when signing"
    )
    sig_signing_type: integer_BIND | None = Field(
        default=None, description="Private RDATA type for signing-state records"
    )


class DNSSECSigningMixin(BasicDNSSECSigningMixin):
    pass


class AlsoNotifyMixin(BaseModel):
    also_notify: AlsoNotifyBlock | None = Field(
        default=None, description="Additional servers to notify"
    )


class RateLimitingMixin(BaseModel):
    rate_limit: RateLimitBlock | None = Field(
        default=None, description="Response rate limiting configuration"
    )


class ResponsePolicyMixin(BaseModel):
    response_policy: ResponsePolicyBlock | None = Field(
        default=None, description="Response policy configuration"
    )


class CatalogZonesMixin(BaseModel):
    catalog_zones: list[CatalogZoneBlock] | None = Field(
        default=None, description="Catalog zones configuration"
    )

    def _format_catalog_zones(self, value: list[CatalogZoneBlock], indent_level: int) -> str:
        indent = self._indent(indent_level)  # type: ignore[attr-defined]
        lines = [f"{indent}catalog-zones {{"]
        for catalog_zone in sorted(value):
            lines.append(catalog_zone.model_bind_syntax(indent_level + 1))
        lines.append(f"{indent}}};")
        return "\n".join(lines)


class BasicOptionsMixin(
    BasicAccessControlMixin,
    BasicBooleanOptionsMixin,
    BasicForwardingMixin,
    BasicServerResourceMixin,
    BasicTuningMixin,
    BasicDirectoriesMixin,
    BasicDnssecMixin,
    BasicIXFRAXFDMixin,
    BasicTransferRateMixin,
    BasicDNSSECSigningMixin,
    BindBaseModel,
):
    pass


class ExtendedOptionsMixin(
    AccessControlMixin,
    BooleanOptionsMixin,
    ForwardingMixin,
    ServerResourceMixin,
    TuningMixin,
    EDNSMixin,
    ZoneFileMixin,
    QueryProcessingMixin,
    ServerInfoMixin,
    EmptyZonesMixin,
    ContentFilteringMixin,
    NXDomainMixin,
    DirectoriesMixin,
    DnssecMixin,
    IXFRAXFDMixin,
    QNameMinimizationMixin,
    CheckNamesMixin,
    ResolverMixin,
    IPv4OnlyMixin,
    DNS64Mixin,
    AlgorithmsMixin,
    AddressMatchingMixin,
    CacheMixin,
    LMDBMixin,
    RrsetOrderingMixin,
    TransferRateMixin,
    PreferredGlueMixin,
    DNSSECSigningMixin,
    AlsoNotifyMixin,
    RateLimitingMixin,
    ResponsePolicyMixin,
    CatalogZonesMixin,
    BindBaseModel,
):
    pass


class OptionsBlock(ExtendedOptionsMixin):
    """
    Global options block for BIND configuration.

    This is the grammar of the options statement in the named.conf file

    Grammar:
    ```
    # TODO DOCSTRING WITH BIND9 DOCS
    ```
    """

    directory: quoted_string_BIND | None = Field(
        default=None, description="Server's working directory"
    )
    pid_file: quoted_string_BIND | Literal["none"] | None = Field(
        default=None, description="PID file path"
    )
    session_keyfile: quoted_string_BIND | Literal["none"] | None = Field(
        default=None, description="Session key file path"
    )
    session_keyname: string_BIND | None = Field(default=None, description="Session key name")
    session_keyalg: string_BIND | None = Field(default=None, description="Session key algorithm")

    port: port_BIND | None = Field(default=None, description="UDP/TCP port for DNS traffic")
    tls_port: integer_BIND | None = Field(default=None, description="TCP port for DNS-over-TLS")
    https_port: integer_BIND | None = Field(
        default=None, description="TCP port for DNS-over-HTTPS"
    )
    http_port: integer_BIND | None = Field(
        default=None, description="TCP port for unencrypted DNS-over-HTTP"
    )
    http_listener_clients: integer_BIND | None = Field(
        default=None, description="Maximum concurrent HTTP connections per listener"
    )
    http_streams_per_connection: integer_BIND | None = Field(
        default=None, description="Maximum HTTP/2 streams per connection"
    )

    listen_on: list[str | ip_v4_address_BIND] | None = Field(
        default=None, description="IPv4 addresses to listen on"
    )
    listen_on_v6: list[str | ip_v6_address_BIND] | None = Field(
        default=None, description="IPv6 addresses to listen on"
    )
    query_source: ip_v4_address_BIND | Literal["*", "none"] | None = Field(
        default=None, description="Source IPv4 address for queries"
    )
    query_source_v6: ip_v6_address_BIND | Literal["*", "none"] | None = Field(
        default=None, description="Source IPv6 address for queries"
    )
    transfer_source: ip_v4_address_BIND | Literal["*"] | None = Field(
        default=None, description="Source IPv4 address for zone transfers"
    )
    transfer_source_v6: ip_v6_address_BIND | Literal["*"] | None = Field(
        default=None, description="Source IPv6 address for zone transfers"
    )
    notify_source: ip_v4_address_BIND | Literal["*"] | None = Field(
        default=None, description="Source IPv4 address for NOTIFY messages"
    )
    notify_source_v6: ip_v6_address_BIND | Literal["*"] | None = Field(
        default=None, description="Source IPv6 address for NOTIFY messages"
    )
    parental_source: ip_v4_address_BIND | Literal["*"] | None = Field(
        default=None, description="Source IPv4 address for parental agent queries"
    )
    parental_source_v6: ip_v6_address_BIND | Literal["*"] | None = Field(
        default=None, description="Source IPv6 address for parental agent queries"
    )
    max_transfer_time_in: integer_BIND | None = Field(
        default=None, description="Maximum inbound transfer time in minutes"
    )
    max_transfer_idle_in: integer_BIND | None = Field(
        default=None, description="Maximum idle time for inbound transfers in minutes"
    )
    max_transfer_time_out: integer_BIND | None = Field(
        default=None, description="Maximum outbound transfer time in minutes"
    )
    max_transfer_idle_out: integer_BIND | None = Field(
        default=None, description="Maximum idle time for outbound transfers in minutes"
    )
    max_transfers_in: integer_BIND | None = Field(
        default=None, description="Maximum concurrent inbound transfers"
    )
    max_transfers_out: integer_BIND | None = Field(
        default=None, description="Maximum concurrent outbound transfers"
    )
    transfers_per_ns: integer_BIND | None = Field(
        default=None, description="Maximum inbound transfers per name server"
    )
    notify_rate: integer_BIND | None = Field(
        default=None, description="NOTIFY messages per second during normal operation"
    )
    startup_notify_rate: integer_BIND | None = Field(
        default=None, description="NOTIFY messages per second at startup"
    )
    serial_query_rate: integer_BIND | None = Field(
        default=None, description="SOA queries per second"
    )
    transfer_format: Literal["many-answers", "one-answer"] | None = Field(
        default=None, description="Zone transfer format"
    )
    transfer_message_size: integer_BIND | None = Field(
        default=None, description="Maximum zone transfer message size"
    )
    automatic_interface_scan: boolean_BIND | None = Field(
        default=None, description="Automatically rescan network interfaces"
    )
    responselog: boolean_BIND | None = Field(
        default=None, description="Enable response logging at startup"
    )
    tcp_receive_buffer: integer_BIND | None = Field(
        default=None, description="TCP receive buffer size"
    )
    udp_receive_buffer: integer_BIND | None = Field(
        default=None, description="UDP receive buffer size"
    )
    tcp_send_buffer: integer_BIND | None = Field(default=None, description="TCP send buffer size")
    udp_send_buffer: integer_BIND | None = Field(default=None, description="UDP send buffer size")
    dnstap: list[str] | None = Field(default=None, description="DNSTAP message types to log")
    dnstap_identity: quoted_string_BIND | Literal["none", "hostname"] | None = Field(
        default=None, description="DNSTAP identity string"
    )
    dnstap_version: quoted_string_BIND | Literal["none"] | None = Field(
        default=None, description="DNSTAP version string"
    )
    fstrm_set_buffer_hint: integer_BIND | None = Field(
        default=None, description="FSTRM buffer hint"
    )
    fstrm_set_flush_timeout: integer_BIND | None = Field(
        default=None, description="FSTRM flush timeout"
    )
    fstrm_set_input_queue_size: integer_BIND | None = Field(
        default=None, description="FSTRM input queue size"
    )
    fstrm_set_output_notify_threshold: integer_BIND | None = Field(
        default=None, description="FSTRM output notify threshold"
    )
    fstrm_set_output_queue_model: Literal["mpsc", "spsc"] | None = Field(
        default=None, description="FSTRM output queue model"
    )
    fstrm_set_output_queue_size: integer_BIND | None = Field(
        default=None, description="FSTRM output queue size"
    )
    fstrm_set_reopen_interval: duration_BIND | None = Field(
        default=None, description="FSTRM reopen interval"
    )
    dump_file: quoted_string_BIND | None = Field(
        default=None, description="Database dump file path"
    )
    memstatistics_file: quoted_string_BIND | None = Field(
        default=None, description="Memory statistics file path"
    )
    recursing_file: quoted_string_BIND | None = Field(
        default=None, description="Recursing queries dump file path"
    )
    statistics_file: quoted_string_BIND | None = Field(
        default=None, description="Statistics file path"
    )
    secroots_file: quoted_string_BIND | None = Field(
        default=None, description="Security roots dump file path"
    )
    geoip_directory: quoted_string_BIND | Literal["none"] | None = Field(
        default=None, description="GeoIP database directory"
    )
    interface_interval: duration_BIND | None = Field(
        default=None, description="Network interface scan interval"
    )
    tcp_listen_queue: integer_BIND | None = Field(
        default=None, description="TCP listen queue depth"
    )
    tcp_initial_timeout: integer_BIND | None = Field(
        default=None, description="Initial TCP timeout in deciseconds"
    )
    tcp_idle_timeout: integer_BIND | None = Field(
        default=None, description="TCP idle timeout in deciseconds"
    )
    tcp_keepalive_timeout: integer_BIND | None = Field(
        default=None, description="TCP keepalive timeout in deciseconds"
    )
    tcp_advertised_timeout: integer_BIND | None = Field(
        default=None, description="Advertised TCP timeout in deciseconds"
    )

    @model_validator(mode="after")
    def validate_recursion_settings(self) -> OptionsBlock:
        if self.recursion is False:
            if self.allow_recursion is not None:
                raise ValueError("allow-recursion cannot be set when recursion is off")
            if self.allow_query_cache is not None:
                raise ValueError("allow-query-cache cannot be set when recursion is off")
        return self

    @model_validator(mode="after")
    def validate_dnssec_settings(self) -> OptionsBlock:
        if self.dnssec_validation == "no" and self.dnssec_policy is not None:
            raise ValueError("dnssec-policy cannot be set when dnssec-validation is no")
        return self

    def model_bind_syntax(self, indent_level: int = 0) -> str:
        lines: list[str] = []
        self._add_comment(lines, indent_level)

        indent = self._indent(indent_level)
        lines.append(f"{indent}options {{")
        lines.extend(self.auto_format_fields(indent_level + 1))
        lines.append(f"{indent}}};")
        return "\n".join(lines)
