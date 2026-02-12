from __future__ import annotations

from enum import Enum
from typing import Any, ClassVar, Literal

from pydantic import Field, model_validator

from ._base_model import BindBaseModel
from ._base_types import (
    boolean_BIND,
    domain_name_BIND,
    integer_BIND,
    ip_v4_address_BIND,
    ip_v6_address_BIND,
    port_BIND,
    quoted_string_BIND,
    string_BIND,
)
from .options_block import BasicOptionsMixin
from .zone_block_resource_records import (
    ResourceRecordType,
    sort_resource_records,
)


class ZoneTypeEnum(str, Enum):
    """Zone types in BIND."""

    PRIMARY = "primary"
    SECONDARY = "secondary"
    MIRROR = "mirror"
    HINT = "hint"
    STUB = "stub"
    STATIC_STUB = "static-stub"
    FORWARD = "forward"
    REDIRECT = "redirect"
    IN_VIEW = "in-view"


class ZoneClassEnum(str, Enum):
    """Zone classes in BIND."""

    IN = "IN"
    HS = "HS"
    CHAOS = "CHAOS"


class UpdatePolicyRuleTypeEnum(str, Enum):
    """Rule types for update-policy."""

    NAME = "name"
    SUBDOMAIN = "subdomain"
    ZONESUB = "zonesub"
    WILDCARD = "wildcard"
    SELF = "self"
    SELFSELF = "selfsub"
    SELFWILD = "selfwild"
    MS_SELF = "ms-self"
    MS_SELFSUB = "ms-selfsub"
    MS_SUBDOMAIN = "ms-subdomain"
    MS_SUBDOMAIN_SELF_RHS = "ms-subdomain-self-rhs"
    KRB5_SELF = "krb5-self"
    KRB5_SELFSUB = "krb5-selfsub"
    KRB5_SUBDOMAIN = "krb5-subdomain"
    KRB5_SUBDOMAIN_SELF_RHS = "krb5-subdomain-self-rhs"
    TCP_SELF = "tcp-self"
    SIXTOFOUR_SELF = "6to4-self"
    EXTERNAL = "external"


class UpdatePolicyRule(BindBaseModel):
    """
    Rule for update-policy.

    Grammar: ( deny | grant ) <string> ( 6to4-self | external | krb5-self | krb5-selfsub |
              krb5-subdomain | krb5-subdomain-self-rhs | ms-self | ms-selfsub |
              ms-subdomain | ms-subdomain-self-rhs | name | self | selfsub | selfwild |
              subdomain | tcp-self | wildcard | zonesub ) [ <string> ] <rrtypelist>;
    """

    action: Literal["deny", "grant"] = Field(..., description="Action: deny or grant")
    identity: string_BIND = Field(..., description="Identifier (key or domain name)")
    rule_type: UpdatePolicyRuleTypeEnum = Field(..., description="Rule type")
    name: string_BIND | None = Field(default=None, description="Name for matching (optional)")
    record_types: list[string_BIND] = Field(default_factory=list, description="DNS record types")

    def model_bind_syntax(self, indent_level: int = 0) -> str:
        lines: list[str] = []
        self._add_comment(lines, indent_level)

        indent = self._indent(indent_level)
        parts = [f"{indent}{self.action} {self.identity} {self.rule_type.value}"]
        if self.name:
            parts.append(self.name)
        parts.append(" ".join(self.record_types))
        rule_line = " ".join(parts) + ";"

        lines.append(rule_line)
        return "\n".join(lines)


class UpdatePolicyBlock(BindBaseModel):
    """
    Update-policy block for zone.

    Grammar: update-policy ( local | { ( deny | grant ) <string> ( 6to4-self | external | ... )
              [ <string> ] <rrtypelist>; ... } );
    """

    local: boolean_BIND | None = Field(default=None, description="Use local policy")
    rules: list[UpdatePolicyRule] = Field(default_factory=list, description="List of rules")

    _exclude_from_syntax: ClassVar[set[str]] = {"local", "rules"}

    @model_validator(mode="after")
    def validate_update_policy(self) -> UpdatePolicyBlock:
        """Validate update policy."""
        if self.local and self.rules:
            raise ValueError("Cannot specify both 'local' and individual rules in update-policy")
        if not self.local and not self.rules:
            raise ValueError("update-policy must have either 'local' or a list of rules")
        return self

    def model_bind_syntax(self, indent_level: int = 0) -> str:
        lines: list[str] = []
        self._add_comment(lines, indent_level)

        indent = self._indent(indent_level)
        if self.local == "yes":
            lines.append(f"{indent}update-policy local;")
            return "\n".join(lines)

        lines.append(f"{indent}update-policy {{")
        for rule in self.rules:
            lines.append(rule.model_bind_syntax(indent_level + 1))
        lines.append(f"{indent}}};")
        return "\n".join(lines)


class ZoneBlock(BasicOptionsMixin):
    """
    Zone block for BIND configuration.

    Grammar:
    zone <string> [ <class> ] {
        type primary | secondary | mirror | hint | stub | static-stub | forward | redirect;
        ... # options depending on type
    };
    """

    name: domain_name_BIND = Field(..., description="Zone name")
    zone_type: ZoneTypeEnum = Field(..., description="Zone type")
    zone_class: ZoneClassEnum | None = Field(default=None, description="Zone class")

    check_names: Literal["fail", "warn", "ignore"] | None = Field(
        default=None, description="Check names policy"
    )
    database: string_BIND | None = Field(
        default=None, description="Database type for zone storage"
    )
    file: quoted_string_BIND | None = Field(default=None, description="Zone file name")
    forwarders: list[ip_v4_address_BIND | ip_v6_address_BIND] | None = Field(
        default=None, description="Forwarding servers"
    )
    masterfile_format: Literal["raw", "text"] | None = Field(
        default=None, description="Zone file format"
    )
    masterfile_style: Literal["full", "relative"] | None = Field(
        default=None, description="Zone dump style"
    )
    also_notify: (
        list[string_BIND | tuple[ip_v4_address_BIND | ip_v6_address_BIND, port_BIND | None]] | None
    ) = Field(default=None, description="Additional notify recipients")
    journal: quoted_string_BIND | None = Field(default=None, description="Journal file name")
    dnssec_loadkeys_interval: integer_BIND | None = Field(
        default=None, description="DNSSEC key repository check interval"
    )
    max_transfer_idle_out: integer_BIND | None = Field(
        default=None, description="Maximum idle time for outbound transfers"
    )
    max_transfer_time_out: integer_BIND | None = Field(
        default=None, description="Maximum outbound transfer time"
    )
    notify_defer: integer_BIND | None = Field(
        default=None, description="Delay before sending NOTIFY"
    )
    notify_delay: integer_BIND | None = Field(
        default=None, description="Delay between NOTIFY message sets"
    )
    notify_source: ip_v4_address_BIND | Literal["*"] | None = Field(
        default=None, description="Source IPv4 address for NOTIFY"
    )
    notify_source_v6: ip_v6_address_BIND | Literal["*"] | None = Field(
        default=None, description="Source IPv6 address for NOTIFY"
    )
    parental_agents: (
        list[string_BIND | tuple[ip_v4_address_BIND | ip_v6_address_BIND, port_BIND | None]] | None
    ) = Field(default=None, description="Parental agents for DNSSEC key rollover")
    parental_source: ip_v4_address_BIND | Literal["*"] | None = Field(
        default=None, description="Source IPv4 for parental agent queries"
    )
    parental_source_v6: ip_v6_address_BIND | Literal["*"] | None = Field(
        default=None, description="Source IPv6 for parental agent queries"
    )
    serial_update_method: Literal["date", "increment", "unixtime"] | None = Field(
        default=None, description="Dynamic DNS serial number update method"
    )
    update_policy: UpdatePolicyBlock | None = Field(
        default=None, description="Dynamic update policy"
    )
    max_refresh_time: integer_BIND | None = Field(default=None, description="Maximum refresh time")
    max_retry_time: integer_BIND | None = Field(default=None, description="Maximum retry time")
    max_transfer_idle_in: integer_BIND | None = Field(
        default=None, description="Maximum idle time for inbound transfers"
    )
    max_transfer_time_in: integer_BIND | None = Field(
        default=None, description="Maximum inbound transfer time"
    )
    min_refresh_time: integer_BIND | None = Field(default=None, description="Minimum refresh time")
    min_retry_time: integer_BIND | None = Field(default=None, description="Minimum retry time")
    primaries: (
        list[string_BIND | tuple[ip_v4_address_BIND | ip_v6_address_BIND, port_BIND | None]] | None
    ) = Field(default=None, description="Primary servers for secondary zone")
    transfer_source: ip_v4_address_BIND | Literal["*"] | None = Field(
        default=None, description="Source IPv4 for zone transfers"
    )
    transfer_source_v6: ip_v6_address_BIND | Literal["*"] | None = Field(
        default=None, description="Source IPv6 for zone transfers"
    )
    server_addresses: list[ip_v4_address_BIND | ip_v6_address_BIND] | None = Field(
        default=None, description="IP addresses for static-stub zone"
    )
    server_names: list[string_BIND] | None = Field(
        default=None, description="Server names for static-stub zone"
    )
    in_view: string_BIND | None = Field(default=None, description="View in which zone is defined")

    # NOTE: RR
    resource_records: list[ResourceRecordType] = Field(
        default_factory=list, description="List of resource records"
    )

    _exclude_from_syntax: ClassVar[set[str]] = {
        "name",
        "zone_type",
        "zone_class",
        "in_view",
        "resource_records",
    }

    @property
    def comparison_attr(self) -> str:
        return f"{self.name} {self.zone_type.value}"

    @model_validator(mode="after")
    def validate_zone_type_specific_fields(self) -> ZoneBlock:
        """Validate fields based on zone type."""
        zone_type = self.zone_type

        allowed_fields_map = {
            ZoneTypeEnum.PRIMARY: {
                "allow_query",
                "allow_query_on",
                "allow_transfer",
                "check_names",
                "database",
                "file",
                "forward",
                "forwarders",
                "masterfile_format",
                "masterfile_style",
                "max_records",
                "max_records_per_type",
                "max_types_per_name",
                "zone_statistics",
                # NOTE: SPECIFIC FIELDS
                "allow_update",
                "also_notify",
                "check_dup_records",
                "check_integrity",
                "check_mx",
                "check_mx_cname",
                "check_sibling",
                "check_spf",
                "check_srv_cname",
                "check_svcb",
                "check_wildcard",
                "checkds",
                "dnssec_loadkeys_interval",
                "dnssec_policy",
                "inline_signing",
                "ixfr_from_differences",
                "journal",
                "key_directory",
                "max_ixfr_ratio",
                "max_journal_size",
                "max_transfer_idle_out",
                "max_transfer_time_out",
                "notify",
                "notify_defer",
                "notify_delay",
                "notify_source",
                "notify_source_v6",
                "notify_to_soa",
                "parental_agents",
                "parental_source",
                "parental_source_v6",
                "serial_update_method",
                "sig_signing_nodes",
                "sig_signing_signatures",
                "sig_signing_type",
                "update_policy",
                "zero_no_soa_ttl",
                "resource_records",
            },
            ZoneTypeEnum.SECONDARY: {
                "allow_query",
                "allow_query_on",
                "allow_transfer",
                "check_names",
                "database",
                "file",
                "forward",
                "forwarders",
                "masterfile_format",
                "masterfile_style",
                "max_records",
                "max_records_per_type",
                "max_types_per_name",
                "zone_statistics",
                # NOTE: SPECIFIC FIELDS
                "allow_notify",
                "allow_update_forwarding",
                "also_notify",
                "checkds",
                "dnssec_loadkeys_interval",
                "dnssec_policy",
                "inline_signing",
                "ixfr_from_differences",
                "journal",
                "key_directory",
                "max_ixfr_ratio",
                "max_journal_size",
                "max_refresh_time",
                "max_retry_time",
                "max_transfer_idle_in",
                "max_transfer_idle_out",
                "max_transfer_time_in",
                "max_transfer_time_out",
                "min_refresh_time",
                "min_retry_time",
                "min_transfer_rate_in",
                "multi_master",
                "notify",
                "notify_defer",
                "notify_delay",
                "notify_source",
                "notify_source_v6",
                "notify_to_soa",
                "parental_agents",
                "parental_source",
                "parental_source_v6",
                "primaries",
                "request_expire",
                "request_ixfr",
                "sig_signing_nodes",
                "sig_signing_signatures",
                "sig_signing_type",
                "transfer_source",
                "transfer_source_v6",
                "try_tcp_refresh",
                "zero_no_soa_ttl",
                "resource_records",
            },
            ZoneTypeEnum.MIRROR: {
                "allow_notify",
                "allow_query",
                "allow_query_on",
                "allow_transfer",
                "allow_update_forwarding",
                "also_notify",
                "check_names",
                "database",
                "file",
                "ixfr_from_differences",
                "journal",
                "masterfile_format",
                "masterfile_style",
                "max_ixfr_ratio",
                "max_journal_size",
                "max_records",
                "max_records_per_type",
                "max_refresh_time",
                "max_retry_time",
                "max_transfer_idle_in",
                "max_transfer_idle_out",
                "max_transfer_time_in",
                "max_transfer_time_out",
                "max_types_per_name",
                "min_refresh_time",
                "min_retry_time",
                "min_transfer_rate_in",
                "multi_master",
                "notify",
                "notify_defer",
                "notify_delay",
                "notify_source",
                "notify_source_v6",
                "primaries",
                "request_expire",
                "request_ixfr",
                "transfer_source",
                "transfer_source_v6",
                "try_tcp_refresh",
                "zero_no_soa_ttl",
                "zone_statistics",
                "resource_records",
            },
            ZoneTypeEnum.HINT: {
                "check_names",
                "file",
                "resource_records",
            },
            ZoneTypeEnum.STUB: {
                "allow_query",
                "allow_query_on",
                "check_names",
                "database",
                "file",
                "forward",
                "forwarders",
                "masterfile_format",
                "masterfile_style",
                "max_records",
                "max_records_per_type",
                "max_refresh_time",
                "max_retry_time",
                "max_transfer_idle_in",
                "max_transfer_time_in",
                "max_types_per_name",
                "min_refresh_time",
                "min_retry_time",
                "min_transfer_rate_in",
                "multi_master",
                "primaries",
                "transfer_source",
                "transfer_source_v6",
                "zone_statistics",
                "resource_records",
            },
            ZoneTypeEnum.STATIC_STUB: {
                "allow_query",
                "allow_query_on",
                "forward",
                "forwarders",
                "max_records",
                "max_records_per_type",
                "max_types_per_name",
                "server_addresses",
                "server_names",
                "zone_statistics",
                "resource_records",
            },
            ZoneTypeEnum.FORWARD: {
                "forward",
                "forwarders",
                "resource_records",
            },
            ZoneTypeEnum.REDIRECT: {
                "allow_query",
                "allow_query_on",
                "database",
                "file",
                "masterfile_format",
                "masterfile_style",
                "max_records",
                "max_records_per_type",
                "max_types_per_name",
                "primaries",
                "zone_statistics",
                "resource_records",
            },
            ZoneTypeEnum.IN_VIEW: {"in_view"},
        }

        basic_fields = {"name", "zone_type", "zone_class", "comment"}

        if zone_type == ZoneTypeEnum.IN_VIEW:
            if self.in_view is None:
                raise ValueError("Zone of type 'in-view' must have 'in_view' field specified")

            allowed_fields = basic_fields.union({"in_view"})
            for field_name, value in self.model_dump(exclude_unset=True).items():
                if value is not None and field_name not in allowed_fields:
                    raise ValueError(
                        f"Field '{field_name}' is not allowed for zone of type 'in-view'"
                    )
        else:
            allowed_fields = basic_fields.union(allowed_fields_map.get(zone_type, set()))
            for field_name, value in self.model_dump(exclude_unset=True).items():
                if value is not None and field_name not in allowed_fields:
                    raise ValueError(
                        f"Field '{field_name}' is not allowed for zone of type '{zone_type}'"
                    )

        return self

    def _mixed_server_list_formating(
        self,
        value: list[
            string_BIND | tuple[ip_v4_address_BIND | ip_v6_address_BIND, port_BIND | None]
        ],
        indent_level: int,
        block_name: str,
    ) -> str:
        """Format mixed server list (strings and tuples) for BIND syntax."""
        if not value:
            return ""

        indent = self._indent(indent_level)
        inner_indent = self._indent(indent_level + 1)

        def sort_key(item: Any) -> Any:
            if isinstance(item, tuple):
                address, port = item if len(item) == 2 else (item[0], None)
                return (str(address), port or 0)
            return (str(item), 0)

        lines = [f"{indent}{block_name} {{"]
        for item in sorted(value, key=sort_key):
            if isinstance(item, tuple):
                address, port = item if len(item) == 2 else (item[0], None)
                if port is not None:
                    lines.append(f"{inner_indent}{address} port {port};")
                else:
                    lines.append(f"{inner_indent}{address};")
            else:
                lines.append(f"{inner_indent}{item};")
        lines.append(f"{indent}}};")

        return "\n".join(lines)

    def _format_also_notify(
        self,
        value: list[
            string_BIND | tuple[ip_v4_address_BIND | ip_v6_address_BIND, port_BIND | None]
        ],
        indent_level: int,
    ) -> str:
        return self._mixed_server_list_formating(value, indent_level, "also-notify")

    def _format_primaries(
        self,
        value: list[
            string_BIND | tuple[ip_v4_address_BIND | ip_v6_address_BIND, port_BIND | None]
        ],
        indent_level: int,
    ) -> str:
        return self._mixed_server_list_formating(value, indent_level, "primaries")

    def _format_parental_agents(
        self,
        value: list[
            string_BIND | tuple[ip_v4_address_BIND | ip_v6_address_BIND, port_BIND | None]
        ],
        indent_level: int,
    ) -> str:
        return self._mixed_server_list_formating(value, indent_level, "parental-agents")

    def model_bind_syntax(self, indent_level: int = 0) -> str:
        lines: list[str] = []
        self._add_comment(lines, indent_level)

        indent = self._indent(indent_level)
        inner_indent = self._indent(indent_level + 1)

        zone_header = f"zone {self.name}"
        if self.zone_class and self.zone_class != ZoneClassEnum.IN:
            zone_header += f" {self.zone_class.value}"

        lines.append(f"{indent}{zone_header} {{")
        lines.append(f"{inner_indent}type {self.zone_type.value};")

        lines.extend(self.auto_format_fields(indent_level + 1))

        if self.zone_type == ZoneTypeEnum.IN_VIEW and self.in_view:
            lines.append(f"{inner_indent}in-view {self.in_view};")

        lines.append(f"{indent}}};")
        return "\n".join(lines)

    def model_bind_syntax_zone_file(self, indent_level: int = 0) -> str:
        """
        Generate zone file syntax for BIND zone files.

        Grammar:
        ```
        $TTL <duration>
        $ORIGIN <domain_name>

        ; Zone records follow:
        <name> [<ttl>] [<class>] <type> <rdata>
        ...
        ```
        """
        if not self.resource_records:
            raise ValueError(
                f"Zone '{self.name}' has no resource records to generate zone file content."
            )

        lines: list[str] = []

        sorted_records = sort_resource_records(self.resource_records)  # type: ignore[arg-type]
        for record in sorted_records:
            lines.append(record.model_bind_syntax(indent_level))

        return "\n".join(lines)
