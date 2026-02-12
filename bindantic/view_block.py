from __future__ import annotations

from typing import Any, ClassVar

from pydantic import Field, model_validator

from ._base_types import (
    address_match_list_BIND,
    boolean_BIND,
    string_BIND,
)
from .dnssec_policy_block import DnssecPolicyBlock
from .key_block import KeyBlock
from .options_block import ExtendedOptionsMixin
from .server_block import ServerBlock
from .trust_anchors_block import TrustAnchorsBlock
from .zone_block import ZoneBlock, ZoneClassEnum


class ViewBlock(ExtendedOptionsMixin):
    """
    View block for BIND9 configuration.

    Grammar:
    view <string> [ <class> ] {
        ... # view-specific options and zones
    };

    Allows a name server to answer a DNS query differently depending on who is asking.
    """

    name: string_BIND = Field(..., description="View name")
    view_class: ZoneClassEnum | None = Field(default=None, description="View class (default: IN)")
    match_clients: address_match_list_BIND | None = Field(
        default=None, description="Clients that match this view based on source IP address"
    )
    match_destinations: address_match_list_BIND | None = Field(
        default=None,
        description="Destinations that match this view based on destination IP address",
    )
    match_recursive_only: boolean_BIND | None = Field(
        default=None, description="Only recursive requests can match this view"
    )
    server_blocks: list[ServerBlock] | None = Field(
        default=None, description="Server-specific configuration blocks"
    )
    key_blocks: list[KeyBlock] | None = Field(default=None, description="TSIG key definitions")
    trust_anchors: list[TrustAnchorsBlock] | None = Field(
        default=None, description="DNSSEC trust anchors"
    )
    dnssec_policy_block: DnssecPolicyBlock | None = Field(
        default=None, description="DNSSEC policy configuration"
    )
    # NOTE: ZONE BLOCKS
    view_zones: list[ZoneBlock] | None = Field(
        default=None, description="Zones defined within this view"
    )

    _exclude_from_syntax: ClassVar[set[str]] = {
        "name",
        "zone_type",
        "zone_class",
        "view_class",
        "in_view",
        "version",
        "hostname",
        "server_id",
    }

    @model_validator(mode="after")
    def validate_non_in_view_requires_hint_zone(self) -> ViewBlock:
        """
        Validate that non-IN views contain a hint zone.

        According to BIND9 documentation: "Note that all non-IN views must contain
        a hint zone, since only the IN class has compiled-in default hints."
        """
        if self.view_class and self.view_class != ZoneClassEnum.IN and self.view_zones:
            has_hint_zone = any(zone.zone_type == "hint" for zone in self.view_zones)

            if not has_hint_zone:
                has_root_hint = any(
                    zone.zone_type == "hint" and zone.name == "." for zone in self.view_zones
                )
                if not has_root_hint:
                    raise ValueError(
                        f"non-IN view '{self.name}' (class {self.view_class}) "
                        f"should contain a hint zone for the root ('.') or other necessary hints."
                    )

        return self

    # TODO ? View has no match conditions validator
    # @model_validator(mode="after")
    # def validate_match_conditions(self):
    #     """
    #     Validate match conditions for the view.

    #     A view should have at least one match condition (match-clients,
    #     match-destinations, or match-recursive-only) to be useful.
    #     """
    #     if not any(
    #         [self.match_clients, self.match_destinations, self.match_recursive_only is not None]
    #     ):
    #         print(
    #             f"Warning: view '{self.name}' has no match conditions "
    #             f"(match-clients, match-destinations, or match-recursive-only). "
    #             f"It will match all requests."
    #         )

    #     return self

    def _format_key_blocks(self, value: Any, indent_level: int = 0) -> str:
        if not value:
            return ""

        indent = self._indent(indent_level)
        inner_indent = self._indent(indent_level + 1)

        lines = [f"{indent}key-blocks {{"]
        for key_block in value:
            key_lines = key_block.model_bind_syntax(0).split("\n")
            for line in key_lines:
                lines.append(f"{inner_indent}{line}")
        lines.append(f"{indent}}};")
        return "\n".join(lines)

    def _format_server_blocks(self, value: Any, indent_level: int = 0) -> str:
        if not value:
            return ""

        indent = self._indent(indent_level)
        inner_indent = self._indent(indent_level + 1)

        lines = [f"{indent}server-blocks {{"]
        for server_block in value:
            server_lines = server_block.model_bind_syntax(0).split("\n")
            for line in server_lines:
                lines.append(f"{inner_indent}{line}")
        lines.append(f"{indent}}};")
        return "\n".join(lines)

    def _format_trust_anchors(self, value: Any, indent_level: int = 0) -> str:
        if not value:
            return ""

        indent = self._indent(indent_level)
        inner_indent = self._indent(indent_level + 1)

        lines = [f"{indent}trust-anchors {{"]
        for trust_anchor in value:
            trust_lines = trust_anchor.model_bind_syntax(0).split("\n")
            for line in trust_lines:
                lines.append(f"{inner_indent}{line}")
        lines.append(f"{indent}}};")
        return "\n".join(lines)

    def _format_view_zones(self, value: Any, indent_level: int = 0) -> str:
        if not value:
            return ""

        lines = []
        for zone in value:
            zone_lines = zone.model_bind_syntax(indent_level).split("\n")
            lines.extend(zone_lines)
        return "\n".join(lines)

    def model_bind_syntax(self, indent_level: int = 0) -> str:
        lines: list[str] = []
        self._add_comment(lines, indent_level)

        indent = self._indent(indent_level)

        view_header = f"view {self.name}"
        if self.view_class and self.view_class != ZoneClassEnum.IN:
            view_header += f" {self.view_class.value}"

        lines.append(f"{indent}{view_header} {{")

        lines.extend(self.auto_format_fields(indent_level + 1))

        lines.append(f"{indent}}};")
        return "\n".join(lines)
