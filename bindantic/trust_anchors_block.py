from __future__ import annotations

from enum import Enum
from typing import Any, Literal

from pydantic import Field, field_validator, model_validator

from ._base_model import BindBaseModel
from ._base_types import (
    integer_BIND,
    quoted_string_BIND,
    string_BIND,
)


class AnchorTypeEnum(str, Enum):
    """Типы DNSSEC trust anchors."""

    STATIC_KEY = "static-key"
    INITIAL_KEY = "initial-key"
    STATIC_DS = "static-ds"
    INITIAL_DS = "initial-ds"


class BaseTrustAnchor(BindBaseModel):
    domain: string_BIND = Field(..., description="Domain name for the trust anchor")

    # @property
    # def comparison_attr(self):
    #     pass


class KeyTrustAnchor(BaseTrustAnchor):
    """
    Trust anchor entry for DNSKEY format (static-key or initial-key).

    Format: <domain> static-key|initial-key <flags> <protocol> <algorithm> <key_data>
    """

    anchor_type: Literal[AnchorTypeEnum.STATIC_KEY, AnchorTypeEnum.INITIAL_KEY] = Field(
        ..., description="Type of key trust anchor"
    )
    flags: integer_BIND = Field(..., description="DNSKEY flags (256 for ZSK, 257 for KSK)")
    protocol: integer_BIND = Field(..., description="DNSKEY protocol (must be 3 for DNSSEC)")
    algorithm: integer_BIND = Field(..., description="DNSSEC algorithm number")
    key_data: quoted_string_BIND = Field(..., description="Base64 encoded public key data")

    @property
    def comparison_attr(self) -> str:
        return str(self.anchor_type.value)

    @field_validator("flags")
    def validate_flags(cls, v: integer_BIND) -> integer_BIND:
        """Validate DNSKEY flags."""
        if v not in [256, 257]:
            raise ValueError(f"Invalid DNSKEY flags: {v}. Must be 256 (ZSK) or 257 (KSK)")
        return v

    @field_validator("protocol")
    def validate_protocol(cls, v: integer_BIND) -> integer_BIND:
        """Validate DNSKEY protocol."""
        if v != 3:
            raise ValueError(f"Invalid DNSKEY protocol: {v}. Must be 3 for DNSSEC")
        return v

    @field_validator("algorithm")
    def validate_algorithm(cls, v: integer_BIND) -> integer_BIND:
        """Validate DNSSEC algorithm."""
        if v not in [1, 2, 3, 5, 6, 7, 8, 10, 12, 13, 14, 15, 16]:
            raise ValueError(f"Warning: Uncommon DNSSEC algorithm: {v}")
        return v

    def model_bind_syntax(self, indent_level: int = 0) -> str:
        lines: list[str] = []
        self._add_comment(lines, indent_level)

        indent = self._indent(indent_level)

        line_parts = [
            self.domain,
            self.anchor_type.value,
            str(self.flags),
            str(self.protocol),
            str(self.algorithm),
            self.key_data,
        ]

        lines.append(f"{indent}{' '.join(line_parts)};")
        return "\n".join(lines)


class DSTrustAnchor(BaseTrustAnchor):
    """
    Trust anchor entry for DS format (static-ds or initial-ds).

    Format: <domain> static-ds|initial-ds <key_tag> <algorithm> <digest_type> <digest>
    """

    anchor_type: Literal[AnchorTypeEnum.STATIC_DS, AnchorTypeEnum.INITIAL_DS] = Field(
        ..., description="Type of DS trust anchor"
    )
    key_tag: integer_BIND = Field(..., ge=0, le=65535, description="Key tag value")
    algorithm: integer_BIND = Field(..., description="DNSSEC algorithm number")
    digest_type: integer_BIND = Field(
        ..., description="Digest type (1=SHA1, 2=SHA256, 3=SHA384, 4=SHA512)"
    )
    digest: quoted_string_BIND = Field(..., description="Hexadecimal digest value")

    @property
    def comparison_attr(self) -> str:
        return str(self.anchor_type.value)

    # TODO ? algorithm validator
    # @field_validator("algorithm")
    # def validate_algorithm(cls, v):
    #     """Validate DNSSEC algorithm."""
    #     if v not in [1, 2, 3, 5, 6, 7, 8, 10, 12, 13, 14, 15, 16]:
    #         print(f"Warning: Uncommon DNSSEC algorithm: {v}")
    #     return v

    @field_validator("digest_type")
    def validate_digest_type(cls, v: integer_BIND) -> integer_BIND:
        """Validate digest type."""
        valid_digest_types = [1, 2, 3, 4]  # NOTE: SHA1, SHA256, SHA384, SHA512
        if v not in valid_digest_types:
            raise ValueError(f"Invalid digest type: {v}. Must be one of: {valid_digest_types}")
        return v

    @field_validator("digest")
    def validate_digest(cls, v: quoted_string_BIND) -> quoted_string_BIND:
        """Validate hexadecimal digest."""
        digest_str = v.strip().strip("'\"")

        try:
            int(digest_str, 16)
        except ValueError as exc:
            raise ValueError(f"Invalid hexadecimal digest: {digest_str}") from exc

        return v

    def model_bind_syntax(self, indent_level: int = 0) -> str:
        lines: list[str] = []
        self._add_comment(lines, indent_level)

        indent = self._indent(indent_level)

        line_parts = [
            self.domain,
            self.anchor_type.value,
            str(self.key_tag),
            str(self.algorithm),
            str(self.digest_type),
            self.digest,
        ]

        lines.append(f"{indent}{' '.join(line_parts)};")
        return "\n".join(lines)


TrustAnchorEntry = KeyTrustAnchor | DSTrustAnchor


class TrustAnchorsBlock(BindBaseModel):
    """
    Trust anchors configuration block for DNSSEC in BIND.

    Grammar:
    trust-anchors {
        <string> ( static-key | initial-key | static-ds | initial-ds )
        <integer> <integer> <integer> <quoted_string>;
        ...
    }; // may occur multiple times

    Blocks: topmost, view
    Tags: dnssec
    """

    anchors: list[TrustAnchorEntry] = Field(
        default_factory=list, description="List of trust anchor entries"
    )

    def _format_anchors(self, value: list[TrustAnchorEntry], indent_level: int) -> str:
        """Special formatter for anchors field - don't wrap in a block."""
        lines = []
        for anchor in sorted(value, key=lambda a: a.comparison_attr):
            lines.append(anchor.model_bind_syntax(indent_level))
        return "\n".join(lines)

    @model_validator(mode="after")
    def validate_anchor_uniqueness(self) -> TrustAnchorsBlock:
        """Validate that there are no mixed static/initial anchors for the same domain."""
        domain_types: dict[str, Any] = {}

        for anchor in self.anchors:
            domain = anchor.domain
            anchor_type = anchor.anchor_type

            if domain not in domain_types:
                domain_types[domain] = []

            domain_types[domain].append(anchor_type)

        for domain, types in domain_types.items():
            base_types = []
            for t in types:
                if "static" in t:
                    base_types.append("static")
                elif "initial" in t:
                    base_types.append("initial")

            if len(set(base_types)) > 1:
                raise ValueError(
                    f"Cannot mix static and initial trust anchors for the same domain: {domain}. "
                    f"Found types: {types}"
                )

        return self

    def model_bind_syntax(self, indent_level: int = 0) -> str:
        lines: list[str] = []
        self._add_comment(lines, indent_level)

        indent = self._indent(indent_level)

        lines.append(f"{indent}trust-anchors {{")
        lines.extend(self.auto_format_fields(indent_level + 1))
        lines.append(f"{indent}}};")
        return "\n".join(lines)
