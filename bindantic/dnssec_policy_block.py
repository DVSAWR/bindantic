from __future__ import annotations

from enum import Enum
from typing import ClassVar, Literal

from pydantic import Field, field_validator, model_validator

from ._base_model import BindBaseModel
from ._base_types import (
    boolean_BIND,
    duration_BIND,
    integer_BIND,
    string_BIND,
)


class KeyRoleEnum(str, Enum):
    """Key roles in DNSSEC policy."""

    CSK = "csk"
    KSK = "ksk"
    ZSK = "zsk"


class KeyStorageEnum(str, Enum):
    """Key storage types."""

    KEY_DIRECTORY = "key-directory"
    KEY_STORE = "key-store"


class DnssecAlgorithmEnum(str, Enum):
    """DNSSEC algorithms as defined by BIND."""

    RSAMD5 = "rsamd5"  # NOTE: 1 - DEPRECATED
    DH = "dh"  # NOTE: 2 - DEPRECATED
    DSA = "dsa"  # NOTE: 3 - DEPRECATED
    RSASHA1 = "rsasha1"  # NOTE: 5 - DEPRECATED
    DSA_NSEC3_SHA1 = "dsa-nsec3-sha1"  # NOTE: 6 - DEPRECATED
    RSASHA1_NSEC3_SHA1 = "rsasha1-nsec3-sha1"  # NOTE: 7 - DEPRECATED
    RSASHA256 = "rsasha256"  # NOTE: 8 - Recommended
    RSASHA512 = "rsasha512"  # NOTE: 10 - Recommended
    ECC_GOST = "ecc-gost"  # NOTE: 12 - DEPRECATED
    ECDSAP256SHA256 = "ecdsap256sha256"  # NOTE: 13 - Recommended
    ECDSAP384SHA384 = "ecdsap384sha384"  # NOTE: 14 - Recommended
    ED25519 = "ed25519"  # NOTE: 15 - Recommended
    ED448 = "ed448"  # NOTE: 16 - Recommended

    @classmethod
    def from_value(cls, value: str | int) -> DnssecAlgorithmEnum:
        """Convert string or numeric algorithm to enum."""
        if isinstance(value, int):
            num_to_algo = {
                1: cls.RSAMD5,
                2: cls.DH,
                3: cls.DSA,
                5: cls.RSASHA1,
                6: cls.DSA_NSEC3_SHA1,
                7: cls.RSASHA1_NSEC3_SHA1,
                8: cls.RSASHA256,
                10: cls.RSASHA512,
                12: cls.ECC_GOST,
                13: cls.ECDSAP256SHA256,
                14: cls.ECDSAP384SHA384,
                15: cls.ED25519,
                16: cls.ED448,
            }
            if value in num_to_algo:
                return num_to_algo[value]
            raise ValueError(f"Invalid DNSSEC algorithm number: {value}")

        value_lower = value.lower()
        try:
            return cls(value_lower)
        except ValueError as exc:
            for algo in cls:
                if algo.value.lower() == value_lower:
                    return algo
            raise ValueError(f"Invalid DNSSEC algorithm: {value}") from exc


class DnssecKeyEntry(BindBaseModel):
    """
    Key entry in dnssec-policy keys block.

    Grammar:
    ```
    ( csk | ksk | zsk ) [ key-directory | key-store <string> ]
             lifetime <duration_or_unlimited> algorithm <string>
             [ tag-range <integer> <integer> ] [ <integer> ];
    ```
    """

    role: KeyRoleEnum = Field(..., description="Key role: csk, ksk, or zsk")
    storage_type: KeyStorageEnum | None = Field(
        default=None, description="Storage type: key-directory or key-store"
    )
    key_store_name: string_BIND | None = Field(
        default=None, description="Name of key store (if storage_type is key-store)"
    )
    lifetime: duration_BIND | Literal["unlimited"] = Field(
        ..., description="Key lifetime or 'unlimited'"
    )
    algorithm: DnssecAlgorithmEnum | string_BIND | int = Field(
        ..., description="DNSSEC algorithm name or number"
    )
    key_size: integer_BIND | None = Field(
        default=None, ge=0, description="Key size in bits (optional, must be positive)"
    )
    tag_range: tuple[integer_BIND, integer_BIND] | None = Field(
        default=None, description="Valid key tag range [min, max]"
    )

    @property
    def comparison_attr(self) -> tuple[str, str]:
        return self.role.value, str(self.lifetime)

    @field_validator("algorithm", mode="before")
    @classmethod
    def normalize_algorithm(
        cls, v: DnssecAlgorithmEnum | string_BIND | int
    ) -> DnssecAlgorithmEnum:
        """Normalize algorithm to enum if possible."""
        if isinstance(v, DnssecAlgorithmEnum):
            return v
        return DnssecAlgorithmEnum.from_value(v)

    @field_validator("algorithm", mode="after")
    @classmethod
    def ensure_string_format(cls, v: DnssecAlgorithmEnum | string_BIND | int) -> str:
        """Ensure algorithm is properly formatted for BIND."""
        if isinstance(v, DnssecAlgorithmEnum):
            return v.value
        return str(v)

    @field_validator("tag_range")
    @classmethod
    def validate_tag_range(
        cls, v: tuple[integer_BIND, integer_BIND] | None
    ) -> tuple[integer_BIND, integer_BIND] | None:
        if v is not None:
            min_tag, max_tag = v
            if min_tag < 0 or min_tag > 65535:
                raise ValueError(f"Minimum tag must be between 0 and 65535: {min_tag}")
            if max_tag < 0 or max_tag > 65535:
                raise ValueError(f"Maximum tag must be between 0 and 65535: {max_tag}")
            if min_tag > max_tag:
                raise ValueError(
                    f"Minimum tag ({min_tag}) cannot be greater than maximum tag ({max_tag})"
                )
        return v

    def model_bind_syntax(self, indent_level: int = 0) -> str:
        lines: list[str] = []
        self._add_comment(lines, indent_level)

        indent = self._indent(indent_level)

        parts = [self.role.value]

        if self.storage_type == KeyStorageEnum.KEY_STORE and self.key_store_name:
            parts.append(f"key-store {self.key_store_name}")
        elif self.storage_type == KeyStorageEnum.KEY_DIRECTORY:
            parts.append("key-directory")

        parts.append(f"lifetime {self.lifetime}")
        parts.append(f"algorithm {self.algorithm}")

        if self.tag_range:
            min_tag, max_tag = self.tag_range
            parts.append(f"tag-range {min_tag} {max_tag}")

        if self.key_size is not None:
            parts.append(str(self.key_size))

        line = " ".join(parts)
        lines.append(f"{indent}{line};")
        return "\n".join(lines)


class DnssecDigestTypeEnum(str, Enum):
    """DNSSEC digest types for CDS records."""

    SHA1 = "SHA-1"
    SHA256 = "SHA-256"
    SHA384 = "SHA-384"
    SHA512 = "SHA-512"


class Nsec3ParamBlock(BindBaseModel):
    """
    NSEC3 parameters configuration.

    Grammar:
    ```
    nsec3param [ iterations <integer> ] [ optout <boolean> ] [ salt-length <integer> ];
    ```
    """

    iterations: integer_BIND | None = Field(
        default=None, ge=0, description="Number of hash iterations (default: 0)"
    )
    optout: boolean_BIND | None = Field(default=None, description="Enable opt-out (default: no)")
    salt_length: integer_BIND | None = Field(
        default=None, ge=0, le=255, description="Salt length in bytes (default: 0)"
    )

    def model_bind_syntax(self, indent_level: int = 0) -> str:
        lines: list[str] = []
        self._add_comment(lines, indent_level)

        indent = self._indent(indent_level)

        parts = ["nsec3param"]

        if self.iterations is not None:
            parts.append(f"iterations {self.iterations}")

        if self.optout is not None:
            parts.append(f"optout {self.optout}")

        if self.salt_length is not None:
            parts.append(f"salt-length {self.salt_length}")

        line = " ".join(parts)
        lines.append(f"{indent}{line};")
        return "\n".join(lines)


class DnssecPolicyBlock(BindBaseModel):
    """
    DNSSEC key and signing policy (KASP) configuration block for BIND.

    Built-in policies: "default", "insecure", "none"

    Grammar:
    ```
    dnssec-policy <string> {
        cdnskey <boolean>;
        cds-digest-types { <string>; ... };
        dnskey-ttl <duration>;
        inline-signing <boolean>;
        keys { ... };
        manual-mode <boolean>;
        max-zone-ttl <duration>;
        nsec3param [ ... ];
        offline-ksk <boolean>;
        parent-ds-ttl <duration>;
        parent-propagation-delay <duration>;
        publish-safety <duration>;
        purge-keys <duration>;
        retire-safety <duration>;
        signatures-jitter <duration>;
        signatures-refresh <duration>;
        signatures-validity <duration>;
        signatures-validity-dnskey <duration>;
        zone-propagation-delay <duration>;
    };
    ```
    """

    name: string_BIND = Field(..., description="Name of the DNSSEC policy")
    cdnskey: boolean_BIND | None = Field(
        default=None, description="Publish CDNSKEY records during KSK rollover"
    )
    inline_signing: boolean_BIND | None = Field(
        default=None, description="Maintain separate signed version of zone"
    )
    manual_mode: boolean_BIND | None = Field(
        default=None, description="Run key management in manual mode"
    )
    offline_ksk: boolean_BIND | None = Field(
        default=None, description="Sign DNSKEY/CDS/CDNSKEY RRsets offline"
    )
    dnskey_ttl: duration_BIND | None = Field(
        default=None, description="TTL for DNSKEY records (default: 1h)"
    )
    max_zone_ttl: duration_BIND | None = Field(
        default=None, description="Maximum TTL for zone records (default: 24h)"
    )
    parent_ds_ttl: duration_BIND | None = Field(
        default=None, description="TTL of DS RRset in parent zone (default: 1d)"
    )
    parent_propagation_delay: duration_BIND | None = Field(
        default=None, description="Parent zone propagation delay (default: 1h)"
    )
    publish_safety: duration_BIND | None = Field(
        default=None, description="Safety margin before key activation (default: 1h)"
    )
    purge_keys: duration_BIND | None = Field(
        default=None, description="Time to keep deleted keys (default: 90d)"
    )
    retire_safety: duration_BIND | None = Field(
        default=None, description="Safety margin after key deactivation (default: 1h)"
    )
    signatures_jitter: duration_BIND | None = Field(
        default=None, description="Jitter range for signature expiration (default: 12h)"
    )
    signatures_refresh: duration_BIND | None = Field(
        default=None, description="Signature refresh interval (default: 5d)"
    )
    signatures_validity: duration_BIND | None = Field(
        default=None, description="Signature validity period (default: 2w)"
    )
    signatures_validity_dnskey: duration_BIND | None = Field(
        default=None, description="DNSKEY signature validity period (default: 2w)"
    )
    zone_propagation_delay: duration_BIND | None = Field(
        default=None, description="Zone propagation delay (default: 5m)"
    )
    cds_digest_types: list[DnssecDigestTypeEnum] | None = Field(
        default=None, description="Digest types for CDS records (default: SHA-256 only)"
    )
    keys: list[DnssecKeyEntry] | None = Field(default=None, description="Key specifications")
    nsec3param: Nsec3ParamBlock | None = Field(
        default=None, description="NSEC3 parameters (use NSEC3 instead of NSEC)"
    )

    _BUILTIN_POLICIES: ClassVar[set[str]] = {"default", "insecure", "none"}
    _exclude_from_syntax: ClassVar[set[str]] = {"name"}

    @field_validator("cds_digest_types", mode="before")
    @classmethod
    def normalize_digest_types(
        cls, v: list[DnssecDigestTypeEnum] | None
    ) -> list[DnssecDigestTypeEnum] | None:
        """Normalize digest types to enum."""
        if v is None:
            return v

        result = []
        if isinstance(v, list):
            for item in v:
                if isinstance(item, DnssecDigestTypeEnum):
                    result.append(item)
                else:
                    item_str = str(item).upper()  # type: ignore[unreachable]
                    for digest in DnssecDigestTypeEnum:
                        if digest.value.upper() == item_str:
                            result.append(digest)
                            break
                    else:
                        raise ValueError(
                            f"Invalid CDS digest type: {item}. "
                            f"Must be one of: {', '.join(d.value for d in DnssecDigestTypeEnum)}"
                        )
        return result

    @field_validator("cds_digest_types", mode="after")
    @classmethod
    def validate_digest_types_format(
        cls, v: list[DnssecDigestTypeEnum] | None
    ) -> list[str] | None:
        """Convert digest types to proper BIND syntax."""
        if v is None:
            return v
        return [digest.value for digest in v]

    @model_validator(mode="after")
    def validate_policy_consistency(self) -> DnssecPolicyBlock:
        name = self.name

        if name in self._BUILTIN_POLICIES:
            model_fields = self.__class__.model_fields
            fields_to_check = [
                field
                for field in model_fields
                if field not in ["name", "comment"] and getattr(self, field) is not None
            ]

            if fields_to_check:
                raise ValueError(
                    f"Built-in DNSSEC policy '{name}' cannot have additional parameters. "
                    f"Specified parameters: {fields_to_check}"
                )
            return self

        if self.keys:
            roles = [key.role for key in self.keys]

            # NOTE: ValueError for mix CSK with KSK/ZSK
            if KeyRoleEnum.CSK in roles and (KeyRoleEnum.KSK in roles or KeyRoleEnum.ZSK in roles):
                raise ValueError("Cannot mix CSK with KSK/ZSK in the same policy")

            if KeyRoleEnum.KSK in roles and KeyRoleEnum.ZSK in roles:
                ksk_algorithms = {
                    key.algorithm for key in self.keys if key.role == KeyRoleEnum.KSK
                }
                zsk_algorithms = {
                    key.algorithm for key in self.keys if key.role == KeyRoleEnum.ZSK
                }
                if ksk_algorithms != zsk_algorithms:
                    raise ValueError(
                        f"KSK algorithms ({ksk_algorithms}) "
                        f"must match ZSK algorithms ({zsk_algorithms})"
                    )

            # NOTE: offline-ksk constraint
            if self.offline_ksk == "yes" and any(key.role == KeyRoleEnum.CSK for key in self.keys):
                raise ValueError("Cannot use offline-ksk with CSK")

        return self

    def _format_keys(self, value: list[DnssecKeyEntry], indent_level: int) -> str:
        """Special formatter for keys field in DNSSEC policy."""
        indent = self._indent(indent_level)

        if not value:
            return ""

        lines = [f"{indent}keys {{"]
        for key in value:
            key_str = key.model_bind_syntax(indent_level + 1)
            lines.append(key_str)
        lines.append(f"{indent}}};")

        return "\n".join(lines)

    def model_bind_syntax(self, indent_level: int = 0) -> str:
        lines: list[str] = []
        self._add_comment(lines, indent_level)

        indent = self._indent(indent_level)

        if self.name in self._BUILTIN_POLICIES:
            lines.append(f"{indent}dnssec-policy {self.name};")
            return "\n".join(lines)

        lines.append(f"{indent}dnssec-policy {self.name} {{")
        lines.extend(self.auto_format_fields(indent_level + 1))
        lines.append(f"{indent}}};")
        return "\n".join(lines)
