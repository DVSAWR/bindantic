from __future__ import annotations

from typing import ClassVar

from pydantic import Field, field_validator, model_validator

from ._base_model import BindBaseModel
from ._base_types import (
    boolean_BIND,
    quoted_string_BIND,
    string_BIND,
)


class TlsBlock(BindBaseModel):
    """
    TLS configuration block for BIND.

    Grammar:
    tls <string> {
        ca-file <quoted_string>;
        cert-file <quoted_string>;
        cipher-suites <string>;
        ciphers <string>;
        dhparam-file <quoted_string>;
        key-file <quoted_string>;
        prefer-server-ciphers <boolean>;
        protocols { <string>; ... };
        remote-hostname <quoted_string>;
        session-tickets <boolean>;
    }; // may occur multiple times

    Blocks: topmost
    Tags: security
    """

    name: string_BIND = Field(..., description="Name of the TLS configuration")
    key_file: quoted_string_BIND | None = Field(
        default=None, description="Path to private TLS key file"
    )
    cert_file: quoted_string_BIND | None = Field(
        default=None, description="Path to TLS certificate file"
    )
    ca_file: quoted_string_BIND | None = Field(
        default=None, description="Path to trusted CA certificates file"
    )
    dhparam_file: quoted_string_BIND | None = Field(
        default=None, description="Path to Diffie-Hellman parameters file"
    )
    ciphers: string_BIND | None = Field(
        default=None, description="Allowed ciphers for TLSv1.2/TLSv1.3 (OpenSSL format)"
    )
    protocols: list[string_BIND] | None = Field(
        default=None, description="Allowed TLS protocol versions"
    )
    prefer_server_ciphers: boolean_BIND | None = Field(
        default=None, description="Prefer server ciphers over client ones"
    )
    session_tickets: boolean_BIND | None = Field(
        default=None, description="Enable TLS session tickets (RFC 5077)"
    )
    remote_hostname: quoted_string_BIND | None = Field(
        default=None, description="Expected hostname in remote server certificate"
    )

    BUILTIN_CONFIGS: ClassVar[set] = {"ephemeral", "none"}

    _exclude_from_syntax: ClassVar[set[str]] = {"name"}

    @property
    def comparison_attr(self) -> str:
        return str(self.name)

    @field_validator("protocols")
    def validate_protocols(cls, v: list[string_BIND] | None) -> list[string_BIND] | None:
        """Validate allowed TLS protocol versions."""
        if v is None:
            return v

        valid_protocols = {"TLSv1.2", "TLSv1.3"}
        for protocol in v:
            if protocol not in valid_protocols:
                raise ValueError(
                    f"Invalid TLS protocol: {protocol}. Must be one of: {', '.join(sorted(valid_protocols))}"
                )
        return v

    @model_validator(mode="after")
    def validate_configuration_requirements(self) -> TlsBlock:
        """Validate configuration requirements."""
        name = self.name

        if name in self.BUILTIN_CONFIGS:
            model_fields = self.__class__.model_fields
            fields_to_check = [field for field in model_fields if field not in ["name", "comment"]]

            non_none_fields = []
            for field in fields_to_check:
                if getattr(self, field) is not None:
                    non_none_fields.append(field)

            if non_none_fields:
                raise ValueError(
                    f"Built-in TLS configuration '{name}' cannot have additional parameters. "
                    f"Specified parameters: {non_none_fields}"
                )
            return self

        if not self.key_file:
            raise ValueError(f"Custom TLS configuration '{name}' requires key-file")
        if not self.cert_file:
            raise ValueError(f"Custom TLS configuration '{name}' requires cert-file")

        # TODO ? remote-hostname withou ca-file use system storage
        # if self.remote_hostname and not self.ca_file:
        #     pass
        # TODO ? TLS has both dhparam-file and session-tickets enabled
        # if self.dhparam_file and self.session_tickets == "yes":
        #     print(
        #         f"Warning: TLS configuration '{name}' has both dhparam-file "
        #         "and session-tickets enabled. "
        #         "Consider disabling session-tickets for perfect forward secrecy."
        #     )

        return self

    def model_bind_syntax(self, indent_level: int = 0) -> str:
        lines: list[str] = []
        self._add_comment(lines, indent_level)

        indent = self._indent(indent_level)

        if self.name in self.BUILTIN_CONFIGS:
            lines.append(f"{indent}tls {self.name} {{}};")
            return "\n".join(lines)

        lines.append(f"{indent}tls {self.name} {{")
        lines.extend(self.auto_format_fields(indent_level + 1))
        lines.append(f"{indent}}};")
        return "\n".join(lines)
