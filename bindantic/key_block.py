from __future__ import annotations

from typing import ClassVar

from pydantic import Field, field_validator

from ._base_model import BindBaseModel
from ._base_types import quoted_string_BIND, string_BIND


class KeyBlock(BindBaseModel):
    """
    Key block for BIND configuration.

    Defines a shared secret key for use with TSIG or the command channel.

    Grammar:
    ```
    key <string> {
        algorithm <string>;
        secret <string>;
    };
    ```
    """

    name: quoted_string_BIND = Field(..., description="Key name (server_key)")
    algorithm: string_BIND = Field(..., description="Authentication algorithm")
    secret: quoted_string_BIND = Field(..., description="Base64-encoded secret string")

    _exclude_from_syntax: ClassVar[set[str]] = {"name"}

    @property
    def comparison_attr(self) -> str:
        return str(self.name)

    @field_validator("algorithm")
    def validate_algorithm(cls, v: string_BIND) -> string_BIND:
        """Validate algorithm."""
        valid_algorithms = [
            "hmac-md5",
            "hmac-sha1",
            "hmac-sha224",
            "hmac-sha256",
            "hmac-sha384",
            "hmac-sha512",
        ]
        if not any(v.startswith(algorithm) for algorithm in valid_algorithms):
            raise ValueError(
                f"Invalid algorithm. Must be one of: {', '.join(valid_algorithms)} "
                f"or truncated variants (e.g., hmac-sha1-80)"
            )
        return v

    def model_bind_syntax(self, indent_level: int = 0) -> str:
        lines: list[str] = []
        self._add_comment(lines, indent_level)

        indent = self._indent(indent_level)
        lines.append(f"{indent}key {self.name} {{")
        lines.extend(self.auto_format_fields(indent_level + 1))
        lines.append(f"{indent}}};")
        return "\n".join(lines)


class KeyStoreBlock(BindBaseModel):
    """
    Key-store block for BIND configuration.

    Configures a DNSSEC key store.

    Grammar:
    ```
    key-store <string> {
        directory <string>;
        pkcs11-uri <quoted_string>;
    };
    ```
    """

    name: string_BIND = Field(..., description="Key store name")
    directory: string_BIND | None = Field(default=None, description="Directory for key files")
    pkcs11_uri: quoted_string_BIND | None = Field(
        default=None, description="PKCS#11 URI for token storage"
    )

    _exclude_from_syntax: ClassVar[set[str]] = {"name"}

    @property
    def comparison_attr(self) -> str:
        return str(self.name)

    def model_bind_syntax(self, indent_level: int = 0) -> str:
        lines: list[str] = []
        self._add_comment(lines, indent_level)

        indent = self._indent(indent_level)
        lines.append(f"{indent}key-store {self.name} {{")
        lines.extend(self.auto_format_fields(indent_level + 1))
        lines.append(f"{indent}}};")
        return "\n".join(lines)
