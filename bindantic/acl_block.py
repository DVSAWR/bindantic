from __future__ import annotations

from typing import ClassVar

from pydantic import Field

from ._base_model import BindBaseModel
from ._base_types import acl_name_BIND, address_match_list_BIND


class AclBlock(BindBaseModel):
    """
    ACL block for BIND configuration.

    The acl statement assigns a symbolic name to an address match list. It gets its name from one of the primary uses of address match lists: Access Control Lists (ACLs).

    The following ACLs are built-in:
    - any: Matches all hosts.
    - none: Matches no hosts.
    - localhost: Matches the IPv4 and IPv6 addresses of all network interfaces on the system.
    When addresses are added or removed, the localhost ACL element
    is updated to reflect the changes.
    - localnets: Matches any host on an IPv4 or IPv6 network for which the system
    has an interface. When addresses are added or removed, the localnets ACL element
    is updated to reflect the changes. Some systems do not provide a way to determine
    the prefix lengths of local IPv6 addresses; in such cases, localnets only matches
    the local IPv6 addresses, just like localhost.

    Grammar:
    ```
    acl <string> { <address_match_element>; ... }; // may occur multiple times
    ```
    """

    name: acl_name_BIND = Field(..., description="ACL name")
    addresses: address_match_list_BIND = Field(
        default_factory=list, description="List of address match elements"
    )

    _exclude_from_syntax: ClassVar[set[str]] = {"name"}

    @property
    def comparison_attr(self) -> tuple[str, int]:
        return self.name, len(self.addresses)

    def _format_addresses(self, value: address_match_list_BIND, indent_level: int) -> str:
        """Special formatter for addresses list in ACL."""
        indent = self._indent(indent_level)
        if not value:
            return f"{indent}none;"

        lines = []
        for address in sorted(value):
            lines.append(f"{indent}{address};")

        return "\n".join(lines)

    def model_bind_syntax(self, indent_level: int = 0) -> str:
        lines: list[str] = []
        self._add_comment(lines, indent_level)
        indent = self._indent(indent_level)
        lines.append(f"{indent}acl {self.name} {{")
        addresses_formatted = self._format_addresses(self.addresses, indent_level + 1)
        if addresses_formatted:
            lines.append(addresses_formatted)
        lines.append(f"{indent}}};")
        return "\n".join(lines)
