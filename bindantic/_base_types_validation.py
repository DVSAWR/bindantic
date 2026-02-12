from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address, ip_network
from re import Pattern
from typing import Any, Final

from pydantic import GetCoreSchemaHandler
from pydantic_core import CoreSchema, core_schema

# NOTE: CONSTANTS
MAX_DOMAIN_LENGTH: Final[int] = 253
MAX_LABEL_LENGTH: Final[int] = 63
MAX_UINT32: Final[int] = 4294967295
MAX_UINT64: Final[int] = 18446744073709551615
MAX_FIXEDPOINT: Final[float] = 99999.99
MAX_PORT: Final[int] = 65535
MIN_PORT: Final[int] = 0
# NOTE: TIME
SECONDS_PER_MINUTE: Final[int] = 60
SECONDS_PER_HOUR: Final[int] = 3600
SECONDS_PER_DAY: Final[int] = 86400
SECONDS_PER_WEEK: Final[int] = 604800
SECONDS_PER_MONTH: Final[int] = 2592000
SECONDS_PER_YEAR: Final[int] = 31536000
# NOTE: REGEX
DOMAIN_NAME_REGEX: Final[Pattern] = re.compile(r"^[a-zA-Z0-9-]+$")  # NOTE: RFC 1035
DNS_NAME_REGEX: Final[Pattern] = re.compile(r"^[a-zA-Z0-9_*-]+$")
SERVER_KEY_REGEX: Final[Pattern] = re.compile(r"^[a-zA-Z0-9._-]+$")
TLS_ID_REGEX: Final[Pattern] = re.compile(r"^[a-zA-Z][a-zA-Z0-9._-]*$")
ACL_NAME_REGEX: Final[Pattern] = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_-]*$")
FIXEDPOINT_REGEX: Final[Pattern] = re.compile(r"^\d{1,5}(\.\d{1,2})?$")
DURATION_ISO_REGEX: Final[Pattern] = re.compile(
    r"^P(?:(\d+)Y)?(?:(\d+)M)?(?:(\d+)W)?(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?$",
    re.IGNORECASE,
)
DURATION_TTL_REGEX: Final[Pattern] = re.compile(
    r"^(?:(\d+)W)?(?:(\d+)D)?(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?$", re.IGNORECASE
)
PERCENTAGE_REGEX: Final[Pattern] = re.compile(r"^(\d{1,3})%$")
SIZE_SUFFIX_REGEX: Final[Pattern] = re.compile(r"^(\d+)([KMG]?)$", re.IGNORECASE)
# NOTE: BIND ACL SYSTEM NAMES
PREDEFINED_ACL_NAMES: Final[set[str]] = {"any", "none", "localhost", "localnets"}
# NOTE: BOOLEAN VALUES
BOOLEAN_TRUE_VALUES: Final[set[str]] = {"yes", "true", "1"}
BOOLEAN_FALSE_VALUES: Final[set[str]] = {"no", "false", "0"}
# NOTE: SCALE FACTOR FOR size/sizeval
SCALE_FACTORS: Final[dict[str, int]] = {
    "k": 1024,
    "m": 1024 * 1024,
    "g": 1024 * 1024 * 1024,
}


@dataclass(frozen=True)
class BindTypeCoreSchema:
    """Pydantic after typer validator for BIND validator func."""

    func: Callable[[Any], Any]

    def __get_pydantic_core_schema__(
        self, source_type: Any, handler: GetCoreSchemaHandler
    ) -> CoreSchema:
        """Returns schema that calls a validator function after validating."""
        return core_schema.no_info_after_validator_function(self.func, handler(source_type))


class StringValidator:
    """String validation utilities."""

    @staticmethod
    def strip_quotes(value: str) -> str:
        """Remove surrounding quotes from a string."""
        v = value.strip()
        if (v.startswith('"') and v.endswith('"')) or (v.startswith("'") and v.endswith("'")):
            return v[1:-1]
        return v

    @staticmethod
    def ensure_quotes(value: str) -> str:
        """Ensure string is quoted with double quotes."""
        v = value.strip()
        if v.startswith('"') and v.endswith('"'):
            return v
        return f'"{v}"'

    @staticmethod
    def validate_string(value: Any, type_name: str) -> str:
        """Validate basic string type."""
        if not isinstance(value, str):
            raise ValueError(f"Invalid BIND {type_name}: {value}. Must be a string.")
        return value.strip()

    @staticmethod
    def validate_not_empty(value: str, type_name: str) -> str:
        """Validate string is not empty."""
        if not value.strip():
            raise ValueError(f"BIND {type_name} cannot be empty.")
        return value


class DomainValidator:
    """Domain name validation utilities."""

    @staticmethod
    def validate_label(label: str, domain: str) -> None:
        """Validate a single domain label."""
        if not label:
            raise ValueError(f"Invalid BIND domain name: {domain}. Empty label found.")

        if len(label) > MAX_LABEL_LENGTH:
            raise ValueError(
                f"Invalid BIND domain name: {domain}. "
                f"Label '{label}' exceeds {MAX_LABEL_LENGTH} characters."
            )

        if label.startswith("-") or label.endswith("-"):
            raise ValueError(
                f"Invalid BIND domain name: {domain}. "
                f"Label '{label}' cannot start or end with a hyphen."
            )


class DurationParser:
    """Duration parsing utilities."""

    @staticmethod
    def parse_iso_duration(match: re.Match) -> int:
        """Parse ISO 8601 duration from regex match."""
        return (
            int(match.group(1) or 0) * SECONDS_PER_YEAR
            + int(match.group(2) or 0) * SECONDS_PER_MONTH
            + int(match.group(3) or 0) * SECONDS_PER_WEEK
            + int(match.group(4) or 0) * SECONDS_PER_DAY
            + int(match.group(5) or 0) * SECONDS_PER_HOUR
            + int(match.group(6) or 0) * SECONDS_PER_MINUTE
            + int(match.group(7) or 0)
        )

    @staticmethod
    def parse_ttl_duration(match: re.Match) -> int:
        """Parse TTL-style duration from regex match."""
        return (
            int(match.group(1) or 0) * SECONDS_PER_WEEK
            + int(match.group(2) or 0) * SECONDS_PER_DAY
            + int(match.group(3) or 0) * SECONDS_PER_HOUR
            + int(match.group(4) or 0) * SECONDS_PER_MINUTE
            + int(match.group(5) or 0)
        )


class Validator:
    """Static methods for BIND type validation."""

    @staticmethod
    def validate_string(value: Any) -> str:
        """`<string>` BIND validation."""
        v = StringValidator.validate_string(value, "string")
        v = StringValidator.strip_quotes(v)
        return StringValidator.validate_not_empty(v, "string")

    @staticmethod
    def validate_quoted_string(value: Any) -> str:
        """`<quoted_string>` BIND validation."""
        v = StringValidator.validate_string(value, "quoted string")
        v = StringValidator.validate_not_empty(v, "quoted string")
        return StringValidator.ensure_quotes(v)

    @staticmethod
    def validate_boolean(value: Any) -> str:
        """`<boolean>` BIND validation."""
        if isinstance(value, bool):
            return "yes" if value else "no"

        if isinstance(value, str):
            value_lower = value.lower()
            if value_lower in BOOLEAN_TRUE_VALUES:
                return "yes"
            if value_lower in BOOLEAN_FALSE_VALUES:
                return "no"

        if isinstance(value, (int, float)):
            if value == 1:
                return "yes"
            if value == 0:
                return "no"

        raise ValueError(f"Invalid BIND boolean value: {value}.")

    @staticmethod
    def validate_domain_name(value: Any) -> str:
        """`<domain_name>` BIND validation."""
        v = StringValidator.validate_string(value, "domain name")
        v = StringValidator.strip_quotes(v)

        if v in {"@", "."}:
            return v

        if not v:
            raise ValueError(f"Invalid BIND domain name: {value}. Domain name cannot be empty.")

        effective_length = len(v.rstrip("."))
        if effective_length > MAX_DOMAIN_LENGTH:
            raise ValueError(
                f"Invalid BIND domain name: {v}. Length exceeds {MAX_DOMAIN_LENGTH} characters."
            )

        end_with_dot = v.endswith(".")
        labels = v.rstrip(".").split(".")

        for label in labels:
            DomainValidator.validate_label(label, v)
            if not DOMAIN_NAME_REGEX.match(label):
                raise ValueError(
                    f"Invalid BIND domain name: {v}. Label '{label}' contains invalid characters."
                )

        tld = labels[-1] if labels else ""
        if tld and len(tld) < 2:
            raise ValueError(
                f"Invalid BIND domain name: {v}. Top-level domain must be at least 2 characters."
            )

        if end_with_dot:
            return v
        return v + "."

    @staticmethod
    def validate_dns_name(value: Any) -> str:
        """`<dns_name>` BIND validation."""
        v = StringValidator.validate_string(value, "DNS name")
        v = StringValidator.strip_quotes(v)

        if v in {"@", ".", "*"}:
            return v

        effective_length = len(v.rstrip("."))
        if effective_length > MAX_DOMAIN_LENGTH:
            raise ValueError(
                f"Invalid BIND DNS name: {v}. Length exceeds {MAX_DOMAIN_LENGTH} characters."
            )

        end_with_dot = v.endswith(".")
        labels = v.rstrip(".").split(".")

        for i, label in enumerate(labels):
            DomainValidator.validate_label(label, v)

            if not DNS_NAME_REGEX.match(label):
                raise ValueError(
                    f"Invalid BIND DNS name: {v}. Label '{label}' contains invalid characters."
                )

            if (
                i == len(labels) - 1
                and end_with_dot
                and len(label) < 2
                and label not in {"*", "_"}
            ):
                raise ValueError(
                    f"Invalid BIND DNS name: {v}. Top-level domain must be at least 2 characters."
                )

        if end_with_dot:
            return v
        return v + "."

    @staticmethod
    def validate_duration(value: Any) -> int:
        """`<duration>` BIND validation."""
        if isinstance(value, (int, float)):
            if value < 0:
                raise ValueError(
                    f"Invalid BIND duration value: {value}. Duration must be non-negative."
                )
            return int(value)

        if isinstance(value, str):
            if value.isdigit():
                return int(value)

            iso_match = DURATION_ISO_REGEX.match(value)
            if iso_match:
                return DurationParser.parse_iso_duration(iso_match)

            ttl_match = DURATION_TTL_REGEX.match(value)
            if ttl_match:
                return DurationParser.parse_ttl_duration(ttl_match)

        raise ValueError(
            f"Invalid BIND duration value: {value}. "
            "Must be a non-negative number or string in TTL-style/ISO 8601 format."
        )

    @staticmethod
    def validate_fixedpoint(value: Any) -> float:
        """`<fixedpoint>` BIND validation."""
        try:
            num = float(value)
        except (ValueError, TypeError) as exc:
            raise ValueError(
                f"Invalid BIND fixedpoint value: {value}. Must be a valid number."
            ) from exc

        if num < 0:
            raise ValueError(
                f"Invalid BIND fixedpoint value: {value}. Value must be non-negative."
            )

        if num > MAX_FIXEDPOINT:
            raise ValueError(
                f"Invalid BIND fixedpoint value: {value}. Must be at most {MAX_FIXEDPOINT}."
            )

        if not FIXEDPOINT_REGEX.match(str(num)):
            raise ValueError(
                f"Invalid BIND fixedpoint value: {value}. "
                "Must have at most 5 digits before decimal and 2 after."
            )

        return num

    @staticmethod
    def validate_integer(value: Any) -> int:
        """`<integer>` BIND validation."""
        try:
            num = int(value)
        except (ValueError, TypeError) as exc:
            raise ValueError(f"Invalid BIND integer value: {value}. Must be an integer.") from exc

        if isinstance(value, float) and not value.is_integer():
            raise ValueError(f"Invalid BIND integer value: {value}. Must be an integer.")
        if num < 0:
            raise ValueError(f"Invalid BIND integer value: {num}. Value must be non-negative.")
        if num > MAX_UINT32:
            raise ValueError(f"Invalid BIND integer value: {num}. Maximum value is {MAX_UINT32}.")

        return num

    @staticmethod
    def validate_ip_address(value: Any) -> str:
        """`<ip_address>` BIND validation."""
        try:
            return str(IPv4Address(value))
        except ValueError:
            try:
                return str(IPv6Address(value))
            except ValueError as exc:
                raise ValueError(
                    f"Invalid BIND IP address: {value}. Must be a valid IPv4 or IPv6 address."
                ) from exc

    @staticmethod
    def validate_ip_v4_address(value: Any) -> str:
        """`<ipv4_address>` BIND validation."""
        try:
            return str(IPv4Address(value))
        except ValueError as exc:
            raise ValueError(
                f"Invalid BIND IPv4 address: {value}. Must be a valid IPv4 address."
            ) from exc

    @staticmethod
    def validate_ip_v6_address(value: Any) -> str:
        """`<ipv6_address>` BIND validation."""
        try:
            return str(IPv6Address(value))
        except ValueError as exc:
            raise ValueError(
                f"Invalid BIND IPv6 address: {value}. Must be a valid IPv6 address."
            ) from exc

    @staticmethod
    def validate_netprefix(value: Any) -> str:
        """`<netprefix>` BIND validation."""
        try:
            network = ip_network(value)
            return str(network)
        except ValueError as exc:
            raise ValueError(
                f"Invalid BIND network prefix: {value}. "
                f"Must be a valid IPv4 or IPv6 network prefix."
            ) from exc

    @staticmethod
    def _validate_port_number(port: int) -> int:
        """Validate port number and return as int (for internal use)."""
        if MIN_PORT <= port <= MAX_PORT:
            return port
        raise ValueError(f"Port must be between {MIN_PORT} and {MAX_PORT}.")

    @staticmethod
    def validate_port(value: Any) -> str | int:
        """`<port>` BIND validation."""
        if value == "*":
            return str(value)

        try:
            return Validator._validate_port_number(int(value))
        except (ValueError, TypeError) as exc:
            raise ValueError(
                f"Invalid BIND port value: {value}. "
                f"Must be an integer between {MIN_PORT} and {MAX_PORT} or '*'."
            ) from exc

    @staticmethod
    def validate_portrange(value: Any) -> tuple[int, int]:
        """`<portrange>` BIND validation."""
        if isinstance(value, str):
            parts = value.split()
            if len(parts) == 2:
                try:
                    port_low = int(parts[0])
                    port_high = int(parts[1])
                except ValueError as exc:
                    raise ValueError(f"Invalid BIND portrange value: {value}.") from exc

                port_low = Validator._validate_port_number(port_low)
                port_high = Validator._validate_port_number(port_high)

                if port_low <= port_high:
                    return (port_low, port_high)
                raise ValueError("Low port must not be larger than high port.")

            raise ValueError(
                f"Invalid BIND portrange value: {value}. "
                "Must be two integers separated by a space."
            )

        if isinstance(value, (list, tuple)) and len(value) == 2:
            try:
                port_low, port_high = int(value[0]), int(value[1])
            except ValueError as exc:
                raise ValueError(f"Invalid BIND portrange value: {value}") from exc

            port_low = Validator._validate_port_number(port_low)
            port_high = Validator._validate_port_number(port_high)

            if port_low <= port_high:
                return (port_low, port_high)
            raise ValueError("Low port must not be larger than high port.")

        raise ValueError(
            f"Invalid BIND portrange value: {value}. "
            "Must be a string of two integers separated by a space "
            "or a list/tuple of two integers."
        )

    @staticmethod
    def _parse_size_with_suffix(value: str, type_name: str) -> int:
        """Parse size with suffix K/M/G."""
        match = SIZE_SUFFIX_REGEX.match(value.lower())
        if not match:
            raise ValueError(f"Invalid BIND {type_name} value: {value}.")

        num = int(match.group(1))
        suffix = match.group(2).lower() if match.group(2) else ""
        scale_factor = SCALE_FACTORS.get(suffix, 1)

        scaled_value = num * scale_factor
        if 0 <= scaled_value <= MAX_UINT64:
            return scaled_value

        raise ValueError(f"Scaled value must be between 0 and {MAX_UINT64}, got {scaled_value}.")

    @staticmethod
    def validate_size(value: Any) -> str:
        """`<size>` BIND validation."""
        if isinstance(value, str):
            value_lower = value.lower()
            if value_lower in ("unlimited", "default"):
                return value_lower

            Validator._parse_size_with_suffix(value, "size")
            return value.upper()

        raise ValueError(
            f"Invalid BIND size value: {value}. "
            "Must be a string with optional K, M, or G suffix, "
            "or 'unlimited' or 'default'."
        )

    @staticmethod
    def validate_sizeval(value: Any) -> str:
        """`<sizeval>` BIND validation."""
        if isinstance(value, str):
            Validator._parse_size_with_suffix(value, "sizeval")
            return value.upper()

        raise ValueError(
            f"Invalid BIND sizeval value: {value}. "
            "Must be a string with optional K, M, or G suffix."
        )

    @staticmethod
    def validate_server_key(value: Any) -> str:
        """`<server_key>` BIND validation."""
        v = StringValidator.validate_string(value, "server key")
        v = StringValidator.strip_quotes(v)
        v = StringValidator.validate_not_empty(v, "server key")

        if not SERVER_KEY_REGEX.match(v):
            raise ValueError(
                f"Invalid BIND server key: {v}. "
                "Must contain only letters, digits, dots, hyphens, and underscores."
            )
        return v

    @staticmethod
    def validate_tls_id(value: Any) -> str:
        """`<tls_id>` BIND validation."""
        v = StringValidator.validate_string(value, "TLS ID")
        v = StringValidator.strip_quotes(v)
        v = StringValidator.validate_not_empty(v, "TLS ID")

        if not TLS_ID_REGEX.match(v):
            raise ValueError(
                f"Invalid BIND TLS ID: {v}. "
                "Must start with a letter and contain only letters, digits, "
                "dots, hyphens, and underscores."
            )
        return v

    @staticmethod
    def validate_percentage(value: Any) -> str:
        """`<percentage>` BIND validation."""
        if isinstance(value, (int, float)):
            value = f"{int(value)}%"

        if isinstance(value, str):
            match = PERCENTAGE_REGEX.match(value)
            if match:
                num = int(match.group(1))
                if 0 <= num <= 100:
                    return value
                raise ValueError(
                    f"Invalid BIND percentage value: {value}. Must be between 0% and 100%."
                )
        raise ValueError(
            f"Invalid BIND percentage value: {value}. Must be a string like '50%' (0-100)."
        )

    @staticmethod
    def validate_acl_name(value: Any) -> str:
        """`<acl_name>` BIND validation."""
        v = StringValidator.validate_string(value, "ACL name")
        v = StringValidator.strip_quotes(v)
        v = StringValidator.validate_not_empty(v, "ACL name")

        if v in PREDEFINED_ACL_NAMES:
            return v

        if not ACL_NAME_REGEX.match(v):
            raise ValueError(
                f"Invalid BIND ACL name: {v}. "
                "Must start with a letter or underscore and contain only "
                "letters, digits, underscores, and hyphens."
            )
        return v

    @staticmethod
    def _validate_address_element(element: str) -> None:
        """Validate a single address element without modifiers."""
        try:
            Validator.validate_ip_address(element)
            return
        except ValueError:
            pass

        try:
            Validator.validate_netprefix(element)
            return
        except ValueError:
            pass

        try:
            Validator.validate_acl_name(element)
            return
        except ValueError:
            pass

        raise ValueError(
            f"Invalid BIND address match element: {element}. "
            "Must be an IP address, network prefix, or ACL name."
        )

    @staticmethod
    def validate_address_match_element(value: Any) -> str:
        """`<address_match_element>` BIND validation."""
        v = StringValidator.validate_string(value, "address match element")
        element = v.strip()
        if not element:
            raise ValueError("Address match element cannot be empty")

        if element.startswith("!"):
            element = element[1:].strip()

        if element.startswith("key "):
            key_name = element[4:].strip()
            Validator.validate_server_key(key_name)
            return v

        if element.startswith("{"):
            if not element.endswith("}"):
                raise ValueError(
                    f"Invalid BIND address match element: {value}. "
                    "Nested address match list must end with '}'."
                )
            inner = element[1:-1].strip()
            if not inner:
                raise ValueError("Nested address match list cannot be empty.")
            return v

        Validator._validate_address_element(element)
        return v

    @staticmethod
    def validate_address_match_list(value: Any) -> list[str]:
        """`<address_match_list>` BIND validation."""
        if isinstance(value, list):
            elements = []
            for elem in value:
                valid_elem = Validator.validate_address_match_element(str(elem))
                elements.append(valid_elem)
            return elements

        raise ValueError(
            f"Invalid BIND address match list: {value}. Must be a list of address match elements."
        )
