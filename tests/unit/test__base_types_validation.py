# tests/unit/test__base_types_validation.py
"""
Tests for BIND type validation utilities.
"""

from __future__ import annotations

import re
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network

import pytest

from bindantic._base_types_validation import (
    ACL_NAME_REGEX,
    BOOLEAN_FALSE_VALUES,
    BOOLEAN_TRUE_VALUES,
    DNS_NAME_REGEX,
    DOMAIN_NAME_REGEX,
    DURATION_ISO_REGEX,
    DURATION_TTL_REGEX,
    FIXEDPOINT_REGEX,
    MAX_DOMAIN_LENGTH,
    MAX_LABEL_LENGTH,
    PERCENTAGE_REGEX,
    PREDEFINED_ACL_NAMES,
    SCALE_FACTORS,
    SERVER_KEY_REGEX,
    SIZE_SUFFIX_REGEX,
    TLS_ID_REGEX,
    DomainValidator,
    DurationParser,
    StringValidator,
    Validator,
)


class TestStringValidator:
    """Tests for StringValidator class."""

    @pytest.mark.parametrize(
        "input_str, expected",
        [
            ('"quoted"', "quoted"),
            ("'single'", "single"),
            ("no quotes", "no quotes"),
            ("  spaced  ", "spaced"),
            ('""', ""),
        ],
    )
    def test_strip_quotes(self, input_str, expected):
        """Test stripping quotes from strings."""
        assert StringValidator.strip_quotes(input_str) == expected

    @pytest.mark.parametrize(
        "input_str, expected",
        [
            ("already", '"already"'),
            ('"quoted"', '"quoted"'),
            ("with spaces", '"with spaces"'),
            ("", '""'),
            ("  trimmed  ", '"trimmed"'),
        ],
    )
    def test_ensure_quotes(self, input_str, expected):
        """Test ensuring strings are quoted."""
        assert StringValidator.ensure_quotes(input_str) == expected

    def test_validate_string(self):
        """Test basic string validation."""
        assert StringValidator.validate_string("test", "test") == "test"
        assert StringValidator.validate_string("  test  ", "test") == "test"

        with pytest.raises(ValueError, match="Must be a string"):
            StringValidator.validate_string(123, "test")

        with pytest.raises(ValueError, match="Must be a string"):
            StringValidator.validate_string(None, "test")

    def test_validate_not_empty(self):
        """Test non-empty string validation."""
        assert StringValidator.validate_not_empty("test", "test") == "test"

        with pytest.raises(ValueError, match="cannot be empty"):
            StringValidator.validate_not_empty("", "test")

        with pytest.raises(ValueError, match="cannot be empty"):
            StringValidator.validate_not_empty("   ", "test")


class TestDomainValidator:
    """Tests for DomainValidator class."""

    @pytest.mark.parametrize(
        "label, domain, should_raise",
        [
            ("valid", "example.com", False),
            ("also-valid", "example.com", False),
            ("123", "example.com", False),
            ("", "example.com", True),
            ("a" * (MAX_LABEL_LENGTH + 1), "example.com", True),
            ("-invalid", "example.com", True),
            ("invalid-", "example.com", True),
            ("-invalid-", "example.com", True),
        ],
    )
    def test_validate_label(self, label, domain, should_raise):
        """Test domain label validation."""
        if should_raise:
            with pytest.raises(ValueError):
                DomainValidator.validate_label(label, domain)
        else:
            DomainValidator.validate_label(label, domain)


class TestDurationParser:
    """Tests for DurationParser class."""

    def test_parse_iso_duration(self):
        """Test ISO 8601 duration parsing."""
        test_cases = [
            # NOTE: groups tuple, expected_seconds
            ((None, None, None, None, None, None, "30"), 30),
            ((None, None, None, None, None, "5", None), 300),
            ((None, None, None, None, "2", None, None), 7200),
            ((None, None, None, "3", None, None, None), 259200),
            ((None, None, "1", None, None, None, None), 604800),
            ((None, "2", None, None, None, None, None), 5184000),
            (("1", None, None, None, None, None, None), 31536000),
            (
                ("1", "2", "3", "4", "5", "6", "7"),
                31536000 + 5184000 + 1814400 + 345600 + 18000 + 360 + 7,
            ),
        ]

        class MockMatch:
            def __init__(self, groups):
                self.groups = groups

            def group(self, n):
                return self.groups[n - 1] if n <= len(self.groups) else None

        for groups, expected in test_cases:
            match = MockMatch(groups)
            result = DurationParser.parse_iso_duration(match)
            assert result == expected

    def test_parse_ttl_duration(self):
        """Test TTL-style duration parsing."""
        test_cases = [
            # NOTE: groups tuple, expected_seconds
            ((None, None, None, None, "30"), 30),
            ((None, None, None, "5", None), 300),
            ((None, None, "2", None, None), 7200),
            ((None, "3", None, None, None), 259200),
            (("1", None, None, None, None), 604800),
            (
                ("1", "2", "3", "4", "5"),
                604800 + 172800 + 10800 + 240 + 5,
            ),
        ]

        class MockMatch:
            def __init__(self, groups):
                self.groups = groups

            def group(self, n):
                return self.groups[n - 1] if n <= len(self.groups) else None

        for groups, expected in test_cases:
            match = MockMatch(groups)
            result = DurationParser.parse_ttl_duration(match)
            assert result == expected


class TestValidatorBasicTypes:
    """Tests for basic type validators."""

    @pytest.mark.parametrize(
        "value, expected",
        [
            ("test", "test"),
            ('"quoted"', "quoted"),
            ("  spaced  ", "spaced"),
            ("123", "123"),
        ],
    )
    def test_validate_string(self, value, expected):
        """Test string validation."""
        assert Validator.validate_string(value) == expected

    @pytest.mark.parametrize("value", [123, None, [], {}])
    def test_validate_string_invalid(self, value):
        """Test invalid string validation."""
        with pytest.raises(ValueError):
            Validator.validate_string(value)

    @pytest.mark.parametrize(
        "value, expected",
        [
            ("test", '"test"'),
            ('"already"', '"already"'),
            ("with spaces", '"with spaces"'),
        ],
    )
    def test_validate_quoted_string(self, value, expected):
        """Test quoted string validation."""
        assert Validator.validate_quoted_string(value) == expected

    def test_validate_quoted_string_empty(self):
        """Test empty quoted string validation."""
        with pytest.raises(ValueError, match="cannot be empty"):
            Validator.validate_quoted_string("")

    @pytest.mark.parametrize(
        "value, expected",
        [
            (True, "yes"),
            (False, "no"),
            ("yes", "yes"),
            ("no", "no"),
            ("true", "yes"),
            ("false", "no"),
            ("1", "yes"),
            ("0", "no"),
            (1, "yes"),
            (0, "no"),
            (1.0, "yes"),
            (0.0, "no"),
        ],
    )
    def test_validate_boolean(self, value, expected):
        """Test boolean validation."""
        assert Validator.validate_boolean(value) == expected

    @pytest.mark.parametrize("value", ["maybe", "2", -1, "YES ", "NO "])
    def test_validate_boolean_invalid(self, value):
        """Test invalid boolean validation."""
        with pytest.raises(ValueError):
            Validator.validate_boolean(value)


class TestValidatorDomainTypes:
    """Tests for domain-related validators."""

    @pytest.mark.parametrize(
        "value, expected",
        [
            ("example.com", "example.com."),
            ("EXAMPLE.COM", "EXAMPLE.COM."),
            ('"example.com"', "example.com."),
            ("example.com.", "example.com."),
            ("@", "@"),
            (".", "."),
            ("a" * 63 + ".com", "a" * 63 + ".com."),
            ("example.co", "example.co."),
        ],
    )
    def test_validate_domain_name_valid(self, value, expected):
        """Test valid domain name validation."""
        result = Validator.validate_domain_name(value)
        assert result == expected

    @pytest.mark.parametrize(
        "value, error_contains",
        [
            ("a" * (MAX_DOMAIN_LENGTH + 1), "exceeds"),
            ("-example.com", "cannot start or end"),
            ("example.-com", "cannot start or end"),
            ("example.com-", "cannot start or end"),
            ("", "cannot be empty"),
            ("example.c", "at least 2 characters"),
            (123, "Must be a string"),
        ],
    )
    def test_validate_domain_name_invalid(self, value, error_contains):
        """Test invalid domain name validation."""
        with pytest.raises(ValueError) as exc:
            Validator.validate_domain_name(value)
        assert error_contains in str(exc.value)

    @pytest.mark.parametrize(
        "value, expected",
        [
            ("example.com", "example.com."),
            ("_service._tcp", "_service._tcp."),
            ("*", "*"),
            ("@", "@"),
            (".", "."),
            ("*.example.com", "*.example.com."),
            ("example.com.", "example.com."),
        ],
    )
    def test_validate_dns_name_valid(self, value, expected):
        """Test valid DNS name validation."""
        result = Validator.validate_dns_name(value)
        assert result == expected

    @pytest.mark.parametrize(
        "value",
        [
            "a" * (MAX_DOMAIN_LENGTH + 1),
            "invalid@name",
            "",
        ],
    )
    def test_validate_dns_name_invalid(self, value):
        """Test invalid DNS name validation."""
        with pytest.raises(ValueError):
            Validator.validate_dns_name(value)

    def test_validate_dns_name_single_char_tld(self):
        """Test DNS name with single char TLD."""
        result = Validator.validate_dns_name("example.c")
        assert result == "example.c."


class TestValidatorNumericTypes:
    """Tests for numeric type validators."""

    @pytest.mark.parametrize(
        "value, expected",
        [
            (0, 0),
            (100, 100),
            ("0", 0),
            ("100", 100),
            ("1W", 604800),
            ("2D", 172800),
            ("3H", 10800),
            ("30M", 1800),
            ("45S", 45),
            ("1W2D3H30M45S", 790245),
            ("P1Y", 31536000),
            ("P2M", 5184000),
            ("P3W", 1814400),
            ("P4D", 345600),
            ("PT5H", 18000),
            ("PT6M", 360),
            ("PT7S", 7),
            ("P1Y2M3W4DT5H6M7S", 38898367),
        ],
    )
    def test_validate_duration_valid(self, value, expected):
        """Test valid duration validation."""
        result = Validator.validate_duration(value)
        assert isinstance(result, int)
        assert result == expected

    @pytest.mark.parametrize("value", [-1, "-1S", "invalid", "1.5", []])
    def test_validate_duration_invalid(self, value):
        """Test invalid duration validation."""
        with pytest.raises(ValueError):
            Validator.validate_duration(value)

    @pytest.mark.parametrize(
        "value, expected",
        [
            (0, 0),
            (99999.99, 99999.99),
            ("0", 0.0),
            ("123.45", 123.45),
            (123.45, 123.45),
        ],
    )
    def test_validate_fixedpoint_valid(self, value, expected):
        """Test valid fixedpoint validation."""
        assert Validator.validate_fixedpoint(value) == expected

    @pytest.mark.parametrize("value", [-1, 100000, "99999.999", "abc", []])
    def test_validate_fixedpoint_invalid(self, value):
        """Test invalid fixedpoint validation."""
        with pytest.raises(ValueError):
            Validator.validate_fixedpoint(value)

    @pytest.mark.parametrize(
        "value, expected",
        [
            (0, 0),
            (4294967295, 4294967295),
            ("0", 0),
            ("100", 100),
            (100.0, 100),
        ],
    )
    def test_validate_integer_valid(self, value, expected):
        """Test valid integer validation."""
        assert Validator.validate_integer(value) == expected

    @pytest.mark.parametrize("value", [-1, 4294967296, "abc", []])
    def test_validate_integer_invalid(self, value):
        """Test invalid integer validation."""
        with pytest.raises(ValueError):
            Validator.validate_integer(value)

    def test_validate_integer_float(self):
        """Test float for integer validation."""
        with pytest.raises(ValueError):
            Validator.validate_integer(123.5)

    @pytest.mark.parametrize(
        "value, expected",
        [
            ("50%", "50%"),
            ("0%", "0%"),
            ("100%", "100%"),
            (50, "50%"),
            (100.0, "100%"),
        ],
    )
    def test_validate_percentage_valid(self, value, expected):
        """Test valid percentage validation."""
        assert Validator.validate_percentage(value) == expected

    @pytest.mark.parametrize("value", ["-1%", "101%", "abc", []])
    def test_validate_percentage_invalid(self, value):
        """Test invalid percentage validation."""
        with pytest.raises(ValueError):
            Validator.validate_percentage(value)


class TestValidatorNetworkTypes:
    """Tests for network type validators."""

    @pytest.mark.parametrize(
        "value, expected",
        [
            ("192.168.1.1", "192.168.1.1"),
            (IPv4Address("192.168.1.1"), "192.168.1.1"),
            ("2001:db8::1", "2001:db8::1"),
            (IPv6Address("2001:db8::1"), "2001:db8::1"),
            ("fe80::1%eth0", "fe80::1%eth0"),
        ],
    )
    def test_validate_ip_address_valid(self, value, expected):
        """Test valid IP address validation."""
        assert Validator.validate_ip_address(value) == expected

    @pytest.mark.parametrize("value", ["not.an.ip", "256.256.256.256", "", []])
    def test_validate_ip_address_invalid(self, value):
        """Test invalid IP address validation."""
        with pytest.raises(ValueError):
            Validator.validate_ip_address(value)

    @pytest.mark.parametrize(
        "value, expected",
        [
            ("192.168.1.0/24", "192.168.1.0/24"),
            (IPv4Network("10.0.0.0/8"), "10.0.0.0/8"),
            ("2001:db8::/32", "2001:db8::/32"),
            (IPv6Network("2001:db8::/32"), "2001:db8::/32"),
            ("192.168.1.0/255.255.255.0", "192.168.1.0/24"),
        ],
    )
    def test_validate_netprefix_valid(self, value, expected):
        """Test valid network prefix validation."""
        assert Validator.validate_netprefix(value) == expected

    @pytest.mark.parametrize("value", ["not.a.network", "192.168.1.1/33", "", []])
    def test_validate_netprefix_invalid(self, value):
        """Test invalid network prefix validation."""
        with pytest.raises(ValueError):
            Validator.validate_netprefix(value)

    @pytest.mark.parametrize(
        "value, expected",
        [
            ("192.168.1.1", "192.168.1.1"),
            (IPv4Address("192.168.1.1"), "192.168.1.1"),
            ("0.0.0.0", "0.0.0.0"),
            ("255.255.255.255", "255.255.255.255"),
        ],
    )
    def test_validate_ip_v4_address_valid(self, value, expected):
        """Test valid IPv4 address validation."""
        assert Validator.validate_ip_v4_address(value) == expected

    @pytest.mark.parametrize("value", ["2001:db8::1", "not.ipv4", "256.0.0.0", ""])
    def test_validate_ip_v4_address_invalid(self, value):
        """Test invalid IPv4 address validation."""
        with pytest.raises(ValueError):
            Validator.validate_ip_v4_address(value)

    @pytest.mark.parametrize(
        "value, expected",
        [
            ("2001:db8::1", "2001:db8::1"),
            (IPv6Address("2001:db8::1"), "2001:db8::1"),
            ("::1", "::1"),
            ("fe80::1%eth0", "fe80::1%eth0"),
        ],
    )
    def test_validate_ip_v6_address_valid(self, value, expected):
        """Test valid IPv6 address validation."""
        assert Validator.validate_ip_v6_address(value) == expected

    @pytest.mark.parametrize("value", ["192.168.1.1", "not.ipv6", "", "::g"])
    def test_validate_ip_v6_address_invalid(self, value):
        """Test invalid IPv6 address validation."""
        with pytest.raises(ValueError):
            Validator.validate_ip_v6_address(value)


class TestValidatorPortTypes:
    """Tests for port type validators."""

    @pytest.mark.parametrize(
        "value, expected",
        [
            ("*", "*"),
            (0, 0),
            (53, 53),
            (65535, 65535),
            ("53", 53),
            (8080.0, 8080),
        ],
    )
    def test_validate_port_valid(self, value, expected):
        """Test valid port validation."""
        result = Validator.validate_port(value)
        assert result == expected

    @pytest.mark.parametrize("value", [-1, 65536, "abc", "70000", []])
    def test_validate_port_invalid(self, value):
        """Test invalid port validation."""
        with pytest.raises(ValueError):
            Validator.validate_port(value)

    @pytest.mark.parametrize(
        "value, expected",
        [
            ("1024 65535", (1024, 65535)),
            ([1024, 65535], (1024, 65535)),
            ((1024, 65535), (1024, 65535)),
            ("0 1023", (0, 1023)),
        ],
    )
    def test_validate_portrange_valid(self, value, expected):
        """Test valid port range validation."""
        assert Validator.validate_portrange(value) == expected

    @pytest.mark.parametrize(
        "value",
        [
            "1024 1023",
            "1024",
            "1024 abc",
            [1024, 1023],
            [1024],
            (1024, 1023),
            (1024,),
            "* 1024",
        ],
    )
    def test_validate_portrange_invalid(self, value):
        """Test invalid port range validation."""
        with pytest.raises(ValueError):
            Validator.validate_portrange(value)


class TestValidatorSizeTypes:
    """Tests for size type validators."""

    @pytest.mark.parametrize(
        "value, expected_bytes",
        [
            ("1K", 1024),
            ("1M", 1024 * 1024),
            ("1G", 1024 * 1024 * 1024),
            ("1024", 1024),
            ("unlimited", "unlimited"),
            ("default", "default"),
            ("1k", 1024),
            ("1m", 1024 * 1024),
            ("1g", 1024 * 1024 * 1024),
        ],
    )
    def test_validate_size_valid(self, value, expected_bytes):
        """Test valid size validation."""
        result = Validator.validate_size(value)
        if isinstance(expected_bytes, int):
            assert result == value.upper()
        else:
            assert result == expected_bytes

    @pytest.mark.parametrize("value", ["-1", "abc", "1T", 1024, []])
    def test_validate_size_invalid(self, value):
        """Test invalid size validation."""
        with pytest.raises(ValueError):
            Validator.validate_size(value)

    @pytest.mark.parametrize(
        "value, expected",
        [
            ("1K", "1K"),
            ("1024", "1024"),
            ("1M", "1M"),
            ("1G", "1G"),
        ],
    )
    def test_validate_sizeval_valid(self, value, expected):
        """Test valid sizeval validation."""
        assert Validator.validate_sizeval(value) == expected

    @pytest.mark.parametrize("value", ["unlimited", "default", -1, 1024, []])
    def test_validate_sizeval_invalid(self, value):
        """Test invalid sizeval validation."""
        with pytest.raises(ValueError):
            Validator.validate_sizeval(value)


class TestValidatorIdentifierTypes:
    """Tests for identifier type validators."""

    @pytest.mark.parametrize(
        "value, expected",
        [
            ("tsig-key", "tsig-key"),
            ('"tsig-key"', "tsig-key"),
            ("tsig.key", "tsig.key"),
            ("tsig_key", "tsig_key"),
            ("TSIG-KEY", "TSIG-KEY"),
            ("a", "a"),
            ("a" * 100, "a" * 100),
        ],
    )
    def test_validate_server_key_valid(self, value, expected):
        """Test valid server key validation."""
        assert Validator.validate_server_key(value) == expected

    @pytest.mark.parametrize("value", ["", "tsig key", "@key", "key@", []])
    def test_validate_server_key_invalid(self, value):
        """Test invalid server key validation."""
        with pytest.raises(ValueError):
            Validator.validate_server_key(value)

    def test_validate_server_key_with_leading_space(self):
        """Test server key with leading space."""
        result = Validator.validate_server_key(" tsig-key")
        assert result == "tsig-key"

    @pytest.mark.parametrize(
        "value, expected",
        [
            ("tls-config", "tls-config"),
            ('"tls-config"', "tls-config"),
            ("tls.config", "tls.config"),
            ("tls_config", "tls_config"),
            ("TLS-CONFIG", "TLS-CONFIG"),
            ("a1", "a1"),
        ],
    )
    def test_validate_tls_id_valid(self, value, expected):
        """Test valid TLS ID validation."""
        assert Validator.validate_tls_id(value) == expected

    @pytest.mark.parametrize("value", ["", "1tls", "-tls", "tls config", "@tls", []])
    def test_validate_tls_id_invalid(self, value):
        """Test invalid TLS ID validation."""
        with pytest.raises(ValueError):
            Validator.validate_tls_id(value)

    @pytest.mark.parametrize(
        "value, expected",
        [
            ("internal", "internal"),
            ("internal_net", "internal_net"),
            ("internal-net", "internal-net"),
            ("INTERNAL", "INTERNAL"),
            ("_internal", "_internal"),
            ("a", "a"),
            ("any", "any"),
            ("none", "none"),
            ("localhost", "localhost"),
            ("localnets", "localnets"),
        ],
    )
    def test_validate_acl_name_valid(self, value, expected):
        """Test valid ACL name validation."""
        assert Validator.validate_acl_name(value) == expected

    @pytest.mark.parametrize("value", ["", "1acl", "-acl", "acl name", "@acl", []])
    def test_validate_acl_name_invalid(self, value):
        """Test invalid ACL name validation."""
        with pytest.raises(ValueError):
            Validator.validate_acl_name(value)


class TestValidatorAddressMatch:
    """Tests for address match validators."""

    @pytest.mark.parametrize(
        "value, expected",
        [
            ("192.168.1.1", "192.168.1.1"),
            ("!192.168.1.1", "!192.168.1.1"),
            ("key tsig-key", "key tsig-key"),
            ("any", "any"),
            ("{ 192.168.1.1 10.0.0.1 }", "{ 192.168.1.1 10.0.0.1 }"),
            ("2001:db8::/32", "2001:db8::/32"),
            ("!key tsig-key", "!key tsig-key"),
            ("!any", "!any"),
        ],
    )
    def test_validate_address_match_element_valid(self, value, expected):
        """Test valid address match element validation."""
        result = Validator.validate_address_match_element(value)
        assert result == expected.strip()

    @pytest.mark.parametrize(
        "value",
        [
            "",
            "{",
            "}",
            "{ }",
        ],
    )
    def test_validate_address_match_element_invalid(self, value):
        """Test invalid address match element validation."""
        with pytest.raises(ValueError):
            Validator.validate_address_match_element(value)

    def test_validate_address_match_list_valid(self):
        """Test valid address match list validation."""
        valid_lists = [
            ["192.168.1.1", "10.0.0.1"],
            ["any"],
            ["key tsig-key", "!192.168.1.1"],
            ["{ 192.168.1.1 10.0.0.1 }", "key admin-key"],
        ]

        for lst in valid_lists:
            result = Validator.validate_address_match_list(lst)
            assert result == lst

    @pytest.mark.parametrize(
        "value",
        [
            "not a list",
            123,
            ["invalid element"],
        ],
    )
    def test_validate_address_match_list_invalid(self, value):
        """Test invalid address match list validation."""
        with pytest.raises(ValueError):
            Validator.validate_address_match_list(value)


class TestValidatorEdgeCases:
    """Edge case tests for Validator."""

    def test_scale_factors_completeness(self):
        """Test that all scale factors are defined."""
        assert "k" in SCALE_FACTORS
        assert "m" in SCALE_FACTORS
        assert "g" in SCALE_FACTORS
        assert SCALE_FACTORS["k"] == 1024
        assert SCALE_FACTORS["m"] == 1024 * 1024
        assert SCALE_FACTORS["g"] == 1024 * 1024 * 1024

    def test_boolean_constants(self):
        """Test boolean constants completeness."""
        assert "yes" in BOOLEAN_TRUE_VALUES
        assert "true" in BOOLEAN_TRUE_VALUES
        assert "1" in BOOLEAN_TRUE_VALUES
        assert "no" in BOOLEAN_FALSE_VALUES
        assert "false" in BOOLEAN_FALSE_VALUES
        assert "0" in BOOLEAN_FALSE_VALUES

    def test_predefined_acl_names(self):
        """Test predefined ACL names completeness."""
        assert "any" in PREDEFINED_ACL_NAMES
        assert "none" in PREDEFINED_ACL_NAMES
        assert "localhost" in PREDEFINED_ACL_NAMES
        assert "localnets" in PREDEFINED_ACL_NAMES

    def test_max_constants(self):
        """Test constant values."""
        assert MAX_DOMAIN_LENGTH == 253
        assert MAX_LABEL_LENGTH == 63

    def test_regex_patterns_compiled(self):
        """Test that regex patterns are compiled."""
        patterns = [
            DOMAIN_NAME_REGEX,
            DNS_NAME_REGEX,
            SERVER_KEY_REGEX,
            TLS_ID_REGEX,
            ACL_NAME_REGEX,
            FIXEDPOINT_REGEX,
            DURATION_ISO_REGEX,
            DURATION_TTL_REGEX,
            PERCENTAGE_REGEX,
            SIZE_SUFFIX_REGEX,
        ]

        for pattern in patterns:
            assert isinstance(pattern, re.Pattern)
            if pattern == DURATION_ISO_REGEX:
                assert pattern.match("P1Y") is not None
            elif pattern == DURATION_TTL_REGEX:
                assert pattern.match("1W") is not None
            elif pattern == PERCENTAGE_REGEX:
                assert pattern.match("50%") is not None
            elif pattern == SIZE_SUFFIX_REGEX:
                assert pattern.match("1K") is not None
            else:
                assert pattern.match("test") is not None or pattern.match("123") is not None
