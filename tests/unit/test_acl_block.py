from __future__ import annotations

import json

import pytest

from bindantic import AclBlock


class TestAclBlock:
    """Tests for AclBlock class."""

    def test_init_with_basic_values(self):
        """Test initialization with basic values."""
        acl = AclBlock(
            name="internal_networks", addresses=["192.168.1.0/24", "10.0.0.0/8", "2001:db8::/32"]
        )

        assert acl.name == "internal_networks"
        assert acl.addresses == ["192.168.1.0/24", "10.0.0.0/8", "2001:db8::/32"]
        assert acl.comment is None

    def test_init_with_comment(self):
        """Test initialization with comment."""
        acl = AclBlock(
            name="trusted_hosts",
            addresses=["192.168.0.1", "192.168.0.2"],
            comment="Trusted internal hosts",
        )

        assert acl.comment == "Trusted internal hosts"

    def test_init_with_multiline_comment(self):
        """Test initialization with multiline comment."""
        acl = AclBlock(
            name="multiline_acl",
            addresses=["10.0.0.0/8"],
            comment="First line\nSecond line\nThird line",
        )

        assert acl.comment == "First line\nSecond line\nThird line"

    def test_init_with_different_address_types(self):
        """Test initialization with different address types."""

        acl1 = AclBlock(name="acl1", addresses=["192.168.1.1", "10.0.0.1"])
        assert acl1.addresses == ["192.168.1.1", "10.0.0.1"]

        acl2 = AclBlock(name="acl2", addresses=["192.168.0.0/16", "2001:db8::/32"])
        assert acl2.addresses == ["192.168.0.0/16", "2001:db8::/32"]

        acl3 = AclBlock(name="acl3", addresses=["key mykey"])
        assert acl3.addresses == ["key mykey"]

        acl4 = AclBlock(name="acl4", addresses=["{ 192.168.1.0/24 10.0.0.0/8 }"])
        assert acl4.addresses == ["{ 192.168.1.0/24 10.0.0.0/8 }"]

        acl5 = AclBlock(name="acl5", addresses=["!192.168.1.1", "!key badkey"])
        assert acl5.addresses == ["!192.168.1.1", "!key badkey"]

    def test_init_with_builtin_acl_names(self):
        """Test initialization with built-in ACL names."""
        for builtin_name in ["any", "none", "localhost", "localnets"]:
            acl = AclBlock(name=builtin_name, addresses=["192.168.1.1"])
            assert acl.name == builtin_name

    def test_model_validate(self):
        """Test validation via model_validate."""
        data = {"name": "dns_servers", "addresses": ["8.8.8.8", "8.8.4.4", "1.1.1.1"]}

        acl = AclBlock.model_validate(data)
        assert acl.name == "dns_servers"
        assert acl.addresses == ["8.8.8.8", "8.8.4.4", "1.1.1.1"]

    def test_model_validate_json(self):
        """Test validation via model_validate_json."""
        json_data = """{
            "name": "trusted_hosts",
            "addresses": ["192.168.0.1", "192.168.0.2"],
            "comment": "JSON test"
        }"""

        acl = AclBlock.model_validate_json(json_data)
        assert acl.name == "trusted_hosts"
        assert acl.addresses == ["192.168.0.1", "192.168.0.2"]
        assert acl.comment == "JSON test"

    def test_model_bind_syntax_basic(self):
        """Test BIND syntax generation (basic)."""
        acl = AclBlock(name="simple_acl", addresses=["192.168.1.0/24", "10.0.0.1"])

        expected = """acl simple_acl {
    10.0.0.1;
    192.168.1.0/24;
};"""

        assert acl.model_bind_syntax() == expected

    def test_model_bind_syntax_with_comment(self):
        """Test BIND syntax generation with comment."""
        acl = AclBlock(
            name="commented_acl",
            addresses=["192.168.1.1", "10.0.0.1"],
            comment="Internal trusted hosts",
        )

        expected = """# Internal trusted hosts
acl commented_acl {
    10.0.0.1;
    192.168.1.1;
};"""

        assert acl.model_bind_syntax() == expected

    def test_model_bind_syntax_with_multiline_comment(self):
        """Test BIND syntax generation with multiline comment."""
        acl = AclBlock(
            name="multiline_acl",
            addresses=["192.168.1.0/24"],
            comment="First line\nSecond line\nThird line",
        )

        expected = """# First line
# Second line
# Third line
acl multiline_acl {
    192.168.1.0/24;
};"""

        assert acl.model_bind_syntax() == expected

    def test_model_bind_syntax_empty_addresses(self):
        """Test BIND syntax generation with empty address list."""
        acl = AclBlock(name="empty_acl")

        expected = """acl empty_acl {
    none;
};"""

        assert acl.model_bind_syntax() == expected

    def test_model_bind_syntax_with_key_addresses(self):
        """Test BIND syntax generation with key addresses."""
        acl = AclBlock(name="key_acl", addresses=["key tsig-key", "key rndc-key"])

        expected = """acl key_acl {
    key rndc-key;
    key tsig-key;
};"""

        assert acl.model_bind_syntax() == expected

    def test_model_bind_syntax_with_nested_addresses(self):
        """Test BIND syntax generation with nested addresses."""
        acl = AclBlock(
            name="nested_acl", addresses=["{ 192.168.1.0/24 10.0.0.0/8 }", "key master-key"]
        )

        expected = """acl nested_acl {
    key master-key;
    { 192.168.1.0/24 10.0.0.0/8 };
};"""

        assert acl.model_bind_syntax() == expected

    def test_model_bind_syntax_with_negation(self):
        """Test BIND syntax generation with negation."""
        acl = AclBlock(name="negated_acl", addresses=["!192.168.1.1", "!key badkey", "10.0.0.0/8"])

        expected = """acl negated_acl {
    !192.168.1.1;
    !key badkey;
    10.0.0.0/8;
};"""

        assert acl.model_bind_syntax() == expected

    def test_model_bind_syntax_sorted_addresses(self):
        """Test address sorting in BIND syntax."""
        acl = AclBlock(
            name="sorted_acl",
            addresses=[
                "192.168.2.0/24",
                "10.0.0.1",
                "192.168.1.0/24",
                "key z-key",
                "key a-key",
                "!2001:db8::1",
            ],
        )

        result = acl.model_bind_syntax()

        lines = result.split("\n")
        address_lines = [line.strip() for line in lines if ";" in line]

        assert address_lines[0] == "!2001:db8::1;"
        assert address_lines[1] == "10.0.0.1;"
        assert address_lines[2] == "192.168.1.0/24;"
        assert address_lines[3] == "192.168.2.0/24;"
        assert address_lines[4] == "key a-key;"
        assert address_lines[5] == "key z-key;"

    def test_model_bind_syntax_with_indent(self):
        """Test BIND syntax generation with indentation."""
        acl = AclBlock(name="indented_acl", addresses=["192.168.1.0/24", "10.0.0.1"])

        expected = """        acl indented_acl {
            10.0.0.1;
            192.168.1.0/24;
        };"""

        assert acl.model_bind_syntax(2) == expected

    def test_comparison_attr_property(self):
        """Test comparison_attr property."""
        acl1 = AclBlock(name="acl1", addresses=["192.168.1.1"])
        acl2 = AclBlock(name="acl2", addresses=["192.168.1.1", "10.0.0.1"])
        acl3 = AclBlock(name="acl1", addresses=["192.168.1.1"])

        assert acl1.comparison_attr == ("acl1", 1)
        assert acl2.comparison_attr == ("acl2", 2)
        assert acl3.comparison_attr == ("acl1", 1)

    def test_comparison_operators(self):
        """Test comparison operators."""
        acl1 = AclBlock(name="aaa", addresses=["192.168.1.1"])
        acl2 = AclBlock(name="bbb", addresses=["192.168.1.1"])
        acl3 = AclBlock(name="aaa", addresses=["192.168.1.1", "10.0.0.1"])
        acl4 = AclBlock(name="aaa", addresses=["192.168.1.1"])

        assert acl1 < acl2
        assert not acl2 < acl1
        assert acl2 > acl1
        assert not acl1 > acl2

        assert acl1 < acl3
        assert acl3 > acl1

        assert acl1 <= acl4
        assert acl1 >= acl4
        assert not acl1 < acl4
        assert not acl1 > acl4

    def test_comparison_with_different_type(self):
        """Test comparison with different type returns NotImplemented."""
        acl = AclBlock(name="test", addresses=["192.168.1.1"])

        assert acl.__lt__("not a model") is NotImplemented
        assert acl.__le__(123) is NotImplemented
        assert acl.__gt__([]) is NotImplemented
        assert acl.__ge__({}) is NotImplemented

    def test_model_dump(self):
        """Test serialization to dict."""
        acl = AclBlock(
            name="test_acl", addresses=["192.168.1.0/24", "10.0.0.1"], comment="Test ACL"
        )

        data = acl.model_dump()

        assert data["name"] == "test_acl"
        assert data["addresses"] == ["192.168.1.0/24", "10.0.0.1"]
        assert data["comment"] == "Test ACL"

    def test_model_dump_json(self):
        """Test serialization to JSON."""
        acl = AclBlock(name="json_acl", addresses=["192.168.1.1"], comment="JSON test")

        json_str = acl.model_dump_json()

        data = json.loads(json_str)
        assert data["name"] == "json_acl"
        assert data["addresses"] == ["192.168.1.1"]
        assert data["comment"] == "JSON test"

    def test_field_validation_name(self):
        """Test name field validation."""

        valid_names = [
            "internal",
            "internal_net",
            "internal-net",
            "INTERNAL",
            "_internal",
            "a",
            "any",
            "none",
        ]

        for name in valid_names:
            acl = AclBlock(name=name, addresses=["192.168.1.1"])
            assert acl.name == name

        invalid_names = ["", "1acl", "-acl", "acl name", "@acl"]

        for name in invalid_names:
            with pytest.raises(ValueError):
                AclBlock(name=name, addresses=["192.168.1.1"])

    def test_field_validation_addresses(self):
        """Test addresses field validation."""

        valid_addresses = [
            ["192.168.1.1"],
            ["2001:db8::1"],
            ["192.168.0.0/16"],
            ["2001:db8::/32"],
            ["key tsig-key"],
            ["any"],
            ["{ 192.168.1.0/24 10.0.0.0/8 }"],
            ["!192.168.1.1"],
            ["!key badkey"],
        ]

        for addresses in valid_addresses:
            acl = AclBlock(name="test", addresses=addresses)
            assert acl.addresses == addresses

    def test_field_validation_addresses_not_list(self):
        """Test that addresses must be a list."""
        with pytest.raises(ValueError):
            AclBlock(name="test", addresses="192.168.1.1")

    def test_empty_string_in_addresses(self):
        """Test handling of empty strings in addresses."""
        with pytest.raises(ValueError):
            AclBlock(name="test", addresses=["192.168.1.1", "", "   ", "10.0.0.1"])

    def test_whitespace_in_addresses(self):
        """Test handling of whitespace in addresses."""
        acl = AclBlock(name="test", addresses=["  192.168.1.1  ", "  10.0.0.1  "])

        assert acl.addresses == ["192.168.1.1", "10.0.0.1"]

    def test_model_copy(self):
        """Test object copying."""
        acl1 = AclBlock(
            name="original", addresses=["192.168.1.1", "10.0.0.1"], comment="Original ACL"
        )

        acl2 = acl1.model_copy()

        assert acl2.name == acl1.name
        assert acl2.addresses == acl1.addresses
        assert acl2.comment == acl1.comment
        assert acl2 is not acl1

    def test_model_copy_update(self):
        """Test copying with updates."""
        acl1 = AclBlock(name="original", addresses=["192.168.1.1"], comment="Original")

        acl2 = acl1.model_copy(update={"name": "updated", "addresses": ["10.0.0.1"]})

        assert acl2.name == "updated"
        assert acl2.addresses == ["10.0.0.1"]
        assert acl2.comment == "Original"

    def test_exclude_from_syntax(self):
        """Test that name field is excluded from automatic formatting."""
        acl = AclBlock(name="test", addresses=["192.168.1.1"])
        fields = acl._get_fields_for_syntax()
        field_names = [name for name, _ in fields]

        assert "name" not in field_names
        assert "addresses" in field_names
        assert "comment" not in field_names

    def test_format_addresses_method(self):
        """Test special formatting method _format_addresses."""
        acl = AclBlock(name="test", addresses=[])

        result = acl._format_addresses([], 0)

        if result.strip():
            assert result.strip() == "none;"

        result = acl._format_addresses(["192.168.1.1", "10.0.0.1"], 1)
        expected = """    10.0.0.1;
    192.168.1.1;"""
        assert result == expected

        result = acl._format_addresses(["192.168.1.1"], 2)
        expected = "        192.168.1.1;"
        assert result == expected

    def test_real_world_examples(self):
        """Test real-world usage examples."""

        internal = AclBlock(
            name="internal_networks",
            addresses=["192.168.1.0/24", "10.0.0.0/8", "2001:db8::/32"],
            comment="Internal company networks",
        )

        assert internal.name == "internal_networks"
        assert len(internal.addresses) == 3

        dns_servers = AclBlock.model_validate(
            {"name": "dns_servers", "addresses": ["8.8.8.8", "8.8.4.4", "1.1.1.1"]}
        )

        assert dns_servers.name == "dns_servers"
        assert "8.8.8.8" in dns_servers.addresses

        json_acl = AclBlock.model_validate_json("""{
            "name": "trusted_hosts",
            "addresses": ["192.168.0.1", "192.168.0.2"]
        }""")

        assert json_acl.name == "trusted_hosts"
        assert json_acl.addresses == ["192.168.0.1", "192.168.0.2"]

    def test_edge_cases(self):
        """Test edge cases."""

        long_name = "a" * 100
        acl = AclBlock(name=long_name, addresses=["192.168.1.1"])
        assert acl.name == long_name

        special_names = ["acl_name", "acl-name", "ACL_NAME", "_acl"]
        for name in special_names:
            acl = AclBlock(name=name, addresses=["192.168.1.1"])
            assert acl.name == name

        many_addresses = [f"192.168.{i}.1" for i in range(1, 11)]
        acl = AclBlock(name="many_acl", addresses=many_addresses)
        assert len(acl.addresses) == 10

        acl = AclBlock(name="trimmed", addresses=["  192.168.1.1  ", "  10.0.0.1  "])
        assert acl.addresses == ["192.168.1.1", "10.0.0.1"]

    def test_mutability(self):
        """Test that objects are mutable by default (Pydantic default)."""
        acl = AclBlock(name="mutable", addresses=["192.168.1.1"])

        acl.name = "new_name"
        assert acl.name == "new_name"

    def test_representation(self):
        """Test string representation of object."""
        acl = AclBlock(
            name="test_acl", addresses=["192.168.1.1", "10.0.0.1"], comment="Test representation"
        )

        repr_str = repr(acl)
        assert "test_acl" in repr_str
        assert "AclBlock" in repr_str

        str_str = str(acl)
        assert "test_acl" in str_str

    @pytest.mark.parametrize(
        "name,addresses,expected_output",
        [
            (
                "simple",
                ["192.168.1.1"],
                """acl simple {
    192.168.1.1;
};""",
            ),
            (
                "sorted",
                ["192.168.2.0/24", "192.168.1.0/24", "10.0.0.1"],
                """acl sorted {
    10.0.0.1;
    192.168.1.0/24;
    192.168.2.0/24;
};""",
            ),
            (
                "keys",
                ["key key2", "key key1"],
                """acl keys {
    key key1;
    key key2;
};""",
            ),
            (
                "mixed",
                ["key mykey", "192.168.1.0/24", "!10.0.0.1"],
                """acl mixed {
    !10.0.0.1;
    192.168.1.0/24;
    key mykey;
};""",
            ),
        ],
    )
    def test_parametrized_bind_syntax(self, name, addresses, expected_output):
        """Parametrized test for BIND syntax generation."""
        acl = AclBlock(name=name, addresses=addresses)
        assert acl.model_bind_syntax() == expected_output

    def test_addresses_with_string_representations(self):
        """Test that addresses can be passed as strings (not IP objects)."""

        acl = AclBlock(
            name="string_addresses",
            addresses=[
                "192.168.1.1",
                "10.0.0.0/8",
                "2001:db8::1",
                "key mykey",
            ],
        )

        assert acl.addresses == ["192.168.1.1", "10.0.0.0/8", "2001:db8::1", "key mykey"]

    def test_acl_with_complex_nested_structure(self):
        """Test ACL with complex nested structure."""
        acl = AclBlock(
            name="complex_acl",
            addresses=[
                "!{ 192.168.1.0/24 10.0.0.0/8 }",
                "key admin-key",
                "192.168.2.0/24",
                "!2001:db8::/32",
            ],
        )

        assert acl.name == "complex_acl"
        assert len(acl.addresses) == 4

        output = acl.model_bind_syntax()
        assert output.startswith("acl complex_acl {")
        assert output.endswith("};")
