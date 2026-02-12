from __future__ import annotations

from ipaddress import IPv4Address, IPv6Address

import pytest

from bindantic import ControlsBlock, InetControl


class TestInetControl:
    """Tests for InetControl class."""

    def test_init_with_ipv4_address(self):
        """Test initialization with IPv4 address."""
        control = InetControl(
            ip_address="127.0.0.1",
            port=953,
            allow=["localhost", "127.0.0.1"],
            keys=["rndc-key"],
            read_only=False,
        )

        assert control.ip_address == "127.0.0.1"
        assert control.port == 953
        assert control.allow == ["localhost", "127.0.0.1"]
        assert control.keys == ["rndc-key"]
        assert control.read_only == "no"

    def test_init_with_ipv6_address(self):
        """Test initialization with IPv6 address."""
        control = InetControl(
            ip_address="::1",
            port="*",
            allow=["::1", "2001:db8::/32"],
            keys=None,
            read_only=True,
        )

        assert control.ip_address == "::1"
        assert control.port == "*"
        assert control.allow == ["::1", "2001:db8::/32"]
        assert control.keys is None
        assert control.read_only == "yes"

    def test_init_with_wildcard_addresses(self):
        """Test initialization with wildcard addresses."""
        control_ipv4 = InetControl(
            ip_address="*",
            port=953,
            allow=["any"],
            read_only=None,
        )

        control_ipv6 = InetControl(
            ip_address="::",
            port=1053,
            allow=["any"],
            read_only=None,
        )

        assert control_ipv4.ip_address == "*"
        assert control_ipv6.ip_address == "::"

    def test_init_with_ip_address_objects(self):
        """Test initialization with IP address objects."""
        control_ipv4 = InetControl(
            ip_address=IPv4Address("192.168.1.1"),
            port=53,
            allow=["192.168.1.0/24"],
        )

        control_ipv6 = InetControl(
            ip_address=IPv6Address("2001:db8::1"),
            port=53,
            allow=["2001:db8::/32"],
        )

        assert control_ipv4.ip_address == "192.168.1.1"
        assert control_ipv6.ip_address == "2001:db8::1"

    def test_init_with_default_port(self):
        """Test initialization with default port."""
        control = InetControl(
            ip_address="127.0.0.1",
            allow=["localhost"],
        )

        assert control.port == 953

    def test_init_without_keys(self):
        """Test initialization without keys."""
        control = InetControl(
            ip_address="127.0.0.1",
            allow=["localhost"],
            read_only=True,
        )

        assert control.keys is None
        assert control.read_only == "yes"

    def test_model_bind_syntax_basic_ipv4(self):
        """Test BIND syntax generation for basic IPv4 control."""
        control = InetControl(
            ip_address="127.0.0.1",
            port=953,
            allow=["localhost", "127.0.0.1"],
            keys=["rndc-key", "admin-key"],
            read_only=False,
        )

        expected = """inet 127.0.0.1
    allow {
        127.0.0.1;
        localhost;
    }
    keys {
        admin-key;
        rndc-key;
    }
    read-only no
;"""

        result = control.model_bind_syntax()
        assert result == expected

    def test_model_bind_syntax_basic_ipv6(self):
        """Test BIND syntax generation for basic IPv6 control."""
        control = InetControl(
            ip_address="::1",
            port="*",
            allow=["::1", "2001:db8::/32"],
            keys=None,
            read_only=True,
        )

        expected = """inet ::1 port *
    allow {
        2001:db8::/32;
        ::1;
    }
    read-only yes
;"""

        result = control.model_bind_syntax()
        assert result == expected

    def test_model_bind_syntax_with_custom_port(self):
        """Test BIND syntax generation with custom port."""
        control = InetControl(
            ip_address="192.168.1.100",
            port=1053,
            allow=["192.168.1.0/24"],
            read_only=None,
        )

        expected = """inet 192.168.1.100 port 1053
    allow {
        192.168.1.0/24;
    }
;"""

        result = control.model_bind_syntax()
        assert result == expected

    def test_model_bind_syntax_with_default_port_not_shown(self):
        """Test BIND syntax generation - default port 953 not shown."""
        control = InetControl(
            ip_address="127.0.0.1",
            port=953,
            allow=["localhost"],
        )

        expected = """inet 127.0.0.1
    allow {
        localhost;
    }
;"""

        result = control.model_bind_syntax()
        assert result == expected

    def test_model_bind_syntax_without_read_only(self):
        """Test BIND syntax generation without read-only."""
        control = InetControl(
            ip_address="127.0.0.1",
            allow=["localhost"],
            keys=["my-key"],
            read_only=None,
        )

        expected = """inet 127.0.0.1
    allow {
        localhost;
    }
    keys {
        my-key;
    }
;"""

        result = control.model_bind_syntax()
        assert result == expected

    def test_model_bind_syntax_without_keys(self):
        """Test BIND syntax generation without keys."""
        control = InetControl(
            ip_address="127.0.0.1",
            allow=["localhost"],
            keys=None,
            read_only="yes",
        )

        expected = """inet 127.0.0.1
    allow {
        localhost;
    }
    read-only yes
;"""

        result = control.model_bind_syntax()
        assert result == expected

    def test_model_bind_syntax_empty_allow(self):
        """Test BIND syntax generation with empty allow list."""
        control = InetControl(
            ip_address="127.0.0.1",
            allow=[],
            keys=["test-key"],
        )

        expected = """inet 127.0.0.1
    allow {
    }
    keys {
        test-key;
    }
;"""

        result = control.model_bind_syntax()
        assert result == expected

    def test_model_bind_syntax_with_indentation(self):
        """Test BIND syntax generation with indentation."""
        control = InetControl(
            ip_address="127.0.0.1",
            allow=["localhost"],
            read_only=True,
        )

        expected = """        inet 127.0.0.1
            allow {
                localhost;
            }
            read-only yes
        ;"""

        result = control.model_bind_syntax(2)
        assert result == expected

    def test_model_bind_syntax_with_comment(self):
        """Test BIND syntax generation with comment."""
        control = InetControl(
            ip_address="127.0.0.1",
            allow=["localhost"],
            comment="Local control channel",
        )

        expected = """# Local control channel
inet 127.0.0.1
    allow {
        localhost;
    }
;"""

        result = control.model_bind_syntax()
        assert result == expected

    def test_comparison_attr_property(self):
        """Test comparison_attr property."""
        control1 = InetControl(ip_address="127.0.0.1", port=953, allow=["localhost"])
        control2 = InetControl(ip_address="127.0.0.1", port=1053, allow=["localhost"])
        control3 = InetControl(ip_address="::1", port=953, allow=["localhost"])

        assert control1.comparison_attr == ("127.0.0.1", 953)
        assert control2.comparison_attr == ("127.0.0.1", 1053)
        assert control3.comparison_attr == ("::1", 953)

    def test_comparison_operators(self):
        """Test comparison operators."""
        control1 = InetControl(ip_address="127.0.0.1", port=953, allow=["localhost"])
        control2 = InetControl(ip_address="127.0.0.1", port=1053, allow=["localhost"])
        control3 = InetControl(ip_address="::1", port=953, allow=["localhost"])
        control4 = InetControl(ip_address="127.0.0.1", port=953, allow=["any"])

        assert control1 < control2
        assert control2 > control1
        assert control1 < control3
        assert control3 > control1

        assert control1 <= control4
        assert control1 >= control4

    def test_model_validate(self):
        """Test validation via model_validate."""
        data = {
            "ip_address": "192.168.1.100",
            "port": 1053,
            "allow": ["192.168.1.0/24"],
            "keys": ["key1", "key2"],
            "read_only": True,
        }

        control = InetControl.model_validate(data)
        assert control.ip_address == "192.168.1.100"
        assert control.port == 1053
        assert control.allow == ["192.168.1.0/24"]
        assert control.keys == ["key1", "key2"]
        assert control.read_only == "yes"

    def test_field_validation_ip_address(self):
        """Test IP address field validation."""

        valid_ips = ["127.0.0.1", "192.168.1.1", "::1", "2001:db8::1", "*", "::"]
        for ip in valid_ips:
            control = InetControl(ip_address=ip, allow=["localhost"])
            assert control.ip_address == ip

        invalid_ips = ["not.an.ip", "256.256.256.256", "", "localhost"]
        for ip in invalid_ips:
            with pytest.raises(ValueError):
                InetControl(ip_address=ip, allow=["localhost"])

    def test_field_validation_port(self):
        """Test port field validation."""

        valid_ports = [0, 53, 953, 65535, "*"]
        for port in valid_ports:
            control = InetControl(ip_address="127.0.0.1", port=port, allow=["localhost"])
            assert control.port == port

        invalid_ports = [-1, 65536, "abc", 70000]
        for port in invalid_ports:
            with pytest.raises(ValueError):
                InetControl(ip_address="127.0.0.1", port=port, allow=["localhost"])

    def test_field_validation_boolean(self):
        """Test boolean field validation."""

        valid_bools = [True, False, "yes", "no", "true", "false", 1, 0]
        for bool_val in valid_bools:
            control = InetControl(
                ip_address="127.0.0.1",
                allow=["localhost"],
                read_only=bool_val,
            )
            assert control.read_only in ["yes", "no"]

        invalid_bools = ["maybe", "2", -1]
        for bool_val in invalid_bools:
            with pytest.raises(ValueError):
                InetControl(
                    ip_address="127.0.0.1",
                    allow=["localhost"],
                    read_only=bool_val,
                )

    def test_exclude_from_syntax(self):
        """Test that ip_address and port are excluded from auto-formatting."""

        control1 = InetControl(ip_address="127.0.0.1", port=953, allow=["localhost"])
        fields1 = control1._get_fields_for_syntax()
        field_names1 = [name for name, _ in fields1]

        assert "ip_address" not in field_names1
        assert "port" not in field_names1
        assert "allow" in field_names1
        assert "keys" not in field_names1
        assert "read_only" not in field_names1
        assert "comment" not in field_names1

        control2 = InetControl(
            ip_address="127.0.0.1", port=953, allow=["localhost"], keys=["test-key"]
        )
        fields2 = control2._get_fields_for_syntax()
        field_names2 = [name for name, _ in fields2]

        assert "ip_address" not in field_names2
        assert "port" not in field_names2
        assert "allow" in field_names2
        assert "keys" in field_names2
        assert "read_only" not in field_names2
        assert "comment" not in field_names2

        control3 = InetControl(
            ip_address="127.0.0.1", port=953, allow=["localhost"], read_only=True
        )
        fields3 = control3._get_fields_for_syntax()
        field_names3 = [name for name, _ in fields3]

        assert "ip_address" not in field_names3
        assert "port" not in field_names3
        assert "allow" in field_names3
        assert "keys" not in field_names3
        assert "read_only" in field_names3
        assert "comment" not in field_names3


class TestControlsBlock:
    """Tests for ControlsBlock class."""

    def test_init_empty_controls(self):
        """Test initialization with empty controls list."""
        controls_block = ControlsBlock(controls=[])
        assert controls_block.controls == []

    def test_init_with_single_control(self):
        """Test initialization with single control."""
        control = InetControl(
            ip_address="127.0.0.1",
            allow=["localhost"],
            keys=["rndc-key"],
            read_only=False,
        )

        controls_block = ControlsBlock(controls=[control])
        assert len(controls_block.controls) == 1
        assert controls_block.controls[0] == control

    def test_init_with_multiple_controls(self):
        """Test initialization with multiple controls."""
        control1 = InetControl(ip_address="127.0.0.1", allow=["localhost"])
        control2 = InetControl(ip_address="::1", allow=["::1"])
        control3 = InetControl(ip_address="*", port=1053, allow=["any"])

        controls_block = ControlsBlock(controls=[control1, control2, control3])
        assert len(controls_block.controls) == 3

    def test_model_bind_syntax_empty_controls(self):
        """Test BIND syntax generation with empty controls."""
        controls_block = ControlsBlock(controls=[])
        expected = "controls { };"
        assert controls_block.model_bind_syntax() == expected

    def test_model_bind_syntax_single_control(self):
        """Test BIND syntax generation with single control."""
        control = InetControl(
            ip_address="127.0.0.1",
            allow=["localhost"],
            keys=["rndc-key"],
            read_only=False,
        )

        controls_block = ControlsBlock(controls=[control])

        expected = """controls {
    inet 127.0.0.1
        allow {
            localhost;
        }
        keys {
            rndc-key;
        }
        read-only no
    ;
};"""

        result = controls_block.model_bind_syntax()
        assert result == expected

    def test_model_bind_syntax_multiple_controls(self):
        """Test BIND syntax generation with multiple controls."""
        control1 = InetControl(
            ip_address="127.0.0.1",
            allow=["localhost"],
            keys=["rndc-key"],
            read_only=False,
        )

        control2 = InetControl(
            ip_address="::1",
            port="*",
            allow=["::1"],
            read_only=True,
        )

        controls_block = ControlsBlock(controls=[control1, control2])

        result = controls_block.model_bind_syntax()

        assert "inet 127.0.0.1" in result
        assert "inet ::1 port *" in result
        assert "read-only no" in result
        assert "read-only yes" in result
        assert "keys {\n            rndc-key;\n        }" in result
        assert "allow {\n            localhost;\n        }" in result
        assert "allow {\n            ::1;\n        }" in result

        assert result.startswith("controls {")
        assert result.endswith("};")
        assert result.count("inet ") == 2

    def test_model_bind_syntax_with_indentation(self):
        """Test BIND syntax generation with indentation."""
        control = InetControl(
            ip_address="127.0.0.1",
            allow=["localhost"],
        )

        controls_block = ControlsBlock(controls=[control])

        expected = """        controls {
            inet 127.0.0.1
                allow {
                    localhost;
                }
            ;
        };"""

        result = controls_block.model_bind_syntax(2)
        assert result == expected

    def test_model_bind_syntax_with_comment(self):
        """Test BIND syntax generation with comment."""
        controls_block = ControlsBlock(
            controls=[InetControl(ip_address="127.0.0.1", allow=["localhost"])],
            comment="Control channels configuration",
        )

        result = controls_block.model_bind_syntax()
        assert result.startswith("# Control channels configuration")
        assert "controls {" in result

    def test_validate_controls_configuration_duplicate(self):
        """Test validation for duplicate control configurations."""
        control1 = InetControl(
            ip_address="127.0.0.1",
            port=953,
            allow=["localhost"],
        )

        control2 = InetControl(
            ip_address="127.0.0.1",
            port=953,
            allow=["any"],
        )

        with pytest.raises(ValueError, match="Duplicate control channel configuration"):
            ControlsBlock(controls=[control1, control2])

    def test_validate_controls_configuration_unique(self):
        """Test validation allows unique control configurations."""
        control1 = InetControl(
            ip_address="127.0.0.1",
            port=953,
            allow=["localhost"],
        )

        control2 = InetControl(
            ip_address="127.0.0.1",
            port=1053,
            allow=["any"],
        )

        control3 = InetControl(
            ip_address="::1",
            port=953,
            allow=["::1"],
        )

        controls_block = ControlsBlock(controls=[control1, control2, control3])
        assert len(controls_block.controls) == 3

    def test_model_validate(self):
        """Test validation via model_validate."""
        data = {
            "controls": [
                {
                    "ip_address": "127.0.0.1",
                    "port": 953,
                    "allow": ["localhost"],
                    "keys": ["key1"],
                    "read_only": True,
                },
                {
                    "ip_address": "::1",
                    "port": "*",
                    "allow": ["::1"],
                    "read_only": False,
                },
            ]
        }

        controls_block = ControlsBlock.model_validate(data)
        assert len(controls_block.controls) == 2
        assert controls_block.controls[0].ip_address == "127.0.0.1"
        assert controls_block.controls[1].ip_address == "::1"

    def test_model_copy(self):
        """Test object copying."""
        control = InetControl(ip_address="127.0.0.1", allow=["localhost"])
        controls_block1 = ControlsBlock(controls=[control])

        controls_block2 = controls_block1.model_copy()
        assert controls_block2.controls == controls_block1.controls
        assert controls_block2 is not controls_block1

    def test_model_copy_update(self):
        """Test copying with updates."""
        control1 = InetControl(ip_address="127.0.0.1", allow=["localhost"])
        controls_block1 = ControlsBlock(controls=[control1])

        control2 = InetControl(ip_address="::1", allow=["::1"])
        controls_block2 = controls_block1.model_copy(update={"controls": [control1, control2]})

        assert len(controls_block2.controls) == 2
        assert controls_block2.controls[0].ip_address == "127.0.0.1"
        assert controls_block2.controls[1].ip_address == "::1"

    def test_real_world_examples(self):
        """Test real-world usage examples."""

        default_controls = ControlsBlock(
            controls=[
                InetControl(
                    ip_address="127.0.0.1",
                    allow=["localhost"],
                    keys=["rndc-key"],
                    read_only=False,
                ),
                InetControl(
                    ip_address="::1",
                    allow=["::1"],
                    keys=["rndc-key"],
                    read_only=False,
                ),
            ]
        )

        assert len(default_controls.controls) == 2
        assert default_controls.controls[0].port == 953
        assert default_controls.controls[1].port == 953

        restrictive = ControlsBlock(
            controls=[
                InetControl(
                    ip_address="192.168.1.100",
                    port=1053,
                    allow=["192.168.1.0/24", "key admin-key"],
                    read_only=True,
                )
            ]
        )

        assert restrictive.controls[0].read_only == "yes"

        disabled = ControlsBlock(controls=[])
        assert disabled.controls == []

    def test_edge_cases(self):
        """Test edge cases."""

        control = InetControl(
            ip_address="*",
            port="*",
            allow=["any"],
            keys=["key1", "key2", "key3"],
            read_only=None,
        )

        assert control.ip_address == "*"
        assert control.port == "*"
        assert control.keys == ["key1", "key2", "key3"]

        many_allows = [f"192.168.{i}.1" for i in range(1, 11)]
        control = InetControl(
            ip_address="127.0.0.1",
            allow=many_allows,
        )

        assert len(control.allow) == 10

        control = InetControl(
            ip_address="127.0.0.1",
            allow=["localhost"],
            keys=[],
        )

        assert control.keys == []

    def test_controls_block_with_comment_on_controls(self):
        """Test ControlsBlock where controls have their own comments."""
        control1 = InetControl(
            ip_address="127.0.0.1",
            allow=["localhost"],
            comment="IPv4 control channel",
        )

        control2 = InetControl(
            ip_address="::1",
            allow=["::1"],
            comment="IPv6 control channel",
        )

        controls_block = ControlsBlock(
            controls=[control1, control2],
            comment="Main controls configuration",
        )

        result = controls_block.model_bind_syntax()

        assert "# Main controls configuration" in result
        assert "# IPv4 control channel" in result
        assert "# IPv6 control channel" in result

        assert "inet 127.0.0.1" in result
        assert "inet ::1" in result

    @pytest.mark.parametrize(
        "controls_data,expected_count",
        [
            ([], 0),
            ([{"ip_address": "127.0.0.1", "allow": ["localhost"]}], 1),
            (
                [
                    {"ip_address": "127.0.0.1", "allow": ["localhost"]},
                    {"ip_address": "::1", "allow": ["::1"]},
                ],
                2,
            ),
        ],
    )
    def test_parametrized_controls_count(self, controls_data, expected_count):
        """Parametrized test for controls count."""
        controls = [InetControl.model_validate(data) for data in controls_data]
        controls_block = ControlsBlock(controls=controls)
        assert len(controls_block.controls) == expected_count

    def test_controls_sorted_in_output(self):
        """Test that controls are sorted in output."""
        control1 = InetControl(ip_address="192.168.1.1", allow=["any"])
        control2 = InetControl(ip_address="127.0.0.1", allow=["localhost"])
        control3 = InetControl(ip_address="::1", allow=["::1"])

        controls_block = ControlsBlock(controls=[control1, control2, control3])

        result = controls_block.model_bind_syntax()

        lines = result.split("\n")
        control_lines = [line for line in lines if "inet " in line]

        assert "192.168.1.1" in control_lines[0]
        assert "127.0.0.1" in control_lines[1]
        assert "::1" in control_lines[2]
