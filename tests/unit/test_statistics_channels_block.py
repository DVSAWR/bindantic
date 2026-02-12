from __future__ import annotations

from ipaddress import IPv4Address, IPv6Address

import pytest

from bindantic import InetChannel, StatisticsChannelsBlock


class TestInetChannel:
    """Tests for InetChannel class."""

    def test_init_with_ipv4_string(self):
        """Test initialization with IPv4 address string."""
        channel = InetChannel(
            address="127.0.0.1",
            port=80,
            allow=["localhost", "127.0.0.1", "192.168.1.0/24"],
            comment="Local IPv4 channel",
        )
        assert channel.address == "127.0.0.1"
        assert channel.port == 80
        assert channel.allow == ["localhost", "127.0.0.1", "192.168.1.0/24"]
        assert channel.comment == "Local IPv4 channel"

    def test_init_with_ipv4_object(self):
        """Test initialization with IPv4Address object."""
        channel = InetChannel(address=IPv4Address("192.168.1.100"), port=8080, allow=None)
        assert channel.address == "192.168.1.100"
        assert channel.port == 8080
        assert channel.allow is None

    def test_init_with_ipv6_string(self):
        """Test initialization with IPv6 address string."""
        channel = InetChannel(
            address="::1",
            port="*",
            allow=["10.0.0.0/8", "2001:db8::/32", "key admin-key"],
        )
        assert channel.address == "::1"
        assert channel.port == "*"
        assert channel.allow == ["10.0.0.0/8", "2001:db8::/32", "key admin-key"]

    def test_init_with_ipv6_object(self):
        """Test initialization with IPv6Address object."""
        channel = InetChannel(address=IPv6Address("2001:db8::1"), port=8080, allow=["any"])
        assert channel.address == "2001:db8::1"
        assert channel.port == 8080
        assert channel.allow == ["any"]

    def test_init_with_wildcards(self):
        """Test initialization with wildcard addresses."""
        channel_ipv4 = InetChannel(address="*", port=80, allow=["any"])
        assert channel_ipv4.address == "*"
        assert channel_ipv4.port == 80
        assert channel_ipv4.allow == ["any"]

        channel_ipv6 = InetChannel(address="::", port=443, allow=["localhost"])
        assert channel_ipv6.address == "::"
        assert channel_ipv6.port == 443
        assert channel_ipv6.allow == ["localhost"]

    def test_init_with_port_none(self):
        """Test initialization without port (default)."""
        channel = InetChannel(address="127.0.0.1", allow=["localhost"])
        assert channel.address == "127.0.0.1"
        assert channel.port is None
        assert channel.allow == ["localhost"]

    def test_init_with_allow_none(self):
        """Test initialization without allow list."""
        channel = InetChannel(address="127.0.0.1", port=80)
        assert channel.address == "127.0.0.1"
        assert channel.port == 80
        assert channel.allow is None

    @pytest.mark.parametrize(
        "address, port, allow, expected_syntax",
        [
            (
                "127.0.0.1",
                80,
                ["localhost", "127.0.0.1"],
                "inet 127.0.0.1 port 80 allow {\n    localhost;\n    127.0.0.1;\n};",
            ),
            (
                "::1",
                "*",
                ["key admin-key", "2001:db8::/32"],
                "inet ::1 port * allow {\n    2001:db8::/32;\n    key admin-key;\n};",
            ),
            ("*", 8080, None, "inet * port 8080;"),
            ("::", 80, ["any"], "inet :: port 80 allow {\n    any;\n};"),
            (
                "192.168.1.100",
                8080,
                ["192.168.1.0/24", "10.0.0.1", "localhost"],
                "inet 192.168.1.100 port 8080 allow {\n    10.0.0.1;\n    192.168.1.0/24;\n    localhost;\n};",
            ),
        ],
    )
    def test_model_bind_syntax(self, address, port, allow, expected_syntax):
        """Test BIND syntax generation."""
        channel = InetChannel(address=address, port=port, allow=allow)
        result = channel.model_bind_syntax()

        result_lines = result.strip().split("\n")
        expected_lines = expected_syntax.strip().split("\n")

        assert result_lines[0] == expected_lines[0]

        if "allow" in result:
            result_allow_lines = [
                line.strip()
                for line in result_lines
                if line.strip().endswith(";") and not line.strip().startswith("inet")
            ]
            expected_allow_lines = [
                line.strip()
                for line in expected_lines
                if line.strip().endswith(";") and not line.strip().startswith("inet")
            ]

            assert sorted(result_allow_lines) == sorted(expected_allow_lines)
        else:
            assert result.strip() == expected_syntax.strip()

    def test_model_bind_syntax_with_comment(self):
        """Test BIND syntax generation with comment."""
        channel = InetChannel(
            address="127.0.0.1",
            port=80,
            allow=["localhost"],
            comment="Local statistics channel\nOnly accessible from localhost",
        )
        result = channel.model_bind_syntax()
        assert "# Local statistics channel" in result
        assert "# Only accessible from localhost" in result
        assert "inet 127.0.0.1 port 80 allow" in result
        assert "localhost;" in result

    def test_model_bind_syntax_indented(self):
        """Test BIND syntax generation with indentation."""
        channel = InetChannel(address="127.0.0.1", port=80, allow=["localhost"])
        result = channel.model_bind_syntax(indent_level=2)
        expected = "        inet 127.0.0.1 port 80 allow {\n            localhost;\n        };"
        assert result == expected

    def test_comparison_attribute(self):
        """Test comparison attribute property."""
        channel1 = InetChannel(address="127.0.0.1", port=80)
        assert channel1.comparison_attr == "127.0.0.1"

        channel2 = InetChannel(address="::1", port=80)
        assert channel2.comparison_attr == "::1"

        channel3 = InetChannel(address="*", port=80)
        assert channel3.comparison_attr == "*"

    def test_comparison_operators(self):
        """Test comparison operators."""
        channel_a = InetChannel(address="127.0.0.1", port=80)
        channel_b = InetChannel(address="192.168.1.1", port=80)
        channel_c = InetChannel(address="127.0.0.1", port=8080)

        assert channel_a < channel_b
        assert channel_b > channel_a
        assert channel_a <= channel_c
        assert channel_a >= channel_c

    def test_sorted_channels(self):
        """Test that channels are sorted by address."""
        channels = [
            InetChannel(address="192.168.1.1", port=80),
            InetChannel(address="127.0.0.1", port=80),
            InetChannel(address="10.0.0.1", port=80),
        ]
        sorted_channels = sorted(channels)
        assert [c.address for c in sorted_channels] == ["10.0.0.1", "127.0.0.1", "192.168.1.1"]

    def test_pydantic_validation(self):
        """Test Pydantic validation and type conversion."""

        channel = InetChannel(address="127.0.0.1", port="80")
        assert channel.port == 80

        channel = InetChannel(address="127.0.0.1", port="*")
        assert channel.port == "*"

        channel = InetChannel(address="2001:db8::1", port=80)
        assert channel.address == "2001:db8::1"

    def test_address_validation(self):
        """Test address validation."""

        InetChannel(address="127.0.0.1", port=80)
        InetChannel(address="::1", port=80)
        InetChannel(address="*", port=80)
        InetChannel(address="::", port=80)
        InetChannel(address=IPv4Address("192.168.1.1"), port=80)
        InetChannel(address=IPv6Address("2001:db8::1"), port=80)

        with pytest.raises(ValueError):
            InetChannel(address="not.an.ip", port=80)

    def test_port_validation(self):
        """Test port validation."""

        InetChannel(address="127.0.0.1", port=0)
        InetChannel(address="127.0.0.1", port=65535)
        InetChannel(address="127.0.0.1", port="*")
        InetChannel(address="127.0.0.1", port="80")

        with pytest.raises(ValueError):
            InetChannel(address="127.0.0.1", port=-1)
        with pytest.raises(ValueError):
            InetChannel(address="127.0.0.1", port=65536)
        with pytest.raises(ValueError):
            InetChannel(address="127.0.0.1", port="invalid")


class TestStatisticsChannelsBlock:
    """Tests for StatisticsChannelsBlock class."""

    def test_init_with_single_channel(self):
        """Test initialization with single channel."""
        channel = InetChannel(address="127.0.0.1", port=80, allow=["localhost"])
        block = StatisticsChannelsBlock(channels=[channel])
        assert block.channels == [channel]

    def test_init_with_multiple_channels(self):
        """Test initialization with multiple channels."""
        channels = [
            InetChannel(address="127.0.0.1", port=80, allow=["localhost"]),
            InetChannel(address="::1", port=8080, allow=["::1"]),
            InetChannel(address="*", port=443, allow=["any"]),
        ]
        block = StatisticsChannelsBlock(channels=channels)
        assert block.channels == channels

    def test_init_empty_channels_validation_error(self):
        """Test that empty channels list raises validation error."""
        with pytest.raises(ValueError, match="At least one inet channel must be specified"):
            StatisticsChannelsBlock(channels=[])

    def test_model_bind_syntax_single_channel(self):
        """Test BIND syntax generation with single channel."""
        channel = InetChannel(address="127.0.0.1", port=80, allow=["localhost"])
        block = StatisticsChannelsBlock(channels=[channel])
        expected = (
            "statistics-channels {\n"
            "    inet 127.0.0.1 port 80 allow {\n"
            "        localhost;\n"
            "    };\n"
            "};"
        )
        assert block.model_bind_syntax() == expected

    def test_model_bind_syntax_multiple_channels(self):
        """Test BIND syntax generation with multiple channels."""
        channels = [
            InetChannel(address="192.168.1.100", port=8080, allow=["192.168.1.0/24"]),
            InetChannel(address="127.0.0.1", port=80, allow=["localhost", "127.0.0.1"]),
        ]
        block = StatisticsChannelsBlock(channels=channels)

        result = block.model_bind_syntax()
        assert "127.0.0.1" in result
        assert "192.168.1.100" in result
        assert "statistics-channels {" in result
        assert result.count("inet ") == 2

    def test_model_bind_syntax_with_comments(self):
        """Test BIND syntax generation with comments."""
        channel1 = InetChannel(
            address="127.0.0.1",
            port=80,
            allow=["localhost"],
            comment="Primary stats channel",
        )
        channel2 = InetChannel(
            address="::1",
            port=8080,
            allow=["::1"],
            comment="IPv6 stats channel",
        )
        block = StatisticsChannelsBlock(
            channels=[channel1, channel2],
            comment="Statistics channels configuration\nFor monitoring and debugging",
        )

        result = block.model_bind_syntax()
        assert "# Statistics channels configuration" in result
        assert "# For monitoring and debugging" in result
        assert "# Primary stats channel" in result
        assert "# IPv6 stats channel" in result

    def test_model_bind_syntax_indented(self):
        """Test BIND syntax generation with indentation."""
        channel = InetChannel(address="127.0.0.1", port=80, allow=["localhost"])
        block = StatisticsChannelsBlock(channels=[channel])

        result = block.model_bind_syntax(indent_level=1)
        expected = (
            "    statistics-channels {\n"
            "        inet 127.0.0.1 port 80 allow {\n"
            "            localhost;\n"
            "        };\n"
            "    };"
        )
        assert result == expected

    def test_channels_sorted_in_output(self):
        """Test that channels are sorted in BIND syntax output."""
        channels = [
            InetChannel(address="192.168.1.100", port=8080),
            InetChannel(address="127.0.0.1", port=80),
            InetChannel(address="10.0.0.1", port=443),
        ]
        block = StatisticsChannelsBlock(channels=channels)
        result = block.model_bind_syntax()

        lines = result.split("\n")
        inet_lines = [line for line in lines if line.strip().startswith("inet")]
        assert len(inet_lines) == 3
        assert "10.0.0.1" in inet_lines[0]
        assert "127.0.0.1" in inet_lines[1]
        assert "192.168.1.100" in inet_lines[2]

    def test_with_various_address_types(self):
        """Test with various address types in channels."""
        channels = [
            InetChannel(address=IPv4Address("192.168.1.1"), port=80),
            InetChannel(address="2001:db8::1", port=8080),
            InetChannel(address="*", port=443),
            InetChannel(address=IPv6Address("::1"), port=80),
        ]
        block = StatisticsChannelsBlock(channels=channels)
        result = block.model_bind_syntax()

        assert "192.168.1.1" in result
        assert "2001:db8::1" in result
        assert "*" in result
        assert "::1" in result

    def test_allow_list_parsing(self):
        """Test parsing of allow lists with various formats."""

        channel1 = InetChannel(address="127.0.0.1", port=80, allow=["trusted-nets"])

        channel2 = InetChannel(address="::1", port=80, allow=["2001:db8::/32"])

        channel3 = InetChannel(address="*", port=80, allow=["key admin-key"])

        channel4 = InetChannel(
            address="192.168.1.100",
            port=8080,
            allow=["192.168.1.0/24", "key tsig-key", "!10.0.0.1"],
        )

        block = StatisticsChannelsBlock(channels=[channel1, channel2, channel3, channel4])
        result = block.model_bind_syntax()

        assert "trusted-nets" in result
        assert "2001:db8::/32" in result
        assert "key admin-key" in result
        assert "192.168.1.0/24" in result
        assert "key tsig-key" in result
        assert "!10.0.0.1" in result

    def test_port_special_values(self):
        """Test port special values (* and None)."""

        channel1 = InetChannel(address="127.0.0.1", port="*", allow=["localhost"])
        assert channel1.port == "*"
        assert "port *" in channel1.model_bind_syntax()

        channel2 = InetChannel(address="127.0.0.1", allow=["localhost"])
        assert channel2.port is None
        assert "port" not in channel2.model_bind_syntax()

    def test_pydantic_model_validation(self):
        """Test Pydantic model validation."""

        block_dict = {
            "channels": [
                {
                    "address": "127.0.0.1",
                    "port": 80,
                    "allow": ["localhost"],
                    "comment": "Local channel",
                }
            ]
        }
        block = StatisticsChannelsBlock.model_validate(block_dict)
        assert len(block.channels) == 1
        assert block.channels[0].address == "127.0.0.1"
        assert block.channels[0].port == 80
        assert block.channels[0].allow == ["localhost"]
        assert block.channels[0].comment == "Local channel"

        block_json = """
        {
            "channels": [
                {
                    "address": "::1",
                    "port": 8080,
                    "allow": ["::1", "key admin-key"]
                }
            ]
        }
        """
        block = StatisticsChannelsBlock.model_validate_json(block_json)
        assert len(block.channels) == 1
        assert block.channels[0].address == "::1"
        assert block.channels[0].port == 8080
        assert block.channels[0].allow == ["::1", "key admin-key"]

    def test_real_world_examples(self):
        """Test real-world examples from the manual initialization."""

        channel = InetChannel(
            address="127.0.0.1",
            port=80,
            allow=["127.0.0.1", "192.168.1.0/24", "localhost"],
        )
        block = StatisticsChannelsBlock(channels=[channel])
        result = block.model_bind_syntax()

        assert "statistics-channels {" in result
        assert "inet 127.0.0.1 port 80 allow" in result
        assert "127.0.0.1;" in result
        assert "192.168.1.0/24;" in result
        assert "localhost;" in result

        channel = InetChannel(
            address=IPv6Address("::1"),
            port="*",
            allow=["10.0.0.0/8", "2001:db8::/32", "key admin-key"],
        )
        block = StatisticsChannelsBlock(channels=[channel])
        result = block.model_bind_syntax()
        assert "inet ::1 port *" in result
        assert "2001:db8::/32" in result
        assert "key admin-key" in result

        channel = InetChannel(address="*", port=80, allow=["any"])
        block = StatisticsChannelsBlock(channels=[channel])
        result = block.model_bind_syntax()

        expected = "statistics-channels {\n    inet * port 80 allow {\n        any;\n    };\n};"
        assert result == expected
