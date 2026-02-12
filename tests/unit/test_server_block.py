from __future__ import annotations

import pytest
from pydantic import ValidationError

from bindantic import ServerBlock


class TestServerBlock:
    """Tests for ServerBlock class."""

    def test_init_minimal(self):
        """Test minimal initialization with only required field."""
        server = ServerBlock(netprefix="192.168.1.1")

        assert server.netprefix == "192.168.1.1/32"
        assert server.bogus is None
        assert server.edns is None
        assert server.provide_ixfr is None
        assert server.comment is None

    def test_init_full(self):
        """Test full initialization with all fields."""
        server = ServerBlock(
            netprefix="10.0.0.0/8",
            bogus=True,
            edns=True,
            provide_ixfr=False,
            request_expire=True,
            request_ixfr=False,
            request_nsid=True,
            require_cookie=False,
            send_cookie=True,
            tcp_keepalive=False,
            tcp_only=False,
            edns_udp_size=512,
            edns_version=0,
            max_udp_size=512,
            padding=128,
            transfers=10,
            transfer_format="many-answers",
            keys="tsig-key",
            notify_source="192.168.1.100",
            notify_source_v6="2001:db8::100",
            query_source="*",
            query_source_v6="*",
            transfer_source="10.0.0.1",
            transfer_source_v6="2001:db8::1",
            comment="Internal server configuration",
        )

        assert server.netprefix == "10.0.0.0/8"
        assert server.bogus == "yes"
        assert server.edns == "yes"
        assert server.provide_ixfr == "no"
        assert server.request_expire == "yes"
        assert server.request_ixfr == "no"
        assert server.request_nsid == "yes"
        assert server.require_cookie == "no"
        assert server.send_cookie == "yes"
        assert server.tcp_keepalive == "no"
        assert server.tcp_only == "no"
        assert server.edns_udp_size == 512
        assert server.edns_version == 0
        assert server.max_udp_size == 512
        assert server.padding == 128
        assert server.transfers == 10
        assert server.transfer_format == "many-answers"
        assert server.keys == "tsig-key"
        assert server.notify_source == "192.168.1.100"
        assert server.notify_source_v6 == "2001:db8::100"
        assert server.query_source == "*"
        assert server.query_source_v6 == "*"
        assert server.transfer_source == "10.0.0.1"
        assert server.transfer_source_v6 == "2001:db8::1"
        assert server.comment == "Internal server configuration"

    def test_init_tcp_only(self):
        """Test initialization with tcp-only enabled (without UDP fields)."""
        server = ServerBlock(
            netprefix="192.168.1.1",
            tcp_only=True,
            tcp_keepalive=True,
            transfers=5,
            keys="tsig-key",
            comment="TCP-only server",
        )

        assert server.tcp_only == "yes"
        assert server.tcp_keepalive == "yes"
        assert server.transfers == 5
        assert server.keys == "tsig-key"
        assert server.edns_udp_size is None
        assert server.max_udp_size is None
        assert server.padding is None

    def test_init_ipv6_netprefix(self):
        """Test initialization with IPv6 network prefix."""
        server = ServerBlock(netprefix="2001:db8::/32")
        assert server.netprefix == "2001:db8::/32"

    def test_boolean_field_conversions(self):
        """Test boolean field conversions to yes/no strings."""
        server = ServerBlock(
            netprefix="192.168.1.1",
            bogus=True,
            edns=False,
            provide_ixfr=1,
            request_expire=0,
            tcp_only="yes",
            tcp_keepalive="no",
        )

        assert server.bogus == "yes"
        assert server.edns == "no"
        assert server.provide_ixfr == "yes"
        assert server.request_expire == "no"
        assert server.tcp_only == "yes"
        assert server.tcp_keepalive == "no"

    def test_comparison_operators(self):
        """Test comparison operators."""
        server1 = ServerBlock(netprefix="10.0.0.0/8")
        server2 = ServerBlock(netprefix="192.168.0.0/16")
        server3 = ServerBlock(netprefix="10.0.0.0/8", bogus=True)

        servers = [server2, server1]
        sorted_servers = sorted(servers, key=lambda x: x.netprefix)
        assert sorted_servers == [server1, server2]

        assert server1.comparison_attr == server3.comparison_attr

    def test_model_bind_syntax_minimal(self):
        """Test BIND syntax generation with minimal configuration."""
        server = ServerBlock(netprefix="192.168.1.1")

        expected = """server 192.168.1.1/32 {
};"""
        assert server.model_bind_syntax() == expected

    def test_model_bind_syntax_full(self):
        """Test BIND syntax generation with full configuration."""
        server = ServerBlock(
            netprefix="10.0.0.0/8",
            bogus=True,
            edns=True,
            provide_ixfr=False,
            request_expire=True,
            request_ixfr=False,
            request_nsid=True,
            require_cookie=False,
            send_cookie=True,
            tcp_keepalive=False,
            tcp_only=False,
            edns_udp_size=512,
            edns_version=0,
            max_udp_size=512,
            padding=128,
            transfers=10,
            transfer_format="many-answers",
            keys="tsig-key",
            notify_source="192.168.1.100",
            notify_source_v6="2001:db8::100",
            query_source="*",
            query_source_v6="*",
            transfer_source="10.0.0.1",
            transfer_source_v6="2001:db8::1",
        )

        bind_syntax = server.model_bind_syntax()
        assert "server 10.0.0.0/8 {" in bind_syntax
        assert "bogus yes;" in bind_syntax
        assert "edns yes;" in bind_syntax
        assert "provide-ixfr no;" in bind_syntax
        assert "request-expire yes;" in bind_syntax
        assert "request-ixfr no;" in bind_syntax
        assert "request-nsid yes;" in bind_syntax
        assert "require-cookie no;" in bind_syntax
        assert "send-cookie yes;" in bind_syntax
        assert "tcp-keepalive no;" in bind_syntax
        assert "tcp-only no;" in bind_syntax
        assert "edns-udp-size 512;" in bind_syntax
        assert "edns-version 0;" in bind_syntax
        assert "max-udp-size 512;" in bind_syntax
        assert "padding 128;" in bind_syntax
        assert "transfers 10;" in bind_syntax
        assert "transfer-format many-answers;" in bind_syntax
        assert "keys tsig-key;" in bind_syntax
        assert "notify-source 192.168.1.100;" in bind_syntax
        assert "notify-source-v6 2001:db8::100;" in bind_syntax
        assert "query-source *;" in bind_syntax
        assert "query-source-v6 *;" in bind_syntax
        assert "transfer-source 10.0.0.1;" in bind_syntax
        assert "transfer-source-v6 2001:db8::1;" in bind_syntax

    def test_model_bind_syntax_tcp_only(self):
        """Test BIND syntax generation with TCP-only configuration."""
        server = ServerBlock(
            netprefix="192.168.1.1",
            tcp_only=True,
            tcp_keepalive=True,
            transfers=5,
            keys="tsig-key",
        )

        bind_syntax = server.model_bind_syntax()
        assert "server 192.168.1.1/32 {" in bind_syntax
        assert "tcp-only yes;" in bind_syntax
        assert "tcp-keepalive yes;" in bind_syntax
        assert "transfers 5;" in bind_syntax
        assert "keys tsig-key;" in bind_syntax

        assert "edns-udp-size" not in bind_syntax
        assert "max-udp-size" not in bind_syntax
        assert "padding" not in bind_syntax

    def test_model_bind_syntax_with_comment(self):
        """Test BIND syntax generation with comment."""
        server = ServerBlock(netprefix="8.8.8.8", edns=True, comment="Google DNS server")

        expected = """# Google DNS server
server 8.8.8.8/32 {
    edns yes;
};"""
        assert server.model_bind_syntax() == expected

    def test_model_validate(self):
        """Test validation via model_validate."""
        data = {
            "netprefix": "192.168.0.0/16",
            "bogus": True,
            "edns": False,
            "transfers": 5,
            "keys": "my-tsig-key",
            "transfer_format": "one-answer",
        }

        server = ServerBlock.model_validate(data)
        assert server.netprefix == "192.168.0.0/16"
        assert server.bogus == "yes"
        assert server.edns == "no"
        assert server.transfers == 5
        assert server.keys == "my-tsig-key"
        assert server.transfer_format == "one-answer"

    def test_model_validate_json(self):
        """Test validation via model_validate_json."""
        json_data = """{
            "netprefix": "2001:db8::/32",
            "edns": true,
            "request_nsid": false,
            "transfers": 3,
            "transfer_format": "many-answers"
        }"""

        server = ServerBlock.model_validate_json(json_data)
        assert server.netprefix == "2001:db8::/32"
        assert server.edns == "yes"
        assert server.request_nsid == "no"
        assert server.transfers == 3
        assert server.transfer_format == "many-answers"

    def test_validation_tcp_only_constraints(self):
        """Test validation of TCP-only related constraints."""

        with pytest.raises(
            ValidationError, match="edns-udp-size cannot be set when tcp-only is yes"
        ):
            ServerBlock(netprefix="192.168.1.1", tcp_only=True, edns_udp_size=512)

        with pytest.raises(
            ValidationError, match="max-udp-size cannot be set when tcp-only is yes"
        ):
            ServerBlock(netprefix="192.168.1.1", tcp_only=True, max_udp_size=512)

        with pytest.raises(ValidationError, match="padding cannot be set when tcp-only is yes"):
            ServerBlock(netprefix="192.168.1.1", tcp_only=True, padding=128)

        with pytest.raises(ValidationError) as exc_info:
            ServerBlock(
                netprefix="192.168.1.1",
                tcp_only=True,
                edns_udp_size=512,
                max_udp_size=512,
                padding=128,
            )
        assert "edns-udp-size cannot be set when tcp-only is yes" in str(exc_info.value)

    def test_validation_tcp_keepalive_constraint(self):
        """Test validation of TCP keepalive constraint."""

        with pytest.raises(ValidationError, match="tcp-keepalive requires tcp-only to be yes"):
            ServerBlock(netprefix="192.168.1.1", tcp_keepalive=True, tcp_only=False)

        server = ServerBlock(netprefix="192.168.1.1", tcp_keepalive=True, tcp_only=True)
        assert server.tcp_keepalive == "yes"
        assert server.tcp_only == "yes"

        server = ServerBlock(netprefix="192.168.1.1", tcp_keepalive=False, tcp_only=False)
        assert server.tcp_keepalive == "no"
        assert server.tcp_only == "no"

    def test_validation_edns_udp_size_range(self):
        """Test validation of edns-udp-size range (0-512)."""

        ServerBlock(netprefix="192.168.1.1", edns_udp_size=0)
        ServerBlock(netprefix="192.168.1.1", edns_udp_size=256)
        ServerBlock(netprefix="192.168.1.1", edns_udp_size=512)

        with pytest.raises(ValidationError, match="Invalid BIND integer value"):
            ServerBlock(netprefix="192.168.1.1", edns_udp_size=-1)

        with pytest.raises(ValidationError) as exc_info:
            ServerBlock(netprefix="192.168.1.1", edns_udp_size=513)

        assert exc_info.value is not None

    def test_validation_edns_version_range(self):
        """Test validation of edns-version range (0-255)."""

        ServerBlock(netprefix="192.168.1.1", edns_version=0)
        ServerBlock(netprefix="192.168.1.1", edns_version=128)
        ServerBlock(netprefix="192.168.1.1", edns_version=255)

        with pytest.raises(ValidationError, match="Invalid BIND integer value"):
            ServerBlock(netprefix="192.168.1.1", edns_version=-1)

        with pytest.raises(ValidationError) as exc_info:
            ServerBlock(netprefix="192.168.1.1", edns_version=256)
        assert exc_info.value is not None

    def test_validation_max_udp_size_range(self):
        """Test validation of max-udp-size range (0-512)."""

        ServerBlock(netprefix="192.168.1.1", max_udp_size=0)
        ServerBlock(netprefix="192.168.1.1", max_udp_size=256)
        ServerBlock(netprefix="192.168.1.1", max_udp_size=512)

        with pytest.raises(ValidationError, match="Invalid BIND integer value"):
            ServerBlock(netprefix="192.168.1.1", max_udp_size=-1)

        with pytest.raises(ValidationError) as exc_info:
            ServerBlock(netprefix="192.168.1.1", max_udp_size=513)
        assert exc_info.value is not None

    def test_validation_padding_range(self):
        """Test validation of padding range (0-512)."""

        ServerBlock(netprefix="192.168.1.1", padding=0)
        ServerBlock(netprefix="192.168.1.1", padding=256)
        ServerBlock(netprefix="192.168.1.1", padding=512)

        with pytest.raises(ValidationError, match="Invalid BIND integer value"):
            ServerBlock(netprefix="192.168.1.1", padding=-1)

        with pytest.raises(ValidationError) as exc_info:
            ServerBlock(netprefix="192.168.1.1", padding=513)
        assert exc_info.value is not None

    def test_field_ordering_in_syntax(self):
        """Test that fields are ordered alphabetically in BIND syntax."""
        server = ServerBlock(
            netprefix="192.168.1.1",
            bogus=True,
            edns=False,
            provide_ixfr=True,
            transfers=5,
            keys="my-key",
        )

        bind_syntax = server.model_bind_syntax()

        lines = bind_syntax.strip().split("\n")
        directive_lines = [line.strip() for line in lines if ";" in line and "server" not in line]

        assert directive_lines[0].startswith("bogus yes;")
        assert directive_lines[1].startswith("edns no;")
        assert directive_lines[2].startswith("keys my-key;")
        assert directive_lines[3].startswith("provide-ixfr yes;")
        assert directive_lines[4].startswith("transfers 5;")

    def test_transfer_format_validation(self):
        """Test validation of transfer_format field."""

        ServerBlock(netprefix="192.168.1.1", transfer_format="many-answers")
        ServerBlock(netprefix="192.168.1.1", transfer_format="one-answer")

        with pytest.raises(ValidationError):
            ServerBlock(netprefix="192.168.1.1", transfer_format="invalid-format")

    def test_wildcard_source_addresses(self):
        """Test wildcard source addresses."""
        server = ServerBlock(
            netprefix="192.168.1.1",
            notify_source="*",
            notify_source_v6="*",
            query_source="*",
            query_source_v6="*",
            transfer_source="*",
            transfer_source_v6="*",
        )

        assert server.notify_source == "*"
        assert server.notify_source_v6 == "*"
        assert server.query_source == "*"
        assert server.query_source_v6 == "*"
        assert server.transfer_source == "*"
        assert server.transfer_source_v6 == "*"

        bind_syntax = server.model_bind_syntax()
        assert "notify-source *;" in bind_syntax
        assert "notify-source-v6 *;" in bind_syntax
        assert "query-source *;" in bind_syntax
        assert "query-source-v6 *;" in bind_syntax
        assert "transfer-source *;" in bind_syntax
        assert "transfer-source-v6 *;" in bind_syntax

    def test_ipv4_source_addresses(self):
        """Test IPv4 source addresses."""
        server = ServerBlock(
            netprefix="192.168.1.1",
            notify_source="10.0.0.1",
            query_source="192.168.100.1",
            transfer_source="172.16.0.1",
        )

        assert server.notify_source == "10.0.0.1"
        assert server.query_source == "192.168.100.1"
        assert server.transfer_source == "172.16.0.1"

    def test_ipv6_source_addresses(self):
        """Test IPv6 source addresses."""
        server = ServerBlock(
            netprefix="192.168.1.1",
            notify_source_v6="2001:db8::1",
            query_source_v6="2001:db8::2",
            transfer_source_v6="2001:db8::3",
        )

        assert server.notify_source_v6 == "2001:db8::1"
        assert server.query_source_v6 == "2001:db8::2"
        assert server.transfer_source_v6 == "2001:db8::3"

    def test_mixed_ipv4_ipv6_configuration(self):
        """Test mixed IPv4 and IPv6 configuration."""
        server = ServerBlock(
            netprefix="192.168.1.1",
            notify_source="10.0.0.1",
            notify_source_v6="2001:db8::1",
            query_source="*",
            query_source_v6="2001:db8::2",
            transfer_source="192.168.1.100",
            transfer_source_v6="*",
        )

        bind_syntax = server.model_bind_syntax()
        assert "notify-source 10.0.0.1;" in bind_syntax
        assert "notify-source-v6 2001:db8::1;" in bind_syntax
        assert "query-source *;" in bind_syntax
        assert "query-source-v6 2001:db8::2;" in bind_syntax
        assert "transfer-source 192.168.1.100;" in bind_syntax
        assert "transfer-source-v6 *;" in bind_syntax

    @pytest.mark.parametrize("transfers_value", [0, 1, 10, 100])
    def test_transfers_valid_values(self, transfers_value):
        """Test valid values for transfers field."""
        server = ServerBlock(netprefix="192.168.1.1", transfers=transfers_value)
        assert server.transfers == transfers_value

    def test_transfers_invalid_value(self):
        """Test invalid value for transfers field (negative)."""
        with pytest.raises(ValidationError, match="Invalid BIND integer value"):
            ServerBlock(netprefix="192.168.1.1", transfers=-1)

    def test_real_world_scenario(self):
        """Test a real-world server configuration scenario."""

        external_server = ServerBlock(
            netprefix="8.8.8.8",
            edns=True,
            edns_udp_size=512,
            max_udp_size=512,
            request_nsid=True,
            send_cookie=True,
            transfers=2,
            comment="Google DNS - external resolver",
        )

        internal_secondary = ServerBlock(
            netprefix="10.0.0.2/32",
            provide_ixfr=True,
            request_ixfr=True,
            keys="internal-tsig",
            transfers=5,
            transfer_format="many-answers",
            notify_source="10.0.0.1",
            transfer_source="10.0.0.1",
            comment="Internal secondary nameserver",
        )

        bogus_server = ServerBlock(
            netprefix="203.0.113.0/24",
            bogus=True,
            tcp_only=True,
            comment="Marked as bogus - entire /24 network",
        )

        external_syntax = external_server.model_bind_syntax()
        internal_syntax = internal_secondary.model_bind_syntax()
        bogus_syntax = bogus_server.model_bind_syntax()

        assert "server 8.8.8.8/32 {" in external_syntax
        assert "server 10.0.0.2/32 {" in internal_syntax
        assert "server 203.0.113.0/24 {" in bogus_syntax

        assert "edns yes;" in external_syntax
        assert "provide-ixfr yes;" in internal_syntax
        assert "bogus yes;" in bogus_syntax
        assert "tcp-only yes;" in bogus_syntax

    def test_nested_indentation(self):
        """Test BIND syntax generation with nested indentation."""
        server = ServerBlock(netprefix="192.168.1.1", edns=True, transfers=3)

        syntax_level_0 = server.model_bind_syntax(indent_level=0)
        syntax_level_1 = server.model_bind_syntax(indent_level=1)
        syntax_level_2 = server.model_bind_syntax(indent_level=2)

        assert syntax_level_0.startswith("server 192.168.1.1/32 {")
        assert syntax_level_1.startswith("    server 192.168.1.1/32 {")
        assert syntax_level_2.startswith("        server 192.168.1.1/32 {")

        assert "    edns yes;" in syntax_level_0
        assert "        edns yes;" in syntax_level_1
        assert "            edns yes;" in syntax_level_2
