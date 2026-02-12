from __future__ import annotations

import pytest
from pydantic import ValidationError

from bindantic import RemoteServerEntry, RemoteServersBlock


class TestRemoteServerEntry:
    """Tests for RemoteServerEntry class."""

    def test_init_server_list(self):
        """Test initialization with server list reference."""
        entry = RemoteServerEntry(server="my-servers")

        assert entry.server == "my-servers"
        assert entry.port is None
        assert entry.key is None
        assert entry.tls is None

    def test_init_ipv4_with_port(self):
        """Test initialization with IPv4 address and port."""
        entry = RemoteServerEntry(server="192.168.1.1", port=5353, key="tsig-key")

        assert str(entry.server) == "192.168.1.1"
        assert entry.port == 5353
        assert entry.key == "tsig-key"
        assert entry.tls is None

    def test_init_ipv6_with_tls(self):
        """Test initialization with IPv6 address and TLS."""
        entry = RemoteServerEntry(server="2001:db8::1", port=853, tls="secure-tls", key="auth-key")

        assert str(entry.server) == "2001:db8::1"
        assert entry.port == 853
        assert entry.key == "auth-key"
        assert entry.tls == "secure-tls"

    def test_init_minimal_ipv4(self):
        """Test minimal initialization with IPv4 address."""
        entry = RemoteServerEntry(server="10.0.0.1")

        assert str(entry.server) == "10.0.0.1"
        assert entry.port is None
        assert entry.key is None
        assert entry.tls is None

    def test_validation_server_list_with_port(self):
        """Test validation fails when server list has port."""
        with pytest.raises(ValidationError, match="cannot have a port specification"):
            RemoteServerEntry(server="my-servers", port=53)

    def test_validation_ipv4_without_port_ok(self):
        """Test IPv4 address without port is valid."""
        entry = RemoteServerEntry(server="192.168.1.100")
        assert entry.port is None

    def test_validation_ipv6_without_port_ok(self):
        """Test IPv6 address without port is valid."""
        entry = RemoteServerEntry(server="2001:db8::100")
        assert entry.port is None

    def test_comparison_operators(self):
        """Test comparison operators."""
        entry1 = RemoteServerEntry(server="server-a")
        entry2 = RemoteServerEntry(server="server-b")
        entry3 = RemoteServerEntry(server="192.168.1.1")
        entry4 = RemoteServerEntry(server="192.168.1.2")

        entries = [entry2, entry4, entry1, entry3]
        sorted_entries = sorted(entries, key=lambda x: str(x.server))

        expected_order = [entry3, entry4, entry1, entry2]
        assert sorted_entries == expected_order

    def test_model_bind_syntax_server_list(self):
        """Test BIND syntax generation with server list."""
        entry = RemoteServerEntry(server="secondary-servers", key="shared-key")

        expected = "secondary-servers key shared-key;"
        assert entry.model_bind_syntax() == expected

    def test_model_bind_syntax_ipv4_full(self):
        """Test BIND syntax generation with full IPv4 configuration."""
        entry = RemoteServerEntry(
            server="192.168.1.1", port=5353, key="tsig-key", tls="tls-config"
        )

        expected = "192.168.1.1 port 5353 key tsig-key tls tls-config;"
        assert entry.model_bind_syntax() == expected

    def test_model_bind_syntax_ipv6_minimal(self):
        """Test BIND syntax generation with minimal IPv6 configuration."""
        entry = RemoteServerEntry(server="2001:db8::1", port="*")

        expected = "2001:db8::1 port *;"
        assert entry.model_bind_syntax() == expected

    def test_model_bind_syntax_with_comment(self):
        """Test BIND syntax generation with comment."""

        entry = RemoteServerEntry(server="192.168.1.100", port=53, comment="Primary name server")
        expected = """# Primary name server
192.168.1.100 port 53;"""
        assert entry.model_bind_syntax() == expected

    def test_model_bind_syntax_with_indent(self):
        """Test BIND syntax generation with indentation."""
        entry = RemoteServerEntry(server="192.168.1.1", port=53)

        assert entry.model_bind_syntax() == "192.168.1.1 port 53;"

        assert entry.model_bind_syntax(1) == "    192.168.1.1 port 53;"

        assert entry.model_bind_syntax(2) == "        192.168.1.1 port 53;"

    def test_model_validate(self):
        """Test validation via model_validate."""
        data = {"server": "10.0.0.1", "port": 5353, "key": "rndc-key", "tls": "ephemeral"}

        entry = RemoteServerEntry.model_validate(data)
        assert str(entry.server) == "10.0.0.1"
        assert entry.port == 5353
        assert entry.key == "rndc-key"
        assert entry.tls == "ephemeral"

    def test_model_validate_json(self):
        """Test validation via model_validate_json."""
        json_data = """{
            "server": "secondary-servers",
            "key": "shared-tsig"
        }"""

        entry = RemoteServerEntry.model_validate_json(json_data)
        assert entry.server == "secondary-servers"
        assert entry.key == "shared-tsig"
        assert entry.port is None
        assert entry.tls is None

    @pytest.mark.parametrize(
        "config,expected_output",
        [
            ({"server": "192.0.2.1", "port": 53}, "192.0.2.1 port 53;"),
            (
                {"server": "198.51.100.1", "port": "*", "tls": "tls-profile"},
                "198.51.100.1 port * tls tls-profile;",
            ),
            ({"server": "secondary-dns", "key": "shared-key"}, "secondary-dns key shared-key;"),
            (
                {"server": "2001:db8::1", "port": 853, "tls": "dot"},
                "2001:db8::1 port 853 tls dot;",
            ),
        ],
    )
    def test_parametrized_bind_syntax(self, config, expected_output):
        """Parametrized test for BIND syntax generation."""
        entry = RemoteServerEntry(**config)
        assert entry.model_bind_syntax() == expected_output


class TestRemoteServersBlock:
    """Tests for RemoteServersBlock class."""

    def test_init_full(self):
        """Test full initialization."""
        servers = [
            RemoteServerEntry(server="192.168.1.1", port=53),
            RemoteServerEntry(server="secondary-servers", key="tsig-key"),
            RemoteServerEntry(server="2001:db8::1", port=853, tls="secure"),
        ]

        block = RemoteServersBlock(
            name="my-servers",
            port=53,
            source="10.0.0.1",
            source_v6="2001:db8::100",
            servers=servers,
        )

        assert block.name == "my-servers"
        assert block.port == 53
        assert block.source == "10.0.0.1"
        assert block.source_v6 == "2001:db8::100"
        assert len(block.servers) == 3

    def test_init_minimal(self):
        """Test minimal initialization."""
        servers = [RemoteServerEntry(server="192.168.1.1")]

        block = RemoteServersBlock(name="minimal-servers", servers=servers)

        assert block.name == "minimal-servers"
        assert block.port is None
        assert block.source is None
        assert block.source_v6 is None
        assert len(block.servers) == 1

    def test_validation_empty_servers(self):
        """Test validation fails with empty servers list."""
        with pytest.raises(ValidationError, match="must contain at least one server"):
            RemoteServersBlock(name="empty", servers=[])

    def test_validation_duplicate_servers(self):
        """Test validation fails with duplicate servers."""
        servers = [
            RemoteServerEntry(server="192.168.1.1", port=53),
            RemoteServerEntry(server="192.168.1.1", port=53),
        ]

        with pytest.raises(ValidationError, match="Duplicate server entry"):
            RemoteServersBlock(name="duplicates", servers=servers)

    def test_validation_duplicate_servers_different_ports(self):
        """Test servers with same IP but different ports are not duplicates."""
        servers = [
            RemoteServerEntry(server="192.168.1.1", port=53),
            RemoteServerEntry(server="192.168.1.1", port=5353),
        ]

        block = RemoteServersBlock(name="different-ports", servers=servers)
        assert len(block.servers) == 2

    def test_validation_duplicate_server_lists(self):
        """Test duplicate server list references."""
        servers = [
            RemoteServerEntry(server="server-list-a"),
            RemoteServerEntry(server="server-list-a"),
        ]

        with pytest.raises(ValidationError, match="Duplicate server entry"):
            RemoteServersBlock(name="duplicate-lists", servers=servers)

    def test_comparison_operators(self):
        """Test comparison operators."""
        block1 = RemoteServersBlock(
            name="aaa-servers", servers=[RemoteServerEntry(server="192.168.1.1")]
        )
        block2 = RemoteServersBlock(
            name="bbb-servers", servers=[RemoteServerEntry(server="192.168.1.2")]
        )

        blocks = [block2, block1]
        sorted_blocks = sorted(blocks, key=lambda x: x.name)
        assert sorted_blocks == [block1, block2]

    def test_model_bind_syntax_full(self):
        """Test BIND syntax generation with full configuration."""
        servers = [
            RemoteServerEntry(server="192.168.1.1", port=53, key="key1", tls="tls1"),
            RemoteServerEntry(server="secondary-list"),
            RemoteServerEntry(server="2001:db8::1", port=853, tls="secure"),
        ]

        block = RemoteServersBlock(
            name="my-remote-servers",
            port=53,
            source="10.0.0.1",
            source_v6="2001:db8::100",
            servers=servers,
        )

        expected = """remote-servers my-remote-servers port 53 source 10.0.0.1 source-v6 2001:db8::100 {
    192.168.1.1 port 53 key key1 tls tls1;
    2001:db8::1 port 853 tls secure;
    secondary-list;
};"""
        assert block.model_bind_syntax() == expected

    def test_model_bind_syntax_minimal(self):
        """Test BIND syntax generation with minimal configuration."""
        servers = [
            RemoteServerEntry(server="10.0.0.1"),
            RemoteServerEntry(server="10.0.0.2"),
        ]

        block = RemoteServersBlock(name="simple-servers", servers=servers)

        expected = """remote-servers simple-servers {
    10.0.0.1;
    10.0.0.2;
};"""
        assert block.model_bind_syntax() == expected

    def test_model_bind_syntax_with_port_only(self):
        """Test BIND syntax generation with port only."""
        servers = [
            RemoteServerEntry(server="192.168.1.1"),
            RemoteServerEntry(server="192.168.1.2", port=5353),
        ]

        block = RemoteServersBlock(name="port-override", port=53, servers=servers)

        expected = """remote-servers port-override port 53 {
    192.168.1.1;
    192.168.1.2 port 5353;
};"""
        assert block.model_bind_syntax() == expected

    def test_model_bind_syntax_with_source_only(self):
        """Test BIND syntax generation with source only."""
        servers = [RemoteServerEntry(server="8.8.8.8")]

        block = RemoteServersBlock(
            name="google-dns",
            source="*",
            source_v6="*",
            servers=servers,
        )

        expected = """remote-servers google-dns source * source-v6 * {
    8.8.8.8;
};"""
        assert block.model_bind_syntax() == expected

    def test_model_bind_syntax_with_comment(self):
        """Test BIND syntax generation with comment."""
        servers = [RemoteServerEntry(server="192.168.1.1")]

        block = RemoteServersBlock(
            name="local-servers", servers=servers, comment="Local DNS servers for internal zones"
        )

        expected = """# Local DNS servers for internal zones
remote-servers local-servers {
    192.168.1.1;
};"""
        assert block.model_bind_syntax() == expected

    def test_model_bind_syntax_with_indent(self):
        """Test BIND syntax generation with indentation."""
        servers = [RemoteServerEntry(server="192.168.1.1")]

        block = RemoteServersBlock(name="test", servers=servers)

        syntax = block.model_bind_syntax()
        assert syntax.startswith("remote-servers test {")

        syntax = block.model_bind_syntax(1)
        assert syntax.startswith("    remote-servers test {")

        syntax = block.model_bind_syntax(2)
        assert syntax.startswith("        remote-servers test {")

    def test_model_validate(self):
        """Test validation via model_validate."""
        data = {
            "name": "validated-servers",
            "port": 5353,
            "source": "*",
            "servers": [
                {"server": "192.168.1.1", "port": 53},
                {"server": "server-list-ref", "key": "auth-key"},
            ],
        }

        block = RemoteServersBlock.model_validate(data)
        assert block.name == "validated-servers"
        assert block.port == 5353
        assert block.source == "*"
        assert block.source_v6 is None
        assert len(block.servers) == 2

    def test_model_validate_json(self):
        """Test validation via model_validate_json."""
        json_data = """{
            "name": "json-servers",
            "port": 53,
            "source_v6": "2001:db8::1",
            "servers": [
                {"server": "10.0.0.1"},
                {"server": "10.0.0.2", "key": "tsig"}
            ]
        }"""

        block = RemoteServersBlock.model_validate_json(json_data)
        assert block.name == "json-servers"
        assert block.port == 53
        assert block.source is None
        assert block.source_v6 == "2001:db8::1"
        assert len(block.servers) == 2

    def test_real_world_example(self):
        """Test a real-world configuration example."""
        servers = [
            RemoteServerEntry(
                server="192.168.1.10",
                port=53,
                key="zone-transfer-key",
                comment="Primary nameserver",
            ),
            RemoteServerEntry(
                server="192.168.1.20",
                port=5353,
                tls="zone-tls",
                comment="Secondary nameserver with TLS",
            ),
            RemoteServerEntry(
                server="2001:db8::1",
                port=853,
                tls="dot-config",
                key="tsig-v6",
                comment="IPv6 nameserver with DNS-over-TLS",
            ),
        ]

        block = RemoteServersBlock(
            name="example-zone-servers",
            port=53,
            source="192.168.1.100",
            source_v6="2001:db8::100",
            servers=servers,
            comment="Remote servers for example.com zone transfers",
        )

        syntax = block.model_bind_syntax()
        assert "remote-servers example-zone-servers" in syntax
        assert "port 53" in syntax
        assert "source 192.168.1.100" in syntax
        assert "source-v6 2001:db8::100" in syntax
        assert "192.168.1.10" in syntax
        assert "192.168.1.20" in syntax
        assert "2001:db8::1" in syntax

    def test_server_override_block_port(self):
        """Test that individual server port overrides block port."""
        servers = [
            RemoteServerEntry(server="192.168.1.1"),
            RemoteServerEntry(server="192.168.1.2", port=5353),
        ]

        block = RemoteServersBlock(name="override-test", port=53, servers=servers)
        syntax = block.model_bind_syntax()

        assert "port 53" in syntax
        assert "192.168.1.2 port 5353" in syntax

    @pytest.mark.parametrize(
        "config,expected_contains",
        [
            (
                {"name": "test1", "port": 53, "servers": [{"server": "192.168.1.1"}]},
                ["port 53", "192.168.1.1"],
            ),
            (
                {
                    "name": "test2",
                    "source": "*",
                    "source_v6": "*",
                    "servers": [{"server": "10.0.0.1", "port": "*"}],
                },
                ["source *", "source-v6 *", "10.0.0.1 port *"],
            ),
            (
                {
                    "name": "test3",
                    "servers": [
                        {"server": "server-list-a"},
                        {"server": "2001:db8::1", "tls": "secure"},
                    ],
                },
                ["server-list-a", "2001:db8::1", "tls secure"],
            ),
        ],
    )
    def test_parametrized_configs(self, config, expected_contains):
        """Parametrized test for various configurations."""
        block = RemoteServersBlock(**config)
        syntax = block.model_bind_syntax()

        for expected in expected_contains:
            assert expected in syntax

    def test_duplicate_with_server_lists(self):
        """Test duplicate detection with server list references."""
        servers = [
            RemoteServerEntry(server="dns-servers"),
            RemoteServerEntry(server="dns-servers"),
        ]

        with pytest.raises(ValidationError, match="Duplicate server entry"):
            RemoteServersBlock(name="duplicate-lists", servers=servers)

    def test_mixed_server_types(self):
        """Test mixed server types (IP addresses and server lists)."""
        servers = [
            RemoteServerEntry(server="192.168.1.1"),
            RemoteServerEntry(server="2001:db8::1"),
            RemoteServerEntry(server="external-servers"),
        ]

        block = RemoteServersBlock(name="mixed", servers=servers)
        assert len(block.servers) == 3

        syntax = block.model_bind_syntax()
        assert "192.168.1.1" in syntax
        assert "2001:db8::1" in syntax
        assert "external-servers" in syntax
