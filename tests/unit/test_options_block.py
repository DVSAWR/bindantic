from __future__ import annotations

from ipaddress import IPv6Address

import pytest
from pydantic import ValidationError

from bindantic import (
    AlsoNotifyBlock,
    CatalogZoneBlock,
    Dns64Block,
    ForwardersBlock,
    OptionsBlock,
    RateLimitBlock,
    ResponsePolicyBlock,
    ResponsePolicyZone,
    RrsetOrderRule,
    ServerSpecifier,
)


class TestServerSpecifier:
    """Tests for ServerSpecifier class."""

    def test_init_basic(self):
        """Test basic initialization."""
        server = ServerSpecifier(address="192.168.1.1", port=53, key="my-key", tls="tls-config")

        assert str(server.address) == "192.168.1.1"
        assert server.port == 53
        assert server.key == "my-key"
        assert server.tls == "tls-config"

    def test_init_ipv6(self):
        """Test initialization with IPv6 address."""
        server = ServerSpecifier(address=IPv6Address("2001:db8::1"), port="*")

        assert str(server.address) == "2001:db8::1"
        assert server.port == "*"
        assert server.key is None
        assert server.tls is None

    def test_init_minimal(self):
        """Test minimal initialization."""
        server = ServerSpecifier(address="8.8.8.8")

        assert str(server.address) == "8.8.8.8"
        assert server.port is None
        assert server.key is None
        assert server.tls is None

    def test_comparison_operators(self):
        """Test comparison operators."""
        server1 = ServerSpecifier(address="192.168.1.1", port=53)
        server2 = ServerSpecifier(address="192.168.1.1", port=54)
        server3 = ServerSpecifier(address="192.168.1.2", port=53)

        assert server1 < server2
        assert server1 < server3
        assert server1 <= server1  # noqa: PLR0124
        assert server2 >= server2  # noqa: PLR0124

    def test_model_bind_syntax(self):
        """Test BIND syntax generation."""

        server1 = ServerSpecifier(address="192.168.1.1", port=53, key="tsig-key", tls="secure-tls")
        assert server1.model_bind_syntax() == "192.168.1.1 port 53 key tsig-key tls secure-tls;"

        server2 = ServerSpecifier(address="8.8.8.8")
        assert server2.model_bind_syntax() == "8.8.8.8;"

        server3 = ServerSpecifier(address="2001:db8::1", port="*")
        assert server3.model_bind_syntax() == "2001:db8::1 port *;"

        server4 = ServerSpecifier(address="10.0.0.1", key="auth-key")
        assert server4.model_bind_syntax() == "10.0.0.1 key auth-key;"

    def test_model_bind_syntax_with_comment(self):
        """Test BIND syntax generation with comment."""
        server = ServerSpecifier(address="192.168.1.100", port=5353, comment="Local DNS server")

        expected = """# Local DNS server
192.168.1.100 port 5353;"""
        assert server.model_bind_syntax() == expected

    def test_model_validate(self):
        """Test validation via model_validate."""
        data = {"address": "10.0.0.1", "port": 53, "key": "rndc-key", "tls": "ephemeral"}

        server = ServerSpecifier.model_validate(data)
        assert str(server.address) == "10.0.0.1"
        assert server.port == 53
        assert server.key == "rndc-key"
        assert server.tls == "ephemeral"

    def test_model_validate_json(self):
        """Test validation via model_validate_json."""
        json_data = """{
            "address": "2001:db8::1",
            "port": "*",
            "key": "tsig-key"
        }"""

        server = ServerSpecifier.model_validate_json(json_data)
        assert str(server.address) == "2001:db8::1"
        assert server.port == "*"
        assert server.key == "tsig-key"
        assert server.tls is None

    @pytest.mark.parametrize(
        "config,expected_output",
        [
            ({"address": "192.0.2.1", "port": 53}, "192.0.2.1 port 53;"),
            (
                {"address": "198.51.100.1", "port": "*", "tls": "tls-profile"},
                "198.51.100.1 port * tls tls-profile;",
            ),
            ({"address": "203.0.113.1", "key": "shared-key"}, "203.0.113.1 key shared-key;"),
        ],
    )
    def test_parametrized_bind_syntax(self, config, expected_output):
        """Parametrized test for BIND syntax generation."""
        server = ServerSpecifier(**config)
        assert server.model_bind_syntax() == expected_output


class TestAlsoNotifyBlock:
    """Tests for AlsoNotifyBlock class."""

    def test_init_full(self):
        """Test full initialization."""
        servers = [
            ServerSpecifier(address="192.168.1.1", port=53),
            ServerSpecifier(address="2001:db8::1", port="*", key="tsig-key"),
        ]

        also_notify = AlsoNotifyBlock(
            global_port=53, source="192.168.1.100", source_v6="2001:db8::100", servers=servers
        )

        assert also_notify.global_port == 53
        assert also_notify.source == "192.168.1.100"
        assert also_notify.source_v6 == "2001:db8::100"
        assert len(also_notify.servers) == 2

    def test_init_minimal(self):
        """Test minimal initialization."""
        also_notify = AlsoNotifyBlock(servers=[ServerSpecifier(address="192.168.1.1")])

        assert also_notify.global_port is None
        assert also_notify.source is None
        assert also_notify.source_v6 is None
        assert len(also_notify.servers) == 1

    def test_model_bind_syntax_full(self):
        """Test BIND syntax generation with full configuration."""
        servers = [
            ServerSpecifier(address="192.168.1.1", port=53, key="my-key", tls="tls-config"),
            ServerSpecifier(address="2001:db8::1", port="*"),
        ]

        also_notify = AlsoNotifyBlock(
            global_port=53, source="192.168.1.100", source_v6="2001:db8::100", servers=servers
        )

        expected = """also-notify port 53 source 192.168.1.100 source-v6 2001:db8::100 {
    192.168.1.1 port 53 key my-key tls tls-config;
    2001:db8::1 port *;
};"""
        assert also_notify.model_bind_syntax() == expected

    def test_model_bind_syntax_minimal(self):
        """Test BIND syntax generation with minimal configuration."""
        also_notify = AlsoNotifyBlock(servers=[ServerSpecifier(address="10.0.0.1", port=5353)])

        expected = """also-notify {
    10.0.0.1 port 5353;
};"""
        assert also_notify.model_bind_syntax() == expected

    def test_model_bind_syntax_with_comment(self):
        """Test BIND syntax generation with comment."""
        also_notify = AlsoNotifyBlock(
            servers=[ServerSpecifier(address="192.168.1.1")], comment="Notify secondary servers"
        )

        expected = """# Notify secondary servers
also-notify {
    192.168.1.1;
};"""
        assert also_notify.model_bind_syntax() == expected

    def test_model_validate(self):
        """Test validation via model_validate."""
        data = {
            "global_port": 5353,
            "source": "*",
            "source_v6": "*",
            "servers": [
                {"address": "192.168.1.1", "port": 53},
                {"address": "10.0.0.1", "key": "auth-key"},
            ],
        }

        also_notify = AlsoNotifyBlock.model_validate(data)
        assert also_notify.global_port == 5353
        assert also_notify.source == "*"
        assert also_notify.source_v6 == "*"
        assert len(also_notify.servers) == 2

    @pytest.mark.parametrize(
        "config,expected_contains",
        [
            (
                {"global_port": 53, "servers": [{"address": "192.168.1.1"}]},
                ["port 53", "192.168.1.1"],
            ),
            (
                {
                    "source": "*",
                    "source_v6": "*",
                    "servers": [{"address": "10.0.0.1", "port": "*"}],
                },
                ["source *", "source-v6 *", "10.0.0.1 port *"],
            ),
        ],
    )
    def test_parametrized_bind_syntax(self, config, expected_contains):
        """Parametrized test for BIND syntax generation."""
        also_notify = AlsoNotifyBlock(**config)
        bind_syntax = also_notify.model_bind_syntax()

        for expected in expected_contains:
            assert expected in bind_syntax


class TestForwardersBlock:
    """Tests for ForwardersBlock class."""

    def test_init_full(self):
        """Test full initialization."""
        servers = [
            ServerSpecifier(address="8.8.8.8", port=53),
            ServerSpecifier(address="8.8.4.4", port=53),
        ]

        forwarders = ForwardersBlock(
            global_port=53, source="192.168.1.100", source_v6="2001:db8::100", servers=servers
        )

        assert forwarders.global_port == 53
        assert forwarders.source == "192.168.1.100"
        assert forwarders.source_v6 == "2001:db8::100"
        assert len(forwarders.servers) == 2

    def test_model_bind_syntax_full(self):
        """Test BIND syntax generation with full configuration."""
        servers = [
            ServerSpecifier(address="8.8.8.8", port=53, key="google-key"),
            ServerSpecifier(address="2001:4860:4860::8888", port=53),
        ]

        forwarders = ForwardersBlock(
            global_port=53, source="10.0.0.1", source_v6="2001:db8::1", servers=servers
        )

        expected = """forwarders port 53 source 10.0.0.1 source-v6 2001:db8::1 {
    8.8.8.8 port 53 key google-key;
    2001:4860:4860::8888 port 53;
};"""
        assert forwarders.model_bind_syntax() == expected

    def test_model_bind_syntax_minimal(self):
        """Test BIND syntax generation with minimal configuration."""
        forwarders = ForwardersBlock(
            servers=[
                ServerSpecifier(address="192.168.1.1"),
                ServerSpecifier(address="192.168.1.2"),
            ]
        )

        expected = """forwarders {
    192.168.1.1;
    192.168.1.2;
};"""
        assert forwarders.model_bind_syntax() == expected

    def test_model_validate(self):
        """Test validation via model_validate."""
        data = {
            "global_port": 5353,
            "source": "*",
            "servers": [{"address": "1.1.1.1", "port": 53}, {"address": "1.0.0.1", "port": 53}],
        }

        forwarders = ForwardersBlock.model_validate(data)
        assert forwarders.global_port == 5353
        assert forwarders.source == "*"
        assert forwarders.source_v6 is None
        assert len(forwarders.servers) == 2


class TestDns64Block:
    """Tests for Dns64Block class."""

    def test_init_full(self):
        """Test full initialization."""
        dns64 = Dns64Block(
            prefix="64:ff9b::/96",
            break_dnssec=True,
            clients=["192.168.1.0/24", "2001:db8::/32"],
            exclude=["192.168.1.100", "2001:db8::100"],
            mapped=["10.0.0.0/8"],
            recursive_only=False,
            suffix="::ffff:0:0",
        )

        assert dns64.prefix == "64:ff9b::/96"
        assert dns64.break_dnssec == "yes"
        assert len(dns64.clients) == 2
        assert len(dns64.exclude) == 2
        assert len(dns64.mapped) == 1
        assert dns64.recursive_only == "no"
        assert dns64.suffix == "::ffff:0.0.0.0"

    def test_init_minimal(self):
        """Test minimal initialization."""
        dns64 = Dns64Block(prefix="2001:db8:64::/96")

        assert dns64.prefix == "2001:db8:64::/96"
        assert dns64.break_dnssec is None
        assert dns64.clients is None
        assert dns64.exclude is None
        assert dns64.mapped is None
        assert dns64.recursive_only is None
        assert dns64.suffix is None

    def test_comparison_operators(self):
        """Test comparison operators."""
        dns64_1 = Dns64Block(prefix="2001:db8:64::/96")
        dns64_2 = Dns64Block(prefix="64:ff9b::/96")

        zones = [dns64_2, dns64_1]
        sorted_zones = sorted(zones, key=lambda x: x.prefix)
        assert sorted_zones == [dns64_1, dns64_2]

    def test_model_bind_syntax_full(self):
        """Test BIND syntax generation with full configuration."""
        dns64 = Dns64Block(
            prefix="64:ff9b::/96",
            break_dnssec="yes",
            clients=["192.168.1.0/24", "2001:db8::/32"],
            exclude=["192.168.1.100", "2001:db8::100"],
            recursive_only=1,
            suffix="::ffff:0:0",
        )

        expected = """dns64 64:ff9b::/96 {
    break-dnssec yes;
    clients {
        192.168.1.0/24;
        2001:db8::/32;
    };
    exclude {
        192.168.1.100;
        2001:db8::100;
    };
    recursive-only yes;
    suffix ::ffff:0.0.0.0;
};"""
        assert dns64.model_bind_syntax() == expected

    def test_model_bind_syntax_with_comment(self):
        """Test BIND syntax generation with comment."""
        dns64 = Dns64Block(
            prefix="2001:db8:64::/96",
            mapped=["10.0.0.0/8", "172.16.0.0/12"],
            comment="DNS64 for NAT64",
        )

        expected = """# DNS64 for NAT64
dns64 2001:db8:64::/96 {
    mapped {
        10.0.0.0/8;
        172.16.0.0/12;
    };
};"""
        assert dns64.model_bind_syntax() == expected

    def test_model_validate(self):
        """Test validation via model_validate."""
        data = {
            "prefix": "64:ff9b::/96",
            "break_dnssec": True,
            "clients": ["192.168.0.0/16"],
            "recursive_only": False,
        }

        dns64 = Dns64Block.model_validate(data)
        assert dns64.prefix == "64:ff9b::/96"
        assert dns64.break_dnssec == "yes"
        assert dns64.clients == ["192.168.0.0/16"]
        assert dns64.recursive_only == "no"

    @pytest.mark.parametrize(
        "prefix,break_dnssec,expected_contains",
        [
            ("64:ff9b::/96", True, ["break-dnssec yes"]),
            ("2001:db8:64::/96", False, ["break-dnssec no"]),
            ("64:ff9b::/96", 1, ["break-dnssec yes"]),
            ("64:ff9b::/96", 0, ["break-dnssec no"]),
        ],
    )
    def test_break_dnssec_values(self, prefix, break_dnssec, expected_contains):
        """Test different break-dnssec values."""
        dns64 = Dns64Block(prefix=prefix, break_dnssec=break_dnssec)
        bind_syntax = dns64.model_bind_syntax()

        for expected in expected_contains:
            assert expected in bind_syntax


class TestRateLimitBlock:
    """Tests for RateLimitBlock class."""

    def test_init_full(self):
        """Test full initialization."""
        rate_limit = RateLimitBlock(
            responses_per_second=100,
            errors_per_second=50,
            nxdomains_per_second=20,
            slip=2,
            exempt_clients=["127.0.0.1", "::1"],
            log_only=True,
        )

        assert rate_limit.responses_per_second == 100
        assert rate_limit.errors_per_second == 50
        assert rate_limit.nxdomains_per_second == 20
        assert rate_limit.slip == 2
        assert rate_limit.exempt_clients == ["127.0.0.1", "::1"]
        assert rate_limit.log_only == "yes"

    def test_slip_validation(self):
        """Test slip field validation."""

        RateLimitBlock(slip=0)
        RateLimitBlock(slip=5)
        RateLimitBlock(slip=10)

        with pytest.raises(ValidationError):
            RateLimitBlock(slip=-1)

        with pytest.raises(ValidationError):
            RateLimitBlock(ipv4_prefix_length=33)

        with pytest.raises(ValidationError):
            RateLimitBlock(ipv4_prefix_length=-1)

        with pytest.raises(ValidationError):
            RateLimitBlock(ipv6_prefix_length=129)

        with pytest.raises(ValidationError):
            RateLimitBlock(ipv6_prefix_length=-1)

    def test_prefix_length_validation(self):
        """Test IPv4/IPv6 prefix length validation."""

        RateLimitBlock(ipv4_prefix_length=24)
        RateLimitBlock(ipv6_prefix_length=64)
        RateLimitBlock(ipv4_prefix_length=0, ipv6_prefix_length=0)
        RateLimitBlock(ipv4_prefix_length=32, ipv6_prefix_length=128)

    def test_model_bind_syntax_full(self):
        """Test BIND syntax generation with full configuration."""
        rate_limit = RateLimitBlock(
            responses_per_second=100,
            errors_per_second=50,
            nxdomains_per_second=20,
            slip=2,
            exempt_clients=["127.0.0.1", "::1"],
            log_only=True,
        )

        expected = """rate-limit {
    errors-per-second 50;
    exempt-clients {
        127.0.0.1;
        ::1;
    };
    log-only yes;
    nxdomains-per-second 20;
    responses-per-second 100;
    slip 2;
};"""
        assert rate_limit.model_bind_syntax() == expected

    def test_model_bind_syntax_complex(self):
        """Test BIND syntax generation with complex configuration."""
        rate_limit = RateLimitBlock(
            all_per_second=200,
            ipv4_prefix_length=24,
            ipv6_prefix_length=64,
            window=60,
            qps_scale=1000,
            max_table_size=10000,
            min_table_size=1000,
        )

        bind_syntax = rate_limit.model_bind_syntax()
        assert "all-per-second 200" in bind_syntax
        assert "ipv4-prefix-length 24" in bind_syntax
        assert "ipv6-prefix-length 64" in bind_syntax
        assert "window 60" in bind_syntax
        assert "qps-scale 1000" in bind_syntax
        assert "max-table-size 10000" in bind_syntax
        assert "min-table-size 1000" in bind_syntax

    def test_model_bind_syntax_with_comment(self):
        """Test BIND syntax generation with comment."""
        rate_limit = RateLimitBlock(responses_per_second=50, slip=1, comment="Basic rate limiting")

        expected = """# Basic rate limiting
rate-limit {
    responses-per-second 50;
    slip 1;
};"""
        assert rate_limit.model_bind_syntax() == expected

    def test_model_validate(self):
        """Test validation via model_validate."""
        data = {
            "responses_per_second": 50,
            "errors_per_second": 10,
            "slip": 1,
            "log_only": False,
            "ipv4_prefix_length": 24,
            "ipv6_prefix_length": 48,
        }

        rate_limit = RateLimitBlock.model_validate(data)
        assert rate_limit.responses_per_second == 50
        assert rate_limit.errors_per_second == 10
        assert rate_limit.slip == 1
        assert rate_limit.log_only == "no"
        assert rate_limit.ipv4_prefix_length == 24
        assert rate_limit.ipv6_prefix_length == 48


class TestResponsePolicyZone:
    """Tests for ResponsePolicyZone class."""

    def test_init_full(self):
        """Test full initialization."""
        rpz = ResponsePolicyZone(
            zone="example.com",
            add_soa=True,
            log=True,
            max_policy_ttl="1h",
            policy="drop",
            recursive_only=False,
            nsip_enable=True,
            nsdname_enable=False,
            ede="blocked",
        )

        assert rpz.zone == "example.com."
        assert rpz.add_soa == "yes"
        assert rpz.log == "yes"
        assert rpz.max_policy_ttl == 3600
        assert rpz.policy == "drop"
        assert rpz.recursive_only == "no"
        assert rpz.nsip_enable == "yes"
        assert rpz.nsdname_enable == "no"
        assert rpz.ede == "blocked"

    def test_policy_validation(self):
        """Test policy field validation."""

        valid_policies = [
            "cname",
            "disabled",
            "drop",
            "given",
            "no-op",
            "nodata",
            "nxdomain",
            "passthru",
            "tcp-only",
        ]

        for policy in valid_policies:
            rpz = ResponsePolicyZone(zone="test.com", policy=policy)
            assert rpz.policy == policy

        rpz = ResponsePolicyZone(zone="test.com", policy="tcp-only example.com")
        assert rpz.policy == "tcp-only example.com"

        with pytest.raises(ValidationError):
            ResponsePolicyZone(zone="test.com", policy="invalid")

    def test_ede_validation(self):
        """Test EDE field validation."""

        valid_ede = ["none", "forged", "blocked", "censored", "filtered", "prohibited"]

        for ede in valid_ede:
            rpz = ResponsePolicyZone(zone="test.com", ede=ede)
            assert rpz.ede == ede

        with pytest.raises(ValidationError):
            ResponsePolicyZone(zone="test.com", ede="invalid")

    def test_comparison_operators(self):
        """Test comparison operators."""
        rpz1 = ResponsePolicyZone(zone="aaa.example.com")
        rpz2 = ResponsePolicyZone(zone="bbb.example.com")

        zones = [rpz2, rpz1]
        sorted_zones = sorted(zones, key=lambda x: x.zone)
        assert sorted_zones == [rpz1, rpz2]

    def test_model_bind_syntax_full(self):
        """Test BIND syntax generation with full configuration."""
        rpz = ResponsePolicyZone(
            zone="example.com",
            add_soa=True,
            log=1,
            max_policy_ttl="1h",
            policy="drop",
            ede="blocked",
        )

        expected = """zone example.com. {
    add-soa yes;
    ede blocked;
    log yes;
    max-policy-ttl 3600;
    policy drop;
};"""
        assert rpz.model_bind_syntax() == expected

    def test_model_bind_syntax_with_boolean_false(self):
        """Test BIND syntax generation with false boolean values."""
        rpz = ResponsePolicyZone(
            zone="malware.local", recursive_only="no", nsip_enable=False, nsdname_enable=0
        )

        expected = """zone malware.local. {
    nsdname-enable no;
    nsip-enable no;
    recursive-only no;
};"""
        assert rpz.model_bind_syntax() == expected

    def test_model_validate(self):
        """Test validation via model_validate."""
        data = {"zone": "example.org", "policy": "nxdomain", "log": True, "max_policy_ttl": 7200}

        rpz = ResponsePolicyZone.model_validate(data)
        assert rpz.zone == "example.org."
        assert rpz.policy == "nxdomain"
        assert rpz.log == "yes"
        assert rpz.max_policy_ttl == 7200


class TestResponsePolicyBlock:
    """Tests for ResponsePolicyBlock class."""

    def test_init_with_zones(self):
        """Test initialization with zones."""
        zones = [
            ResponsePolicyZone(zone="example.com", policy="drop"),
            ResponsePolicyZone(zone="malware.local", policy="nxdomain"),
        ]

        rp_block = ResponsePolicyBlock(
            zones=zones,
            add_soa=True,
            break_dnssec=1,
            max_policy_ttl=7200,
            recursive_only=False,
        )

        assert len(rp_block.zones) == 2
        assert rp_block.add_soa == "yes"
        assert rp_block.break_dnssec == "yes"
        assert rp_block.max_policy_ttl == 7200
        assert rp_block.recursive_only == "no"

    def test_model_bind_syntax_with_zones(self):
        """Test BIND syntax generation with zones."""
        zones = [
            ResponsePolicyZone(zone="example.com", policy="drop", log=True),
            ResponsePolicyZone(zone="malware.local", recursive_only=False),
        ]

        rp_block = ResponsePolicyBlock(
            zones=zones,
            add_soa=True,
            break_dnssec=1,
            max_policy_ttl=7200,
        )

        expected = """response-policy {
    zone example.com. {
        log yes;
        policy drop;
    };
    zone malware.local. {
        recursive-only no;
    };
    add-soa yes;
    break-dnssec yes;
    max-policy-ttl 7200;
};"""
        assert rp_block.model_bind_syntax() == expected

    def test_model_bind_syntax_minimal(self):
        """Test BIND syntax generation with minimal configuration."""
        rp_block = ResponsePolicyBlock(zones=[ResponsePolicyZone(zone="example.com")])

        expected = """response-policy {
    zone example.com. {
    };
};"""
        assert rp_block.model_bind_syntax() == expected

    def test_model_bind_syntax_with_comment(self):
        """Test BIND syntax generation with comment."""
        rp_block = ResponsePolicyBlock(
            zones=[ResponsePolicyZone(zone="example.com", policy="drop")],
            comment="Response policy for security",
        )

        expected = """# Response policy for security
response-policy {
    zone example.com. {
        policy drop;
    };
};"""
        assert rp_block.model_bind_syntax() == expected

    def test_model_validate(self):
        """Test validation via model_validate."""
        data = {
            "zones": [
                {"zone": "example.com", "policy": "drop"},
                {"zone": "example.org", "policy": "nxdomain"},
            ],
            "add_soa": True,
            "recursive_only": False,
        }

        rp_block = ResponsePolicyBlock.model_validate(data)
        assert len(rp_block.zones) == 2
        assert rp_block.add_soa == "yes"
        assert rp_block.recursive_only == "no"


class TestCatalogZoneBlock:
    """Tests for CatalogZoneBlock class."""

    def test_init_full(self):
        """Test full initialization."""
        catalog = CatalogZoneBlock(
            zone="catalog.example.com",
            zone_directory="/var/lib/bind/catalog",
            in_memory="yes",
            min_update_interval="30m",
        )

        assert catalog.zone == "catalog.example.com."
        assert catalog.zone_directory == '"/var/lib/bind/catalog"'
        assert catalog.in_memory == "yes"
        assert catalog.min_update_interval == 1800

    def test_comparison_operators(self):
        """Test comparison operators."""
        catalog1 = CatalogZoneBlock(zone="aaa.example.com")
        catalog2 = CatalogZoneBlock(zone="bbb.example.com")

        zones = [catalog2, catalog1]
        sorted_zones = sorted(zones, key=lambda x: x.zone)
        assert sorted_zones == [catalog1, catalog2]

    def test_model_bind_syntax_full(self):
        """Test BIND syntax generation with full configuration."""
        catalog = CatalogZoneBlock(
            zone="catalog.example.com",
            zone_directory="/var/lib/bind/catalog",
            in_memory="yes",
            min_update_interval="30m",
        )

        expected = """zone catalog.example.com. {
    in-memory yes;
    min-update-interval 1800;
    zone-directory "/var/lib/bind/catalog";
};"""
        assert catalog.model_bind_syntax() == expected

    def test_model_bind_syntax_minimal(self):
        """Test BIND syntax generation with minimal configuration."""
        catalog = CatalogZoneBlock(zone="catalog.example.com")

        expected = """zone catalog.example.com. {
};"""
        assert catalog.model_bind_syntax() == expected

    def test_model_validate(self):
        """Test validation via model_validate."""
        data = {
            "zone": "catalog.test.com",
            "in_memory": False,
            "min_update_interval": "1h",
        }

        catalog = CatalogZoneBlock.model_validate(data)
        assert catalog.zone == "catalog.test.com."
        assert catalog.in_memory == "no"
        assert catalog.min_update_interval == 3600


class TestRrsetOrderRule:
    """Tests for RrsetOrderRule class."""

    def test_init_full(self):
        """Test full initialization."""
        rule = RrsetOrderRule(
            order_class="IN", order_type="A", order_name="example.com", order="random"
        )

        assert rule.order_class == "IN"
        assert rule.order_type == "A"
        assert rule.order_name == '"example.com"'
        assert rule.order == "random"

    def test_init_minimal(self):
        """Test minimal initialization."""
        rule = RrsetOrderRule(order="fixed")

        assert rule.order_class is None
        assert rule.order_type is None
        assert rule.order_name is None
        assert rule.order == "fixed"

    def test_order_validation(self):
        """Test order field validation."""

        valid_orders = ["fixed", "random", "cyclic", "none"]

        for order in valid_orders:
            RrsetOrderRule(order=order)

        with pytest.raises(ValidationError):
            RrsetOrderRule(order="invalid")

    def test_comparison_operators(self):
        """Test comparison operators."""

        rule1 = RrsetOrderRule(order_class="AAA", order="fixed")
        rule2 = RrsetOrderRule(order_class="BBB", order="fixed")

        rules = [rule2, rule1]
        sorted_rules = sorted(rules, key=lambda x: x.comparison_attr)
        assert sorted_rules == [rule1, rule2]

    def test_model_bind_syntax_full(self):
        """Test BIND syntax generation with full configuration."""
        rule = RrsetOrderRule(
            order_class="IN", order_type="A", order_name="example.com", order="random"
        )

        expected = """class IN type A name "example.com" order random;"""
        assert rule.model_bind_syntax() == expected

    def test_model_bind_syntax_minimal(self):
        """Test BIND syntax generation with minimal configuration."""
        rule = RrsetOrderRule(order="fixed")

        expected = """order fixed;"""
        assert rule.model_bind_syntax() == expected

    def test_model_bind_syntax_with_comment(self):
        """Test BIND syntax generation with comment."""
        rule = RrsetOrderRule(
            order_class="IN", order_type="MX", order="cyclic", comment="Round-robin MX records"
        )

        expected = """# Round-robin MX records
class IN type MX order cyclic;"""
        assert rule.model_bind_syntax() == expected

    def test_model_validate(self):
        """Test validation via model_validate."""
        data = {
            "order_class": "CH",
            "order_type": "TXT",
            "order_name": '"chaos.example.com"',
            "order": "random",
        }

        rule = RrsetOrderRule.model_validate(data)
        assert rule.order_class == "CH"
        assert rule.order_type == "TXT"
        assert rule.order_name == '"chaos.example.com"'
        assert rule.order == "random"

    @pytest.mark.parametrize(
        "config,expected_output",
        [
            (
                {"order_class": "IN", "order_type": "AAAA", "order": "cyclic"},
                "class IN type AAAA order cyclic;",
            ),
            ({"order_type": "SRV", "order": "random"}, "type SRV order random;"),
            (
                {"order_name": '"www.example.com"', "order": "fixed"},
                'name "www.example.com" order fixed;',
            ),
        ],
    )
    def test_parametrized_bind_syntax(self, config, expected_output):
        """Parametrized test for BIND syntax generation."""
        rule = RrsetOrderRule(**config)
        assert rule.model_bind_syntax() == expected_output


class TestOptionsBlock:
    """Tests for OptionsBlock class."""

    def test_init_minimal(self):
        """Test minimal initialization."""
        options = OptionsBlock(
            directory="/etc/bind",
            recursion="yes",
            allow_recursion=["localhost", "localnets"],
            listen_on=["any"],
            listen_on_v6=["any"],
        )

        assert options.directory == '"/etc/bind"'
        assert options.recursion == "yes"
        assert options.allow_recursion == ["localhost", "localnets"]
        assert options.listen_on == ["any"]
        assert options.listen_on_v6 == ["any"]

    def test_init_complex(self):
        """Test complex initialization."""
        servers = [
            ServerSpecifier(address="8.8.8.8", port=53),
            ServerSpecifier(address="8.8.4.4", port=53),
        ]
        forwarders = ForwardersBlock(servers=servers)

        options = OptionsBlock(
            directory="/var/named",
            recursion=True,
            dnssec_validation="auto",
            listen_on=["127.0.0.1", "192.168.1.100"],
            listen_on_v6=["::1", "2001:db8::1"],
            allow_query=["any"],
            max_cache_size="90%",
            forward="first",
            forwarders=forwarders,
        )

        assert options.directory == '"/var/named"'
        assert options.recursion == "yes"
        assert options.dnssec_validation == "auto"
        assert options.listen_on == ["127.0.0.1", "192.168.1.100"]
        assert options.max_cache_size == "90%"
        assert options.forward == "first"
        assert options.forwarders is not None

    def test_recursion_validation(self):
        """Test recursion settings validation."""

        pass

    def test_dnssec_validation_constraint(self):
        """Test DNSSEC validation constraints."""

        OptionsBlock(dnssec_validation="auto", dnssec_policy="default")

    def test_prefetch_validation(self):
        """Test prefetch field validation."""

        OptionsBlock(prefetch=(3, 10))
        OptionsBlock(prefetch=(1, 8))
        OptionsBlock(prefetch=(10, 20))

        with pytest.raises(ValidationError, match="prefetch trigger TTL cannot exceed 10 seconds"):
            OptionsBlock(prefetch=(11, 20))

        with pytest.raises(
            ValidationError,
            match="prefetch eligibility TTL must be at least 6 seconds longer than trigger",
        ):
            OptionsBlock(prefetch=(5, 10))

    def test_max_rsa_exponent_size_validation(self):
        """Test max-rsa-exponent-size validation."""

        OptionsBlock(max_rsa_exponent_size=2048)
        OptionsBlock(max_rsa_exponent_size=4096)

        with pytest.raises(ValidationError, match="max-rsa-exponent-size cannot exceed 4096"):
            OptionsBlock(max_rsa_exponent_size=4097)

    def test_min_transfer_rate_in_validation(self):
        """Test min-transfer-rate-in validation."""

        OptionsBlock(min_transfer_rate_in=(1024, 1))
        OptionsBlock(min_transfer_rate_in=(0, 0))

        with pytest.raises(ValidationError, match="Invalid BIND integer value"):
            OptionsBlock(min_transfer_rate_in=(-1, 1))

        with pytest.raises(ValidationError, match="Invalid BIND integer value"):
            OptionsBlock(min_transfer_rate_in=(1024, -1))

    def test_model_bind_syntax_minimal(self):
        """Test BIND syntax generation with minimal configuration."""
        options = OptionsBlock(
            directory="/etc/bind",
            recursion="yes",
            allow_recursion=["localhost", "localnets"],
            listen_on=["any"],
            listen_on_v6=["any"],
        )

        bind_syntax = options.model_bind_syntax()
        assert 'directory "/etc/bind"' in bind_syntax
        assert "recursion yes" in bind_syntax
        assert "allow-recursion" in bind_syntax
        assert "listen-on" in bind_syntax
        assert "listen-on-v6" in bind_syntax

    def test_model_bind_syntax_complex(self):
        """Test BIND syntax generation with complex configuration."""

        forwarders = ForwardersBlock(
            servers=[
                ServerSpecifier(address="8.8.8.8", port=53),
                ServerSpecifier(address="8.8.4.4", port=53),
            ]
        )

        rate_limit = RateLimitBlock(responses_per_second=100, slip=2)

        options = OptionsBlock(
            directory="/var/named",
            pid_file="/var/run/named/named.pid",
            recursion=True,
            dnssec_validation="auto",
            listen_on=["127.0.0.1", "192.168.1.100"],
            listen_on_v6=["::1", "2001:db8::100"],
            allow_query=["any"],
            allow_transfer=["secondary-servers"],
            max_cache_size="90%",
            max_cache_ttl="1d",
            min_cache_ttl="1s",
            forward="first",
            forwarders=forwarders,
            rate_limit=rate_limit,
            querylog=True,
            version='"My DNS Server"',
            hostname='"dns.example.com"',
        )

        bind_syntax = options.model_bind_syntax()

        assert 'directory "/var/named"' in bind_syntax
        assert 'pid-file "/var/run/named/named.pid"' in bind_syntax
        assert "recursion yes" in bind_syntax
        assert "dnssec-validation auto" in bind_syntax
        assert "allow-query" in bind_syntax
        assert "max-cache-size 90%" in bind_syntax
        assert "forward first" in bind_syntax
        assert "forwarders" in bind_syntax
        assert "rate-limit" in bind_syntax
        assert "querylog yes" in bind_syntax

        assert 'version ""My DNS Server""' in bind_syntax or '"My DNS Server"' in bind_syntax
        assert 'hostname "dns.example.com"' in bind_syntax

    def test_model_bind_syntax_with_subblocks(self):
        """Test BIND syntax generation with various subblocks."""

        dns64_block = Dns64Block(prefix="64:ff9b::/96", break_dnssec=True)

        catalog_zone = CatalogZoneBlock(
            zone="catalog.example.com", zone_directory="/var/lib/bind/catalog"
        )

        rrset_rule = RrsetOrderRule(order_class="IN", order_type="A", order="random")

        options = OptionsBlock(
            directory="/etc/bind",
            dns64_blocks=[dns64_block],
            catalog_zones=[catalog_zone],
            rrset_order=[rrset_rule],
            recursion=True,
        )

        bind_syntax = options.model_bind_syntax()
        assert "dns64 64:ff9b::/96" in bind_syntax
        assert "catalog-zones" in bind_syntax
        assert "rrset-order" in bind_syntax
        assert "class IN type A order random" in bind_syntax

    def test_model_bind_syntax_with_comment(self):
        """Test BIND syntax generation with comment."""
        options = OptionsBlock(
            directory="/etc/bind", recursion=True, comment="Main DNS server options"
        )

        expected_start = """# Main DNS server options
options {
    directory "/etc/bind";
    recursion yes;
"""
        assert options.model_bind_syntax().startswith(expected_start)

    def test_model_validate(self):
        """Test validation via model_validate."""
        data = {
            "directory": "/var/named",
            "recursion": True,
            "dnssec_validation": "auto",
            "listen_on": ["127.0.0.1", "192.168.1.100"],
            "allow_query": ["any"],
            "max_cache_size": "80%",
            "querylog": True,
            "version": '"My DNS Server"',
        }

        options = OptionsBlock.model_validate(data)
        assert options.directory == '"/var/named"'
        assert options.recursion == "yes"
        assert options.dnssec_validation == "auto"
        assert options.listen_on == ["127.0.0.1", "192.168.1.100"]
        assert options.max_cache_size == "80%"
        assert options.querylog == "yes"
        assert options.version == '"My DNS Server"'

    def test_model_validate_json(self):
        """Test validation via model_validate_json."""
        json_data = """{
            "directory": "/etc/bind",
            "recursion": true,
            "allow_recursion": ["localhost"],
            "listen_on": ["any"],
            "listen_on_v6": ["any"],
            "querylog": false,
            "version": "none"
        }"""

        options = OptionsBlock.model_validate_json(json_data)
        assert options.directory == '"/etc/bind"'
        assert options.recursion == "yes"
        assert options.allow_recursion == ["localhost"]
        assert options.listen_on == ["any"]
        assert options.listen_on_v6 == ["any"]
        assert options.querylog == "no"
        assert options.version == "none"

    def test_boolean_field_conversions(self):
        """Test boolean field conversions to yes/no strings."""
        options = OptionsBlock(
            recursion=True,
            querylog=False,
            allow_new_zones=1,
            auth_nxdomain=0,
            reuseport=True,
            message_compression=False,
        )

        assert options.recursion == "yes"
        assert options.querylog == "no"
        assert options.allow_new_zones == "yes"
        assert options.auth_nxdomain == "no"
        assert options.reuseport == "yes"
        assert options.message_compression == "no"

    def test_special_field_formatting(self):
        """Test special field formatting methods."""

        options1 = OptionsBlock(response_padding=(["any"], 128))
        bind_syntax1 = options1.model_bind_syntax()
        assert "response-padding" in bind_syntax1
        assert "block-size 128" in bind_syntax1

        options2 = OptionsBlock(deny_answer_addresses=(["spoofers"], ["trusted.example.com"]))
        bind_syntax2 = options2.model_bind_syntax()
        assert "deny-answer-addresses" in bind_syntax2
        assert "except-from" in bind_syntax2

        options3 = OptionsBlock(
            deny_answer_aliases=(["bad-alias.example.com"], ["good.example.com"])
        )
        bind_syntax3 = options3.model_bind_syntax()
        assert "deny-answer-aliases" in bind_syntax3

        options4 = OptionsBlock(cookie_secret=["secret1", "secret2"])
        bind_syntax4 = options4.model_bind_syntax()
        assert "cookie-secret secret1" in bind_syntax4
        assert "cookie-secret secret2" in bind_syntax4

        options5 = OptionsBlock(check_names=[("primary", "fail"), ("secondary", "warn")])
        bind_syntax5 = options5.model_bind_syntax()
        assert "check-names primary fail" in bind_syntax5
        assert "check-names secondary warn" in bind_syntax5

    @pytest.mark.parametrize(
        "field_name,value,expected_contains",
        [
            ("check_dup_records", "warn", "check-dup-records warn"),
            ("check_mx", "fail", "check-mx fail"),
            ("minimal_responses", "no-auth", "minimal-responses no-auth"),
            ("zone_statistics", "full", "zone-statistics full"),
            ("notify", "explicit", "notify explicit"),
            ("checkds", "explicit", "checkds explicit"),
            ("max_ixfr_ratio", "100%", "max-ixfr-ratio 100%"),
            ("qname_minimization", "relaxed", "qname-minimization relaxed"),
            ("preferred_glue", "A", "preferred-glue A"),
            ("transfer_format", "many-answers", "transfer-format many-answers"),
        ],
    )
    def test_enum_literal_fields(self, field_name, value, expected_contains):
        """Test enum and literal fields."""
        options = OptionsBlock(**{field_name: value})
        bind_syntax = options.model_bind_syntax()
        assert expected_contains in bind_syntax

    def test_real_world_configuration(self):
        """Test a real-world configuration example."""

        forwarders1 = ForwardersBlock(
            global_port=53,
            source="10.0.0.1",
            source_v6="2001:db8::1",
            servers=[
                ServerSpecifier(address="192.168.1.1", port=53, key="my-key", tls="tls-config"),
                ServerSpecifier(address="2001:db8::1", port="*"),
            ],
        )

        also_notify1 = AlsoNotifyBlock(
            global_port=53,
            source="192.168.1.100",
            source_v6="2001:db8::100",
            servers=[
                ServerSpecifier(address="192.168.1.1", port=53, key="my-key", tls="tls-config"),
                ServerSpecifier(address="2001:db8::1", port="*"),
            ],
        )

        dns64_1 = Dns64Block(
            prefix="64:ff9b::/96",
            break_dnssec="yes",
            clients=["192.168.1.0/24", "2001:db8::/32"],
            exclude=["192.168.1.100", "2001:db8::100"],
            recursive_only=1,
        )

        rate_limit1 = RateLimitBlock(
            responses_per_second=100,
            errors_per_second=50,
            nxdomains_per_second=20,
            slip=2,
            exempt_clients=["127.0.0.1", "::1"],
            log_only=True,
        )

        options = OptionsBlock(
            directory="/etc/bind",
            recursion="yes",
            allow_query=["any"],
            allow_transfer=["192.168.1.0/24"],
            dnssec_validation="auto",
            querylog=True,
            forward="first",
            forwarders=forwarders1,
            rate_limit=rate_limit1,
            dns64_blocks=[dns64_1],
            also_notify=also_notify1,
            max_cache_size="90%",
            listen_on=["192.168.1.1", "10.0.0.1"],
            listen_on_v6=["2001:db8::1", "::1"],
        )

        bind_syntax = options.model_bind_syntax()
        assert "options {" in bind_syntax
        assert "}" in bind_syntax

        assert "directory" in bind_syntax
        assert "recursion yes" in bind_syntax
        assert "allow-query" in bind_syntax
        assert "forwarders" in bind_syntax
        assert "rate-limit" in bind_syntax
        assert "dns64" in bind_syntax
        assert "also-notify" in bind_syntax
