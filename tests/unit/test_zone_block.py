"""
Tests for BIND zone configuration blocks.
"""

from __future__ import annotations

from ipaddress import IPv4Address, IPv6Address

import pytest

from bindantic import (
    ARecord,
    MXRecord,
    NSRecord,
    SOARecord,
    UpdatePolicyBlock,
    UpdatePolicyRule,
    UpdatePolicyRuleTypeEnum,
    ZoneBlock,
    ZoneClassEnum,
    ZoneTypeEnum,
)


class TestUpdatePolicyRule:
    """Tests for UpdatePolicyRule class."""

    def test_basic_creation(self):
        """Test basic update policy rule creation."""
        rule = UpdatePolicyRule(
            action="grant",
            identity="key admin-key",
            rule_type=UpdatePolicyRuleTypeEnum.SUBDOMAIN,
            name="admin.example.com",
            record_types=["A", "AAAA", "MX"],
        )
        assert rule.action == "grant"
        assert rule.identity == "key admin-key"
        assert rule.rule_type == UpdatePolicyRuleTypeEnum.SUBDOMAIN
        assert rule.name == "admin.example.com"
        assert rule.record_types == ["A", "AAAA", "MX"]

    def test_rule_without_name(self):
        """Test rule without optional name field."""
        rule = UpdatePolicyRule(
            action="deny",
            identity="*",
            rule_type=UpdatePolicyRuleTypeEnum.WILDCARD,
            record_types=["ANY"],
        )
        assert rule.action == "deny"
        assert rule.identity == "*"
        assert rule.rule_type == UpdatePolicyRuleTypeEnum.WILDCARD
        assert rule.name is None
        assert rule.record_types == ["ANY"]

    def test_rule_without_record_types(self):
        """Test rule without record types (empty list)."""
        rule = UpdatePolicyRule(
            action="grant",
            identity="key test-key",
            rule_type=UpdatePolicyRuleTypeEnum.SELF,
        )
        assert rule.record_types == []

    def test_model_bind_syntax(self):
        """Test BIND syntax generation for rule."""
        rule = UpdatePolicyRule(
            action="grant",
            identity="key admin-key",
            rule_type=UpdatePolicyRuleTypeEnum.SUBDOMAIN,
            name="admin.example.com",
            record_types=["A", "AAAA", "MX"],
        )
        syntax = rule.model_bind_syntax()
        assert "grant key admin-key subdomain admin.example.com A AAAA MX;" in syntax

    def test_model_bind_syntax_without_name(self):
        """Test syntax generation for rule without name."""
        rule = UpdatePolicyRule(
            action="deny",
            identity="*",
            rule_type=UpdatePolicyRuleTypeEnum.WILDCARD,
            record_types=["ANY"],
        )
        syntax = rule.model_bind_syntax()
        assert "deny * wildcard ANY;" in syntax

    def test_model_bind_syntax_with_comment(self):
        """Test syntax with comment."""
        rule = UpdatePolicyRule(
            action="grant",
            identity="key user-key",
            rule_type=UpdatePolicyRuleTypeEnum.NAME,
            name="user.example.com",
            record_types=["TXT"],
            comment="Allow user to update TXT records",
        )
        syntax = rule.model_bind_syntax()

        assert "# Allow user to update TXT records" in syntax
        assert "grant key user-key name user.example.com TXT;" in syntax


class TestUpdatePolicyBlock:
    """Tests for UpdatePolicyBlock class."""

    def test_local_policy_creation(self):
        """Test local policy creation."""
        policy = UpdatePolicyBlock(local="yes")
        assert policy.local == "yes"
        assert policy.rules == []

    def test_rules_policy_creation(self):
        """Test policy with rules creation."""
        rules = [
            UpdatePolicyRule(
                action="grant",
                identity="key admin-key",
                rule_type=UpdatePolicyRuleTypeEnum.SUBDOMAIN,
                name="admin.example.com",
                record_types=["A", "AAAA", "MX"],
            ),
            UpdatePolicyRule(
                action="deny",
                identity="*",
                rule_type=UpdatePolicyRuleTypeEnum.WILDCARD,
                record_types=["ANY"],
            ),
        ]
        policy = UpdatePolicyBlock(rules=rules)
        assert policy.local is None
        assert policy.rules == rules

    def test_validation_both_local_and_rules(self):
        """Test validation when both local and rules are specified."""
        with pytest.raises(ValueError, match="Cannot specify both 'local' and individual rules"):
            UpdatePolicyBlock(
                local="yes",
                rules=[
                    UpdatePolicyRule(
                        action="grant",
                        identity="key test",
                        rule_type=UpdatePolicyRuleTypeEnum.SELF,
                    )
                ],
            )

    def test_validation_neither_local_nor_rules(self):
        """Test validation when neither local nor rules are specified."""
        with pytest.raises(
            ValueError, match="update-policy must have either 'local' or a list of rules"
        ):
            UpdatePolicyBlock()

    def test_model_bind_syntax_local(self):
        """Test BIND syntax for local policy."""
        policy = UpdatePolicyBlock(local="yes")
        syntax = policy.model_bind_syntax()
        assert "update-policy local;" in syntax

    def test_model_bind_syntax_rules(self):
        """Test BIND syntax for policy with rules."""
        rules = [
            UpdatePolicyRule(
                action="grant",
                identity="key admin-key",
                rule_type=UpdatePolicyRuleTypeEnum.SUBDOMAIN,
                name="admin.example.com",
                record_types=["A", "AAAA"],
            ),
            UpdatePolicyRule(
                action="deny",
                identity="*",
                rule_type=UpdatePolicyRuleTypeEnum.WILDCARD,
                record_types=["ANY"],
            ),
        ]
        policy = UpdatePolicyBlock(rules=rules)
        syntax = policy.model_bind_syntax()

        assert "update-policy {" in syntax
        assert "    grant key admin-key subdomain admin.example.com A AAAA;" in syntax
        assert "    deny * wildcard ANY;" in syntax
        assert "};" in syntax

    def test_model_bind_syntax_with_indentation(self):
        """Test syntax with indentation."""
        policy = UpdatePolicyBlock(local="yes")
        syntax = policy.model_bind_syntax(indent_level=2)
        assert "        update-policy local;" in syntax


class TestZoneBlockBasic:
    """Basic tests for ZoneBlock class."""

    def test_primary_zone_creation(self):
        """Test primary zone creation."""
        zone = ZoneBlock(
            name="example.com",
            zone_type=ZoneTypeEnum.PRIMARY,
            file="/var/lib/bind/db.example.com",
            allow_query=["any"],
            allow_transfer=["secondary-servers"],
            allow_update=["key dhcp-key"],
            dnssec_policy="default",
        )
        assert zone.name == "example.com."
        assert zone.zone_type == ZoneTypeEnum.PRIMARY
        assert zone.file == '"/var/lib/bind/db.example.com"'
        assert zone.allow_query == ["any"]
        assert zone.allow_transfer == ["secondary-servers"]
        assert zone.allow_update == ["key dhcp-key"]
        assert zone.dnssec_policy == "default"

    def test_zone_with_class(self):
        """Test zone with non-default class."""
        zone = ZoneBlock(
            name="example.com",
            zone_type=ZoneTypeEnum.PRIMARY,
            zone_class=ZoneClassEnum.CHAOS,
            file="/var/lib/bind/db.example.com",
        )
        assert zone.zone_class == ZoneClassEnum.CHAOS

    def test_zone_without_class(self):
        """Test zone without class (defaults to IN)."""
        zone = ZoneBlock(
            name="example.com",
            zone_type=ZoneTypeEnum.PRIMARY,
            file="/var/lib/bind/db.example.com",
        )
        assert zone.zone_class is None

    def test_secondary_zone_creation(self):
        """Test secondary zone creation."""
        zone = ZoneBlock(
            name="secondary.example.com",
            zone_type=ZoneTypeEnum.SECONDARY,
            primaries=[("192.168.1.1", 53), ("2001:db8::1", 53)],
            file="/var/lib/bind/db.secondary",
        )
        assert zone.name == "secondary.example.com."
        assert zone.zone_type == ZoneTypeEnum.SECONDARY
        assert zone.primaries == [("192.168.1.1", 53), ("2001:db8::1", 53)]
        assert zone.file == '"/var/lib/bind/db.secondary"'

    def test_forward_zone_creation(self):
        """Test forward zone creation."""
        zone = ZoneBlock(
            name="forward.example.com",
            zone_type=ZoneTypeEnum.FORWARD,
            forward="only",
            forwarders=["8.8.8.8", "8.8.4.4"],
        )
        assert zone.name == "forward.example.com."
        assert zone.zone_type == ZoneTypeEnum.FORWARD
        assert zone.forward == "only"
        assert zone.forwarders == ["8.8.8.8", "8.8.4.4"]

    def test_hint_zone_creation(self):
        """Test hint zone creation."""
        zone = ZoneBlock(
            name=".",
            zone_type=ZoneTypeEnum.HINT,
            file="/var/lib/bind/db.root",
        )
        assert zone.name == "."
        assert zone.zone_type == ZoneTypeEnum.HINT
        assert zone.file == '"/var/lib/bind/db.root"'

    def test_static_stub_zone_creation(self):
        """Test static-stub zone creation."""
        zone = ZoneBlock(
            name="static.example.com",
            zone_type=ZoneTypeEnum.STATIC_STUB,
            server_addresses=["192.168.1.100", "10.0.0.100"],
            server_names=["ns1.static.example.com", "ns2.static.example.com"],
        )
        assert zone.name == "static.example.com."
        assert zone.zone_type == ZoneTypeEnum.STATIC_STUB
        assert zone.server_addresses == ["192.168.1.100", "10.0.0.100"]
        assert zone.server_names == ["ns1.static.example.com", "ns2.static.example.com"]

    def test_zone_with_resource_records(self):
        """Test zone with resource records."""
        zone = ZoneBlock(
            name="example.com",
            zone_type=ZoneTypeEnum.PRIMARY,
            file="/var/lib/bind/db.example.com",
            resource_records=[
                SOARecord(
                    mname="ns1.example.com",
                    rname="admin.example.com",
                    serial=2024010101,
                    refresh=10800,
                    retry=3600,
                    expire=604800,
                    minimum=3600,
                ),
                NSRecord(nsdname="ns1.example.com"),
                NSRecord(nsdname="ns2.example.com"),
                ARecord(name="@", address="192.168.1.1"),
            ],
        )
        assert len(zone.resource_records) == 4
        assert isinstance(zone.resource_records[0], SOARecord)
        assert isinstance(zone.resource_records[1], NSRecord)
        assert isinstance(zone.resource_records[2], NSRecord)
        assert isinstance(zone.resource_records[3], ARecord)


class TestZoneBlockValidation:
    """Tests for ZoneBlock validation based on zone type."""

    def test_in_view_zone_without_in_view_field(self):
        """Test in-view zone without required in_view field."""
        with pytest.raises(ValueError, match="must have 'in_view' field specified"):
            ZoneBlock(
                name="example.com",
                zone_type=ZoneTypeEnum.IN_VIEW,
            )

    def test_in_view_zone_with_in_view_field(self):
        """Test in-view zone with required in_view field."""
        zone = ZoneBlock(
            name="example.com",
            zone_type=ZoneTypeEnum.IN_VIEW,
            in_view="internal-view",
        )
        assert zone.in_view == "internal-view"

    def test_in_view_zone_with_extra_fields(self):
        """Test in-view zone with extra fields (should fail)."""
        with pytest.raises(ValueError, match="is not allowed for zone of type 'in-view'"):
            ZoneBlock(
                name="example.com",
                zone_type=ZoneTypeEnum.IN_VIEW,
                in_view="internal-view",
                file="/path/to/file",
            )

    def test_primary_zone_with_secondary_field(self):
        """Test primary zone with secondary-only field (should fail)."""
        with pytest.raises(ValueError, match=r".*is not allowed for zone of type.*PRIMARY.*"):
            ZoneBlock(
                name="example.com",
                zone_type=ZoneTypeEnum.PRIMARY,
                file="/var/lib/bind/db.example.com",
                primaries=["192.168.1.1"],
            )

    def test_secondary_zone_with_primary_field(self):
        """Test secondary zone with primary-only field (should fail)."""
        with pytest.raises(ValueError, match=r".*is not allowed for zone of type.*SECONDARY.*"):
            ZoneBlock(
                name="secondary.example.com",
                zone_type=ZoneTypeEnum.SECONDARY,
                primaries=["192.168.1.1"],
                allow_update=["key test"],
            )

    def test_forward_zone_with_zone_file(self):
        """Test forward zone with zone file (should fail)."""
        with pytest.raises(ValueError, match=r".*is not allowed for zone of type.*FORWARD.*"):
            ZoneBlock(
                name="forward.example.com",
                zone_type=ZoneTypeEnum.FORWARD,
                forward="only",
                file="/var/lib/bind/db.forward",
            )

    def test_static_stub_with_primaries(self):
        """Test static-stub zone with primaries (should fail)."""
        with pytest.raises(ValueError, match=r".*is not allowed for zone of type.*STATIC_STUB.*"):
            ZoneBlock(
                name="static.example.com",
                zone_type=ZoneTypeEnum.STATIC_STUB,
                server_addresses=["192.168.1.100"],
                primaries=["192.168.1.1"],
            )


class TestZoneBlockMixedServerLists:
    """Tests for mixed server list formatting in ZoneBlock."""

    def test_also_notify_mixed_list(self):
        """Test also-notify with mixed addresses and hostnames."""
        zone = ZoneBlock(
            name="example.com",
            zone_type=ZoneTypeEnum.PRIMARY,
            also_notify=[
                "secondary.example.com",
                ("192.168.1.100", 53),
                ("2001:db8::1", 53),
                "tertiary.example.com",
                ("10.0.0.1", None),
            ],
        )
        syntax = zone.model_bind_syntax()

        assert "also-notify {" in syntax
        assert "    secondary.example.com;" in syntax
        assert "    192.168.1.100 port 53;" in syntax
        assert "    2001:db8::1 port 53;" in syntax
        assert "    tertiary.example.com;" in syntax
        assert "    10.0.0.1;" in syntax

    def test_primaries_mixed_list(self):
        """Test primaries with mixed addresses and hostnames."""
        zone = ZoneBlock(
            name="secondary.example.com",
            zone_type=ZoneTypeEnum.SECONDARY,
            primaries=[
                "primary.example.com",
                ("192.168.1.1", 53),
                ("2001:db8::1", 5353),
                ("10.0.0.1", None),
            ],
        )
        syntax = zone.model_bind_syntax()

        assert "primaries {" in syntax
        assert "    primary.example.com;" in syntax
        assert "    192.168.1.1 port 53;" in syntax
        assert "    2001:db8::1 port 5353;" in syntax
        assert "    10.0.0.1;" in syntax

    def test_parental_agents_mixed_list(self):
        """Test parental-agents with mixed addresses."""
        zone = ZoneBlock(
            name="example.com",
            zone_type=ZoneTypeEnum.PRIMARY,
            parental_agents=[
                "agent1.example.com",
                ("192.168.1.200", 53),
                ("2001:db8::200", 53),
            ],
        )
        syntax = zone.model_bind_syntax()

        assert "parental-agents {" in syntax
        assert "    agent1.example.com;" in syntax
        assert "    192.168.1.200 port 53;" in syntax
        assert "    2001:db8::200 port 53;" in syntax


class TestZoneBlockSyntaxGeneration:
    """Tests for BIND syntax generation in ZoneBlock."""

    def test_primary_zone_syntax(self):
        """Test BIND syntax for primary zone."""
        zone = ZoneBlock(
            name="example.com",
            zone_type=ZoneTypeEnum.PRIMARY,
            file="/var/lib/bind/db.example.com",
            allow_query=["any"],
            allow_transfer=["secondary-servers"],
            allow_update=["key dhcp-key"],
            dnssec_policy="default",
            notify="yes",
            also_notify=[("192.168.1.100", 53), "secondary.example.com"],
            update_policy=UpdatePolicyBlock(
                rules=[
                    UpdatePolicyRule(
                        action="grant",
                        identity="key admin-key",
                        rule_type=UpdatePolicyRuleTypeEnum.SUBDOMAIN,
                        name="admin.example.com",
                        record_types=["A", "AAAA", "MX"],
                    )
                ]
            ),
        )

        syntax = zone.model_bind_syntax()

        assert "zone example.com. {" in syntax
        assert "    type primary;" in syntax

        assert "    allow-query {" in syntax
        assert "        any;" in syntax
        assert "    };" in syntax

        assert "    allow-transfer {" in syntax
        assert "        secondary-servers;" in syntax
        assert "    };" in syntax

        assert "    allow-update {" in syntax
        assert '        "key dhcp-key";' in syntax
        assert "    };" in syntax

        assert "    also-notify {" in syntax
        assert "        192.168.1.100 port 53;" in syntax
        assert "        secondary.example.com;" in syntax
        assert "    };" in syntax

        assert "    dnssec-policy default;" in syntax
        assert '    file "/var/lib/bind/db.example.com";' in syntax
        assert "    notify yes;" in syntax

        assert "    update-policy {" in syntax
        assert "        grant key admin-key subdomain admin.example.com A AAAA MX;" in syntax
        assert "    };" in syntax

    def test_secondary_zone_syntax(self):
        """Test BIND syntax for secondary zone."""
        zone = ZoneBlock(
            name="secondary.example.com",
            zone_type=ZoneTypeEnum.SECONDARY,
            file="/var/lib/bind/db.secondary",
            primaries=[("192.168.1.1", 53), "primary.example.com"],
            allow_transfer=["none"],
            allow_notify=["192.168.1.1"],
        )

        syntax = zone.model_bind_syntax()

        assert "zone secondary.example.com. {" in syntax
        assert "    type secondary;" in syntax
        assert '    file "/var/lib/bind/db.secondary";' in syntax

        assert "    allow-notify {" in syntax
        assert "        192.168.1.1;" in syntax
        assert "    };" in syntax

        assert "    allow-transfer {" in syntax
        assert "        none;" in syntax
        assert "    };" in syntax

        assert "    primaries {" in syntax
        assert "        192.168.1.1 port 53;" in syntax
        assert "        primary.example.com;" in syntax
        assert "    };" in syntax

    def test_forward_zone_syntax(self):
        """Test BIND syntax for forward zone."""
        zone = ZoneBlock(
            name="forward.example.com",
            zone_type=ZoneTypeEnum.FORWARD,
            forward="only",
            forwarders=["8.8.8.8", IPv6Address("2001:4860:4860::8888")],
        )

        syntax = zone.model_bind_syntax()

        assert "zone forward.example.com. {" in syntax
        assert "    type forward;" in syntax
        assert "    forward only;" in syntax
        assert "    forwarders {" in syntax
        assert "        2001:4860:4860::8888;" in syntax
        assert "        8.8.8.8;" in syntax
        assert "    };" in syntax

    def test_hint_zone_syntax(self):
        """Test BIND syntax for hint zone."""
        zone = ZoneBlock(
            name=".",
            zone_type=ZoneTypeEnum.HINT,
            file="/var/lib/bind/db.root",
        )

        syntax = zone.model_bind_syntax()

        assert "zone . {" in syntax
        assert "    type hint;" in syntax
        assert '    file "/var/lib/bind/db.root";' in syntax

    def test_static_stub_zone_syntax(self):
        """Test BIND syntax for static-stub zone."""
        zone = ZoneBlock(
            name="static.example.com",
            zone_type=ZoneTypeEnum.STATIC_STUB,
            server_addresses=["192.168.1.100", IPv6Address("2001:db8::100")],
            server_names=["ns1.static.example.com", "ns2.static.example.com"],
        )

        syntax = zone.model_bind_syntax()

        assert "zone static.example.com. {" in syntax
        assert "    type static-stub;" in syntax
        assert "    server-addresses {" in syntax
        assert "        192.168.1.100;" in syntax
        assert "        2001:db8::100;" in syntax
        assert "    };" in syntax
        assert "    server-names {" in syntax
        assert "        ns1.static.example.com;" in syntax
        assert "        ns2.static.example.com;" in syntax
        assert "    };" in syntax

    def test_zone_with_chaos_class(self):
        """Test zone with CHAOS class."""
        zone = ZoneBlock(
            name="version.bind",
            zone_type=ZoneTypeEnum.PRIMARY,
            zone_class=ZoneClassEnum.CHAOS,
            file="/var/lib/bind/db.version",
        )

        syntax = zone.model_bind_syntax()

        assert "zone version.bind. CHAOS {" in syntax
        assert "    type primary;" in syntax
        assert '    file "/var/lib/bind/db.version";' in syntax

    def test_zone_with_hs_class(self):
        """Test zone with HS class."""
        zone = ZoneBlock(
            name="example.hs",
            zone_type=ZoneTypeEnum.PRIMARY,
            zone_class=ZoneClassEnum.HS,
            file="/var/lib/bind/db.hs",
        )

        syntax = zone.model_bind_syntax()

        assert "zone example.hs. HS {" in syntax
        assert "    type primary;" in syntax
        assert '    file "/var/lib/bind/db.hs";' in syntax

    def test_in_view_zone_syntax(self):
        """Test BIND syntax for in-view zone."""
        zone = ZoneBlock(
            name="example.com",
            zone_type=ZoneTypeEnum.IN_VIEW,
            in_view="internal-view",
        )

        syntax = zone.model_bind_syntax()

        assert "zone example.com. {" in syntax
        assert "    type in-view;" in syntax
        assert "    in-view internal-view;" in syntax

    def test_zone_with_comment(self):
        """Test zone with comment."""
        zone = ZoneBlock(
            name="example.com",
            zone_type=ZoneTypeEnum.PRIMARY,
            file="/var/lib/bind/db.example.com",
            comment="Example zone configuration\nFor testing purposes",
        )

        syntax = zone.model_bind_syntax()

        assert "# Example zone configuration" in syntax
        assert "# For testing purposes" in syntax
        assert "zone example.com. {" in syntax


class TestZoneFileGeneration:
    """Tests for zone file syntax generation."""

    def test_zone_file_generation_basic(self):
        """Test basic zone file generation."""
        zone = ZoneBlock(
            name="example.com",
            zone_type=ZoneTypeEnum.PRIMARY,
            file="/var/lib/bind/db.example.com",
            resource_records=[
                SOARecord(
                    mname="ns1.example.com",
                    rname="admin.example.com",
                    serial=2024010101,
                    refresh=10800,
                    retry=3600,
                    expire=604800,
                    minimum=3600,
                ),
                NSRecord(nsdname="ns1.example.com"),
                NSRecord(nsdname="ns2.example.com"),
                ARecord(name="@", address="192.168.1.1"),
                ARecord(name="www", address="192.168.1.2"),
                MXRecord(name="@", preference=10, exchange="mail.example.com"),
            ],
        )

        zone_file = zone.model_bind_syntax_zone_file()

        assert "SOA" in zone_file
        assert "ns1.example.com." in zone_file
        assert "admin.example.com." in zone_file
        assert "2024010101" in zone_file

        assert "NS" in zone_file
        assert "ns1.example.com." in zone_file
        assert "ns2.example.com." in zone_file

        assert "A" in zone_file
        assert "192.168.1.1" in zone_file
        assert "192.168.1.2" in zone_file

        assert "MX" in zone_file
        assert "10" in zone_file
        assert "mail.example.com." in zone_file

    def test_zone_file_generation_with_ttl_and_origin(self):
        """Test zone file generation with $TTL and $ORIGIN."""
        zone = ZoneBlock(
            name="example.com",
            zone_type=ZoneTypeEnum.PRIMARY,
            file="/var/lib/bind/db.example.com",
            resource_records=[
                SOARecord(
                    ttl=3600,
                    origin="example.com",
                    mname="ns1.example.com",
                    rname="admin.example.com",
                    serial=2024010101,
                    refresh=10800,
                    retry=3600,
                    expire=604800,
                    minimum=3600,
                ),
                ARecord(name="@", address="192.168.1.1"),
            ],
        )

        zone_file = zone.model_bind_syntax_zone_file()

        assert "$TTL 3600" in zone_file
        assert "$ORIGIN example.com." in zone_file
        assert "SOA" in zone_file

    def test_zone_file_generation_no_records(self):
        """Test zone file generation with no records (should raise error)."""
        zone = ZoneBlock(
            name="example.com",
            zone_type=ZoneTypeEnum.PRIMARY,
            file="/var/lib/bind/db.example.com",
        )

        with pytest.raises(ValueError, match="has no resource records"):
            zone.model_bind_syntax_zone_file()

    def test_zone_file_records_sorted(self):
        """Test that zone file records are sorted correctly."""
        zone = ZoneBlock(
            name="example.com",
            zone_type=ZoneTypeEnum.PRIMARY,
            file="/var/lib/bind/db.example.com",
            resource_records=[
                ARecord(name="zebra.example.com", address="192.168.1.3"),
                SOARecord(
                    mname="ns1.example.com",
                    rname="admin.example.com",
                    serial=2024010101,
                    refresh=10800,
                    retry=3600,
                    expire=604800,
                    minimum=3600,
                ),
                ARecord(name="apple.example.com", address="192.168.1.1"),
                NSRecord(nsdname="ns1.example.com"),
                ARecord(name="banana.example.com", address="192.168.1.2"),
                MXRecord(name="@", preference=10, exchange="mail.example.com"),
            ],
        )

        zone_file = zone.model_bind_syntax_zone_file()
        lines = zone_file.split("\n")

        soa_index = next(
            i for i, line in enumerate(lines) if "SOA" in line and not line.strip().startswith(";")
        )

        ns_indices = [
            i
            for i, line in enumerate(lines)
            if " NS " in line and not line.strip().startswith(";")
        ]

        mx_indices = [
            i
            for i, line in enumerate(lines)
            if " MX " in line and not line.strip().startswith(";")
        ]

        a_indices = [
            i
            for i, line in enumerate(lines)
            if " A " in line and "AAAA" not in line and not line.strip().startswith(";")
        ]

        assert soa_index < min(ns_indices + mx_indices + a_indices)

        assert ns_indices[0] < mx_indices[0]

        assert ns_indices[0] < a_indices[0]

        assert mx_indices[0] < a_indices[0]

        a_lines = [line for line in lines if " A " in line and "AAAA" not in line]
        a_names = [line.strip().split()[0] for line in a_lines]
        expected_names = ["apple.example.com.", "banana.example.com.", "zebra.example.com."]
        assert a_names == expected_names


class TestZoneBlockAdvancedFeatures:
    """Tests for advanced zone block features."""

    def test_zone_with_update_policy_local(self):
        """Test zone with local update policy."""
        zone = ZoneBlock(
            name="example.com",
            zone_type=ZoneTypeEnum.PRIMARY,
            file="/var/lib/bind/db.example.com",
            update_policy=UpdatePolicyBlock(local="yes"),
        )

        syntax = zone.model_bind_syntax()
        assert "    update-policy local;" in syntax

    def test_zone_with_update_policy_rules(self):
        """Test zone with update policy rules."""
        zone = ZoneBlock(
            name="example.com",
            zone_type=ZoneTypeEnum.PRIMARY,
            file="/var/lib/bind/db.example.com",
            update_policy=UpdatePolicyBlock(
                rules=[
                    UpdatePolicyRule(
                        action="grant",
                        identity="key admin-key",
                        rule_type=UpdatePolicyRuleTypeEnum.SELF,
                        record_types=["A", "AAAA"],
                    ),
                    UpdatePolicyRule(
                        action="deny",
                        identity="*",
                        rule_type=UpdatePolicyRuleTypeEnum.WILDCARD,
                        record_types=["ANY"],
                    ),
                ]
            ),
        )

        syntax = zone.model_bind_syntax()
        assert "    update-policy {" in syntax
        assert "        grant key admin-key self A AAAA;" in syntax
        assert "        deny * wildcard ANY;" in syntax
        assert "    };" in syntax

    def test_zone_with_notify_source(self):
        """Test zone with notify source addresses."""
        zone = ZoneBlock(
            name="example.com",
            zone_type=ZoneTypeEnum.PRIMARY,
            file="/var/lib/bind/db.example.com",
            notify_source="192.168.1.100",
            notify_source_v6="2001:db8::100",
        )

        syntax = zone.model_bind_syntax()
        assert "    notify-source 192.168.1.100;" in syntax
        assert "    notify-source-v6 2001:db8::100;" in syntax

    def test_zone_with_transfer_source(self):
        """Test zone with transfer source addresses."""
        zone = ZoneBlock(
            name="secondary.example.com",
            zone_type=ZoneTypeEnum.SECONDARY,
            primaries=["192.168.1.1"],
            file="/var/lib/bind/db.secondary",
            transfer_source="192.168.1.200",
            transfer_source_v6="2001:db8::200",
        )

        syntax = zone.model_bind_syntax()
        assert "    transfer-source 192.168.1.200;" in syntax
        assert "    transfer-source-v6 2001:db8::200;" in syntax

    def test_zone_with_parental_settings(self):
        """Test zone with parental settings for DNSSEC."""
        zone = ZoneBlock(
            name="example.com",
            zone_type=ZoneTypeEnum.PRIMARY,
            file="/var/lib/bind/db.example.com",
            parental_agents=[("192.168.1.200", 53)],
            parental_source="192.168.1.100",
            parental_source_v6="2001:db8::100",
        )

        syntax = zone.model_bind_syntax()
        assert "    parental-agents {" in syntax
        assert "        192.168.1.200 port 53;" in syntax
        assert "    };" in syntax
        assert "    parental-source 192.168.1.100;" in syntax
        assert "    parental-source-v6 2001:db8::100;" in syntax

    def test_zone_with_serial_update_method(self):
        """Test zone with serial update method."""
        zone = ZoneBlock(
            name="example.com",
            zone_type=ZoneTypeEnum.PRIMARY,
            file="/var/lib/bind/db.example.com",
            serial_update_method="date",
        )

        syntax = zone.model_bind_syntax()
        assert "    serial-update-method date;" in syntax

    def test_zone_with_dnssec_loadkeys_interval(self):
        """Test zone with DNSSEC loadkeys interval."""
        zone = ZoneBlock(
            name="example.com",
            zone_type=ZoneTypeEnum.PRIMARY,
            file="/var/lib/bind/db.example.com",
            dnssec_loadkeys_interval=3600,
        )

        syntax = zone.model_bind_syntax()
        assert "    dnssec-loadkeys-interval 3600;" in syntax

    def test_zone_with_time_limits(self):
        """Test zone with time limits."""
        zone = ZoneBlock(
            name="secondary.example.com",
            zone_type=ZoneTypeEnum.SECONDARY,
            primaries=["192.168.1.1"],
            file="/var/lib/bind/db.secondary",
            max_transfer_time_in=300,
            max_transfer_idle_in=60,
            max_refresh_time=86400,
            min_refresh_time=3600,
            max_retry_time=7200,
            min_retry_time=300,
        )

        syntax = zone.model_bind_syntax()
        assert "    max-transfer-time-in 300;" in syntax
        assert "    max-transfer-idle-in 60;" in syntax
        assert "    max-refresh-time 86400;" in syntax
        assert "    min-refresh-time 3600;" in syntax
        assert "    max-retry-time 7200;" in syntax
        assert "    min-retry-time 300;" in syntax

    def test_zone_with_notify_timing(self):
        """Test zone with notify timing settings."""
        zone = ZoneBlock(
            name="example.com",
            zone_type=ZoneTypeEnum.PRIMARY,
            file="/var/lib/bind/db.example.com",
            notify_defer=30,
            notify_delay=5,
        )

        syntax = zone.model_bind_syntax()
        assert "    notify-defer 30;" in syntax
        assert "    notify-delay 5;" in syntax


class TestZoneBlockEdgeCases:
    """Tests for edge cases in ZoneBlock."""

    def test_zone_with_root_name(self):
        """Test zone with root name."""
        zone = ZoneBlock(
            name=".",
            zone_type=ZoneTypeEnum.HINT,
            file="/var/lib/bind/db.root",
        )
        assert zone.name == "."

        syntax = zone.model_bind_syntax()
        assert "zone . {" in syntax

    def test_zone_with_ipv6_address_objects_in_valid_context(self):
        """Test zone with IPv6 address objects in appropriate context."""
        zone = ZoneBlock(
            name="static.example.com",
            zone_type=ZoneTypeEnum.STATIC_STUB,
            server_addresses=[
                IPv4Address("192.168.1.100"),
                IPv6Address("2001:db8::100"),
            ],
            server_names=["ns1.static.example.com"],
        )

        syntax = zone.model_bind_syntax()
        assert "server-addresses {" in syntax
        assert "    192.168.1.100;" in syntax
        assert "    2001:db8::100;" in syntax

    def test_zone_with_mixed_forward_types(self):
        """Test zone with different forward types."""
        for forward_type in ["first", "only"]:
            zone = ZoneBlock(
                name="example.com",
                zone_type=ZoneTypeEnum.FORWARD,
                forward=forward_type,
                forwarders=["8.8.8.8"],
            )
            syntax = zone.model_bind_syntax()
            assert f"    forward {forward_type};" in syntax

    def test_zone_with_different_check_names_values(self):
        """Test zone with different check-names values."""
        for check_value in ["fail", "warn", "ignore"]:
            zone = ZoneBlock(
                name="example.com",
                zone_type=ZoneTypeEnum.PRIMARY,
                file="/var/lib/bind/db.example.com",
                check_names=check_value,
            )
            syntax = zone.model_bind_syntax()
            assert f"    check-names {check_value};" in syntax

    def test_zone_with_different_masterfile_settings(self):
        """Test zone with different masterfile settings."""
        zone = ZoneBlock(
            name="example.com",
            zone_type=ZoneTypeEnum.PRIMARY,
            file="/var/lib/bind/db.example.com",
            masterfile_format="text",
            masterfile_style="full",
        )

        syntax = zone.model_bind_syntax()
        assert "    masterfile-format text;" in syntax
        assert "    masterfile-style full;" in syntax

    def test_zone_with_database_backend(self):
        """Test zone with database backend."""
        zone = ZoneBlock(
            name="example.com",
            zone_type=ZoneTypeEnum.PRIMARY,
            database="lmdb",
            file="/var/lib/bind/db.example.com",
        )

        syntax = zone.model_bind_syntax()
        assert "    database lmdb;" in syntax

    def test_zone_with_journal_file(self):
        """Test zone with journal file."""
        zone = ZoneBlock(
            name="example.com",
            zone_type=ZoneTypeEnum.PRIMARY,
            file="/var/lib/bind/db.example.com",
            journal="/var/lib/bind/db.example.com.jnl",
        )

        syntax = zone.model_bind_syntax()
        assert '    journal "/var/lib/bind/db.example.com.jnl";' in syntax

    def test_zone_with_unset_fields(self):
        """Test that unset fields are not included in syntax."""
        zone = ZoneBlock(
            name="example.com",
            zone_type=ZoneTypeEnum.PRIMARY,
            file="/var/lib/bind/db.example.com",
        )
        syntax = zone.model_bind_syntax()
        assert "allow-query" not in syntax
        assert "allow-transfer" not in syntax
        assert "also-notify" not in syntax
