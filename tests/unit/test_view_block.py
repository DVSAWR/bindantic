"""
Tests for BIND view configuration block.
"""

from __future__ import annotations

import pytest

from bindantic import (
    AnchorTypeEnum,
    DnssecAlgorithmEnum,
    DnssecKeyEntry,
    DnssecPolicyBlock,
    KeyBlock,
    KeyRoleEnum,
    KeyTrustAnchor,
    ServerBlock,
    TrustAnchorsBlock,
    ViewBlock,
    ZoneBlock,
    ZoneClassEnum,
    ZoneTypeEnum,
)


class TestViewBlockBasic:
    """Basic tests for ViewBlock class."""

    def test_minimal_view_creation(self):
        """Test creation of a minimal view."""
        view = ViewBlock(name="internal")
        assert view.name == "internal"
        assert view.view_class is None
        assert view.match_clients is None
        assert view.match_destinations is None
        assert view.match_recursive_only is None
        assert view.server_blocks is None
        assert view.key_blocks is None
        assert view.trust_anchors is None
        assert view.dnssec_policy_block is None
        assert view.view_zones is None

    def test_view_with_class(self):
        """Test view with explicit class."""
        view = ViewBlock(name="chaos-view", view_class=ZoneClassEnum.CHAOS)
        assert view.view_class == ZoneClassEnum.CHAOS

    def test_view_with_match_conditions(self):
        """Test view with match clients/destinations."""
        view = ViewBlock(
            name="secure-view",
            match_clients=["trusted-nets", "key secure-key"],
            match_destinations=["any"],
            match_recursive_only="yes",
        )
        assert view.match_clients == ["trusted-nets", "key secure-key"]
        assert view.match_destinations == ["any"]
        assert view.match_recursive_only == "yes"

    def test_view_with_options(self):
        """Test view with options inherited from mixin."""
        view = ViewBlock(
            name="external",
            recursion="yes",
            allow_query=["any"],
            dnssec_validation="auto",
            querylog="yes",
        )
        assert view.recursion == "yes"
        assert view.allow_query == ["any"]
        assert view.dnssec_validation == "auto"
        assert view.querylog == "yes"  # boolean_BIND returns "yes"/"no", not bool


class TestViewBlockValidation:
    """Tests for ViewBlock validators."""

    def test_non_in_view_without_hint_zone_raises(self):
        """Test that non-IN view without a hint zone raises ValueError."""
        with pytest.raises(ValueError, match="should contain a hint zone"):
            ViewBlock(
                name="chaos-view",
                view_class=ZoneClassEnum.CHAOS,
                view_zones=[
                    ZoneBlock(
                        name="example.com",
                        zone_type=ZoneTypeEnum.PRIMARY,
                        file="db.example",
                    ),
                ],
            )

    def test_non_in_view_with_hint_zone_passes(self):
        """Test that non-IN view with a hint zone passes validation."""
        view = ViewBlock(
            name="chaos-view",
            view_class=ZoneClassEnum.CHAOS,
            view_zones=[
                ZoneBlock(name=".", zone_type=ZoneTypeEnum.HINT, file="db.root"),
            ],
        )
        # Should not raise
        assert view is not None

    def test_no_warning_with_match_clients(self, capsys):
        """Test that a view with match_clients does not print warning."""
        view = ViewBlock(name="internal", match_clients=["localhost"])
        view.model_post_init(None)
        captured = capsys.readouterr()
        assert captured.out == ""


class TestViewBlockSyntaxGeneration:
    """Tests for BIND syntax generation in ViewBlock."""

    def test_minimal_view_syntax(self):
        """Test syntax generation for a minimal view."""
        view = ViewBlock(name="internal")
        syntax = view.model_bind_syntax()
        expected = "view internal {\n};"
        assert syntax == expected

    def test_view_with_class_syntax(self):
        """Test syntax with explicit class."""
        view = ViewBlock(name="chaos-view", view_class=ZoneClassEnum.CHAOS)
        syntax = view.model_bind_syntax()
        expected = "view chaos-view CHAOS {\n};"
        assert syntax == expected

    def test_view_with_match_conditions_syntax(self):
        """Test syntax with match conditions."""
        view = ViewBlock(
            name="secure-view",
            match_clients=["trusted-nets", "key secure-key"],
            match_destinations=["any"],
            match_recursive_only="yes",
        )
        syntax = view.model_bind_syntax()
        assert "view secure-view {" in syntax
        assert "    match-clients {" in syntax
        # address_match_element with spaces is quoted automatically
        assert '        "key secure-key";' in syntax or "        key secure-key;" in syntax
        assert "        trusted-nets;" in syntax
        assert "    };" in syntax
        assert "    match-destinations {" in syntax
        assert "        any;" in syntax
        assert "    };" in syntax
        assert "    match-recursive-only yes;" in syntax

    def test_view_with_options_syntax(self):
        """Test syntax with inherited options."""
        view = ViewBlock(
            name="external",
            recursion="yes",
            allow_query=["any"],
            dnssec_validation="auto",
            querylog="yes",
        )
        syntax = view.model_bind_syntax()
        assert "    recursion yes;" in syntax
        # allow-query is formatted as multi-line block
        assert "    allow-query {" in syntax
        assert "        any;" in syntax
        assert "    };" in syntax
        assert "    dnssec-validation auto;" in syntax
        assert "    querylog yes;" in syntax

    def test_view_with_comment(self):
        """Test syntax with comment."""
        view = ViewBlock(
            name="internal",
            comment="Internal view for trusted clients\nOnly recursive queries allowed",
        )
        syntax = view.model_bind_syntax()
        assert "# Internal view for trusted clients" in syntax
        assert "# Only recursive queries allowed" in syntax
        assert "view internal {" in syntax

    def test_view_with_indentation(self):
        """Test syntax with custom indentation level."""
        view = ViewBlock(name="internal")
        syntax = view.model_bind_syntax(indent_level=2)
        expected = "        view internal {\n        };"
        assert syntax == expected


class TestViewBlockNestedBlocks:
    """Tests for nested block formatting in ViewBlock."""

    def test_view_with_server_blocks(self):
        """Test view with server-blocks."""
        server1 = ServerBlock(netprefix="192.168.1.0/24", bogus=True, edns="yes")
        server2 = ServerBlock(netprefix="10.0.0.0/8", tcp_only=True, request_nsid=True)
        view = ViewBlock(
            name="secure-view",
            server_blocks=[server1, server2],
        )
        syntax = view.model_bind_syntax()
        assert "    server-blocks {" in syntax
        assert "        server 192.168.1.0/24 {" in syntax
        assert "            bogus yes;" in syntax
        assert "            edns yes;" in syntax
        assert "        };" in syntax
        assert "        server 10.0.0.0/8 {" in syntax
        assert "            request-nsid yes;" in syntax
        assert "            tcp-only yes;" in syntax
        assert "        };" in syntax
        assert "    };" in syntax

    def test_view_with_key_blocks(self):
        """Test view with key-blocks."""
        key1 = KeyBlock(name="tsig-key", algorithm="hmac-sha256", secret="aGVsbG8=")
        key2 = KeyBlock(name="rndc-key", algorithm="hmac-sha512", secret="c2VjcmV0")
        view = ViewBlock(
            name="secure-view",
            key_blocks=[key1, key2],
        )
        syntax = view.model_bind_syntax()
        assert "    key-blocks {" in syntax
        assert '        key "tsig-key" {' in syntax
        assert "            algorithm hmac-sha256;" in syntax
        assert '            secret "aGVsbG8=";' in syntax
        assert "        };" in syntax
        assert '        key "rndc-key" {' in syntax
        assert "            algorithm hmac-sha512;" in syntax
        assert '            secret "c2VjcmV0";' in syntax
        assert "        };" in syntax
        assert "    };" in syntax

    def test_view_with_trust_anchors(self):
        """Test view with trust-anchors block."""
        trust_anchor = TrustAnchorsBlock(
            anchors=[
                KeyTrustAnchor(
                    domain="example.com",
                    anchor_type=AnchorTypeEnum.STATIC_KEY,
                    flags=257,
                    protocol=3,
                    algorithm=8,
                    key_data='"AwEAAcFcGsaxxdKkuJ..."',
                )
            ]
        )
        view = ViewBlock(
            name="secure-view",
            trust_anchors=[trust_anchor],
        )
        syntax = view.model_bind_syntax()
        assert "    trust-anchors {" in syntax
        assert "        trust-anchors {" in syntax
        assert '            example.com static-key 257 3 8 "AwEAAcFcGsaxxdKkuJ...";' in syntax
        assert "        };" in syntax
        assert "    };" in syntax

    def test_view_with_dnssec_policy_block(self):
        """Test view with dnssec-policy block."""
        policy = DnssecPolicyBlock(
            name="secure-policy",
            keys=[
                DnssecKeyEntry(
                    role=KeyRoleEnum.KSK,
                    lifetime="365d",
                    algorithm=DnssecAlgorithmEnum.ECDSAP256SHA256,
                    key_size=256,
                )
            ],
        )
        view = ViewBlock(
            name="secure-view",
            dnssec_policy_block=policy,
        )
        syntax = view.model_bind_syntax()
        assert "    dnssec-policy secure-policy {" in syntax
        assert "        keys {" in syntax
        assert "            ksk lifetime 31536000 algorithm ecdsap256sha256 256;" in syntax
        assert "        };" in syntax
        assert "    };" in syntax

    def test_view_with_zones(self):
        """Test view with view-zones."""
        zone1 = ZoneBlock(
            name="example.com",
            zone_type=ZoneTypeEnum.PRIMARY,
            file="/var/lib/bind/db.example.com",
        )
        zone2 = ZoneBlock(
            name="secondary.example.com",
            zone_type=ZoneTypeEnum.SECONDARY,
            primaries=[("192.168.1.1", 53)],
        )
        view = ViewBlock(
            name="internal-view",
            view_zones=[zone1, zone2],
        )
        syntax = view.model_bind_syntax()
        # Check that zone blocks appear correctly
        assert "zone example.com. {" in syntax
        assert "    type primary;" in syntax
        assert '    file "/var/lib/bind/db.example.com";' in syntax
        assert "zone secondary.example.com. {" in syntax
        assert "    type secondary;" in syntax
        assert "    primaries {" in syntax
        assert "        192.168.1.1 port 53;" in syntax

    def test_view_with_all_blocks(self):
        """Test view with all nested blocks together."""
        policy = DnssecPolicyBlock(
            name="policy",
            keys=[
                DnssecKeyEntry(
                    role=KeyRoleEnum.ZSK,
                    lifetime="30d",
                    algorithm=DnssecAlgorithmEnum.ECDSAP256SHA256,
                    key_size=256,
                )
            ],
        )
        view = ViewBlock(
            name="full-view",
            match_clients=["trusted"],
            server_blocks=[
                ServerBlock(netprefix="192.168.1.0/24", bogus=True),
            ],
            key_blocks=[
                KeyBlock(name="key1", algorithm="hmac-sha256", secret="sec1"),
            ],
            trust_anchors=[
                TrustAnchorsBlock(
                    anchors=[
                        KeyTrustAnchor(
                            domain=".",
                            anchor_type=AnchorTypeEnum.INITIAL_KEY,
                            flags=257,
                            protocol=3,
                            algorithm=8,
                            key_data='"key"',
                        )
                    ]
                )
            ],
            dnssec_policy_block=policy,
            view_zones=[
                ZoneBlock(name="example.com", zone_type=ZoneTypeEnum.PRIMARY),
            ],
        )
        syntax = view.model_bind_syntax()
        # Check that all sections are present
        assert "view full-view {" in syntax
        assert "    match-clients {" in syntax
        assert "        trusted;" in syntax
        assert "    };" in syntax
        assert "    server-blocks {" in syntax
        assert "    key-blocks {" in syntax
        assert '        key "key1" {' in syntax
        assert "    trust-anchors {" in syntax
        assert "    dnssec-policy policy {" in syntax
        assert "    zone example.com. {" in syntax


class TestViewBlockIntegration:
    """Integration tests with real-world examples."""

    def test_minimal_internal_view(self):
        """Test a minimal internal view."""
        view = ViewBlock(
            name="internal-view",
            match_clients=["192.168.0.0/16", "10.0.0.0/8"],
        )
        syntax = view.model_bind_syntax()
        assert "view internal-view {" in syntax
        assert "    match-clients {" in syntax
        assert "        10.0.0.0/8;" in syntax
        assert "        192.168.0.0/16;" in syntax
        assert "    };" in syntax

    def test_chaos_view_with_hint(self):
        """Test a CHAOS view with hint zone."""
        view = ViewBlock(
            name="chaos-view",
            view_class=ZoneClassEnum.CHAOS,
            match_clients=["any"],
            view_zones=[
                ZoneBlock(name=".", zone_type=ZoneTypeEnum.HINT, file="/etc/bind/db.root"),
            ],
        )
        syntax = view.model_bind_syntax()
        assert "view chaos-view CHAOS {" in syntax
        assert "    match-clients {" in syntax
        assert "        any;" in syntax
        assert "    };" in syntax
        assert "    zone . {" in syntax
        assert "        type hint;" in syntax
        assert '        file "/etc/bind/db.root";' in syntax
        assert "    };" in syntax

    def test_full_view_with_all_features(self):  # noqa: PLR0915
        """Test a comprehensive view with many options (based on manual example)."""
        key_zsk = DnssecKeyEntry(
            role=KeyRoleEnum.ZSK,
            lifetime="unlimited",
            algorithm=14,  # NOTE: ECDSAP384SHA384
        )

        view = ViewBlock(
            name="secure-view",
            match_clients=["trusted-nets", "key secure-key"],
            match_destinations=["any"],
            match_recursive_only="yes",
            server_blocks=[
                ServerBlock(
                    netprefix="192.168.1.0/24",
                    bogus="yes",
                    edns="yes",
                    provide_ixfr="no",
                    request_ixfr="no",
                ),
                ServerBlock(
                    netprefix="10.0.0.0/8",
                    tcp_only="yes",
                    request_nsid="yes",
                    require_cookie="yes",
                ),
            ],
            key_blocks=[
                KeyBlock(name="tsig-key", algorithm="hmac-sha256", secret="aGVsbG8="),
                KeyBlock(
                    name="secure-key", algorithm="hmac-sha512", secret="dGhpcy1pc2FzZWNyZXQ="
                ),
            ],
            trust_anchors=[
                TrustAnchorsBlock(
                    anchors=[
                        KeyTrustAnchor(
                            domain="example.com",
                            anchor_type=AnchorTypeEnum.STATIC_KEY,
                            flags=257,
                            protocol=3,
                            algorithm=8,
                            key_data='"AwEAAcFcGsaxxdKkuJ..."',
                        )
                    ]
                )
            ],
            dnssec_policy_block=DnssecPolicyBlock(
                name="policy_mixed",
                manual_mode="no",
                offline_ksk="no",
                parent_propagation_delay=3600,
                publish_safety="PT1H",
                signatures_refresh="5D",
                cds_digest_types=["SHA-256", "SHA-384"],
                keys=[key_zsk],
            ),
            view_zones=[
                ZoneBlock(
                    name="example.com",
                    zone_type=ZoneTypeEnum.PRIMARY,
                    file="/var/lib/bind/db.example.com",
                    allow_query=["any"],
                    dnssec_policy="default",
                ),
                ZoneBlock(
                    name="secondary.example.com",
                    zone_type=ZoneTypeEnum.SECONDARY,
                    primaries=[("192.168.1.1", 53)],
                    file="/var/lib/bind/db.secondary",
                ),
            ],
            recursion="yes",
            allow_query=["any"],
            allow_transfer=["secondary-servers"],
            dnssec_validation="auto",
            querylog="yes",
        )

        syntax = view.model_bind_syntax()

        # Check view header
        assert "view secure-view {" in syntax

        # Check match conditions
        assert "    match-clients {" in syntax
        # Key entry may be quoted
        assert '"key secure-key";' in syntax or "key secure-key;" in syntax
        assert "        trusted-nets;" in syntax
        assert "    };" in syntax
        assert "    match-destinations {" in syntax
        assert "        any;" in syntax
        assert "    };" in syntax
        assert "    match-recursive-only yes;" in syntax

        # Check server-blocks
        assert "    server-blocks {" in syntax
        assert "        server 192.168.1.0/24 {" in syntax
        assert "            bogus yes;" in syntax
        assert "            edns yes;" in syntax
        assert "            provide-ixfr no;" in syntax
        assert "            request-ixfr no;" in syntax
        assert "        };" in syntax
        assert "        server 10.0.0.0/8 {" in syntax
        assert "            request-nsid yes;" in syntax
        assert "            require-cookie yes;" in syntax
        assert "            tcp-only yes;" in syntax
        assert "        };" in syntax
        assert "    };" in syntax

        # Check key-blocks
        assert "    key-blocks {" in syntax
        assert '        key "tsig-key" {' in syntax
        assert "            algorithm hmac-sha256;" in syntax
        assert '            secret "aGVsbG8=";' in syntax
        assert '        key "secure-key" {' in syntax
        assert "            algorithm hmac-sha512;" in syntax
        assert '            secret "dGhpcy1pc2FzZWNyZXQ=";' in syntax

        # Check trust-anchors
        assert "    trust-anchors {" in syntax
        assert "        trust-anchors {" in syntax
        assert (
            '            example.com static-key 257 3 8 "AwEAAcFcGsaxxdKkuJ...";' in syntax
            or '            example.com. static-key 257 3 8 "AwEAAcFcGsaxxdKkuJ...";' in syntax
        )
        assert "        };" in syntax
        assert "    };" in syntax

        # Check DNSSEC policy
        assert "    dnssec-policy policy_mixed {" in syntax
        assert "        cds-digest-types {" in syntax
        assert "            SHA-256;" in syntax
        assert "            SHA-384;" in syntax
        assert "        };" in syntax
        assert "        keys {" in syntax
        assert "            zsk lifetime unlimited algorithm ecdsap384sha384;" in syntax
        assert "        };" in syntax
        assert "        manual-mode no;" in syntax
        assert "        offline-ksk no;" in syntax
        assert "        parent-propagation-delay 3600;" in syntax
        assert "        publish-safety 3600;" in syntax
        assert "        signatures-refresh 432000;" in syntax
        assert "    };" in syntax

        # Check options
        assert "    recursion yes;" in syntax
        assert "    allow-query {" in syntax
        assert "        any;" in syntax
        assert "    };" in syntax
        assert "    allow-transfer {" in syntax
        assert "        secondary-servers;" in syntax
        assert "    };" in syntax
        assert "    dnssec-validation auto;" in syntax
        assert "    querylog yes;" in syntax

        # Check zones
        assert "    zone example.com. {" in syntax
        assert "        type primary;" in syntax
        assert '        file "/var/lib/bind/db.example.com";' in syntax
        assert "    zone secondary.example.com. {" in syntax
        assert "        type secondary;" in syntax
        assert '        file "/var/lib/bind/db.secondary";' in syntax


class TestViewBlockEdgeCases:
    """Edge cases for ViewBlock."""

    def test_view_with_empty_match_clients_list(self):
        """Test view with empty match_clients list."""
        view = ViewBlock(
            name="empty-match",
            match_clients=[],
        )
        syntax = view.model_bind_syntax()
        assert "match-clients" not in syntax  # empty list should be omitted

    def test_view_with_empty_match_destinations_list(self):
        """Test view with empty match_destinations list."""
        view = ViewBlock(
            name="empty-match",
            match_destinations=[],
        )
        syntax = view.model_bind_syntax()
        assert "match-destinations" not in syntax

    def test_view_without_any_zones(self):
        """Test view without any zones (valid in BIND9)."""
        view = ViewBlock(
            name="no-zones",
            match_clients=["any"],
        )
        syntax = view.model_bind_syntax()
        # Ensure no zone block is present
        assert not any(line.strip().startswith("zone") for line in syntax.split("\n"))

    def test_view_with_excluded_fields(self):
        """Test that excluded fields are not rendered."""
        view = ViewBlock(
            name="test",
            version="should-not-appear",
            hostname="should-not-appear",
            server_id="should-not-appear",
        )
        syntax = view.model_bind_syntax()
        assert "version" not in syntax
        assert "hostname" not in syntax
        assert "server-id" not in syntax

    def test_view_class_default_not_printed(self):
        """Test that default class IN is not printed in header."""
        view = ViewBlock(name="test", view_class=ZoneClassEnum.IN)
        syntax = view.model_bind_syntax()
        assert "view test {" in syntax
        assert "view test IN {" not in syntax
