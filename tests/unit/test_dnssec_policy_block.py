from __future__ import annotations

import pytest

from bindantic import (
    DnssecAlgorithmEnum,
    DnssecDigestTypeEnum,
    DnssecKeyEntry,
    DnssecPolicyBlock,
    KeyRoleEnum,
    KeyStorageEnum,
    Nsec3ParamBlock,
)


class TestDnssecAlgorithmEnum:
    """Tests for DnssecAlgorithmEnum class."""

    def test_from_value_string_valid(self):
        """Test from_value with valid string values."""

        assert DnssecAlgorithmEnum.from_value("rsasha256") == DnssecAlgorithmEnum.RSASHA256
        assert (
            DnssecAlgorithmEnum.from_value("ecdsap256sha256")
            == DnssecAlgorithmEnum.ECDSAP256SHA256
        )
        assert DnssecAlgorithmEnum.from_value("ed25519") == DnssecAlgorithmEnum.ED25519

        assert DnssecAlgorithmEnum.from_value("RSASHA256") == DnssecAlgorithmEnum.RSASHA256
        assert DnssecAlgorithmEnum.from_value("ED25519") == DnssecAlgorithmEnum.ED25519

    def test_from_value_int_valid(self):
        """Test from_value with valid integer values."""
        assert DnssecAlgorithmEnum.from_value(8) == DnssecAlgorithmEnum.RSASHA256
        assert DnssecAlgorithmEnum.from_value(13) == DnssecAlgorithmEnum.ECDSAP256SHA256
        assert DnssecAlgorithmEnum.from_value(15) == DnssecAlgorithmEnum.ED25519
        assert DnssecAlgorithmEnum.from_value(16) == DnssecAlgorithmEnum.ED448

    def test_from_value_invalid(self):
        """Test from_value with invalid values."""
        with pytest.raises(ValueError, match="Invalid DNSSEC algorithm number"):
            DnssecAlgorithmEnum.from_value(99)

        with pytest.raises(ValueError, match="Invalid DNSSEC algorithm"):
            DnssecAlgorithmEnum.from_value("invalid_algo")

    def test_enum_values(self):
        """Test that all enum values are correct."""
        assert DnssecAlgorithmEnum.RSAMD5.value == "rsamd5"
        assert DnssecAlgorithmEnum.RSASHA256.value == "rsasha256"
        assert DnssecAlgorithmEnum.ECDSAP256SHA256.value == "ecdsap256sha256"
        assert DnssecAlgorithmEnum.ED25519.value == "ed25519"

    def test_deprecated_algorithms(self):
        """Test that deprecated algorithms are still accessible."""
        assert DnssecAlgorithmEnum.RSAMD5.value == "rsamd5"
        assert DnssecAlgorithmEnum.DSA.value == "dsa"
        assert DnssecAlgorithmEnum.RSASHA1.value == "rsasha1"


class TestDnssecKeyEntry:
    """Tests for DnssecKeyEntry class."""

    def test_init_with_minimal_zsk(self):
        """Test initialization with minimal ZSK parameters."""
        key = DnssecKeyEntry(role=KeyRoleEnum.ZSK, lifetime=3600, algorithm="ecdsap256sha256")

        assert key.role == KeyRoleEnum.ZSK
        assert key.lifetime == 3600
        assert key.algorithm == "ecdsap256sha256"
        assert key.storage_type is None
        assert key.key_store_name is None
        assert key.key_size is None
        assert key.tag_range is None

    def test_init_with_full_csk(self):
        """Test initialization with full CSK parameters."""
        key = DnssecKeyEntry(
            role=KeyRoleEnum.CSK,
            storage_type=KeyStorageEnum.KEY_DIRECTORY,
            lifetime="unlimited",
            algorithm=DnssecAlgorithmEnum.ED25519,
            key_size=256,
            tag_range=(1000, 2000),
        )

        assert key.role == KeyRoleEnum.CSK
        assert key.storage_type == KeyStorageEnum.KEY_DIRECTORY
        assert key.lifetime == "unlimited"
        assert key.algorithm == "ed25519"
        assert key.key_size == 256
        assert key.tag_range == (1000, 2000)

    def test_init_with_key_store(self):
        """Test initialization with key store storage."""
        key = DnssecKeyEntry(
            role=KeyRoleEnum.KSK,
            storage_type=KeyStorageEnum.KEY_STORE,
            key_store_name="my-keystore",
            lifetime="90d",
            algorithm=13,
            key_size=2048,
        )

        assert key.role == KeyRoleEnum.KSK
        assert key.storage_type == KeyStorageEnum.KEY_STORE
        assert key.key_store_name == "my-keystore"
        assert key.lifetime == 7776000
        assert key.algorithm == "ecdsap256sha256"
        assert key.key_size == 2048

    def test_algorithm_conversion(self):
        """Test algorithm conversion from various types."""

        key1 = DnssecKeyEntry(role=KeyRoleEnum.ZSK, lifetime=3600, algorithm="rsasha256")
        assert key1.algorithm == "rsasha256"

        key2 = DnssecKeyEntry(
            role=KeyRoleEnum.ZSK, lifetime=3600, algorithm=DnssecAlgorithmEnum.ECDSAP384SHA384
        )
        assert key2.algorithm == "ecdsap384sha384"

        key3 = DnssecKeyEntry(
            role=KeyRoleEnum.ZSK,
            lifetime=3600,
            algorithm=15,
        )
        assert key3.algorithm == "ed25519"

    def test_tag_range_validation(self):
        """Test tag range validation."""

        key1 = DnssecKeyEntry(
            role=KeyRoleEnum.ZSK,
            lifetime=3600,
            algorithm="ecdsap256sha256",
            tag_range=(1000, 2000),
        )
        assert key1.tag_range == (1000, 2000)

        with pytest.raises(ValueError, match="cannot be greater than"):
            DnssecKeyEntry(
                role=KeyRoleEnum.ZSK,
                lifetime=3600,
                algorithm="ecdsap256sha256",
                tag_range=(2000, 1000),
            )

        with pytest.raises(ValueError, match="Value must be non-negative"):
            DnssecKeyEntry(
                role=KeyRoleEnum.ZSK,
                lifetime=3600,
                algorithm="ecdsap256sha256",
                tag_range=(-1, 1000),
            )

        with pytest.raises(ValueError, match="Maximum tag must be between"):
            DnssecKeyEntry(
                role=KeyRoleEnum.ZSK,
                lifetime=3600,
                algorithm="ecdsap256sha256",
                tag_range=(1000, 70000),
            )

    def test_model_bind_syntax_zsk(self):
        """Test BIND syntax generation for ZSK."""
        key = DnssecKeyEntry(
            role=KeyRoleEnum.ZSK, lifetime=3600, algorithm="ecdsap256sha256", key_size=256
        )

        expected = "zsk lifetime 3600 algorithm ecdsap256sha256 256;"
        assert key.model_bind_syntax() == expected

    def test_model_bind_syntax_csk_with_key_directory(self):
        """Test BIND syntax generation for CSK with key directory."""
        key = DnssecKeyEntry(
            role=KeyRoleEnum.CSK,
            storage_type=KeyStorageEnum.KEY_DIRECTORY,
            lifetime="unlimited",
            algorithm="ed25519",
            key_size=256,
            tag_range=(1000, 2000),
        )

        expected = (
            "csk key-directory lifetime unlimited algorithm ed25519 tag-range 1000 2000 256;"
        )
        assert key.model_bind_syntax() == expected

    def test_model_bind_syntax_ksk_with_key_store(self):
        """Test BIND syntax generation for KSK with key store."""
        key = DnssecKeyEntry(
            role=KeyRoleEnum.KSK,
            storage_type=KeyStorageEnum.KEY_STORE,
            key_store_name="secure-keystore",
            lifetime=7776000,
            algorithm=8,
            key_size=2048,
        )

        expected = "ksk key-store secure-keystore lifetime 7776000 algorithm rsasha256 2048;"
        assert key.model_bind_syntax() == expected

    def test_model_bind_syntax_with_comment(self):
        """Test BIND syntax generation with comment."""
        key = DnssecKeyEntry(
            role=KeyRoleEnum.ZSK,
            lifetime=3600,
            algorithm="ecdsap256sha256",
            comment="This is a ZSK key",
        )

        expected = "# This is a ZSK key\nzsk lifetime 3600 algorithm ecdsap256sha256;"
        assert key.model_bind_syntax() == expected

    def test_model_bind_syntax_with_indent(self):
        """Test BIND syntax generation with indentation."""
        key = DnssecKeyEntry(role=KeyRoleEnum.ZSK, lifetime=3600, algorithm="ecdsap256sha256")

        expected = "    zsk lifetime 3600 algorithm ecdsap256sha256;"
        assert key.model_bind_syntax(1) == expected

    def test_comparison_attr(self):
        """Test comparison_attr property."""
        key = DnssecKeyEntry(role=KeyRoleEnum.ZSK, lifetime=3600, algorithm="ecdsap256sha256")

        assert key.comparison_attr == (KeyRoleEnum.ZSK.value, "3600")


class TestNsec3ParamBlock:
    """Tests for Nsec3ParamBlock class."""

    def test_init_with_all_parameters(self):
        """Test initialization with all parameters."""
        nsec3 = Nsec3ParamBlock(iterations=10, optout=True, salt_length=8)

        assert nsec3.iterations == 10
        assert nsec3.optout == "yes"
        assert nsec3.salt_length == 8

    def test_init_with_minimal_parameters(self):
        """Test initialization with minimal parameters."""
        nsec3 = Nsec3ParamBlock(optout=False)

        assert nsec3.iterations is None
        assert nsec3.optout == "no"
        assert nsec3.salt_length is None

    def test_init_with_partial_parameters(self):
        """Test initialization with partial parameters."""
        nsec3 = Nsec3ParamBlock(iterations=5, salt_length=0)

        assert nsec3.iterations == 5
        assert nsec3.optout is None
        assert nsec3.salt_length == 0

    def test_salt_length_validation(self):
        """Test salt length validation."""

        nsec3 = Nsec3ParamBlock(salt_length=0)
        assert nsec3.salt_length == 0

        nsec3 = Nsec3ParamBlock(salt_length=255)
        assert nsec3.salt_length == 255

        with pytest.raises(ValueError):
            Nsec3ParamBlock(salt_length=-1)

        with pytest.raises(ValueError):
            Nsec3ParamBlock(salt_length=256)

    def test_model_bind_syntax_full(self):
        """Test BIND syntax generation with all parameters."""
        nsec3 = Nsec3ParamBlock(iterations=10, optout="yes", salt_length=8)

        expected = "nsec3param iterations 10 optout yes salt-length 8;"
        assert nsec3.model_bind_syntax() == expected

    def test_model_bind_syntax_partial(self):
        """Test BIND syntax generation with partial parameters."""
        nsec3 = Nsec3ParamBlock(iterations=5, optout=False)

        expected = "nsec3param iterations 5 optout no;"
        assert nsec3.model_bind_syntax() == expected

    def test_model_bind_syntax_minimal(self):
        """Test BIND syntax generation with minimal parameters."""
        nsec3 = Nsec3ParamBlock(optout=True)

        expected = "nsec3param optout yes;"
        assert nsec3.model_bind_syntax() == expected

    def test_model_bind_syntax_with_comment(self):
        """Test BIND syntax generation with comment."""
        nsec3 = Nsec3ParamBlock(
            iterations=10, optout=True, salt_length=8, comment="NSEC3 parameters for zone"
        )

        expected = (
            "# NSEC3 parameters for zone\nnsec3param iterations 10 optout yes salt-length 8;"
        )
        assert nsec3.model_bind_syntax() == expected

    def test_model_bind_syntax_with_indent(self):
        """Test BIND syntax generation with indentation."""
        nsec3 = Nsec3ParamBlock(iterations=10, optout=True)

        expected = "    nsec3param iterations 10 optout yes;"
        assert nsec3.model_bind_syntax(1) == expected


class TestDnssecPolicyBlock:
    """Tests for DnssecPolicyBlock class."""

    def test_init_with_custom_policy(self):
        """Test initialization with custom policy."""
        policy = DnssecPolicyBlock(
            name="custom-policy", inline_signing=True, dnskey_ttl=3600, max_zone_ttl=86400
        )

        assert policy.name == "custom-policy"
        assert policy.inline_signing == "yes"
        assert policy.dnskey_ttl == 3600
        assert policy.max_zone_ttl == 86400
        assert policy.keys is None
        assert policy.nsec3param is None

    def test_init_with_builtin_policy(self):
        """Test initialization with built-in policy."""
        policy = DnssecPolicyBlock(name="default")

        assert policy.name == "default"
        assert policy.inline_signing is None
        assert policy.dnskey_ttl is None
        assert policy.max_zone_ttl is None

    def test_init_with_keys(self):
        """Test initialization with keys."""
        key = DnssecKeyEntry(role=KeyRoleEnum.ZSK, lifetime=3600, algorithm="ecdsap256sha256")

        policy = DnssecPolicyBlock(name="key-policy", keys=[key])

        assert policy.name == "key-policy"
        assert len(policy.keys) == 1
        assert policy.keys[0].role == KeyRoleEnum.ZSK

    def test_init_with_nsec3param(self):
        """Test initialization with NSEC3 parameters."""
        nsec3 = Nsec3ParamBlock(iterations=10, optout=True, salt_length=8)

        policy = DnssecPolicyBlock(name="nsec3-policy", nsec3param=nsec3)

        assert policy.name == "nsec3-policy"
        assert policy.nsec3param.iterations == 10
        assert policy.nsec3param.optout == "yes"
        assert policy.nsec3param.salt_length == 8

    def test_init_with_cds_digest_types(self):
        """Test initialization with CDS digest types."""
        policy = DnssecPolicyBlock(name="digest-policy", cds_digest_types=["SHA-256", "SHA-512"])

        assert policy.name == "digest-policy"
        assert len(policy.cds_digest_types) == 2
        assert "SHA-256" in policy.cds_digest_types
        assert "SHA-512" in policy.cds_digest_types

    def test_builtin_policy_validation(self):
        """Test validation for built-in policies."""

        policy = DnssecPolicyBlock(name="default")
        assert policy.name == "default"

        with pytest.raises(ValueError, match="cannot have additional parameters"):
            DnssecPolicyBlock(name="default", inline_signing=True)

    def test_key_validation_csk_mix(self):
        """Test validation for mixing CSK with KSK/ZSK."""
        csk = DnssecKeyEntry(role=KeyRoleEnum.CSK, lifetime=3600, algorithm="ecdsap256sha256")
        ksk = DnssecKeyEntry(role=KeyRoleEnum.KSK, lifetime=3600, algorithm="ecdsap256sha256")

        with pytest.raises(ValueError, match="Cannot mix CSK with KSK/ZSK"):
            DnssecPolicyBlock(name="mixed-policy", keys=[csk, ksk])

    def test_key_validation_ksk_zsk_algorithm_mismatch(self):
        """Test validation for KSK/ZSK algorithm mismatch."""
        ksk = DnssecKeyEntry(role=KeyRoleEnum.KSK, lifetime=3600, algorithm="rsasha256")
        zsk = DnssecKeyEntry(role=KeyRoleEnum.ZSK, lifetime=3600, algorithm="ecdsap256sha256")

        with pytest.raises(ValueError, match="must match ZSK algorithms"):
            DnssecPolicyBlock(name="algorithm-policy", keys=[ksk, zsk])

    def test_key_validation_offline_ksk_with_csk(self):
        """Test validation for offline-ksk with CSK."""
        csk = DnssecKeyEntry(role=KeyRoleEnum.CSK, lifetime=3600, algorithm="ecdsap256sha256")

        with pytest.raises(ValueError, match="Cannot use offline-ksk with CSK"):
            DnssecPolicyBlock(name="offline-policy", keys=[csk], offline_ksk=True)

    def test_model_bind_syntax_builtin(self):
        """Test BIND syntax generation for built-in policy."""
        policy = DnssecPolicyBlock(name="default")

        expected = "dnssec-policy default;"
        assert policy.model_bind_syntax() == expected

    def test_model_bind_syntax_custom(self):
        """Test BIND syntax generation for custom policy."""
        policy = DnssecPolicyBlock(
            name="custom-policy", inline_signing=True, dnskey_ttl=3600, max_zone_ttl=86400
        )

        expected = """dnssec-policy custom-policy {
    dnskey-ttl 3600;
    inline-signing yes;
    max-zone-ttl 86400;
};"""
        assert policy.model_bind_syntax() == expected

    def test_model_bind_syntax_with_keys(self):
        """Test BIND syntax generation with keys."""
        zsk = DnssecKeyEntry(role=KeyRoleEnum.ZSK, lifetime=3600, algorithm="ecdsap256sha256")

        policy = DnssecPolicyBlock(name="key-policy", keys=[zsk], inline_signing=True)

        expected = """dnssec-policy key-policy {
    inline-signing yes;
    keys {
        zsk lifetime 3600 algorithm ecdsap256sha256;
    };
};"""
        assert policy.model_bind_syntax() == expected

    def test_model_bind_syntax_with_nsec3param(self):
        """Test BIND syntax generation with NSEC3 parameters."""
        nsec3 = Nsec3ParamBlock(iterations=10, optout=True, salt_length=8)

        policy = DnssecPolicyBlock(name="nsec3-policy", nsec3param=nsec3, inline_signing=True)

        expected = """dnssec-policy nsec3-policy {
    inline-signing yes;
    nsec3param iterations 10 optout yes salt-length 8;
};"""
        assert policy.model_bind_syntax() == expected

    def test_model_bind_syntax_with_cds_digest_types(self):
        """Test BIND syntax generation with CDS digest types."""
        policy = DnssecPolicyBlock(
            name="digest-policy",
            cds_digest_types=[DnssecDigestTypeEnum.SHA256, DnssecDigestTypeEnum.SHA512],
            inline_signing=True,
        )

        expected = """dnssec-policy digest-policy {
    cds-digest-types {
        SHA-256;
        SHA-512;
    };
    inline-signing yes;
};"""
        assert policy.model_bind_syntax() == expected

    def test_model_bind_syntax_with_comment(self):
        """Test BIND syntax generation with comment."""
        policy = DnssecPolicyBlock(
            name="commented-policy", inline_signing=True, comment="This is a DNSSEC policy"
        )

        expected = """# This is a DNSSEC policy
dnssec-policy commented-policy {
    inline-signing yes;
};"""
        assert policy.model_bind_syntax() == expected

    def test_model_bind_syntax_with_indent(self):
        """Test BIND syntax generation with indentation."""
        policy = DnssecPolicyBlock(name="indented-policy", inline_signing=True)

        expected = """    dnssec-policy indented-policy {
        inline-signing yes;
    };"""
        assert policy.model_bind_syntax(1) == expected

    def test_real_world_scenarios(self):
        """Test real-world DNSSEC policy scenarios."""

        zsk = DnssecKeyEntry(
            role=KeyRoleEnum.ZSK,
            lifetime=2592000,
            algorithm="ecdsap256sha256",
            key_size=256,
        )

        policy1 = DnssecPolicyBlock(
            name="simple-zone-policy",
            keys=[zsk],
            inline_signing=True,
            dnskey_ttl=3600,
            max_zone_ttl=86400,
        )

        assert policy1.name == "simple-zone-policy"
        assert len(policy1.keys) == 1

        ksk = DnssecKeyEntry(
            role=KeyRoleEnum.KSK,
            lifetime=31536000,
            algorithm="ed25519",
            key_size=256,
        )
        zsk2 = DnssecKeyEntry(
            role=KeyRoleEnum.ZSK,
            lifetime=2592000,
            algorithm="ed25519",
            key_size=256,
        )

        policy2 = DnssecPolicyBlock(
            name="secure-zone-policy",
            keys=[ksk, zsk2],
            inline_signing=True,
            dnskey_ttl=7200,
            max_zone_ttl=172800,
            parent_propagation_delay=3600,
            publish_safety=3600,
            signatures_refresh=604800,
        )

        assert policy2.name == "secure-zone-policy"
        assert len(policy2.keys) == 2

        nsec3 = Nsec3ParamBlock(iterations=5, optout=True, salt_length=16)

        policy3 = DnssecPolicyBlock(
            name="nsec3-secure-policy",
            nsec3param=nsec3,
            inline_signing=True,
            cds_digest_types=["SHA-256", "SHA-384"],
        )

        assert policy3.name == "nsec3-secure-policy"
        assert policy3.nsec3param.iterations == 5

    def test_digest_types_validation(self):
        """Test CDS digest types validation."""

        policy1 = DnssecPolicyBlock(name="valid-digests", cds_digest_types=["SHA-256", "SHA-512"])
        assert policy1.cds_digest_types == ["SHA-256", "SHA-512"]

        policy2 = DnssecPolicyBlock(
            name="enum-digests",
            cds_digest_types=[DnssecDigestTypeEnum.SHA256, DnssecDigestTypeEnum.SHA384],
        )
        assert policy2.cds_digest_types == ["SHA-256", "SHA-384"]

        with pytest.raises(ValueError, match="Invalid CDS digest type"):
            DnssecPolicyBlock(name="invalid-digests", cds_digest_types=["INVALID-DIGEST"])

    def test_duration_conversions(self):
        """Test duration conversions in policy parameters."""
        policy = DnssecPolicyBlock(
            name="duration-policy",
            dnskey_ttl="1h",
            max_zone_ttl=86400,
            parent_propagation_delay=3600,
            publish_safety="3600",
        )

        assert policy.dnskey_ttl == 3600
        assert policy.max_zone_ttl == 86400
        assert policy.parent_propagation_delay == 3600
        assert policy.publish_safety == 3600

    @pytest.mark.parametrize("policy_name", ["default", "insecure", "none"])
    def test_all_builtin_policies(self, policy_name):
        """Test all built-in policy names."""
        policy = DnssecPolicyBlock(name=policy_name)
        assert policy.name == policy_name

        assert policy.model_bind_syntax() == f"dnssec-policy {policy_name};"

        with pytest.raises(ValueError, match="cannot have additional parameters"):
            DnssecPolicyBlock(name=policy_name, inline_signing=True)
