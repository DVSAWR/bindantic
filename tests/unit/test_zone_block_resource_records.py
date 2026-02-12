from __future__ import annotations

from ipaddress import IPv4Address, IPv6Address

import pytest

from bindantic.zone_block_resource_records import (
    RR_TYPE_PRIORITY,
    RR_TYPE_REGISTRY,
    AAAARecord,
    ARecord,
    CAARecord,
    CAATagEnum,
    CERTRecord,
    CNAMERecord,
    DNAMERecord,
    DNSKEYRecord,
    DNSSECAlgorithmEnum,
    DSRecord,
    HINFORecord,
    LOCRecord,
    MXRecord,
    NAPTRRecord,
    NSECRecord,
    NSRecord,
    PTRRecord,
    ResourceRecord,
    RPRecord,
    RRClassEnum,
    RRSIGRecord,
    RRTypeEnum,
    SOARecord,
    SPFRecord,
    SRVRecord,
    SSHFPAlgorithmEnum,
    SSHFPHashTypeEnum,
    SSHFPRecord,
    TLSACertUsageEnum,
    TLSAMatchingTypeEnum,
    TLSARecord,
    TLSASelectorEnum,
    TXTRecord,
    sort_resource_records,
)


class TestResourceRecordBase:
    """Base tests for ResourceRecord abstract class."""

    def test_base_class_abstract_methods(self):
        """Test that ResourceRecord has required abstract properties."""
        # ResourceRecord should be instantiable through concrete implementations
        # but not directly
        record = ARecord(name="example.com", address="192.168.1.1")
        assert isinstance(record, ResourceRecord)
        assert hasattr(record, "comparison_attr")
        assert hasattr(record, "model_bind_syntax")

    def test_default_values(self):
        """Test default values for ResourceRecord fields."""
        record = ARecord(name="example.com", address="192.168.1.1")
        assert record.name == "example.com."
        assert record.ttl is None
        assert record.rr_class == RRClassEnum.IN
        assert record.rr_type == RRTypeEnum.A

    def test_optional_fields(self):
        """Test that optional fields can be omitted or set."""
        # Test with minimal fields
        record = ARecord(address="192.168.1.1")
        assert record.name is None
        assert record.ttl is None
        assert record.rr_class == RRClassEnum.IN

        # Test with all fields
        record = ARecord(
            name="example.com",
            ttl=3600,
            rr_class=RRClassEnum.IN,
            address="192.168.1.1",
            comment="Test record",
        )
        assert record.name == "example.com."
        assert record.ttl == 3600
        assert record.rr_class == RRClassEnum.IN
        assert record.comment == "Test record"

    def test_name_normalization(self):
        """Test that names are normalized (add trailing dot)."""
        record = ARecord(name="example.com", address="192.168.1.1")
        assert record.name == "example.com."

        record = ARecord(name="example.com.", address="192.168.1.1")
        assert record.name == "example.com."

        # Special names
        record = ARecord(name="@", address="192.168.1.1")
        assert record.name == "@"

        record = ARecord(name="*", address="192.168.1.1")
        assert record.name == "*"

    def test_comment_handling(self):
        """Test comment handling in resource records."""
        record = ARecord(
            name="example.com",
            address="192.168.1.1",
            comment="This is a comment\nwith multiple lines",
        )
        assert record.comment == "This is a comment\nwith multiple lines"

        # Test that comment appears in syntax
        syntax = record.model_bind_syntax()
        assert "This is a comment" in syntax

    def test_comparison_attr_implementation(self):
        """Test that all concrete classes implement comparison_attr."""
        # Test a few concrete classes
        classes_to_test = [
            (ARecord, {"name": "example.com", "address": "192.168.1.1"}),
            (AAAARecord, {"name": "example.com", "address": "2001:db8::1"}),
            (CNAMERecord, {"name": "www.example.com", "canonical_name": "example.com"}),
            (MXRecord, {"name": "example.com", "preference": 10, "exchange": "mail.example.com"}),
        ]

        for cls, kwargs in classes_to_test:
            record = cls(**kwargs)
            assert hasattr(record, "comparison_attr")
            assert isinstance(record.comparison_attr, str)

    def test_rr_class_validation(self):
        """Test RR class validation and default."""
        # Test default is IN
        record = ARecord(address="192.168.1.1")
        assert record.rr_class == RRClassEnum.IN

        # Test other classes
        record = ARecord(address="192.168.1.1", rr_class=RRClassEnum.CH)
        assert record.rr_class == RRClassEnum.CH

        record = ARecord(address="192.168.1.1", rr_class=RRClassEnum.HS)
        assert record.rr_class == RRClassEnum.HS


class TestARecord:
    """Tests for ARecord class."""

    def test_basic_creation(self):
        """Test basic A record creation."""
        record = ARecord(name="example.com", address="192.168.1.1")
        assert record.name == "example.com."
        assert record.address == "192.168.1.1"
        assert record.rr_type == RRTypeEnum.A

    def test_with_ipv4_address_object(self):
        """Test with IPv4Address object."""
        record = ARecord(name="example.com", address=IPv4Address("192.168.1.1"))
        assert record.address == "192.168.1.1"

    def test_with_ttl_and_class(self):
        """Test with TTL and class."""
        record = ARecord(
            name="example.com", ttl=3600, rr_class=RRClassEnum.IN, address="192.168.1.1"
        )
        assert record.ttl == 3600
        assert record.rr_class == RRClassEnum.IN

    def test_model_bind_syntax(self):
        """Test BIND syntax generation."""
        record = ARecord(name="example.com", ttl=3600, address="192.168.1.1")
        syntax = record.model_bind_syntax()
        assert "example.com." in syntax
        assert "3600" in syntax
        assert "IN" in syntax
        assert "A" in syntax
        assert "192.168.1.1" in syntax

    def test_model_bind_syntax_no_name(self):
        """Test syntax without name (uses @)."""
        record = ARecord(address="192.168.1.1")
        syntax = record.model_bind_syntax()
        assert "@" in syntax
        assert "A" in syntax
        assert "192.168.1.1" in syntax

    def test_model_bind_syntax_no_ttl(self):
        """Test syntax without TTL."""
        record = ARecord(name="example.com", address="192.168.1.1")
        syntax = record.model_bind_syntax()
        # Should have empty space where TTL would be
        lines = syntax.split("\n")
        assert "example.com." in lines[0]
        assert "IN" in lines[0]
        assert "A" in lines[0]
        assert "192.168.1.1" in lines[0]

    def test_comparison_attr(self):
        """Test comparison attribute."""
        record = ARecord(name="example.com", address="192.168.1.1")
        assert record.comparison_attr == "A:example.com.:192.168.1.1"

        record2 = ARecord(address="192.168.1.1")
        assert record2.comparison_attr == "A:@:192.168.1.1"


class TestAAAARecord:
    """Tests for AAAARecord class."""

    def test_basic_creation(self):
        """Test basic AAAA record creation."""
        record = AAAARecord(name="example.com", address="2001:db8::1")
        assert record.name == "example.com."
        assert record.address == "2001:db8::1"
        assert record.rr_type == RRTypeEnum.AAAA

    def test_with_ipv6_address_object(self):
        """Test with IPv6Address object."""
        record = AAAARecord(name="example.com", address=IPv6Address("2001:db8::1"))
        assert record.address == "2001:db8::1"

    def test_with_scoped_ipv6_address(self):
        """Test with scoped IPv6 address."""
        record = AAAARecord(name="example.com", address="fe80::1%eth0")
        assert record.address == "fe80::1%eth0"

    def test_model_bind_syntax(self):
        """Test BIND syntax generation."""
        record = AAAARecord(name="example.com", ttl=3600, address="2001:db8::1")
        syntax = record.model_bind_syntax()
        assert "example.com." in syntax
        assert "3600" in syntax
        assert "IN" in syntax
        assert "AAAA" in syntax
        assert "2001:db8::1" in syntax

    def test_comparison_attr(self):
        """Test comparison attribute."""
        record = AAAARecord(name="example.com", address="2001:db8::1")
        assert record.comparison_attr == "AAAA:example.com.:2001:db8::1"


class TestCNAMERecord:
    """Tests for CNAMERecord class."""

    def test_basic_creation(self):
        """Test basic CNAME record creation."""
        record = CNAMERecord(name="www.example.com", canonical_name="example.com")
        assert record.name == "www.example.com."
        assert record.canonical_name == "example.com."
        assert record.rr_type == RRTypeEnum.CNAME

    def test_model_bind_syntax(self):
        """Test BIND syntax generation."""
        record = CNAMERecord(name="www.example.com", ttl=3600, canonical_name="example.com")
        syntax = record.model_bind_syntax()
        assert "www.example.com." in syntax
        assert "3600" in syntax
        assert "IN" in syntax
        assert "CNAME" in syntax
        assert "example.com." in syntax

    def test_comparison_attr(self):
        """Test comparison attribute."""
        record = CNAMERecord(name="www.example.com", canonical_name="example.com")
        assert record.comparison_attr == "CNAME:www.example.com.:example.com."


class TestMXRecord:
    """Tests for MXRecord class."""

    def test_basic_creation(self):
        """Test basic MX record creation."""
        record = MXRecord(name="example.com", preference=10, exchange="mail.example.com")
        assert record.name == "example.com."
        assert record.preference == 10
        assert record.exchange == "mail.example.com."
        assert record.rr_type == RRTypeEnum.MX

    def test_preference_validation(self):
        """Test preference value validation."""
        # Valid values
        MXRecord(name="example.com", preference=0, exchange="mail.example.com")
        MXRecord(name="example.com", preference=65535, exchange="mail.example.com")

        # Invalid values should raise error via Pydantic
        with pytest.raises(ValueError):
            MXRecord(name="example.com", preference=-1, exchange="mail.example.com")

        with pytest.raises(ValueError):
            MXRecord(name="example.com", preference=65536, exchange="mail.example.com")

    def test_model_bind_syntax(self):
        """Test BIND syntax generation."""
        record = MXRecord(name="example.com", ttl=3600, preference=10, exchange="mail.example.com")
        syntax = record.model_bind_syntax()
        assert "example.com." in syntax
        assert "3600" in syntax
        assert "IN" in syntax
        assert "MX" in syntax
        assert "10" in syntax
        assert "mail.example.com." in syntax

    def test_comparison_attr(self):
        """Test comparison attribute."""
        record = MXRecord(name="example.com", preference=10, exchange="mail.example.com")
        assert record.comparison_attr == "MX:example.com.:10:mail.example.com."


class TestNSRecord:
    """Tests for NSRecord class."""

    def test_basic_creation(self):
        """Test basic NS record creation."""
        record = NSRecord(name="example.com", nsdname="ns1.example.com")
        assert record.name == "example.com."
        assert record.nsdname == "ns1.example.com."
        assert record.rr_type == RRTypeEnum.NS

    def test_model_bind_syntax(self):
        """Test BIND syntax generation."""
        record = NSRecord(name="example.com", ttl=86400, nsdname="ns1.example.com")
        syntax = record.model_bind_syntax()
        assert "example.com." in syntax
        assert "86400" in syntax
        assert "IN" in syntax
        assert "NS" in syntax
        assert "ns1.example.com." in syntax

    def test_comparison_attr(self):
        """Test comparison attribute."""
        record = NSRecord(name="example.com", nsdname="ns1.example.com")
        assert record.comparison_attr == "NS:example.com.:ns1.example.com."


class TestSOARecord:
    """Tests for SOARecord class."""

    def test_basic_creation(self):
        """Test basic SOA record creation."""
        record = SOARecord(
            name="example.com",
            mname="ns1.example.com",
            rname="admin.example.com",
            serial=2024010101,
            refresh=10800,
            retry=3600,
            expire=604800,
            minimum=3600,
        )
        assert record.name == "example.com."
        assert record.mname == "ns1.example.com."
        assert record.rname == "admin.example.com."
        assert record.serial == 2024010101
        assert record.refresh == 10800
        assert record.retry == 3600
        assert record.expire == 604800
        assert record.minimum == 3600
        assert record.rr_type == RRTypeEnum.SOA

    def test_with_ttl_and_origin(self):
        """Test SOA record with TTL and ORIGIN."""
        record = SOARecord(
            ttl=3600,
            origin="example.com",
            mname="ns1.example.com",
            rname="admin.example.com",
            serial=2024010101,
            refresh="3h",
            retry="1h",
            expire="1w",
            minimum="1h",
        )
        assert record.ttl == 3600
        assert record.origin == "example.com."
        assert record.refresh == 10800
        assert record.retry == 3600
        assert record.expire == 604800
        assert record.minimum == 3600

    def test_model_bind_syntax(self):
        """Test BIND syntax generation for SOA."""
        record = SOARecord(
            name="example.com",
            mname="ns1.example.com",
            rname="admin.example.com",
            serial=2024010101,
            refresh=10800,
            retry=3600,
            expire=604800,
            minimum=3600,
        )
        syntax = record.model_bind_syntax()

        # Check multiline structure
        lines = syntax.split("\n")
        assert len(lines) >= 7  # Header + 5 data lines + closing

        # Check for SOA signature
        assert "SOA" in syntax
        assert "ns1.example.com." in syntax
        assert "admin.example.com." in syntax
        assert "2024010101" in syntax
        assert "10800" in syntax
        assert "3600" in syntax
        assert "604800" in syntax
        assert "3600" in syntax

    def test_model_bind_syntax_with_global_directives(self):
        """Test SOA syntax with $TTL and $ORIGIN."""
        record = SOARecord(
            ttl=3600,
            origin="example.com",
            mname="ns1.example.com",
            rname="admin.example.com",
            serial=2024010101,
            refresh=10800,
            retry=3600,
            expire=604800,
            minimum=3600,
        )
        syntax = record.model_bind_syntax()

        assert "$TTL 3600" in syntax
        assert "$ORIGIN example.com." in syntax
        assert "SOA" in syntax

    def test_comparison_attr(self):
        """Test comparison attribute."""
        record = SOARecord(
            name="example.com",
            mname="ns1.example.com",
            rname="admin.example.com",
            serial=2024010101,
            refresh=10800,
            retry=3600,
            expire=604800,
            minimum=3600,
        )
        assert record.comparison_attr == "SOA:example.com.:ns1.example.com."


class TestTXTRecord:
    """Tests for TXTRecord class."""

    def test_basic_creation(self):
        """Test basic TXT record creation."""
        record = TXTRecord(name="example.com", text_data=['"v=spf1 mx ~all"'])
        assert record.name == "example.com."
        assert record.text_data == ['"v=spf1 mx ~all"']
        assert record.rr_type == RRTypeEnum.TXT

    def test_multiple_text_strings(self):
        """Test TXT record with multiple text strings."""
        record = TXTRecord(
            name="example.com", text_data=['"v=spf1"', '"include:_spf.google.com"', '"~all"']
        )
        assert len(record.text_data) == 3

    def test_text_length_validation(self):
        """Test TXT string length validation."""
        # Valid: 255 chars
        valid_text = '"' + "a" * 255 + '"'
        TXTRecord(name="example.com", text_data=[valid_text])

        # Invalid: 256 chars should raise error
        invalid_text = '"' + "a" * 256 + '"'
        with pytest.raises(ValueError, match="TXT string too long"):
            TXTRecord(name="example.com", text_data=[invalid_text])

    def test_model_bind_syntax(self):
        """Test BIND syntax generation."""
        record = TXTRecord(name="example.com", ttl=3600, text_data=['"v=spf1 mx ~all"'])
        syntax = record.model_bind_syntax()
        assert "example.com." in syntax
        assert "3600" in syntax
        assert "IN" in syntax
        assert "TXT" in syntax
        assert '"v=spf1 mx ~all"' in syntax

    def test_model_bind_syntax_multiple_strings(self):
        """Test syntax with multiple text strings."""
        record = TXTRecord(name="example.com", text_data=['"part1"', '"part2"', '"part3"'])
        syntax = record.model_bind_syntax()
        # All parts should be in the output
        assert '"part1"' in syntax
        assert '"part2"' in syntax
        assert '"part3"' in syntax

    def test_comparison_attr(self):
        """Test comparison attribute."""
        record = TXTRecord(name="example.com", text_data=["test"])
        assert record.comparison_attr == 'TXT:example.com.:"test"'


class TestSRVRecord:
    """Tests for SRVRecord class."""

    def test_basic_creation(self):
        """Test basic SRV record creation."""
        record = SRVRecord(
            name="_sip._tcp.example.com", priority=0, weight=5, port=5060, target="sip.example.com"
        )
        assert record.name == "_sip._tcp.example.com."
        assert record.priority == 0
        assert record.weight == 5
        assert record.port == 5060
        assert record.target == "sip.example.com."
        assert record.rr_type == RRTypeEnum.SRV

    def test_priority_weight_validation(self):
        """Test priority and weight validation."""
        # Valid values
        SRVRecord(name="test", priority=0, weight=0, port=80, target="example.com")
        SRVRecord(name="test", priority=65535, weight=65535, port=80, target="example.com")

        # Invalid values should raise error via Pydantic
        with pytest.raises(ValueError):
            SRVRecord(name="test", priority=-1, weight=0, port=80, target="example.com")

        with pytest.raises(ValueError):
            SRVRecord(name="test", priority=0, weight=65536, port=80, target="example.com")

    def test_port_validation(self):
        """Test port validation."""
        # Valid ports
        SRVRecord(name="test", priority=0, weight=0, port=0, target="example.com")
        SRVRecord(name="test", priority=0, weight=0, port=65535, target="example.com")
        SRVRecord(name="test", priority=0, weight=0, port="80", target="example.com")

        # Invalid ports
        with pytest.raises(ValueError):
            SRVRecord(name="test", priority=0, weight=0, port=-1, target="example.com")

        with pytest.raises(ValueError):
            SRVRecord(name="test", priority=0, weight=0, port=65536, target="example.com")

    def test_model_bind_syntax(self):
        """Test BIND syntax generation."""
        record = SRVRecord(
            name="_sip._tcp.example.com",
            ttl=3600,
            priority=0,
            weight=5,
            port=5060,
            target="sip.example.com",
        )
        syntax = record.model_bind_syntax()
        assert "_sip._tcp.example.com." in syntax
        assert "3600" in syntax
        assert "IN" in syntax
        assert "SRV" in syntax
        assert "0" in syntax
        assert "5" in syntax
        assert "5060" in syntax
        assert "sip.example.com." in syntax

    def test_comparison_attr(self):
        """Test comparison attribute."""
        record = SRVRecord(
            name="_sip._tcp.example.com", priority=0, weight=5, port=5060, target="sip.example.com"
        )
        assert record.comparison_attr == "SRV:_sip._tcp.example.com.:0:sip.example.com."


class TestDNSSECRecords:
    """Tests for DNSSEC-related records."""

    def test_ds_record_basic(self):
        """Test basic DS record creation."""
        record = DSRecord(
            name="example.com",
            key_tag=12345,
            algorithm=DNSSECAlgorithmEnum.RSASHA256,
            digest_type=2,
            digest="2BB183AF5F225...",
        )
        assert record.name == "example.com."
        assert record.key_tag == 12345
        assert record.algorithm == DNSSECAlgorithmEnum.RSASHA256
        assert record.digest_type == 2
        assert record.digest == "2BB183AF5F225..."
        assert record.rr_type == RRTypeEnum.DS

    def test_dnskey_record_basic(self):
        """Test basic DNSKEY record creation."""
        record = DNSKEYRecord(
            name="example.com",
            flags=256,
            algorithm=DNSSECAlgorithmEnum.ECDSAP256SHA256,
            public_key="AwEAAcFcGsaxxdKkuJ...",
        )
        assert record.name == "example.com."
        assert record.flags == 256
        assert record.protocol == 3  # Default
        assert record.algorithm == DNSSECAlgorithmEnum.ECDSAP256SHA256
        assert record.public_key == "AwEAAcFcGsaxxdKkuJ..."
        assert record.rr_type == RRTypeEnum.DNSKEY

    def test_rrsig_record_basic(self):
        """Test basic RRSIG record creation."""
        record = RRSIGRecord(
            name="example.com",
            type_covered="A",
            algorithm=DNSSECAlgorithmEnum.RSASHA256,
            labels=2,
            original_ttl=3600,
            signature_expiration=4294967295,
            signature_inception=4294967295,
            key_tag=12345,
            signer_name="example.com",
            signature="AwEAAcFcGsaxxdKkuJ...",
        )
        assert record.name == "example.com."
        assert record.type_covered == "A"
        assert record.algorithm == DNSSECAlgorithmEnum.RSASHA256
        assert record.labels == 2
        assert record.original_ttl == 3600
        assert record.signature_expiration == 4294967295
        assert record.signature_inception == 4294967295
        assert record.key_tag == 12345
        assert record.signer_name == "example.com."
        assert record.signature == "AwEAAcFcGsaxxdKkuJ..."
        assert record.rr_type == RRTypeEnum.RRSIG

    def test_nsec_record_basic(self):
        """Test basic NSEC record creation."""
        record = NSECRecord(
            name="example.com",
            next_domain_name="next.example.com",
            type_bit_maps=["A", "AAAA", "MX"],
        )
        assert record.name == "example.com."
        assert record.next_domain_name == "next.example.com."
        assert record.type_bit_maps == ["A", "AAAA", "MX"]
        assert record.rr_type == RRTypeEnum.NSEC


class TestSpecialRecords:
    """Tests for special record types."""

    def test_sshfp_record_basic(self):
        """Test basic SSHFP record creation."""
        record = SSHFPRecord(
            name="server.example.com",
            algorithm=SSHFPAlgorithmEnum.RSA,
            hash_type=SSHFPHashTypeEnum.SHA256,
            fingerprint="1234567890ABCDEF...",
        )
        assert record.name == "server.example.com."
        assert record.algorithm == SSHFPAlgorithmEnum.RSA
        assert record.hash_type == SSHFPHashTypeEnum.SHA256
        assert record.fingerprint == "1234567890ABCDEF..."
        assert record.rr_type == RRTypeEnum.SSHFP

    def test_tlsa_record_basic(self):
        """Test basic TLSA record creation."""
        record = TLSARecord(
            name="_443._tcp.example.com",
            cert_usage=TLSACertUsageEnum.DANE_EE,
            selector=TLSASelectorEnum.FULL_CERT,
            matching_type=TLSAMatchingTypeEnum.SHA256,
            cert_data="ABCDEF123456",
        )
        assert record.name == "_443._tcp.example.com."
        assert record.cert_usage == TLSACertUsageEnum.DANE_EE
        assert record.selector == TLSASelectorEnum.FULL_CERT
        assert record.matching_type == TLSAMatchingTypeEnum.SHA256
        assert record.cert_data == "ABCDEF123456"
        assert record.rr_type == RRTypeEnum.TLSA

    def test_caa_record_basic(self):
        """Test basic CAA record creation."""
        record = CAARecord(
            name="example.com", flags=0, tag=CAATagEnum.ISSUE, value='"letsencrypt.org"'
        )
        assert record.name == "example.com."
        assert record.flags == 0
        assert record.tag == CAATagEnum.ISSUE
        assert record.value == '"letsencrypt.org"'
        assert record.rr_type == RRTypeEnum.CAA

    def test_caa_record_critical_flag(self):
        """Test CAA record with critical flag (128)."""
        record = CAARecord(
            name="example.com",
            flags=128,
            tag=CAATagEnum.ISSUEWILD,
            value='"digicert.com; policy=ev"',
        )
        assert record.flags == 128
        assert record.tag == CAATagEnum.ISSUEWILD
        assert record.value == '"digicert.com; policy=ev"'

    def test_ptr_record_basic(self):
        """Test basic PTR record creation."""
        record = PTRRecord(name="1.1.168.192.in-addr.arpa", domain_name="server.example.com")
        assert record.name == "1.1.168.192.in-addr.arpa."
        assert record.domain_name == "server.example.com."
        assert record.rr_type == RRTypeEnum.PTR

    def test_dname_record_basic(self):
        """Test basic DNAME record creation."""
        record = DNAMERecord(name="dept.example.com", target="corp.example.com")
        assert record.name == "dept.example.com."
        assert record.target == "corp.example.com."
        assert record.rr_type == RRTypeEnum.DNAME

    def test_spf_record_basic(self):
        """Test basic SPF record creation."""
        record = SPFRecord(name="example.com", spf_data=['"v=spf1 mx ~all"'])
        assert record.name == "example.com."
        assert record.spf_data == ['"v=spf1 mx ~all"']
        assert record.rr_type == RRTypeEnum.SPF


class TestOtherRecordTypes:
    """Tests for other less common record types."""

    def test_cert_record_basic(self):
        """Test basic CERT record creation."""
        record = CERTRecord(
            name="example.com",
            cert_type=1,
            key_tag=12345,
            algorithm=DNSSECAlgorithmEnum.RSASHA256,
            certificate="ABCDEF...",
        )
        assert record.name == "example.com."
        assert record.cert_type == 1
        assert record.key_tag == 12345
        assert record.algorithm == 8  # RSASHA256 value
        assert record.certificate == "ABCDEF..."
        assert record.rr_type == RRTypeEnum.CERT

    def test_loc_record_basic(self):
        """Test basic LOC record creation."""
        record = LOCRecord(
            name="example.com",
            latitude="51 30 12.123 N",
            longitude="0 7 39.456 W",
            altitude=10,
            size=100.0,
            hprecision=10.0,
            vprecision=2.0,
        )
        assert record.name == "example.com."
        assert record.latitude == "51 30 12.123 N"
        assert record.longitude == "0 7 39.456 W"
        assert record.altitude == 10
        assert record.size == 100.0
        assert record.hprecision == 10.0
        assert record.vprecision == 2.0
        assert record.rr_type == RRTypeEnum.LOC

    def test_naptr_record_basic(self):
        """Test basic NAPTR record creation."""
        record = NAPTRRecord(
            name="example.com",
            order=100,
            preference=10,
            flags="S",
            services="SIP+D2U",
            regexp='"!^.*$!sip:info@example.com!"',
            replacement="_sip._udp.example.com",
        )
        assert record.name == "example.com."
        assert record.order == 100
        assert record.preference == 10
        assert record.flags == "S"
        assert record.services == "SIP+D2U"
        assert record.regexp == '"!^.*$!sip:info@example.com!"'
        assert record.replacement == "_sip._udp.example.com."
        assert record.rr_type == RRTypeEnum.NAPTR

    def test_hinfo_record_basic(self):
        """Test basic HINFO record creation."""
        record = HINFORecord(name="server.example.com", cpu="x86-64", os="Ubuntu 20.04")
        assert record.name == "server.example.com."
        assert record.cpu == "x86-64"
        assert record.os == "Ubuntu 20.04"
        assert record.rr_type == RRTypeEnum.HINFO

    def test_rp_record_basic(self):
        """Test basic RP record creation."""
        record = RPRecord(
            name="example.com", mbox_dname="admin.example.com", txt_dname="contact.example.com"
        )
        assert record.name == "example.com."
        assert record.mbox_dname == "admin.example.com."
        assert record.txt_dname == "contact.example.com."
        assert record.rr_type == RRTypeEnum.RP


class TestRecordSorting:
    """Tests for resource record sorting."""

    def test_sort_resource_records_basic(self):
        """Test basic sorting of resource records."""
        records = [
            ARecord(name="mail.example.com", address="192.168.1.10"),
            NSRecord(name="example.com", nsdname="ns1.example.com"),
            SOARecord(
                name="example.com",
                mname="ns1.example.com",
                rname="admin.example.com",
                serial=2024010101,
                refresh=10800,
                retry=3600,
                expire=604800,
                minimum=3600,
            ),
            ARecord(name="example.com", address="192.168.1.1"),
            MXRecord(name="example.com", preference=10, exchange="mail.example.com"),
        ]

        sorted_records = sort_resource_records(records)

        # SOA should be first
        assert sorted_records[0].rr_type == RRTypeEnum.SOA

        # NS should be second
        assert sorted_records[1].rr_type == RRTypeEnum.NS

        # MX should be third
        assert sorted_records[2].rr_type == RRTypeEnum.MX

        # Then A records, sorted by name
        assert sorted_records[3].rr_type == RRTypeEnum.A
        assert sorted_records[3].name == "example.com."

        assert sorted_records[4].rr_type == RRTypeEnum.A
        assert sorted_records[4].name == "mail.example.com."

    def test_sort_by_name_with_same_type(self):
        """Test sorting records of same type by name."""
        records = [
            ARecord(name="zebra.example.com", address="192.168.1.3"),
            ARecord(name="apple.example.com", address="192.168.1.1"),
            ARecord(name="banana.example.com", address="192.168.1.2"),
        ]

        sorted_records = sort_resource_records(records)

        names = [record.name for record in sorted_records]
        expected = ["apple.example.com.", "banana.example.com.", "zebra.example.com."]
        assert names == expected

    def test_sort_with_root_name(self):
        """Test sorting with @ (root) name."""
        records = [
            ARecord(name="www.example.com", address="192.168.1.2"),
            ARecord(address="192.168.1.1"),  # name is None, becomes @
            ARecord(name="mail.example.com", address="192.168.1.3"),
        ]

        sorted_records = sort_resource_records(records)

        # @ should come first
        assert sorted_records[0].name is None
        # Then mail, then www (alphabetical)
        assert sorted_records[1].name == "mail.example.com."
        assert sorted_records[2].name == "www.example.com."


class TestRegistryAndConstants:
    """Tests for RR type registry and constants."""

    def test_rr_type_registry_completeness(self):
        """Test that all RR types are in the registry."""
        # Check that all enum values are in registry
        for rr_type in RRTypeEnum:
            assert rr_type in RR_TYPE_REGISTRY
            assert rr_type in RR_TYPE_PRIORITY

    def test_rr_type_priority_values(self):
        """Test RR type priority values."""
        # Check some known priorities
        assert RR_TYPE_PRIORITY[RRTypeEnum.SOA] == 0
        assert RR_TYPE_PRIORITY[RRTypeEnum.NS] == 1
        assert RR_TYPE_PRIORITY[RRTypeEnum.MX] == 2
        assert RR_TYPE_PRIORITY[RRTypeEnum.A] == 3
        assert RR_TYPE_PRIORITY[RRTypeEnum.AAAA] == 4

    def test_all_record_types_can_be_instantiated(self):
        """Test that all record types in registry can be instantiated."""
        # Test data for each record type
        test_data = {
            RRTypeEnum.A: {"address": "192.168.1.1"},
            RRTypeEnum.AAAA: {"address": "2001:db8::1"},
            RRTypeEnum.CNAME: {"canonical_name": "example.com"},
            RRTypeEnum.DNAME: {"target": "example.com"},
            RRTypeEnum.MX: {"preference": 10, "exchange": "mail.example.com"},
            RRTypeEnum.NS: {"nsdname": "ns1.example.com"},
            RRTypeEnum.PTR: {"domain_name": "example.com"},
            RRTypeEnum.SOA: {
                "mname": "ns1.example.com",
                "rname": "admin.example.com",
                "serial": 2024010101,
                "refresh": 10800,
                "retry": 3600,
                "expire": 604800,
                "minimum": 3600,
            },
            RRTypeEnum.TXT: {"text_data": ['"test"']},
            RRTypeEnum.SPF: {"spf_data": ['"v=spf1"']},
            RRTypeEnum.SRV: {"priority": 0, "weight": 5, "port": 80, "target": "example.com"},
            RRTypeEnum.DS: {
                "key_tag": 12345,
                "algorithm": DNSSECAlgorithmEnum.RSASHA256,
                "digest_type": 2,
                "digest": "ABCDEF",
            },
            RRTypeEnum.DNSKEY: {
                "flags": 256,
                "algorithm": DNSSECAlgorithmEnum.RSASHA256,
                "public_key": "ABCDEF",
            },
            RRTypeEnum.RRSIG: {
                "type_covered": "A",
                "algorithm": DNSSECAlgorithmEnum.RSASHA256,
                "labels": 2,
                "original_ttl": 3600,
                "signature_expiration": 4294967295,
                "signature_inception": 4294967295,
                "key_tag": 12345,
                "signer_name": "example.com",
                "signature": "ABCDEF",
            },
            RRTypeEnum.NSEC: {"next_domain_name": "next.example.com", "type_bit_maps": ["A"]},
            RRTypeEnum.SSHFP: {
                "algorithm": SSHFPAlgorithmEnum.RSA,
                "hash_type": SSHFPHashTypeEnum.SHA256,
                "fingerprint": "ABCDEF",
            },
            RRTypeEnum.TLSA: {
                "cert_usage": TLSACertUsageEnum.DANE_EE,
                "selector": TLSASelectorEnum.FULL_CERT,
                "matching_type": TLSAMatchingTypeEnum.SHA256,
                "cert_data": "ABCDEF",
            },
            RRTypeEnum.CAA: {"flags": 0, "tag": CAATagEnum.ISSUE, "value": '"test"'},
            RRTypeEnum.CERT: {
                "cert_type": 1,
                "key_tag": 12345,
                "algorithm": 8,
                "certificate": "ABCDEF",
            },
            RRTypeEnum.LOC: {
                "latitude": "51 30 12.123 N",
                "longitude": "0 7 39.456 W",
                "altitude": 10,
                "size": 100.0,
                "hprecision": 10.0,
                "vprecision": 2.0,
            },
            RRTypeEnum.NAPTR: {
                "order": 100,
                "preference": 10,
                "flags": "S",
                "services": "SIP+D2U",
                "regexp": '"test"',
                "replacement": "example.com",
            },
            RRTypeEnum.HINFO: {"cpu": "x86-64", "os": "Linux"},
            RRTypeEnum.RP: {"mbox_dname": "admin.example.com", "txt_dname": "contact.example.com"},
        }

        # Try to instantiate each record type
        for rr_type, data in test_data.items():
            record_class = RR_TYPE_REGISTRY[rr_type]
            try:
                record = record_class(name="example.com", **data)
                assert record.rr_type == rr_type
            except Exception as e:
                pytest.fail(f"Failed to instantiate {rr_type}: {e}")


@pytest.mark.parametrize(
    "record_class,kwargs,expected_syntax_contains",
    [
        # A record
        (
            ARecord,
            {"name": "example.com", "ttl": 3600, "address": "192.168.1.1"},
            ["example.com.", "3600", "IN", "A", "192.168.1.1"],
        ),
        # AAAA record
        (
            AAAARecord,
            {"name": "example.com", "ttl": 7200, "address": "2001:db8::1"},
            ["example.com.", "7200", "IN", "AAAA", "2001:db8::1"],
        ),
        # CNAME record
        (
            CNAMERecord,
            {"name": "www.example.com", "ttl": 3600, "canonical_name": "example.com"},
            ["www.example.com.", "3600", "IN", "CNAME", "example.com."],
        ),
        # MX record
        (
            MXRecord,
            {"name": "example.com", "ttl": 3600, "preference": 10, "exchange": "mail.example.com"},
            ["example.com.", "3600", "IN", "MX", "10", "mail.example.com."],
        ),
        # NS record
        (
            NSRecord,
            {"name": "example.com", "ttl": 86400, "nsdname": "ns1.example.com"},
            ["example.com.", "86400", "IN", "NS", "ns1.example.com."],
        ),
    ],
)
def test_record_syntax_generation(record_class, kwargs, expected_syntax_contains):
    """Parameterized test for record syntax generation."""
    record = record_class(**kwargs)
    syntax = record.model_bind_syntax()

    for expected in expected_syntax_contains:
        assert expected in syntax


class TestEdgeCases:
    """Tests for edge cases and error conditions."""

    def test_invalid_ip_address(self):
        """Test with invalid IP address."""
        with pytest.raises(ValueError):
            ARecord(name="example.com", address="not.an.ip")

    def test_invalid_domain_name(self):
        """Test with invalid domain name."""
        with pytest.raises(ValueError):
            NSRecord(name="invalid name", nsdname="ns1.example.com")

    def test_invalid_port_for_srv(self):
        """Test SRV with invalid port."""
        with pytest.raises(ValueError):
            SRVRecord(
                name="_service._tcp.example.com",
                priority=0,
                weight=0,
                port=70000,  # Too large
                target="example.com",
            )

    def test_txt_record_too_long(self):
        """Test TXT record with string too long."""
        long_string = '"' + "a" * 256 + '"'  # 256 chars
        with pytest.raises(ValueError, match="TXT string too long"):
            TXTRecord(name="example.com", text_data=[long_string])

    def test_mx_preference_out_of_range(self):
        """Test MX preference out of valid range."""
        with pytest.raises(ValueError):
            MXRecord(
                name="example.com",
                preference=70000,  # Too large
                exchange="mail.example.com",
            )

    def test_srv_weight_out_of_range(self):
        """Test SRV weight out of valid range."""
        with pytest.raises(ValueError):
            SRVRecord(
                name="_service._tcp.example.com",
                priority=0,
                weight=70000,  # Too large
                port=80,
                target="example.com",
            )

    def test_ds_key_tag_out_of_range(self):
        """Test DS key_tag out of valid range."""
        # This will fail during Pydantic validation
        with pytest.raises(ValueError):
            DSRecord(
                name="example.com",
                key_tag=70000,  # Too large for 16-bit
                algorithm=DNSSECAlgorithmEnum.RSASHA256,
                digest_type=2,
                digest="ABCDEF",
            )
