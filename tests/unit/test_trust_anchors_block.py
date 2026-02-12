from __future__ import annotations

import pytest

from bindantic import (
    AnchorTypeEnum,
    DSTrustAnchor,
    KeyTrustAnchor,
    TrustAnchorEntry,
    TrustAnchorsBlock,
)


class TestAnchorTypeEnum:
    """Tests for AnchorTypeEnum."""

    def test_enum_values(self):
        """Test enum values."""
        assert AnchorTypeEnum.STATIC_KEY == "static-key"
        assert AnchorTypeEnum.INITIAL_KEY == "initial-key"
        assert AnchorTypeEnum.STATIC_DS == "static-ds"
        assert AnchorTypeEnum.INITIAL_DS == "initial-ds"

    def test_enum_membership(self):
        """Test enum membership."""
        assert "static-key" in AnchorTypeEnum
        assert "initial-key" in AnchorTypeEnum
        assert "static-ds" in AnchorTypeEnum
        assert "initial-ds" in AnchorTypeEnum


class TestKeyTrustAnchor:
    """Tests for KeyTrustAnchor class."""

    def test_init_valid(self):
        """Test valid initialization."""
        anchor = KeyTrustAnchor(
            domain="example.com",
            anchor_type=AnchorTypeEnum.STATIC_KEY,
            flags=257,
            protocol=3,
            algorithm=8,
            key_data='"AwEAAcFcGsaxxdKkuJ..."',
            comment="Test key anchor",
        )
        assert anchor.domain == "example.com"
        assert anchor.anchor_type == AnchorTypeEnum.STATIC_KEY
        assert anchor.flags == 257
        assert anchor.protocol == 3
        assert anchor.algorithm == 8
        assert anchor.key_data == '"AwEAAcFcGsaxxdKkuJ..."'
        assert anchor.comment == "Test key anchor"

    def test_init_with_initial_key(self):
        """Test initialization with initial-key."""
        anchor = KeyTrustAnchor(
            domain="example.com",
            anchor_type=AnchorTypeEnum.INITIAL_KEY,
            flags=256,
            protocol=3,
            algorithm=13,
            key_data='"AwEAAaz/tAm8yTn4..."',
        )
        assert anchor.anchor_type == AnchorTypeEnum.INITIAL_KEY
        assert anchor.flags == 256
        assert anchor.algorithm == 13

    def test_flags_validation_valid(self):
        """Test valid flags validation."""

        anchor1 = KeyTrustAnchor(
            domain="example.com",
            anchor_type=AnchorTypeEnum.STATIC_KEY,
            flags=257,
            protocol=3,
            algorithm=8,
            key_data='"test"',
        )
        assert anchor1.flags == 257

        anchor2 = KeyTrustAnchor(
            domain="example.com",
            anchor_type=AnchorTypeEnum.STATIC_KEY,
            flags=256,
            protocol=3,
            algorithm=8,
            key_data='"test"',
        )
        assert anchor2.flags == 256

    def test_flags_validation_invalid(self):
        """Test invalid flags validation."""
        with pytest.raises(ValueError, match="Invalid DNSKEY flags"):
            KeyTrustAnchor(
                domain="example.com",
                anchor_type=AnchorTypeEnum.STATIC_KEY,
                flags=255,
                protocol=3,
                algorithm=8,
                key_data='"test"',
            )

        with pytest.raises(ValueError, match="Invalid DNSKEY flags"):
            KeyTrustAnchor(
                domain="example.com",
                anchor_type=AnchorTypeEnum.STATIC_KEY,
                flags=258,
                protocol=3,
                algorithm=8,
                key_data='"test"',
            )

    def test_protocol_validation_valid(self):
        """Test valid protocol validation."""
        anchor = KeyTrustAnchor(
            domain="example.com",
            anchor_type=AnchorTypeEnum.STATIC_KEY,
            flags=257,
            protocol=3,
            algorithm=8,
            key_data='"test"',
        )
        assert anchor.protocol == 3

    def test_protocol_validation_invalid(self):
        """Test invalid protocol validation."""
        with pytest.raises(ValueError, match="Invalid DNSKEY protocol"):
            KeyTrustAnchor(
                domain="example.com",
                anchor_type=AnchorTypeEnum.STATIC_KEY,
                flags=257,
                protocol=2,
                algorithm=8,
                key_data='"test"',
            )

    def test_algorithm_validation(self):
        """Test algorithm validation (warning for uncommon algorithms)."""

        anchor1 = KeyTrustAnchor(
            domain="example.com",
            anchor_type=AnchorTypeEnum.STATIC_KEY,
            flags=257,
            protocol=3,
            algorithm=8,
            key_data='"test"',
        )
        assert anchor1.algorithm == 8

        anchor2 = KeyTrustAnchor(
            domain="example.com",
            anchor_type=AnchorTypeEnum.STATIC_KEY,
            flags=257,
            protocol=3,
            algorithm=13,
            key_data='"test"',
        )
        assert anchor2.algorithm == 13

    def test_model_bind_syntax_static_key(self):
        """Test BIND syntax generation for static-key."""
        anchor = KeyTrustAnchor(
            domain="example.com",
            anchor_type=AnchorTypeEnum.STATIC_KEY,
            flags=257,
            protocol=3,
            algorithm=8,
            key_data='"AwEAAcFcGsaxxdKkuJ..."',
            comment="Example static key",
        )
        expected = 'example.com static-key 257 3 8 "AwEAAcFcGsaxxdKkuJ...";'
        result = anchor.model_bind_syntax()

        assert expected in result
        assert "# Example static key" in result

    def test_model_bind_syntax_initial_key(self):
        """Test BIND syntax generation for initial-key."""
        anchor = KeyTrustAnchor(
            domain="example.com",
            anchor_type=AnchorTypeEnum.INITIAL_KEY,
            flags=256,
            protocol=3,
            algorithm=13,
            key_data='"AwEAAaz/tAm8yTn4..."',
        )
        expected = 'example.com initial-key 256 3 13 "AwEAAaz/tAm8yTn4...";'
        assert anchor.model_bind_syntax().strip() == expected

    def test_model_bind_syntax_with_indent(self):
        """Test BIND syntax generation with indentation."""
        anchor = KeyTrustAnchor(
            domain="example.com",
            anchor_type=AnchorTypeEnum.STATIC_KEY,
            flags=257,
            protocol=3,
            algorithm=8,
            key_data='"test"',
        )
        result = anchor.model_bind_syntax(indent_level=2)
        expected = '        example.com static-key 257 3 8 "test";'
        assert result == expected

    def test_comparison_attr(self):
        """Test comparison attribute."""
        anchor = KeyTrustAnchor(
            domain="example.com",
            anchor_type=AnchorTypeEnum.STATIC_KEY,
            flags=257,
            protocol=3,
            algorithm=8,
            key_data='"test"',
        )
        assert anchor.comparison_attr == "static-key"

        anchor2 = KeyTrustAnchor(
            domain="example.com",
            anchor_type=AnchorTypeEnum.INITIAL_KEY,
            flags=256,
            protocol=3,
            algorithm=13,
            key_data='"test"',
        )
        assert anchor2.comparison_attr == "initial-key"

    def test_domain_validation(self):
        """Test domain validation."""

        anchor = KeyTrustAnchor(
            domain="example.com.",
            anchor_type=AnchorTypeEnum.STATIC_KEY,
            flags=257,
            protocol=3,
            algorithm=8,
            key_data='"test"',
        )
        assert anchor.domain == "example.com."

        anchor = KeyTrustAnchor(
            domain='"example.com"',
            anchor_type=AnchorTypeEnum.STATIC_KEY,
            flags=257,
            protocol=3,
            algorithm=8,
            key_data='"test"',
        )
        assert anchor.domain == "example.com"

    def test_key_data_validation(self):
        """Test key data validation."""

        anchor = KeyTrustAnchor(
            domain="example.com",
            anchor_type=AnchorTypeEnum.STATIC_KEY,
            flags=257,
            protocol=3,
            algorithm=8,
            key_data='"base64data"',
        )
        assert anchor.key_data == '"base64data"'

        anchor = KeyTrustAnchor(
            domain="example.com",
            anchor_type=AnchorTypeEnum.STATIC_KEY,
            flags=257,
            protocol=3,
            algorithm=8,
            key_data="base64data",
        )

        assert anchor.key_data == '"base64data"'

    def test_pydantic_validation(self):
        """Test Pydantic validation and type conversion."""

        anchor = KeyTrustAnchor(
            domain="example.com",
            anchor_type="static-key",
            flags="257",
            protocol="3",
            algorithm="8",
            key_data="test",
        )
        assert anchor.flags == 257
        assert anchor.protocol == 3
        assert anchor.algorithm == 8
        assert anchor.key_data == '"test"'

        anchor_dict = {
            "domain": "example.com",
            "anchor_type": "initial-key",
            "flags": 256,
            "protocol": 3,
            "algorithm": 13,
            "key_data": "AwEAA...",
            "comment": "Test anchor",
        }
        anchor = KeyTrustAnchor.model_validate(anchor_dict)
        assert anchor.anchor_type == AnchorTypeEnum.INITIAL_KEY
        assert anchor.comment == "Test anchor"

    def test_sorting(self):
        """Test sorting of key trust anchors."""
        anchor1 = KeyTrustAnchor(
            domain="a.example.com",
            anchor_type=AnchorTypeEnum.STATIC_KEY,
            flags=257,
            protocol=3,
            algorithm=8,
            key_data='"test1"',
        )
        anchor2 = KeyTrustAnchor(
            domain="b.example.com",
            anchor_type=AnchorTypeEnum.INITIAL_KEY,
            flags=256,
            protocol=3,
            algorithm=13,
            key_data='"test2"',
        )
        anchor3 = KeyTrustAnchor(
            domain="c.example.com",
            anchor_type=AnchorTypeEnum.STATIC_KEY,
            flags=257,
            protocol=3,
            algorithm=8,
            key_data='"test3"',
        )

        anchors = [anchor2, anchor1, anchor3]
        sorted_anchors = sorted(anchors, key=lambda a: a.comparison_attr)

        assert sorted_anchors[0].anchor_type == AnchorTypeEnum.INITIAL_KEY
        assert sorted_anchors[1].anchor_type == AnchorTypeEnum.STATIC_KEY
        assert sorted_anchors[2].anchor_type == AnchorTypeEnum.STATIC_KEY


class TestDSTrustAnchor:
    """Tests for DSTrustAnchor class."""

    def test_init_valid(self):
        """Test valid initialization."""
        anchor = DSTrustAnchor(
            domain="example.org",
            anchor_type=AnchorTypeEnum.STATIC_DS,
            key_tag=12345,
            algorithm=8,
            digest_type=2,
            digest='"2BB183AF5F225"',
            comment="Test DS anchor",
        )
        assert anchor.domain == "example.org"
        assert anchor.anchor_type == AnchorTypeEnum.STATIC_DS
        assert anchor.key_tag == 12345
        assert anchor.algorithm == 8
        assert anchor.digest_type == 2
        assert anchor.digest == '"2BB183AF5F225"'
        assert anchor.comment == "Test DS anchor"

    def test_init_with_initial_ds(self):
        """Test initialization with initial-ds."""
        anchor = DSTrustAnchor(
            domain="dnssec.test",
            anchor_type=AnchorTypeEnum.INITIAL_DS,
            key_tag=54321,
            algorithm=13,
            digest_type=3,
            digest='"4CDB3E8D0A0F"',
        )
        assert anchor.anchor_type == AnchorTypeEnum.INITIAL_DS
        assert anchor.key_tag == 54321
        assert anchor.algorithm == 13
        assert anchor.digest_type == 3

    def test_key_tag_validation(self):
        """Test key tag validation."""

        anchor1 = DSTrustAnchor(
            domain="example.com",
            anchor_type=AnchorTypeEnum.STATIC_DS,
            key_tag=0,
            algorithm=8,
            digest_type=2,
            digest='"ABCDEF"',
        )
        assert anchor1.key_tag == 0

        anchor2 = DSTrustAnchor(
            domain="example.com",
            anchor_type=AnchorTypeEnum.STATIC_DS,
            key_tag=65535,
            algorithm=8,
            digest_type=2,
            digest='"ABCDEF"',
        )
        assert anchor2.key_tag == 65535

        with pytest.raises(ValueError):
            DSTrustAnchor(
                domain="example.com",
                anchor_type=AnchorTypeEnum.STATIC_DS,
                key_tag=-1,
                algorithm=8,
                digest_type=2,
                digest='"ABCDEF"',
            )

        with pytest.raises(ValueError):
            DSTrustAnchor(
                domain="example.com",
                anchor_type=AnchorTypeEnum.STATIC_DS,
                key_tag=65536,
                algorithm=8,
                digest_type=2,
                digest='"ABCDEF"',
            )

    def test_algorithm_validation(self):
        """Test algorithm validation (prints warning for uncommon algorithms)."""

        anchor = DSTrustAnchor(
            domain="example.com",
            anchor_type=AnchorTypeEnum.STATIC_DS,
            key_tag=12345,
            algorithm=99,
            digest_type=2,
            digest='"ABCDEF"',
        )
        assert anchor.algorithm == 99

    def test_digest_type_validation_valid(self):
        """Test valid digest type validation."""

        anchor1 = DSTrustAnchor(
            domain="example.com",
            anchor_type=AnchorTypeEnum.STATIC_DS,
            key_tag=12345,
            algorithm=8,
            digest_type=1,
            digest='"ABCDEF"',
        )
        assert anchor1.digest_type == 1

        anchor2 = DSTrustAnchor(
            domain="example.com",
            anchor_type=AnchorTypeEnum.STATIC_DS,
            key_tag=12345,
            algorithm=8,
            digest_type=2,
            digest='"ABCDEF"',
        )
        assert anchor2.digest_type == 2

        anchor3 = DSTrustAnchor(
            domain="example.com",
            anchor_type=AnchorTypeEnum.STATIC_DS,
            key_tag=12345,
            algorithm=8,
            digest_type=3,
            digest='"ABCDEF"',
        )
        assert anchor3.digest_type == 3

        anchor4 = DSTrustAnchor(
            domain="example.com",
            anchor_type=AnchorTypeEnum.STATIC_DS,
            key_tag=12345,
            algorithm=8,
            digest_type=4,
            digest='"ABCDEF"',
        )
        assert anchor4.digest_type == 4

    def test_digest_type_validation_invalid(self):
        """Test invalid digest type validation."""
        with pytest.raises(ValueError, match="Invalid digest type"):
            DSTrustAnchor(
                domain="example.com",
                anchor_type=AnchorTypeEnum.STATIC_DS,
                key_tag=12345,
                algorithm=8,
                digest_type=0,
                digest='"ABCDEF"',
            )

        with pytest.raises(ValueError, match="Invalid digest type"):
            DSTrustAnchor(
                domain="example.com",
                anchor_type=AnchorTypeEnum.STATIC_DS,
                key_tag=12345,
                algorithm=8,
                digest_type=5,
                digest='"ABCDEF"',
            )

    def test_digest_validation_valid(self):
        """Test valid digest validation."""

        anchors = [
            DSTrustAnchor(
                domain="example.com",
                anchor_type=AnchorTypeEnum.STATIC_DS,
                key_tag=12345,
                algorithm=8,
                digest_type=2,
                digest='"ABCDEF123456"',
            ),
            DSTrustAnchor(
                domain="example.com",
                anchor_type=AnchorTypeEnum.STATIC_DS,
                key_tag=12345,
                algorithm=8,
                digest_type=2,
                digest="'abcdef'",
            ),
            DSTrustAnchor(
                domain="example.com",
                anchor_type=AnchorTypeEnum.STATIC_DS,
                key_tag=12345,
                algorithm=8,
                digest_type=2,
                digest="abcdef",
            ),
        ]
        for anchor in anchors:
            assert anchor.digest

    def test_digest_validation_invalid(self):
        """Test invalid digest validation."""
        with pytest.raises(ValueError, match="Invalid hexadecimal digest"):
            DSTrustAnchor(
                domain="example.com",
                anchor_type=AnchorTypeEnum.STATIC_DS,
                key_tag=12345,
                algorithm=8,
                digest_type=2,
                digest='"not-hex"',
            )

        with pytest.raises(ValueError, match="Invalid hexadecimal digest"):
            DSTrustAnchor(
                domain="example.com",
                anchor_type=AnchorTypeEnum.STATIC_DS,
                key_tag=12345,
                algorithm=8,
                digest_type=2,
                digest='"123XYZ"',
            )

    def test_model_bind_syntax_static_ds(self):
        """Test BIND syntax generation for static-ds."""
        anchor = DSTrustAnchor(
            domain="example.org",
            anchor_type=AnchorTypeEnum.STATIC_DS,
            key_tag=12345,
            algorithm=8,
            digest_type=2,
            digest='"2BB183AF5F225"',
            comment="Example DS record",
        )
        expected = 'example.org static-ds 12345 8 2 "2BB183AF5F225";'
        result = anchor.model_bind_syntax()

        assert expected in result
        assert "# Example DS record" in result

    def test_model_bind_syntax_initial_ds(self):
        """Test BIND syntax generation for initial-ds."""
        anchor = DSTrustAnchor(
            domain="dnssec.test",
            anchor_type=AnchorTypeEnum.INITIAL_DS,
            key_tag=54321,
            algorithm=13,
            digest_type=3,
            digest='"4CDB3E8D0A0F"',
        )
        expected = 'dnssec.test initial-ds 54321 13 3 "4CDB3E8D0A0F";'
        assert anchor.model_bind_syntax().strip() == expected

    def test_model_bind_syntax_with_indent(self):
        """Test BIND syntax generation with indentation."""
        anchor = DSTrustAnchor(
            domain="example.com",
            anchor_type=AnchorTypeEnum.STATIC_DS,
            key_tag=12345,
            algorithm=8,
            digest_type=2,
            digest='"ABCDEF"',
        )
        result = anchor.model_bind_syntax(indent_level=2)
        expected = '        example.com static-ds 12345 8 2 "ABCDEF";'
        assert result == expected

    def test_comparison_attr(self):
        """Test comparison attribute."""
        anchor = DSTrustAnchor(
            domain="example.com",
            anchor_type=AnchorTypeEnum.STATIC_DS,
            key_tag=12345,
            algorithm=8,
            digest_type=2,
            digest='"ABCDEF"',
        )
        assert anchor.comparison_attr == "static-ds"

        anchor2 = DSTrustAnchor(
            domain="example.com",
            anchor_type=AnchorTypeEnum.INITIAL_DS,
            key_tag=12345,
            algorithm=8,
            digest_type=2,
            digest='"ABCDEF"',
        )
        assert anchor2.comparison_attr == "initial-ds"

    def test_pydantic_validation(self):
        """Test Pydantic validation and type conversion."""

        anchor = DSTrustAnchor(
            domain="example.com",
            anchor_type="static-ds",
            key_tag="12345",
            algorithm="8",
            digest_type="2",
            digest="ABCDEF",
        )
        assert anchor.key_tag == 12345
        assert anchor.algorithm == 8
        assert anchor.digest_type == 2
        assert anchor.digest == '"ABCDEF"'

        anchor_dict = {
            "domain": "example.com",
            "anchor_type": "initial-ds",
            "key_tag": 54321,
            "algorithm": 13,
            "digest_type": 3,
            "digest": "4CDB3E8D0A0F",
            "comment": "Test DS anchor",
        }
        anchor = DSTrustAnchor.model_validate(anchor_dict)
        assert anchor.anchor_type == AnchorTypeEnum.INITIAL_DS
        assert anchor.comment == "Test DS anchor"


class TestTrustAnchorsBlock:
    """Tests for TrustAnchorsBlock class."""

    def test_init_empty(self):
        """Test initialization with empty anchors list."""
        block = TrustAnchorsBlock(anchors=[])
        assert block.anchors == []

    def test_init_with_key_anchors(self):
        """Test initialization with key trust anchors."""
        anchors = [
            KeyTrustAnchor(
                domain="example.com",
                anchor_type=AnchorTypeEnum.STATIC_KEY,
                flags=257,
                protocol=3,
                algorithm=8,
                key_data='"AwEAAcFcGsaxxdKkuJ..."',
            ),
            KeyTrustAnchor(
                domain="secure.example.com",
                anchor_type=AnchorTypeEnum.INITIAL_KEY,
                flags=257,
                protocol=3,
                algorithm=15,
                key_data='"AwEAAcVNPM7Rf..."',
            ),
        ]
        block = TrustAnchorsBlock(anchors=anchors)
        assert len(block.anchors) == 2
        assert all(isinstance(a, KeyTrustAnchor) for a in block.anchors)

    def test_init_with_ds_anchors(self):
        """Test initialization with DS trust anchors."""
        anchors = [
            DSTrustAnchor(
                domain="example.org",
                anchor_type=AnchorTypeEnum.STATIC_DS,
                key_tag=12345,
                algorithm=8,
                digest_type=2,
                digest='"2BB183AF5F225"',
            ),
            DSTrustAnchor(
                domain="secure.org",
                anchor_type=AnchorTypeEnum.INITIAL_DS,
                key_tag=65535,
                algorithm=14,
                digest_type=4,
                digest='"ABCDEF123456"',
            ),
        ]
        block = TrustAnchorsBlock(anchors=anchors)
        assert len(block.anchors) == 2
        assert all(isinstance(a, DSTrustAnchor) for a in block.anchors)

    def test_init_mixed_anchors(self):
        """Test initialization with mixed key and DS anchors."""
        anchors: list[TrustAnchorEntry] = [
            KeyTrustAnchor(
                domain="example.com",
                anchor_type=AnchorTypeEnum.STATIC_KEY,
                flags=257,
                protocol=3,
                algorithm=8,
                key_data='"AwEAAcFcGsaxxdKkuJ..."',
            ),
            DSTrustAnchor(
                domain="example.org",
                anchor_type=AnchorTypeEnum.STATIC_DS,
                key_tag=12345,
                algorithm=8,
                digest_type=2,
                digest='"2BB183AF5F225"',
            ),
        ]
        block = TrustAnchorsBlock(anchors=anchors)
        assert len(block.anchors) == 2
        assert isinstance(block.anchors[0], KeyTrustAnchor)
        assert isinstance(block.anchors[1], DSTrustAnchor)

    def test_validate_anchor_uniqueness_valid(self):
        """Test validation of anchor uniqueness (valid cases)."""

        anchors = [
            KeyTrustAnchor(
                domain="example.com",
                anchor_type=AnchorTypeEnum.STATIC_KEY,
                flags=257,
                protocol=3,
                algorithm=8,
                key_data='"test1"',
            ),
            KeyTrustAnchor(
                domain="example.org",
                anchor_type=AnchorTypeEnum.STATIC_KEY,
                flags=257,
                protocol=3,
                algorithm=8,
                key_data='"test2"',
            ),
        ]
        block = TrustAnchorsBlock(anchors=anchors)
        assert len(block.anchors) == 2

        anchors = [
            KeyTrustAnchor(
                domain="example.com",
                anchor_type=AnchorTypeEnum.STATIC_KEY,
                flags=257,
                protocol=3,
                algorithm=8,
                key_data='"test1"',
            ),
            DSTrustAnchor(
                domain="example.com",
                anchor_type=AnchorTypeEnum.STATIC_DS,
                key_tag=12345,
                algorithm=8,
                digest_type=2,
                digest='"ABCDEF"',
            ),
        ]
        block = TrustAnchorsBlock(anchors=anchors)
        assert len(block.anchors) == 2

        anchors = [
            KeyTrustAnchor(
                domain="example.com",
                anchor_type=AnchorTypeEnum.INITIAL_KEY,
                flags=256,
                protocol=3,
                algorithm=13,
                key_data='"test1"',
            ),
            DSTrustAnchor(
                domain="example.com",
                anchor_type=AnchorTypeEnum.INITIAL_DS,
                key_tag=12345,
                algorithm=8,
                digest_type=2,
                digest='"ABCDEF"',
            ),
        ]
        block = TrustAnchorsBlock(anchors=anchors)
        assert len(block.anchors) == 2

    def test_validate_anchor_uniqueness_invalid(self):
        """Test validation of anchor uniqueness (invalid cases)."""

        anchors = [
            KeyTrustAnchor(
                domain="example.com",
                anchor_type=AnchorTypeEnum.STATIC_KEY,
                flags=257,
                protocol=3,
                algorithm=8,
                key_data='"test1"',
            ),
            KeyTrustAnchor(
                domain="example.com",
                anchor_type=AnchorTypeEnum.INITIAL_KEY,
                flags=256,
                protocol=3,
                algorithm=13,
                key_data='"test2"',
            ),
        ]
        with pytest.raises(ValueError, match="Cannot mix static and initial trust anchors"):
            TrustAnchorsBlock(anchors=anchors)

        anchors = [
            KeyTrustAnchor(
                domain="example.com",
                anchor_type=AnchorTypeEnum.STATIC_KEY,
                flags=257,
                protocol=3,
                algorithm=8,
                key_data='"test1"',
            ),
            DSTrustAnchor(
                domain="example.com",
                anchor_type=AnchorTypeEnum.INITIAL_DS,
                key_tag=12345,
                algorithm=8,
                digest_type=2,
                digest='"ABCDEF"',
            ),
        ]
        with pytest.raises(ValueError, match="Cannot mix static and initial trust anchors"):
            TrustAnchorsBlock(anchors=anchors)

    def test_model_bind_syntax_empty(self):
        """Test BIND syntax generation with empty anchors."""
        block = TrustAnchorsBlock(anchors=[])
        expected = "trust-anchors {\n};"
        assert block.model_bind_syntax().strip() == expected

    def test_model_bind_syntax_single_anchor(self):
        """Test BIND syntax generation with single anchor."""
        anchor = KeyTrustAnchor(
            domain="example.com",
            anchor_type=AnchorTypeEnum.STATIC_KEY,
            flags=257,
            protocol=3,
            algorithm=8,
            key_data='"AwEAAcFcGsaxxdKkuJ..."',
        )
        block = TrustAnchorsBlock(anchors=[anchor], comment="Trust anchors block")
        result = block.model_bind_syntax()

        assert "# Trust anchors block" in result
        assert "trust-anchors {" in result
        assert 'example.com static-key 257 3 8 "AwEAAcFcGsaxxdKkuJ...";' in result
        assert "};" in result

    def test_model_bind_syntax_multiple_anchors(self):
        """Test BIND syntax generation with multiple anchors."""
        anchors = [
            DSTrustAnchor(
                domain="dnssec.test",
                anchor_type=AnchorTypeEnum.INITIAL_DS,
                key_tag=54321,
                algorithm=13,
                digest_type=3,
                digest='"4CDB3E8D0A0F"',
            ),
            KeyTrustAnchor(
                domain="root-servers.net",
                anchor_type=AnchorTypeEnum.INITIAL_KEY,
                flags=256,
                protocol=3,
                algorithm=13,
                key_data='"AwEAAaz/tAm8yTn4..."',
            ),
            DSTrustAnchor(
                domain="secure.org",
                anchor_type=AnchorTypeEnum.INITIAL_DS,
                key_tag=65535,
                algorithm=14,
                digest_type=4,
                digest='"ABCDEF123456"',
            ),
            KeyTrustAnchor(
                domain="example.com",
                anchor_type=AnchorTypeEnum.STATIC_KEY,
                flags=257,
                protocol=3,
                algorithm=8,
                key_data='"AwEAAcFcGsaxxdKkuJ..."',
            ),
        ]
        block = TrustAnchorsBlock(anchors=anchors)
        result = block.model_bind_syntax()

        lines = result.split("\n")

        anchor_lines = [
            line.strip()
            for line in lines
            if line.strip() and not line.strip().startswith(("#", "trust-anchors", "}"))
        ]

        assert len(anchor_lines) == 4

        assert "initial-ds" in anchor_lines[0]
        assert "initial-ds" in anchor_lines[1]
        assert "initial-key" in anchor_lines[2]
        assert "static-key" in anchor_lines[3]

    def test_model_bind_syntax_with_indent(self):
        """Test BIND syntax generation with indentation."""
        anchor = KeyTrustAnchor(
            domain="example.com",
            anchor_type=AnchorTypeEnum.STATIC_KEY,
            flags=257,
            protocol=3,
            algorithm=8,
            key_data='"test"',
        )
        block = TrustAnchorsBlock(anchors=[anchor])
        result = block.model_bind_syntax(indent_level=1)

        expected_lines = [
            "    trust-anchors {",
            '        example.com static-key 257 3 8 "test";',
            "    };",
        ]
        assert result == "\n".join(expected_lines)

    def test_format_anchors_method(self):
        """Test the _format_anchors method."""
        anchors = [
            KeyTrustAnchor(
                domain="example.com",
                anchor_type=AnchorTypeEnum.STATIC_KEY,
                flags=257,
                protocol=3,
                algorithm=8,
                key_data='"test1"',
            ),
            KeyTrustAnchor(
                domain="example.org",
                anchor_type=AnchorTypeEnum.INITIAL_KEY,
                flags=256,
                protocol=3,
                algorithm=13,
                key_data='"test2"',
            ),
        ]
        block = TrustAnchorsBlock(anchors=anchors)

        formatted = block._format_anchors(anchors, indent_level=0)
        lines = formatted.split("\n")
        assert len(lines) == 2

        assert "initial-key" in lines[0]
        assert "static-key" in lines[1]

    def test_pydantic_validation(self):
        """Test Pydantic validation and type conversion."""

        block_dict = {
            "anchors": [
                {
                    "domain": "example.com",
                    "anchor_type": "static-key",
                    "flags": 257,
                    "protocol": 3,
                    "algorithm": 8,
                    "key_data": "AwEAA...",
                },
                {
                    "domain": "example.org",
                    "anchor_type": "static-ds",
                    "key_tag": 12345,
                    "algorithm": 8,
                    "digest_type": 2,
                    "digest": "ABCDEF",
                },
            ],
            "comment": "Test trust anchors",
        }
        block = TrustAnchorsBlock.model_validate(block_dict)
        assert len(block.anchors) == 2
        assert block.comment == "Test trust anchors"
        assert isinstance(block.anchors[0], KeyTrustAnchor)
        assert isinstance(block.anchors[1], DSTrustAnchor)

    def test_real_world_examples(self):
        """Test real-world examples from manual initialization."""

        key_anchor = KeyTrustAnchor(
            domain="example.com",
            anchor_type=AnchorTypeEnum.STATIC_KEY,
            flags=257,
            protocol=3,
            algorithm=8,
            key_data='"AwEAAcFcGsaxxdKkuJ..."',
        )
        ds_anchor = DSTrustAnchor(
            domain="example.org",
            anchor_type=AnchorTypeEnum.STATIC_DS,
            key_tag=12345,
            algorithm=8,
            digest_type=2,
            digest='"2BB183AF5F225"',
        )
        block = TrustAnchorsBlock(anchors=[key_anchor, ds_anchor])
        result = block.model_bind_syntax()

        assert "trust-anchors {" in result
        assert 'example.com static-key 257 3 8 "AwEAAcFcGsaxxdKkuJ...";' in result
        assert 'example.org static-ds 12345 8 2 "2BB183AF5F225";' in result

        anchors = [
            KeyTrustAnchor(
                domain="secure.example.com",
                anchor_type=AnchorTypeEnum.INITIAL_KEY,
                flags=257,
                protocol=3,
                algorithm=15,
                key_data='"AwEAAcVNPM7Rf..."',
            ),
            KeyTrustAnchor(
                domain="example.com",
                anchor_type=AnchorTypeEnum.STATIC_KEY,
                flags=257,
                protocol=3,
                algorithm=8,
                key_data='"AwEAAcFcGsaxxdKkuJ..."',
            ),
        ]
        block = TrustAnchorsBlock(anchors=anchors)
        result = block.model_bind_syntax()
        lines = result.split("\n")

        anchor_lines = [line for line in lines if "static-key" in line or "initial-key" in line]
        assert "initial-key" in anchor_lines[0]
        assert "static-key" in anchor_lines[1]
