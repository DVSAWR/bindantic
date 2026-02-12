from __future__ import annotations

import pytest
from pydantic import ValidationError

from bindantic import KeyBlock, KeyStoreBlock


class TestKeyBlock:
    """Tests for KeyBlock class."""

    def test_init_with_basic_parameters(self):
        """Test basic initialization."""
        key = KeyBlock(name="rndc-key", algorithm="hmac-sha256", secret="aGVsbG8td29ybGQ=")

        assert key.name == '"rndc-key"'
        assert key.algorithm == "hmac-sha256"
        assert key.secret == '"aGVsbG8td29ybGQ="'

    def test_algorithm_validation_valid(self):
        """Test valid algorithm validation."""
        valid_algorithms = ["hmac-sha256", "hmac-sha512", "hmac-sha1-80"]

        for algorithm in valid_algorithms:
            key = KeyBlock(name="test-key", algorithm=algorithm, secret="dGVzdA==")
            assert key.algorithm == algorithm

    def test_algorithm_validation_invalid(self):
        """Test invalid algorithm validation."""
        with pytest.raises(ValidationError, match="Invalid algorithm"):
            KeyBlock(name="test-key", algorithm="invalid", secret="dGVzdA==")

    def test_model_bind_syntax(self):
        """Test BIND syntax generation."""
        key = KeyBlock(name="test-key", algorithm="hmac-sha256", secret="dGVzdA==")

        expected = """key "test-key" {
    algorithm hmac-sha256;
    secret "dGVzdA==";
};"""
        assert key.model_bind_syntax() == expected

    def test_model_bind_syntax_with_comment(self):
        """Test BIND syntax generation with comment."""
        key = KeyBlock(
            name="commented-key",
            algorithm="hmac-sha512",
            secret="YXNkZmFzZGZhc2Rm",
            comment="Secure key",
        )

        expected = """# Secure key
key "commented-key" {
    algorithm hmac-sha512;
    secret "YXNkZmFzZGZhc2Rm";
};"""
        assert key.model_bind_syntax() == expected

    def test_comparison_operators(self):
        """Test comparison operators."""
        key1 = KeyBlock(name="aaa", algorithm="hmac-sha256", secret="dGVzdA==")
        key2 = KeyBlock(name="bbb", algorithm="hmac-sha256", secret="dGVzdA==")

        assert key1 < key2
        assert key2 > key1
        assert key1 <= key1  # noqa: PLR0124
        assert key2 >= key2  # noqa: PLR0124

    def test_model_validate(self):
        """Test validation via model_validate."""
        data = {"name": "validated-key", "algorithm": "hmac-sha384", "secret": "c2VjcmV0LWtleQ=="}

        key = KeyBlock.model_validate(data)
        assert key.name == '"validated-key"'
        assert key.algorithm == "hmac-sha384"
        assert key.secret == '"c2VjcmV0LWtleQ=="'

    def test_name_field_validation(self):
        """Test name field validation."""

        valid_names = ["rndc-key", "tsig_key", "KEY123"]

        for name in valid_names:
            key = KeyBlock(name=name, algorithm="hmac-sha256", secret="dGVzdA==")
            assert f'"{name}"' in key.name

        with pytest.raises(ValidationError):
            KeyBlock(name="", algorithm="hmac-sha256", secret="dGVzdA==")

    def test_real_world_examples(self):
        """Test real-world examples."""

        rndc_key = KeyBlock(
            name="rndc-key",
            algorithm="hmac-sha256",
            secret="aGVsbG8td29ybGQ=",
            comment="RNDC control channel",
        )

        assert rndc_key.name == '"rndc-key"'
        assert rndc_key.algorithm == "hmac-sha256"

        tsig_key = KeyBlock.model_validate_json("""{
            "name": "tsig-key",
            "algorithm": "hmac-sha512",
            "secret": "dHNpZy1zZWNyZXQ="
        }""")

        assert tsig_key.name == '"tsig-key"'
        assert tsig_key.algorithm == "hmac-sha512"

    @pytest.mark.parametrize(
        "name,algorithm,secret,expected_output",
        [
            (
                "basic",
                "hmac-sha256",
                "dGVzdA==",
                """key "basic" {
    algorithm hmac-sha256;
    secret "dGVzdA==";
};""",
            ),
            (
                "truncated",
                "hmac-sha1-80",
                "c2hvcnQ=",
                """key "truncated" {
    algorithm hmac-sha1-80;
    secret "c2hvcnQ=";
};""",
            ),
        ],
    )
    def test_parametrized_bind_syntax(self, name, algorithm, secret, expected_output):
        """Parametrized test for BIND syntax generation."""
        key = KeyBlock(name=name, algorithm=algorithm, secret=secret)
        assert key.model_bind_syntax() == expected_output


class TestKeyStoreBlock:
    """Tests for KeyStoreBlock class."""

    def test_init_with_directory(self):
        """Test initialization with directory."""
        keystore = KeyStoreBlock(name="local-keys", directory="/etc/bind/keys")

        assert keystore.name == "local-keys"
        assert keystore.directory == "/etc/bind/keys"
        assert keystore.pkcs11_uri is None

    def test_init_with_pkcs11_uri(self):
        """Test initialization with PKCS#11 URI."""
        keystore = KeyStoreBlock(name="hsm-keys", pkcs11_uri='"pkcs11:token=bind-token"')

        assert keystore.name == "hsm-keys"
        assert keystore.directory is None
        assert keystore.pkcs11_uri == '"pkcs11:token=bind-token"'

    def test_model_bind_syntax_directory(self):
        """Test BIND syntax generation with directory."""
        keystore = KeyStoreBlock(name="local-store", directory="/etc/bind/keys")

        expected = """key-store local-store {
    directory /etc/bind/keys;
};"""
        assert keystore.model_bind_syntax() == expected

    def test_model_bind_syntax_pkcs11_uri(self):
        """Test BIND syntax generation with PKCS#11 URI."""
        keystore = KeyStoreBlock(name="hsm-store", pkcs11_uri='"pkcs11:token=secure"')

        expected = """key-store hsm-store {
    pkcs11-uri "pkcs11:token=secure";
};"""
        assert keystore.model_bind_syntax() == expected

    def test_model_bind_syntax_with_comment(self):
        """Test BIND syntax generation with comment."""
        keystore = KeyStoreBlock(
            name="secure-store", directory="/secure/keys", comment="Secure key storage"
        )

        expected = """# Secure key storage
key-store secure-store {
    directory /secure/keys;
};"""
        assert keystore.model_bind_syntax() == expected

    def test_comparison_operators(self):
        """Test comparison operators."""
        store1 = KeyStoreBlock(name="aaa", directory="/keys")
        store2 = KeyStoreBlock(name="bbb", directory="/keys")

        assert store1 < store2
        assert store2 > store1
        assert store1 <= store1  # noqa: PLR0124
        assert store2 >= store2  # noqa: PLR0124

    def test_model_validate(self):
        """Test validation via model_validate."""
        data = {"name": "validated-store", "directory": "/valid/keys"}

        keystore = KeyStoreBlock.model_validate(data)
        assert keystore.name == "validated-store"
        assert keystore.directory == "/valid/keys"

    def test_name_field_validation(self):
        """Test name field validation."""

        valid_names = ["local-keys", "hsm_store", "key-store-123"]

        for name in valid_names:
            keystore = KeyStoreBlock(name=name, directory="/keys")
            assert keystore.name == name

        with pytest.raises(ValidationError):
            KeyStoreBlock(name="", directory="/keys")

    def test_real_world_examples(self):
        """Test real-world examples."""

        local_store = KeyStoreBlock(
            name="local-dnssec", directory="/etc/bind/keys", comment="Local DNSSEC keys"
        )

        assert local_store.name == "local-dnssec"
        assert local_store.directory == "/etc/bind/keys"

        hsm_store = KeyStoreBlock.model_validate_json("""{
            "name": "hsm-dnssec",
            "pkcs11_uri": "pkcs11:token=secure-hsm"
        }""")

        assert hsm_store.name == "hsm-dnssec"
        assert hsm_store.pkcs11_uri == '"pkcs11:token=secure-hsm"'

    @pytest.mark.parametrize(
        "name,directory,pkcs11_uri,expected_output",
        [
            (
                "dir-only",
                "/keys",
                None,
                """key-store dir-only {
    directory /keys;
};""",
            ),
            (
                "uri-only",
                None,
                '"pkcs11:token=test"',
                """key-store uri-only {
    pkcs11-uri "pkcs11:token=test";
};""",
            ),
            (
                "empty",
                None,
                None,
                """key-store empty {
};""",
            ),
        ],
    )
    def test_parametrized_bind_syntax(self, name, directory, pkcs11_uri, expected_output):
        """Parametrized test for BIND syntax generation."""
        keystore = KeyStoreBlock(name=name, directory=directory, pkcs11_uri=pkcs11_uri)
        assert keystore.model_bind_syntax() == expected_output
