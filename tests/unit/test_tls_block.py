from __future__ import annotations

import pytest
from pydantic import ValidationError

from bindantic import TlsBlock


class TestTlsBlock:
    """Tests for TlsBlock class."""

    def test_init_with_builtin_ephemeral(self):
        """Test initialization with built-in ephemeral configuration."""
        tls = TlsBlock(name="ephemeral")
        assert tls.name == "ephemeral"
        assert tls.key_file is None
        assert tls.cert_file is None
        assert tls.ca_file is None
        assert tls.dhparam_file is None
        assert tls.ciphers is None
        assert tls.protocols is None
        assert tls.prefer_server_ciphers is None
        assert tls.session_tickets is None
        assert tls.remote_hostname is None

    def test_init_with_builtin_none(self):
        """Test initialization with built-in none configuration."""
        tls = TlsBlock(name="none")
        assert tls.name == "none"
        assert tls.key_file is None
        assert tls.cert_file is None
        assert tls.ca_file is None
        assert tls.dhparam_file is None
        assert tls.ciphers is None
        assert tls.protocols is None
        assert tls.prefer_server_ciphers is None
        assert tls.session_tickets is None
        assert tls.remote_hostname is None

    def test_init_with_minimal_custom_config(self):
        """Test initialization with minimal custom configuration."""
        tls = TlsBlock(
            name="minimal-tls",
            key_file="/etc/bind/tls/server.key",
            cert_file="/etc/bind/tls/server.crt",
        )
        assert tls.name == "minimal-tls"
        assert tls.key_file == '"' + "/etc/bind/tls/server.key" + '"'
        assert tls.cert_file == '"' + "/etc/bind/tls/server.crt" + '"'
        assert tls.ca_file is None
        assert tls.dhparam_file is None
        assert tls.ciphers is None
        assert tls.protocols is None
        assert tls.prefer_server_ciphers is None
        assert tls.session_tickets is None
        assert tls.remote_hostname is None

    def test_init_with_full_custom_config(self):
        """Test initialization with full custom configuration."""
        tls = TlsBlock(
            name="secure-tls",
            key_file="/etc/bind/tls/private.key",
            cert_file="/etc/bind/tls/certificate.crt",
            ca_file="/etc/bind/tls/ca-bundle.crt",
            dhparam_file="/etc/bind/tls/dhparam.pem",
            ciphers="ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256",
            protocols=["TLSv1.2", "TLSv1.3"],
            prefer_server_ciphers="yes",
            session_tickets="no",
            remote_hostname="dns.example.com",
            comment="Secure TLS configuration",
        )
        assert tls.name == "secure-tls"
        assert tls.key_file == '"' + "/etc/bind/tls/private.key" + '"'
        assert tls.cert_file == '"' + "/etc/bind/tls/certificate.crt" + '"'
        assert tls.ca_file == '"' + "/etc/bind/tls/ca-bundle.crt" + '"'
        assert tls.dhparam_file == '"' + "/etc/bind/tls/dhparam.pem" + '"'
        assert tls.ciphers == "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256"
        assert tls.protocols == ["TLSv1.2", "TLSv1.3"]
        assert tls.prefer_server_ciphers == "yes"
        assert tls.session_tickets == "no"
        assert tls.remote_hostname == '"' + "dns.example.com" + '"'
        assert tls.comment == "Secure TLS configuration"

    def test_builtin_config_with_additional_params_fails(self):
        """Test that built-in configs cannot have additional parameters."""
        with pytest.raises(ValidationError) as exc_info:
            TlsBlock(
                name="ephemeral",
                key_file="/etc/bind/tls/key.pem",
                cert_file="/etc/bind/tls/cert.pem",
            )
        assert "Built-in TLS configuration 'ephemeral' cannot have additional parameters" in str(
            exc_info.value
        )

    def test_custom_config_without_key_file_fails(self):
        """Test that custom config requires key-file."""
        with pytest.raises(ValidationError) as exc_info:
            TlsBlock(
                name="custom-tls",
                cert_file="/etc/bind/tls/cert.pem",
            )
        assert "Custom TLS configuration 'custom-tls' requires key-file" in str(exc_info.value)

    def test_custom_config_without_cert_file_fails(self):
        """Test that custom config requires cert-file."""
        with pytest.raises(ValidationError) as exc_info:
            TlsBlock(
                name="custom-tls",
                key_file="/etc/bind/tls/key.pem",
            )
        assert "Custom TLS configuration 'custom-tls' requires cert-file" in str(exc_info.value)

    def test_protocols_validation_valid(self):
        """Test valid TLS protocols."""
        tls = TlsBlock(
            name="tls-protocols",
            key_file="/etc/bind/tls/key.pem",
            cert_file="/etc/bind/tls/cert.pem",
            protocols=["TLSv1.2", "TLSv1.3"],
        )
        assert tls.protocols == ["TLSv1.2", "TLSv1.3"]

    def test_protocols_validation_invalid(self):
        """Test invalid TLS protocols raise error."""
        with pytest.raises(ValidationError) as exc_info:
            TlsBlock(
                name="tls-protocols",
                key_file="/etc/bind/tls/key.pem",
                cert_file="/etc/bind/tls/cert.pem",
                protocols=["TLSv1.0", "TLSv1.1"],
            )
        assert "Invalid TLS protocol" in str(exc_info.value)

    def test_protocols_validation_none(self):
        """Test None protocols."""
        tls = TlsBlock(
            name="tls-protocols",
            key_file="/etc/bind/tls/key.pem",
            cert_file="/etc/bind/tls/cert.pem",
            protocols=None,
        )
        assert tls.protocols is None

    def test_boolean_fields_conversion(self):
        """Test boolean field conversions."""

        tls1 = TlsBlock(
            name="tls1",
            key_file="/key.pem",
            cert_file="/cert.pem",
            prefer_server_ciphers=True,
            session_tickets=False,
        )
        assert tls1.prefer_server_ciphers == "yes"
        assert tls1.session_tickets == "no"

        tls2 = TlsBlock(
            name="tls2",
            key_file="/key.pem",
            cert_file="/cert.pem",
            prefer_server_ciphers="1",
            session_tickets="0",
        )
        assert tls2.prefer_server_ciphers == "yes"
        assert tls2.session_tickets == "no"

        tls3 = TlsBlock(
            name="tls3",
            key_file="/key.pem",
            cert_file="/cert.pem",
            prefer_server_ciphers="true",
            session_tickets="false",
        )
        assert tls3.prefer_server_ciphers == "yes"
        assert tls3.session_tickets == "no"

    def test_remote_hostname_without_ca_file_allowed(self):
        """Test remote-hostname without ca-file is allowed."""
        tls = TlsBlock(
            name="remote-tls",
            key_file="/key.pem",
            cert_file="/cert.pem",
            remote_hostname="dns.example.com",
        )
        assert tls.remote_hostname == '"' + "dns.example.com" + '"'
        assert tls.ca_file is None

    def test_dhparam_without_session_tickets_no_warning(self, capsys):
        """Test no warning for dhparam-file without session-tickets."""
        TlsBlock(
            name="no-warning-tls",
            key_file="/key.pem",
            cert_file="/cert.pem",
            dhparam_file="/dhparam.pem",
            session_tickets="no",
        )
        captured = capsys.readouterr()
        assert "Warning:" not in captured.out

    def test_comparison_attribute(self):
        """Test comparison attribute property."""
        tls1 = TlsBlock(name="tls-a", key_file="/key.pem", cert_file="/cert.pem")
        assert tls1.comparison_attr == "tls-a"

        tls2 = TlsBlock(name="ephemeral")
        assert tls2.comparison_attr == "ephemeral"

    def test_model_bind_syntax_builtin_ephemeral(self):
        """Test BIND syntax generation for built-in ephemeral."""
        tls = TlsBlock(name="ephemeral")
        assert tls.model_bind_syntax() == "tls ephemeral {};"

    def test_model_bind_syntax_builtin_none(self):
        """Test BIND syntax generation for built-in none."""
        tls = TlsBlock(name="none")
        assert tls.model_bind_syntax() == "tls none {};"

    def test_model_bind_syntax_minimal_custom(self):
        """Test BIND syntax generation for minimal custom config."""
        tls = TlsBlock(
            name="minimal-tls",
            key_file="/etc/bind/tls/server.key",
            cert_file="/etc/bind/tls/server.crt",
        )
        result = tls.model_bind_syntax()
        assert "tls minimal-tls {" in result
        assert 'key-file "/etc/bind/tls/server.key";' in result
        assert 'cert-file "/etc/bind/tls/server.crt";' in result

    def test_model_bind_syntax_full_custom(self):
        """Test BIND syntax generation for full custom config."""
        tls = TlsBlock(
            name="secure-tls",
            key_file="/etc/bind/tls/private.key",
            cert_file="/etc/bind/tls/certificate.crt",
            ca_file="/etc/bind/tls/ca-bundle.crt",
            dhparam_file="/etc/bind/tls/dhparam.pem",
            ciphers="ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256",
            protocols=["TLSv1.2", "TLSv1.3"],
            prefer_server_ciphers="yes",
            session_tickets="no",
            remote_hostname="dns.example.com",
        )
        result = tls.model_bind_syntax()

        assert "tls secure-tls {" in result
        assert 'key-file "/etc/bind/tls/private.key";' in result
        assert 'cert-file "/etc/bind/tls/certificate.crt";' in result
        assert 'ca-file "/etc/bind/tls/ca-bundle.crt";' in result
        assert 'dhparam-file "/etc/bind/tls/dhparam.pem";' in result
        assert "ciphers ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256;" in result
        assert "prefer-server-ciphers yes;" in result
        assert "session-tickets no;" in result
        assert 'remote-hostname "dns.example.com";' in result

        assert "protocols {" in result
        assert "TLSv1.2;" in result
        assert "TLSv1.3;" in result
        assert "};" in result

    def test_model_bind_syntax_with_comment(self):
        """Test BIND syntax generation with comment."""
        tls = TlsBlock(
            name="commented-tls",
            key_file="/key.pem",
            cert_file="/cert.pem",
            comment="TLS configuration\nfor secure DNS",
        )
        result = tls.model_bind_syntax()
        assert "# TLS configuration" in result
        assert "# for secure DNS" in result
        assert "tls commented-tls {" in result

    def test_model_bind_syntax_indented(self):
        """Test BIND syntax generation with indentation."""
        tls = TlsBlock(
            name="indented-tls",
            key_file="/key.pem",
            cert_file="/cert.pem",
        )
        result = tls.model_bind_syntax(indent_level=2)
        assert result.startswith("        tls indented-tls {")
        assert '            key-file "/key.pem";' in result
        assert '            cert-file "/cert.pem";' in result
        assert "        };" in result

    def test_auto_format_fields(self):
        """Test auto-formatting of fields."""
        tls = TlsBlock(
            name="test-tls",
            key_file="/key.pem",
            cert_file="/cert.pem",
            protocols=["TLSv1.3"],
            prefer_server_ciphers=True,
        )
        formatted = tls.auto_format_fields()

        assert not any("name " in line for line in formatted)

        assert any('key-file "/key.pem";' in line for line in formatted)
        assert any('cert-file "/cert.pem";' in line for line in formatted)
        assert any("protocols {" in line for line in formatted)
        assert any("TLSv1.3;" in line for line in formatted)
        assert any("prefer-server-ciphers yes;" in line for line in formatted)

    def test_exclude_from_syntax(self):
        """Test that excluded fields are not in syntax."""
        tls = TlsBlock(
            name="exclude-test",
            key_file="/key.pem",
            cert_file="/cert.pem",
        )
        fields = tls._get_fields_for_syntax()
        field_names = [name for name, _ in fields]

        assert "name" not in field_names

        assert "comment" not in field_names

        assert "key_file" in field_names
        assert "cert_file" in field_names

    def test_pydantic_validation_from_dict(self):
        """Test Pydantic validation from dictionary."""
        tls_dict = {
            "name": "from-dict",
            "key_file": "/key.pem",
            "cert_file": "/cert.pem",
            "protocols": ["TLSv1.2"],
            "prefer_server_ciphers": "yes",
        }
        tls = TlsBlock.model_validate(tls_dict)
        assert tls.name == "from-dict"
        assert tls.key_file == '"' + "/key.pem" + '"'
        assert tls.cert_file == '"' + "/cert.pem" + '"'
        assert tls.protocols == ["TLSv1.2"]
        assert tls.prefer_server_ciphers == "yes"

    def test_pydantic_validation_from_json(self):
        """Test Pydantic validation from JSON."""
        tls_json = """
        {
            "name": "from-json",
            "key_file": "/key.pem",
            "cert_file": "/cert.pem",
            "remote_hostname": "dns.example.com"
        }
        """
        tls = TlsBlock.model_validate_json(tls_json)
        assert tls.name == "from-json"
        assert tls.key_file == '"' + "/key.pem" + '"'
        assert tls.cert_file == '"' + "/cert.pem" + '"'
        assert tls.remote_hostname == '"' + "dns.example.com" + '"'

    def test_quoted_string_fields(self):
        """Test that paths can be quoted strings."""

        tls = TlsBlock(
            name="quoted-tls",
            key_file='"C:\\Program Files\\Bind\\tls\\key.pem"',
            cert_file='"C:\\Program Files\\Bind\\tls\\cert.pem"',
            ca_file='"C:\\Program Files\\Bind\\tls\\ca.crt"',
        )

        assert tls.key_file == '"C:\\Program Files\\Bind\\tls\\key.pem"'
        assert tls.cert_file == '"C:\\Program Files\\Bind\\tls\\cert.pem"'
        assert tls.ca_file == '"C:\\Program Files\\Bind\\tls\\ca.crt"'

    def test_ciphers_field(self):
        """Test ciphers field with different formats."""
        tls1 = TlsBlock(
            name="ciphers1",
            key_file="/key.pem",
            cert_file="/cert.pem",
            ciphers="ECDHE-RSA-AES256-GCM-SHA384",
        )
        assert tls1.ciphers == "ECDHE-RSA-AES256-GCM-SHA384"

        tls2 = TlsBlock(
            name="ciphers2",
            key_file="/key.pem",
            cert_file="/cert.pem",
            ciphers="TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256",
        )
        assert tls2.ciphers == "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256"

    def test_comparison_operators(self):
        """Test comparison operators for sorting."""
        tls1 = TlsBlock(name="aaa-tls", key_file="/key.pem", cert_file="/cert.pem")
        tls2 = TlsBlock(name="bbb-tls", key_file="/key.pem", cert_file="/cert.pem")
        tls3 = TlsBlock(name="aaa-tls", key_file="/other.pem", cert_file="/other.pem")

        assert tls1 < tls2
        assert tls2 > tls1
        assert tls1 <= tls3
        assert tls1 >= tls3

    def test_builtin_configs_set(self):
        """Test BUILTIN_CONFIGS class variable."""
        assert {"ephemeral", "none"} == TlsBlock.BUILTIN_CONFIGS
        assert "ephemeral" in TlsBlock.BUILTIN_CONFIGS
        assert "none" in TlsBlock.BUILTIN_CONFIGS

    def test_real_world_examples(self):
        """Test real-world examples from manual initialization."""

        tls = TlsBlock(name="ephemeral")
        assert tls.model_bind_syntax() == "tls ephemeral {};"

        tls = TlsBlock(
            name="minimal-tls",
            key_file="/etc/bind/tls/server.key",
            cert_file="/etc/bind/tls/server.crt",
        )
        result = tls.model_bind_syntax()
        assert "tls minimal-tls {" in result
        assert 'key-file "/etc/bind/tls/server.key";' in result
        assert 'cert-file "/etc/bind/tls/server.crt";' in result

        tls = TlsBlock(
            name="secure-tls",
            key_file="/etc/bind/tls/private.key",
            cert_file="/etc/bind/tls/certificate.crt",
            ca_file="/etc/bind/tls/ca-bundle.crt",
            dhparam_file="/etc/bind/tls/dhparam.pem",
            ciphers="ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256",
            protocols=["TLSv1.2", "TLSv1.3"],
            prefer_server_ciphers=True,
            session_tickets="no",
            remote_hostname="dns.example.com",
        )
        result = tls.model_bind_syntax()
        assert "tls secure-tls {" in result
        assert "ciphers ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256;" in result
        assert "prefer-server-ciphers yes;" in result
