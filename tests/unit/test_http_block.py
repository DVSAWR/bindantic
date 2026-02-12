from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from bindantic import HttpBlock


class TestHttpBlock:
    """Tests for HttpBlock class."""

    def test_init_with_minimal_parameters(self):
        """Test initialization with minimal parameters."""
        http = HttpBlock(name="doh_server", endpoints=["/dns-query"])

        assert http.name == "doh_server"
        assert http.endpoints == ['"/dns-query"']
        assert http.listener_clients is None
        assert http.streams_per_connection is None

    def test_init_with_all_parameters(self):
        """Test initialization with all parameters."""
        http = HttpBlock(
            name="secure_api",
            endpoints=['"/api/dns"', '"/secure/resolve"'],
            listener_clients=500,
            streams_per_connection=250,
        )

        assert http.name == "secure_api"
        assert http.endpoints == ['"/api/dns"', '"/secure/resolve"']
        assert http.listener_clients == 500
        assert http.streams_per_connection == 250

    def test_init_with_comment(self):
        """Test initialization with comment."""
        http = HttpBlock(name="doh", endpoints=["/dns-query"], comment="DNS-over-HTTPS endpoint")

        assert http.name == "doh"
        assert http.comment == "DNS-over-HTTPS endpoint"

    def test_init_with_numeric_endpoints(self):
        """Test initialization with numeric endpoint values."""
        http = HttpBlock(name="test", endpoints=["/api/v1", "/api/v2"])
        assert http.endpoints == ['"/api/v1"', '"/api/v2"']

    def test_validate_endpoints_valid(self):
        """Test validation of valid endpoints."""
        valid_endpoints = [
            ["/"],
            ["/dns"],
            ["/dns-query"],
            ["/api/dns"],
            ["/v1/query"],
            ["/secure/resolve"],
            ["/dns-query", "/api/dns"],
        ]

        for endpoints in valid_endpoints:
            http = HttpBlock(name="test", endpoints=endpoints)
            assert len(http.endpoints) == len(endpoints)
            for i, endpoint in enumerate(endpoints):
                assert f'"{endpoint}"' in http.endpoints[i] or endpoint == "/"

    def test_validate_endpoints_invalid(self):
        """Test validation of invalid endpoints."""
        invalid_cases = [
            ([""], "BIND quoted string cannot be empty"),
            (["dns"], "must start with '/'"),
            (["http://example.com/dns"], "must start with '/'"),
            (["https://dns.example.com"], "must start with '/'"),
            (["//double-slash"], "contains double slashes"),
            (["/ends-with/"], "should not end with '/'"),
            (["/valid", "/invalid//path"], "contains double slashes"),
        ]

        for endpoints, error_msg in invalid_cases:
            with pytest.raises(ValidationError, match=error_msg):
                HttpBlock(name="test", endpoints=endpoints)

    def test_validate_endpoints_root_slash(self):
        """Test that root slash endpoint is allowed."""
        http = HttpBlock(name="root", endpoints=["/"])
        assert http.endpoints == ['"/"']

    def test_validate_endpoints_with_quotes(self):
        """Test that endpoints with quotes are handled correctly."""

        http1 = HttpBlock(name="test1", endpoints=['"/dns"'])
        assert http1.endpoints == ['"/dns"']

        http2 = HttpBlock(name="test2", endpoints=["/dns"])
        assert http2.endpoints == ['"/dns"']

    def test_listener_clients_validation(self):
        """Test listener_clients field validation."""

        valid_values = [0, 1, 100, 1000, 10000]
        for value in valid_values:
            http = HttpBlock(name="test", endpoints=["/dns"], listener_clients=value)
            assert http.listener_clients == value

        with pytest.raises(ValidationError):
            HttpBlock(name="test", endpoints=["/dns"], listener_clients=-1)

    def test_streams_per_connection_validation(self):
        """Test streams_per_connection field validation."""

        valid_values = [0, 1, 10, 100, 1000]
        for value in valid_values:
            http = HttpBlock(name="test", endpoints=["/dns"], streams_per_connection=value)
            assert http.streams_per_connection == value

        with pytest.raises(ValidationError):
            HttpBlock(name="test", endpoints=["/dns"], streams_per_connection=-1)

    def test_model_bind_syntax_minimal(self):
        """Test BIND syntax generation with minimal parameters."""
        http = HttpBlock(name="minimal", endpoints=["/dns"])

        expected = """http minimal {
    endpoints {
        "/dns";
    };
};"""
        assert http.model_bind_syntax() == expected

    def test_model_bind_syntax_full(self):
        """Test BIND syntax generation with all parameters."""
        http = HttpBlock(
            name="full_config",
            endpoints=['"/api/dns"', '"/resolve"'],
            listener_clients=100,
            streams_per_connection=50,
        )

        expected = """http full_config {
    endpoints {
        "/api/dns";
        "/resolve";
    };
    listener-clients 100;
    streams-per-connection 50;
};"""
        assert http.model_bind_syntax() == expected

    def test_model_bind_syntax_without_endpoints(self):
        """Test BIND syntax generation without endpoints."""
        http = HttpBlock(name="no_endpoints")

        expected = """http no_endpoints {
};"""
        assert http.model_bind_syntax() == expected

    def test_model_bind_syntax_with_comment(self):
        """Test BIND syntax generation with comment."""
        http = HttpBlock(
            name="commented", endpoints=["/dns-query"], comment="DoH endpoint configuration"
        )

        expected = """# DoH endpoint configuration
http commented {
    endpoints {
        "/dns-query";
    };
};"""
        assert http.model_bind_syntax() == expected

    def test_model_bind_syntax_with_multiline_comment(self):
        """Test BIND syntax generation with multiline comment."""
        http = HttpBlock(
            name="multiline", endpoints=["/dns"], comment="First line\nSecond line\nThird line"
        )

        expected = """# First line
# Second line
# Third line
http multiline {
    endpoints {
        "/dns";
    };
};"""
        assert http.model_bind_syntax() == expected

    def test_model_bind_syntax_with_indent(self):
        """Test BIND syntax generation with indentation."""
        http = HttpBlock(name="indented", endpoints=["/dns"], listener_clients=100)

        expected = """    http indented {
        endpoints {
            "/dns";
        };
        listener-clients 100;
    };"""
        assert http.model_bind_syntax(1) == expected

    def test_model_bind_syntax_sorted_endpoints(self):
        """Test that endpoints are sorted in BIND syntax."""
        http = HttpBlock(name="sorted", endpoints=["/zebra", "/apple", "/middle", "/beta"])

        output = http.model_bind_syntax()

        lines = output.split("\n")
        endpoint_lines = [line.strip() for line in lines if '"/' in line]

        expected_order = ['"/apple";', '"/beta";', '"/middle";', '"/zebra";']
        assert endpoint_lines == expected_order

    def test_comparison_attr_property(self):
        """Test comparison_attr property."""
        http1 = HttpBlock(name="http1", endpoints=["/dns"])
        http2 = HttpBlock(name="http2", endpoints=["/dns"])
        http3 = HttpBlock(name="http1", endpoints=["/different"])

        assert http1.comparison_attr == "http1"
        assert http2.comparison_attr == "http2"
        assert http3.comparison_attr == "http1"

    def test_comparison_operators(self):
        """Test comparison operators."""
        http1 = HttpBlock(name="aaa", endpoints=["/dns"])
        http2 = HttpBlock(name="bbb", endpoints=["/dns"])
        http3 = HttpBlock(name="aaa", endpoints=["/dns"])

        assert http1 < http2
        assert not http2 < http1
        assert http2 > http1
        assert not http1 > http2

        assert http1 <= http3
        assert http1 >= http3
        assert not http1 < http3
        assert not http1 > http3

    def test_comparison_with_different_type(self):
        """Test comparison with different type returns NotImplemented."""
        http = HttpBlock(name="test", endpoints=["/dns"])

        assert http.__lt__("not a model") is NotImplemented
        assert http.__le__(123) is NotImplemented
        assert http.__gt__([]) is NotImplemented
        assert http.__ge__({}) is NotImplemented

    def test_model_validate(self):
        """Test validation via model_validate."""
        data = {
            "name": "api_server",
            "endpoints": ["/api/v1", "/api/v2"],
            "listener_clients": 200,
            "streams_per_connection": 100,
        }

        http = HttpBlock.model_validate(data)
        assert http.name == "api_server"
        assert len(http.endpoints) == 2
        assert http.listener_clients == 200
        assert http.streams_per_connection == 100

    def test_model_validate_json(self):
        """Test validation via model_validate_json."""
        json_data = """{
            "name": "json_config",
            "endpoints": ["/dns"],
            "listener_clients": 150,
            "comment": "JSON configuration"
        }"""

        http = HttpBlock.model_validate_json(json_data)
        assert http.name == "json_config"
        assert http.endpoints == ['"/dns"']
        assert http.listener_clients == 150
        assert http.comment == "JSON configuration"

    def test_model_dump(self):
        """Test serialization to dict."""
        http = HttpBlock(
            name="test_http",
            endpoints=["/api", "/query"],
            listener_clients=300,
            streams_per_connection=150,
            comment="Test HTTP block",
        )

        data = http.model_dump()

        assert data["name"] == "test_http"
        assert data["endpoints"] == ['"/api"', '"/query"']
        assert data["listener_clients"] == 300
        assert data["streams_per_connection"] == 150
        assert data["comment"] == "Test HTTP block"

    def test_model_dump_json(self):
        """Test serialization to JSON."""
        http = HttpBlock(name="json_http", endpoints=["/dns"], comment="JSON test")

        json_str = http.model_dump_json()
        data = json.loads(json_str)

        assert data["name"] == "json_http"
        assert data["endpoints"] == ['"/dns"']
        assert data["comment"] == "JSON test"

    def test_field_validation_name(self):
        """Test name field validation."""

        valid_names = [
            "doh-server",
            "doh_server",
            "DoH-Server",
            "api-gateway",
            "a",
            "test123",
            " doh ",
        ]

        for name in valid_names:
            http = HttpBlock(name=name, endpoints=["/dns"])

            assert http.name == name.strip() if name.strip() != name else name

        invalid_names = [""]

        for name in invalid_names:
            with pytest.raises(ValidationError):
                HttpBlock(name=name, endpoints=["/dns"])

    def test_empty_endpoints_list(self):
        """Test with empty endpoints list."""
        http = HttpBlock(name="empty_endpoints", endpoints=[])
        assert http.endpoints == []

    def test_none_endpoints(self):
        """Test with None endpoints."""
        http = HttpBlock(name="none_endpoints", endpoints=None)
        assert http.endpoints is None

    def test_whitespace_in_endpoints(self):
        """Test handling of whitespace in endpoints."""

        http = HttpBlock(name="test", endpoints=["  /dns  ", "  /api  "])
        assert http.endpoints == ['"/dns"', '"/api"']

    def test_model_copy(self):
        """Test object copying."""
        http1 = HttpBlock(
            name="original", endpoints=["/api"], listener_clients=100, comment="Original"
        )

        http2 = http1.model_copy()

        assert http2.name == http1.name
        assert http2.endpoints == http1.endpoints
        assert http2.listener_clients == http1.listener_clients
        assert http2.comment == http1.comment
        assert http2 is not http1

    def test_model_copy_update(self):
        """Test copying with updates."""
        http1 = HttpBlock(name="original", endpoints=["/api"], listener_clients=100)

        http2 = http1.model_copy(
            update={
                "name": "updated",
                "endpoints": ['"/new-api"'],
                "streams_per_connection": 50,
            }
        )

        assert http2.name == "updated"

        assert http2.endpoints == ['"/new-api"']
        assert http2.listener_clients == 100
        assert http2.streams_per_connection == 50

    def test_exclude_from_syntax(self):
        """Test that name field is excluded from automatic formatting."""

        http = HttpBlock(
            name="test", endpoints=["/dns"], listener_clients=100, streams_per_connection=50
        )
        fields = http._get_fields_for_syntax()
        field_names = [name for name, _ in fields]

        assert "name" not in field_names
        assert "endpoints" in field_names
        assert "listener_clients" in field_names
        assert "streams_per_connection" in field_names
        assert "comment" not in field_names

    def test_real_world_examples(self):
        """Test real-world usage examples."""

        doh = HttpBlock(
            name="doh_server",
            endpoints=["/dns-query"],
            listener_clients=1000,
            streams_per_connection=100,
            comment="Public DoH endpoint",
        )

        assert doh.name == "doh_server"
        assert doh.listener_clients == 1000

        api = HttpBlock.model_validate(
            {
                "name": "api_gateway",
                "endpoints": ["/api/dns", "/api/resolve", "/api/status"],
                "listener_clients": 500,
                "streams_per_connection": 200,
            }
        )

        assert api.name == "api_gateway"
        assert len(api.endpoints) == 3

        json_config = HttpBlock.model_validate_json("""{
            "name": "json_doh",
            "endpoints": ["/resolve"],
            "listener_clients": 300
        }""")

        assert json_config.name == "json_doh"
        assert json_config.endpoints == ['"/resolve"']

    def test_edge_cases(self):
        """Test edge cases."""

        long_name = "a" * 100
        http = HttpBlock(name=long_name, endpoints=["/dns"])
        assert http.name == long_name

        http = HttpBlock(
            name="max_values",
            endpoints=["/dns"],
            listener_clients=4294967295,
            streams_per_connection=4294967295,
        )

        assert http.listener_clients == 4294967295
        assert http.streams_per_connection == 4294967295

        http = HttpBlock(
            name="zero_values", endpoints=["/dns"], listener_clients=0, streams_per_connection=0
        )

        assert http.listener_clients == 0
        assert http.streams_per_connection == 0

    @pytest.mark.parametrize(
        "name,endpoints,listener_clients,streams_per_connection,expected_output",
        [
            (
                "simple",
                ["/dns"],
                None,
                None,
                """http simple {
    endpoints {
        "/dns";
    };
};""",
            ),
            (
                "full",
                ["/api", "/query"],
                200,
                100,
                """http full {
    endpoints {
        "/api";
        "/query";
    };
    listener-clients 200;
    streams-per-connection 100;
};""",
            ),
            (
                "root",
                ["/"],
                100,
                50,
                """http root {
    endpoints {
        "/";
    };
    listener-clients 100;
    streams-per-connection 50;
};""",
            ),
            (
                "noendpoints",
                None,
                100,
                None,
                """http noendpoints {
    listener-clients 100;
};""",
            ),
        ],
    )
    def test_parametrized_bind_syntax(
        self, name, endpoints, listener_clients, streams_per_connection, expected_output
    ):
        """Parametrized test for BIND syntax generation."""
        http = HttpBlock(
            name=name,
            endpoints=endpoints,
            listener_clients=listener_clients,
            streams_per_connection=streams_per_connection,
        )
        assert http.model_bind_syntax() == expected_output

    def test_endpoints_with_special_characters(self):
        """Test endpoints with special characters."""
        special_endpoints = [
            "/api/v1/dns-query",
            "/dns_secure",
            "/dns-query-v2",
            "/api/v1.0/resolve",
            "/custom-path",
        ]

        http = HttpBlock(name="special", endpoints=special_endpoints)
        assert len(http.endpoints) == len(special_endpoints)

        output = http.model_bind_syntax()
        for endpoint in special_endpoints:
            assert f'"{endpoint}"' in output

    def test_multiple_http_blocks_comparison(self):
        """Test comparison of multiple HTTP blocks."""
        blocks = [
            HttpBlock(name="block1", endpoints=["/a"]),
            HttpBlock(name="block2", endpoints=["/b"]),
            HttpBlock(name="block3", endpoints=["/c"]),
            HttpBlock(name="block1", endpoints=["/d"]),
        ]

        sorted_blocks = sorted(blocks)
        assert [b.name for b in sorted_blocks] == ["block1", "block1", "block2", "block3"]

        assert sorted_blocks[0] <= sorted_blocks[1]
        assert sorted_blocks[0] >= sorted_blocks[1]

    def test_repr_and_str(self):
        """Test string representations."""
        http = HttpBlock(
            name="test_http",
            endpoints=["/dns"],
            listener_clients=100,
            comment="Test representation",
        )

        assert "HttpBlock" in repr(http)
        assert "test_http" in repr(http)

        str_rep = str(http)
        assert "test_http" in str_rep

    def test_default_values_preserved(self):
        """Test that default values are properly preserved."""

        http = HttpBlock(name="test", endpoints=["/dns"])

        assert http.listener_clients is None
        assert http.streams_per_connection is None

        output = http.model_bind_syntax()
        assert "listener-clients" not in output
        assert "streams-per-connection" not in output

    def test_bind_syntax_with_only_numerics(self):
        """Test BIND syntax with only numeric fields."""
        http = HttpBlock(name="numeric_only", listener_clients=500, streams_per_connection=250)

        expected = """http numeric_only {
    listener-clients 500;
    streams-per-connection 250;
};"""
        assert http.model_bind_syntax() == expected
