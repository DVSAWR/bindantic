from __future__ import annotations

import pytest
from pydantic import ValidationError

from bindantic import (
    FileSuffixEnum,
    LogCategory,
    LogCategoryEnum,
    LogChannel,
    LoggingBlock,
    LogSeverityEnum,
    SyslogFacilityEnum,
    TimeFormatEnum,
)


class TestLogChannel:
    """Tests for LogChannel class."""

    def test_init_with_file_destination(self):
        """Test initialization with file destination."""
        channel = LogChannel(
            name="query_log",
            file="/var/log/bind/query.log",
            versions=10,
            size="100M",
            suffix=FileSuffixEnum.TIMESTAMP,
            buffered=True,
            print_category=True,
            print_severity=True,
            print_time=TimeFormatEnum.ISO8601,
            severity=LogSeverityEnum.INFO,
        )

        assert channel.name == "query_log"
        assert channel.file == '"/var/log/bind/query.log"'
        assert channel.versions == 10
        assert channel.size == "100M"
        assert channel.suffix == FileSuffixEnum.TIMESTAMP
        assert channel.buffered == "yes"
        assert channel.print_category == "yes"
        assert channel.print_severity == "yes"
        assert channel.print_time == TimeFormatEnum.ISO8601
        assert channel.severity == LogSeverityEnum.INFO
        assert channel.syslog is None
        assert channel.stderr is None
        assert channel.null is None

    def test_init_with_syslog_destination(self):
        """Test initialization with syslog destination."""
        channel = LogChannel(
            name="syslog_channel",
            syslog=SyslogFacilityEnum.DAEMON,
            print_category=False,
            print_severity="no",
            print_time="iso8601-utc",
            severity="debug 3",
        )

        assert channel.name == "syslog_channel"
        assert channel.syslog == SyslogFacilityEnum.DAEMON
        assert channel.file is None
        assert channel.print_category == "no"
        assert channel.print_severity == "no"
        assert channel.print_time == TimeFormatEnum.ISO8601_UTC
        assert channel.severity == "debug 3"

    def test_init_with_stderr_destination(self):
        """Test initialization with stderr destination."""
        channel = LogChannel(
            name="stderr_channel",
            stderr=True,
            severity=LogSeverityEnum.WARNING,
        )

        assert channel.name == "stderr_channel"
        assert channel.stderr is True
        assert channel.file is None
        assert channel.syslog is None
        assert channel.null is None
        assert channel.severity == LogSeverityEnum.WARNING

    def test_init_with_null_destination(self):
        """Test initialization with null destination."""
        channel = LogChannel(name="null_channel", null=True)

        assert channel.name == "null_channel"
        assert channel.null is True
        assert channel.file is None
        assert channel.syslog is None
        assert channel.stderr is None

    def test_destination_exclusivity_validation(self):
        """Test that only one destination can be specified."""

        LogChannel(name="test", file="/var/log/test.log")
        LogChannel(name="test", syslog=SyslogFacilityEnum.DAEMON)
        LogChannel(name="test", stderr=True)
        LogChannel(name="test", null=True)

        with pytest.raises(ValidationError, match="Exactly one destination must be specified"):
            LogChannel(name="test")

        with pytest.raises(ValidationError, match="Exactly one destination must be specified"):
            LogChannel(name="test", file="/var/log/test.log", syslog=SyslogFacilityEnum.DAEMON)

        with pytest.raises(ValidationError, match="Exactly one destination must be specified"):
            LogChannel(name="test", stderr=True, null=True)

    def test_file_only_options_validation(self):
        """Test that file-specific options are only valid with file destination."""

        LogChannel(
            name="test",
            file="/var/log/test.log",
            versions=5,
            size="50M",
            suffix=FileSuffixEnum.INCREMENT,
        )

        with pytest.raises(
            ValidationError, match="'versions' can only be used with file destination"
        ):
            LogChannel(name="test", syslog=SyslogFacilityEnum.DAEMON, versions=5)

        with pytest.raises(ValidationError, match="'size' can only be used with file destination"):
            LogChannel(name="test", stderr=True, size="50M")

        with pytest.raises(
            ValidationError, match="'suffix' can only be used with file destination"
        ):
            LogChannel(name="test", null=True, suffix=FileSuffixEnum.TIMESTAMP)

    def test_severity_validation(self):
        """Test severity validation."""

        for severity in LogSeverityEnum:
            channel = LogChannel(name="test", file="/var/log/test.log", severity=severity)
            assert channel.severity == severity

        channel = LogChannel(name="test", file="/var/log/test.log", severity="debug 5")
        assert channel.severity == "debug 5"

        channel = LogChannel(name="test", file="/var/log/test.log", severity="DEBUG 99")
        assert channel.severity == "debug 99"

        with pytest.raises(ValidationError, match="Invalid debug severity format"):
            LogChannel(name="test", file="/var/log/test.log", severity="debug 100")

        with pytest.raises(ValidationError, match="Invalid debug severity format"):
            LogChannel(name="test", file="/var/log/test.log", severity="debug -1")

        with pytest.raises(ValidationError):
            LogChannel(name="test", file="/var/log/test.log", severity="invalid")

    def test_syslog_facility_validation(self):
        """Test syslog facility validation."""

        for facility in SyslogFacilityEnum:
            channel = LogChannel(name="test", syslog=facility)
            assert channel.syslog == facility

        channel = LogChannel(name="test", syslog="daemon")
        assert channel.syslog == SyslogFacilityEnum.DAEMON

        with pytest.raises(ValidationError):
            LogChannel(name="test", syslog="invalid")

    def test_print_time_validation(self):
        """Test print-time validation."""

        for time_format in TimeFormatEnum:
            channel = LogChannel(name="test", file="/var/log/test.log", print_time=time_format)
            assert channel.print_time == time_format

        channel = LogChannel(name="test", file="/var/log/test.log", print_time=True)
        assert channel.print_time == "yes"

        channel = LogChannel(name="test", file="/var/log/test.log", print_time=False)
        assert channel.print_time == "no"

        channel = LogChannel(name="test", file="/var/log/test.log", print_time="iso8601")
        assert channel.print_time == TimeFormatEnum.ISO8601

        channel = LogChannel(name="test", file="/var/log/test.log", print_time="local")
        assert channel.print_time == TimeFormatEnum.LOCAL

    def test_model_bind_syntax_file(self):
        """Test BIND syntax generation with file destination."""
        channel = LogChannel(
            name="query_log",
            file="/var/log/bind/query.log",
            versions=10,
            size="100M",
            suffix=FileSuffixEnum.TIMESTAMP,
            buffered=True,
            print_category=True,
            print_severity=True,
            print_time=TimeFormatEnum.ISO8601,
            severity=LogSeverityEnum.INFO,
        )

        expected = """channel query_log {
    file "/var/log/bind/query.log" versions 10 size 100M suffix timestamp;
    buffered yes;
    print-category yes;
    print-severity yes;
    print-time iso8601;
    severity info;
};"""
        assert channel.model_bind_syntax() == expected

    def test_model_bind_syntax_syslog(self):
        """Test BIND syntax generation with syslog destination."""
        channel = LogChannel(
            name="syslog_channel",
            syslog=SyslogFacilityEnum.DAEMON,
            print_category=False,
            print_severity="no",
            print_time="iso8601-utc",
            severity="debug 3",
        )

        expected = """channel syslog_channel {
    syslog daemon;
    print-category no;
    print-severity no;
    print-time iso8601-utc;
    severity debug 3;
};"""
        assert channel.model_bind_syntax() == expected

    def test_model_bind_syntax_stderr(self):
        """Test BIND syntax generation with stderr destination."""
        channel = LogChannel(
            name="stderr_channel",
            stderr=True,
            severity=LogSeverityEnum.WARNING,
        )

        expected = """channel stderr_channel {
    stderr;
    severity warning;
};"""
        assert channel.model_bind_syntax() == expected

    def test_model_bind_syntax_null(self):
        """Test BIND syntax generation with null destination."""
        channel = LogChannel(name="null_channel", null=True)

        expected = """channel null_channel {
    null;
};"""
        assert channel.model_bind_syntax() == expected

    def test_model_bind_syntax_with_comment(self):
        """Test BIND syntax generation with comment."""
        channel = LogChannel(
            name="commented_channel",
            file="/var/log/bind/test.log",
            comment="Test log channel",
        )

        expected = """# Test log channel
channel commented_channel {
    file "/var/log/bind/test.log";
};"""
        assert channel.model_bind_syntax() == expected

    def test_model_bind_syntax_minimal_file(self):
        """Test BIND syntax generation with minimal file configuration."""
        channel = LogChannel(name="minimal", file="/var/log/minimal.log")

        expected = """channel minimal {
    file "/var/log/minimal.log";
};"""
        assert channel.model_bind_syntax() == expected

    def test_model_bind_syntax_minimal_syslog(self):
        """Test BIND syntax generation with minimal syslog configuration."""
        channel = LogChannel(name="minimal", syslog=SyslogFacilityEnum.DAEMON)

        expected = """channel minimal {
    syslog daemon;
};"""
        assert channel.model_bind_syntax() == expected

    def test_comparison_operators(self):
        """Test comparison operators."""
        channel1 = LogChannel(name="aaa", file="/var/log/a.log")
        channel2 = LogChannel(name="bbb", file="/var/log/b.log")

        assert channel1 < channel2
        assert channel2 > channel1
        assert channel1 <= channel1  # noqa: PLR0124
        assert channel2 >= channel2  # noqa: PLR0124

    def test_model_validate(self):
        """Test validation via model_validate."""
        data = {
            "name": "validated_channel",
            "file": "/var/log/validated.log",
            "buffered": False,
            "severity": "error",
        }

        channel = LogChannel.model_validate(data)
        assert channel.name == "validated_channel"
        assert channel.file == '"/var/log/validated.log"'
        assert channel.buffered == "no"
        assert channel.severity == LogSeverityEnum.ERROR

    def test_model_validate_json(self):
        """Test validation via model_validate_json."""
        json_data = """{
            "name": "json_channel",
            "syslog": "local0",
            "print_time": true,
            "severity": "notice"
        }"""

        channel = LogChannel.model_validate_json(json_data)
        assert channel.name == "json_channel"
        assert channel.syslog == SyslogFacilityEnum.LOCAL0
        assert channel.print_time == "yes"
        assert channel.severity == LogSeverityEnum.NOTICE

    def test_boolean_field_conversion(self):
        """Test boolean field conversion to yes/no strings."""
        channel = LogChannel(
            name="test",
            file="/var/log/test.log",
            buffered=True,
            print_category=False,
            print_severity=1,
            print_time=0,
        )

        assert channel.buffered == "yes"
        assert channel.print_category == "no"
        assert channel.print_severity == "yes"
        assert channel.print_time == "no"

    def test_real_world_examples(self):
        """Test real-world examples."""

        query_log = LogChannel(
            name="query_log",
            file="/var/log/bind/query.log",
            versions="unlimited",
            size="1G",
            suffix=FileSuffixEnum.INCREMENT,
            buffered=False,
            print_time=TimeFormatEnum.ISO8601_UTC,
            severity=LogSeverityEnum.INFO,
            comment="DNS query log",
        )

        assert query_log.name == "query_log"
        assert query_log.file == '"/var/log/bind/query.log"'
        assert query_log.versions == "unlimited"
        assert query_log.size == "1G"

        error_log = LogChannel.model_validate_json("""{
            "name": "error_log",
            "syslog": "local1",
            "severity": "error",
            "print_category": true,
            "print_severity": true
        }""")

        assert error_log.name == "error_log"
        assert error_log.syslog == SyslogFacilityEnum.LOCAL1
        assert error_log.severity == LogSeverityEnum.ERROR

    @pytest.mark.parametrize(
        "config,expected_output",
        [
            (
                {
                    "name": "file_channel",
                    "file": "/var/log/file.log",
                    "versions": 5,
                    "size": "50M",
                },
                """channel file_channel {
    file "/var/log/file.log" versions 5 size 50M;
};""",
            ),
            (
                {
                    "name": "syslog_channel",
                    "syslog": "auth",
                    "print_time": "iso8601",
                },
                """channel syslog_channel {
    syslog auth;
    print-time iso8601;
};""",
            ),
            (
                {
                    "name": "debug_channel",
                    "stderr": True,
                    "severity": "debug 5",
                },
                """channel debug_channel {
    stderr;
    severity debug 5;
};""",
            ),
            (
                {
                    "name": "null_channel",
                    "null": True,
                    "severity": "dynamic",
                },
                """channel null_channel {
    null;
    severity dynamic;
};""",
            ),
        ],
    )
    def test_parametrized_bind_syntax(self, config, expected_output):
        """Parametrized test for BIND syntax generation."""
        channel = LogChannel(**config)
        assert channel.model_bind_syntax() == expected_output


class TestLogCategory:
    """Tests for LogCategory class."""

    def test_init_with_channels(self):
        """Test initialization with channels."""
        category = LogCategory(
            name=LogCategoryEnum.QUERIES,
            channels=["query_log", "default_syslog"],
        )

        assert category.name == LogCategoryEnum.QUERIES

        assert category.channels == ["query_log", "default_syslog"]

    def test_channels_validation(self):
        """Test that category must have at least one channel."""

        LogCategory(name=LogCategoryEnum.QUERIES, channels=["query_log"])
        LogCategory(name=LogCategoryEnum.SECURITY, channels=["syslog", "stderr"])

        with pytest.raises(ValidationError, match="Category must have at least one channel"):
            LogCategory(name=LogCategoryEnum.QUERIES, channels=[])

    def test_model_bind_syntax(self):
        """Test BIND syntax generation."""
        category = LogCategory(
            name=LogCategoryEnum.SECURITY,
            channels=["syslog_channel", "stderr_channel", "null"],
        )

        expected = """category security {
    syslog_channel;
    stderr_channel;
    null;
};"""
        assert category.model_bind_syntax() == expected

    def test_model_bind_syntax_with_comment(self):
        """Test BIND syntax generation with comment."""
        category = LogCategory(
            name=LogCategoryEnum.DNSSEC,
            channels=["dnssec_log"],
            comment="DNSSEC events",
        )

        expected = """# DNSSEC events
category dnssec {
    dnssec_log;
};"""
        assert category.model_bind_syntax() == expected

    def test_comparison_operators(self):
        """Test comparison operators."""
        category1 = LogCategory(name=LogCategoryEnum.CLIENT, channels=["channel1"])
        category2 = LogCategory(name=LogCategoryEnum.DATABASE, channels=["channel1"])

        assert category1 < category2
        assert category2 > category1
        assert category1 <= category1  # noqa: PLR0124
        assert category2 >= category2  # noqa: PLR0124

    def test_model_validate(self):
        """Test validation via model_validate."""
        data = {
            "name": "default",
            "channels": ["default_syslog", "default_debug"],
        }

        category = LogCategory.model_validate(data)
        assert category.name == LogCategoryEnum.DEFAULT

        assert category.channels == ["default_syslog", "default_debug"]

    def test_model_validate_json(self):
        """Test validation via model_validate_json."""
        json_data = """{
            "name": "resolver",
            "channels": ["resolver_log", "syslog"]
        }"""

        category = LogCategory.model_validate_json(json_data)
        assert category.name == LogCategoryEnum.RESOLVER

        assert category.channels == ["resolver_log", "syslog"]

    def test_all_category_enum_values(self):
        """Test all LogCategoryEnum values."""
        for category_enum in LogCategoryEnum:
            category = LogCategory(name=category_enum, channels=["default_channel"])
            assert category.name == category_enum
            assert category.model_bind_syntax().startswith(f"category {category_enum.value}")

    def test_real_world_examples(self):
        """Test real-world examples."""

        default_category = LogCategory(
            name=LogCategoryEnum.DEFAULT,
            channels=["default_syslog", "default_stderr"],
            comment="Default logging",
        )

        assert default_category.name == LogCategoryEnum.DEFAULT
        assert "default_stderr" in default_category.channels
        assert "default_syslog" in default_category.channels

        query_errors = LogCategory.model_validate_json("""{
            "name": "query-errors",
            "channels": ["error_log", "syslog"]
        }""")

        assert query_errors.name == LogCategoryEnum.QUERY_ERRORS
        assert len(query_errors.channels) == 2

    @pytest.mark.parametrize(
        "name,channels,expected_output",
        [
            (
                LogCategoryEnum.CLIENT,
                ["client_log"],
                """category client {
    client_log;
};""",
            ),
            (
                LogCategoryEnum.NETWORK,
                ["net_log1", "net_log2", "syslog"],
                """category network {
    net_log1;
    net_log2;
    syslog;
};""",
            ),
        ],
    )
    def test_parametrized_bind_syntax(self, name, channels, expected_output):
        """Parametrized test for BIND syntax generation."""
        category = LogCategory(name=name, channels=channels)
        assert category.model_bind_syntax() == expected_output


class TestLoggingBlock:
    """Tests for LoggingBlock class."""

    def test_init_empty(self):
        """Test initialization with empty logging."""
        logging_block = LoggingBlock()

        assert logging_block.channels == []
        assert logging_block.categories == []
        assert logging_block.model_bind_syntax() == "logging { };"

    def test_init_with_channels_and_categories(self):
        """Test initialization with channels and categories."""
        channel1 = LogChannel(name="query_log", file="/var/log/query.log")
        channel2 = LogChannel(name="error_log", syslog=SyslogFacilityEnum.DAEMON)
        category1 = LogCategory(name=LogCategoryEnum.QUERIES, channels=["query_log"])
        category2 = LogCategory(name=LogCategoryEnum.QUERY_ERRORS, channels=["error_log"])

        logging_block = LoggingBlock(
            channels=[channel1, channel2],
            categories=[category1, category2],
        )

        assert len(logging_block.channels) == 2
        assert len(logging_block.categories) == 2

        assert logging_block.channels[0].name == "query_log"
        assert logging_block.channels[1].name == "error_log"

        assert logging_block.categories[0].name == LogCategoryEnum.QUERIES
        assert logging_block.categories[1].name == LogCategoryEnum.QUERY_ERRORS

    def test_channel_reference_validation(self):
        """Test that categories reference existing channels."""

        channel = LogChannel(name="defined_channel", file="/var/log/test.log")
        category = LogCategory(name=LogCategoryEnum.DEFAULT, channels=["defined_channel"])

        _ = LoggingBlock(channels=[channel], categories=[category])

        category_builtin = LogCategory(
            name=LogCategoryEnum.DEFAULT,
            channels=["default_syslog", "null"],
        )
        _ = LoggingBlock(categories=[category_builtin])

        category_undefined = LogCategory(
            name=LogCategoryEnum.DEFAULT,
            channels=["undefined_channel"],
        )

        with pytest.raises(
            ValidationError,
            match="Category 'default' references undefined channel 'undefined_channel'",
        ):
            LoggingBlock(categories=[category_undefined])

    def test_model_bind_syntax_with_channels_only(self):
        """Test BIND syntax generation with channels only."""
        channel1 = LogChannel(name="query_log", file="/var/log/query.log")
        channel2 = LogChannel(name="error_log", syslog=SyslogFacilityEnum.LOCAL0)

        logging_block = LoggingBlock(channels=[channel1, channel2])

        expected = """logging {
    channel error_log {
        syslog local0;
    };
    channel query_log {
        file "/var/log/query.log";
    };
};"""
        assert logging_block.model_bind_syntax() == expected

    def test_model_bind_syntax_with_categories_only(self):
        """Test BIND syntax generation with categories only."""
        category1 = LogCategory(name=LogCategoryEnum.QUERIES, channels=["default_syslog"])
        category2 = LogCategory(name=LogCategoryEnum.QUERY_ERRORS, channels=["null"])

        logging_block = LoggingBlock(categories=[category1, category2])

        expected = """logging {
    category queries {
        default_syslog;
    };
    category query-errors {
        null;
    };
};"""
        assert logging_block.model_bind_syntax() == expected

    def test_model_bind_syntax_complete(self):
        """Test complete BIND syntax generation."""
        channel1 = LogChannel(
            name="query_log",
            file="/var/log/query.log",
            severity=LogSeverityEnum.INFO,
        )
        channel2 = LogChannel(
            name="error_log",
            syslog=SyslogFacilityEnum.DAEMON,
            severity=LogSeverityEnum.ERROR,
        )
        category1 = LogCategory(
            name=LogCategoryEnum.QUERIES,
            channels=["query_log"],
        )
        category2 = LogCategory(
            name=LogCategoryEnum.QUERY_ERRORS,
            channels=["error_log"],
        )

        logging_block = LoggingBlock(
            channels=[channel1, channel2],
            categories=[category1, category2],
        )

        expected = """logging {
    channel error_log {
        syslog daemon;
        severity error;
    };
    channel query_log {
        file "/var/log/query.log";
        severity info;
    };
    category queries {
        query_log;
    };
    category query-errors {
        error_log;
    };
};"""
        assert logging_block.model_bind_syntax() == expected

    def test_model_bind_syntax_with_comment(self):
        """Test BIND syntax generation with comment."""
        channel = LogChannel(name="test_log", file="/var/log/test.log")
        logging_block = LoggingBlock(channels=[channel], comment="Test logging configuration")

        expected = """# Test logging configuration
logging {
    channel test_log {
        file "/var/log/test.log";
    };
};"""
        assert logging_block.model_bind_syntax() == expected

    def test_model_validate(self):
        """Test validation via model_validate."""
        data = {
            "channels": [
                {
                    "name": "validated_channel",
                    "file": "/var/log/validated.log",
                }
            ],
            "categories": [
                {
                    "name": "default",
                    "channels": ["validated_channel"],
                }
            ],
        }

        logging_block = LoggingBlock.model_validate(data)
        assert len(logging_block.channels) == 1
        assert len(logging_block.categories) == 1
        assert logging_block.channels[0].name == "validated_channel"
        assert logging_block.categories[0].name == LogCategoryEnum.DEFAULT

    def test_model_validate_json(self):
        """Test validation via model_validate_json."""
        json_data = """{
            "channels": [
                {
                    "name": "json_channel",
                    "syslog": "local1",
                    "severity": "warning"
                }
            ],
            "categories": [
                {
                    "name": "security",
                    "channels": ["json_channel"]
                }
            ]
        }"""

        logging_block = LoggingBlock.model_validate_json(json_data)
        assert len(logging_block.channels) == 1
        assert len(logging_block.categories) == 1
        assert logging_block.channels[0].name == "json_channel"
        assert logging_block.categories[0].name == LogCategoryEnum.SECURITY

    def test_real_world_example(self):
        """Test real-world example."""

        query_log = LogChannel(
            name="query_log",
            file="/var/log/bind/query.log",
            versions="unlimited",
            size="1G",
            suffix=FileSuffixEnum.INCREMENT,
            buffered=False,
            print_time=TimeFormatEnum.ISO8601_UTC,
            severity=LogSeverityEnum.INFO,
        )

        error_log = LogChannel(
            name="error_log",
            syslog=SyslogFacilityEnum.LOCAL0,
            severity=LogSeverityEnum.ERROR,
            print_category=True,
            print_severity=True,
        )

        debug_log = LogChannel(
            name="debug_log",
            file="/var/log/bind/debug.log",
            severity="debug 5",
        )

        categories = [
            LogCategory(
                name=LogCategoryEnum.QUERIES,
                channels=["query_log", "debug_log"],
            ),
            LogCategory(
                name=LogCategoryEnum.QUERY_ERRORS,
                channels=["error_log"],
            ),
            LogCategory(
                name=LogCategoryEnum.DEFAULT,
                channels=["error_log", "default_syslog"],
            ),
        ]

        logging_config = LoggingBlock(
            channels=[query_log, error_log, debug_log],
            categories=categories,
            comment="Production logging configuration",
        )

        assert len(logging_config.channels) == 3
        assert len(logging_config.categories) == 3

        bind_syntax = logging_config.model_bind_syntax()
        assert "# Production logging configuration" in bind_syntax
        assert "channel debug_log" in bind_syntax
        assert "channel error_log" in bind_syntax
        assert "channel query_log" in bind_syntax
        assert "category queries" in bind_syntax
        assert "default_syslog" in bind_syntax

    def test_empty_logging_block_syntax(self):
        """Test BIND syntax for empty logging block."""
        logging_block = LoggingBlock()
        assert logging_block.model_bind_syntax() == "logging { };"

        logging_block_with_comment = LoggingBlock(comment="Empty logging")
        assert logging_block_with_comment.model_bind_syntax() == "# Empty logging\nlogging { };"

    @pytest.mark.parametrize(
        "config,expected_contains",
        [
            (
                {
                    "channels": [
                        {"name": "ch1", "file": "/var/log/1.log"},
                        {"name": "ch2", "syslog": "daemon"},
                    ],
                    "categories": [
                        {"name": "default", "channels": ["ch1", "ch2"]},
                    ],
                },
                ["channel ch1", "channel ch2", "category default"],
            ),
            (
                {
                    "channels": [],
                    "categories": [
                        {"name": "queries", "channels": ["default_syslog"]},
                    ],
                },
                ["category queries", "default_syslog"],
            ),
        ],
    )
    def test_parametrized_bind_syntax(self, config, expected_contains):
        """Parametrized test for BIND syntax generation."""
        logging_block = LoggingBlock(**config)
        bind_syntax = logging_block.model_bind_syntax()

        for expected in expected_contains:
            assert expected in bind_syntax

    def test_builtin_channels_reference(self):
        """Test that categories can reference built-in channels."""
        builtin_channels = {
            "default_syslog",
            "default_debug",
            "default_stderr",
            "null",
            "default_logfile",
        }

        for channel_name in builtin_channels:
            category = LogCategory(
                name=LogCategoryEnum.DEFAULT,
                channels=[channel_name, "some_other_channel"],
            )
            defined_channel = LogChannel(name="some_other_channel", file="/var/log/other.log")
            _ = LoggingBlock(
                channels=[defined_channel],
                categories=[category],
            )

    def test_duplicate_channel_names(self):
        """Test that duplicate channel names are handled."""
        channel1 = LogChannel(name="duplicate", file="/var/log/1.log")
        channel2 = LogChannel(name="duplicate", syslog=SyslogFacilityEnum.DAEMON)

        logging_block = LoggingBlock(channels=[channel1, channel2])
        assert len(logging_block.channels) == 2
        bind_syntax = logging_block.model_bind_syntax()
        assert "channel duplicate" in bind_syntax

    def test_category_with_multiple_channels(self):
        """Test category with multiple channels."""
        category = LogCategory(
            name=LogCategoryEnum.DEFAULT,
            channels=["channel1", "channel2", "channel3", "default_syslog"],
        )

        channels = [
            LogChannel(name="channel1", file="/var/log/1.log"),
            LogChannel(name="channel2", syslog=SyslogFacilityEnum.USER),
            LogChannel(name="channel3", stderr=True),
        ]

        logging_block = LoggingBlock(channels=channels, categories=[category])

        bind_syntax = logging_block.model_bind_syntax()
        assert "category default" in bind_syntax
        assert "channel1" in bind_syntax
        assert "channel2" in bind_syntax
        assert "channel3" in bind_syntax
        assert "default_syslog" in bind_syntax
