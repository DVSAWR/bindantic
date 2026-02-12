from __future__ import annotations

from enum import Enum
from typing import ClassVar, Literal

from pydantic import Field, field_validator, model_validator

from ._base_model import BindBaseModel
from ._base_types import (
    boolean_BIND,
    integer_BIND,
    quoted_string_BIND,
    size_BIND,
    string_BIND,
)


class SyslogFacilityEnum(str, Enum):
    KERN = "kern"
    USER = "user"
    MAIL = "mail"
    DAEMON = "daemon"
    AUTH = "auth"
    SYSLOG = "syslog"
    LPR = "lpr"
    NEWS = "news"
    UUCP = "uucp"
    CRON = "cron"
    AUTHPRIV = "authpriv"
    FTP = "ftp"
    LOCAL0 = "local0"
    LOCAL1 = "local1"
    LOCAL2 = "local2"
    LOCAL3 = "local3"
    LOCAL4 = "local4"
    LOCAL5 = "local5"
    LOCAL6 = "local6"
    LOCAL7 = "local7"


class LogSeverityEnum(str, Enum):
    CRITICAL = "critical"
    ERROR = "error"
    WARNING = "warning"
    NOTICE = "notice"
    INFO = "info"
    DEBUG = "debug"
    DYNAMIC = "dynamic"


class TimeFormatEnum(str, Enum):
    ISO8601 = "iso8601"
    ISO8601_UTC = "iso8601-utc"
    LOCAL = "local"


class FileSuffixEnum(str, Enum):
    INCREMENT = "increment"
    TIMESTAMP = "timestamp"


class LogCategoryEnum(str, Enum):
    CLIENT = "client"
    CNAME = "cname"
    CONFIG = "config"
    DATABASE = "database"
    DEFAULT = "default"
    DISPATCH = "dispatch"
    DNSSEC = "dnssec"
    DNSTAP = "dnstap"
    EDNS_DISABLED = "edns-disabled"
    GENERAL = "general"
    LAME_SERVERS = "lame-servers"
    NETWORK = "network"
    NOTIFY = "notify"
    NSID = "nsid"
    QUERIES = "queries"
    QUERY_ERRORS = "query-errors"
    RATE_LIMIT = "rate-limit"
    RESOLVER = "resolver"
    RESPONSES = "responses"
    RPZ = "rpz"
    RPZ_PASSTHRU = "rpz-passthru"
    SECURITY = "security"
    SERVE_STALE = "serve-stale"
    SPILL = "spill"
    SSLKEYLOG = "sslkeylog"
    TRUST_ANCHOR_TELEMETRY = "trust-anchor-telemetry"
    UNMATCHED = "unmatched"
    UPDATE = "update"
    UPDATE_SECURITY = "update-security"
    XFER_IN = "xfer-in"
    XFER_OUT = "xfer-out"
    ZONELOAD = "zoneload"


class LogChannel(BindBaseModel):
    """
    Log channel definition for BIND9 logging configuration.

    Grammar:
    ```
    channel <string> {
        buffered <boolean>;
        file <quoted_string> [ versions ( unlimited | <integer> ) ] [ size <size> ] [ suffix ( increment | timestamp ) ];
        null;
        print-category <boolean>;
        print-severity <boolean>;
        print-time ( iso8601 | iso8601-utc | local | <boolean> );
        severity <log_severity>;
        stderr;
        syslog [ <syslog_facility> ];
    };
    ```
    """

    name: string_BIND = Field(..., description="Channel name")
    file: quoted_string_BIND | None = Field(
        default=None,
        description="Log to specified file. Mutually exclusive with syslog/stderr/null",
    )
    syslog: SyslogFacilityEnum | str | None = Field(
        default=None,
        description="Log to syslog with optional facility. Mutually exclusive with file/stderr/null",
    )
    stderr: bool | None = Field(
        default=None, description="Log to standard error. Mutually exclusive with file/syslog/null"
    )
    null: bool | None = Field(
        default=None,
        description="Discard all messages. Mutually exclusive with file/syslog/stderr",
    )
    versions: Literal["unlimited"] | integer_BIND | None = Field(
        default=None, description="Number of backup versions to keep (unlimited or integer)"
    )
    size: size_BIND | None = Field(default=None, description="Maximum file size before rotation")
    suffix: FileSuffixEnum | None = Field(default=None, description="Backup file naming method")
    buffered: boolean_BIND | None = Field(
        default=None, description="If yes, output is not flushed after each log entry"
    )
    print_category: boolean_BIND | None = Field(
        default=None, description="Include category name in log messages"
    )
    print_severity: boolean_BIND | None = Field(
        default=None, description="Include severity level in log messages"
    )
    print_time: TimeFormatEnum | boolean_BIND | None = Field(
        default=None, description="Include timestamp in log messages"
    )
    severity: LogSeverityEnum | str | None = Field(
        default=None, description="Minimum severity level to log"
    )

    _exclude_from_syntax: ClassVar[set[str]] = {"name"}

    @property
    def comparison_attr(self) -> str:
        return str(self.name)

    @model_validator(mode="after")
    def validate_destination_exclusivity(self) -> LogChannel:
        """Ensure exactly one destination is specified."""
        destinations = [
            self.file is not None,
            self.syslog is not None,
            self.stderr is not None,
            self.null is not None,
        ]

        if sum(destinations) != 1:
            raise ValueError(
                "Exactly one destination must be specified: file, syslog, stderr, or null"
            )

        # Validate file-specific options
        if self.file is not None:
            # File-specific options are allowed
            pass
        else:
            # These options are only valid with file destination
            if self.versions is not None:
                raise ValueError("'versions' can only be used with file destination")
            if self.size is not None:
                raise ValueError("'size' can only be used with file destination")
            if self.suffix is not None:
                raise ValueError("'suffix' can only be used with file destination")

        return self

    @field_validator("severity")
    def validate_severity(cls, v: LogSeverityEnum | str | None) -> LogSeverityEnum | str | None:
        """Validate severity value."""
        if v is None:
            return v

        if isinstance(v, str):
            v_lower = v.lower()
            if v_lower.startswith("debug "):
                try:
                    level = int(v_lower.split()[1])
                    if level < 0 or level > 99:
                        raise ValueError("Debug level must be between 0 and 99")
                    return f"debug {level}"
                except (IndexError, ValueError) as exc:
                    raise ValueError("Invalid debug severity format. Use 'debug <level>'") from exc

            try:
                return LogSeverityEnum(v_lower)
            except ValueError as exc:
                raise ValueError(
                    f"Invalid severity: {v}. Must be one of: "
                    f"{', '.join([e.value for e in LogSeverityEnum])} or 'debug <level>'"
                ) from exc

        return v  # type: ignore[unreachable]

    @field_validator("syslog")
    def validate_syslog_facility(
        cls, v: SyslogFacilityEnum | str | None
    ) -> SyslogFacilityEnum | None:
        """Validate syslog facility."""
        if v is None:
            return v

        if isinstance(v, str):
            try:
                return SyslogFacilityEnum(v.lower())
            except ValueError as exc:
                raise ValueError(
                    f"Invalid syslog facility: {v}. Must be one of: "
                    f"{', '.join([e.value for e in SyslogFacilityEnum])} or 'debug <level>'"
                ) from exc

        return v  # type: ignore[unreachable]

    def _format_file_line(self) -> str:
        if not self.file:
            return ""

        parts = [f"file {self.file}"]

        if self.versions is not None:
            parts.append(f"versions {self.versions}")
        if self.size is not None:
            parts.append(f"size {self.size}")
        if self.suffix is not None:
            parts.append(f"suffix {self.suffix.value}")

        return " ".join(parts) + ";"

    def _format_syslog_line(self) -> str:
        if not self.syslog:
            return ""

        if isinstance(self.syslog, SyslogFacilityEnum):
            return f"syslog {self.syslog.value};"
        return f"syslog {self.syslog};"

    def _format_print_time(self) -> str:
        if self.print_time is None:
            return ""

        if isinstance(self.print_time, TimeFormatEnum):
            return f"print-time {self.print_time.value};"
        if self.print_time is True:
            return "print-time;"
        if self.print_time is False:
            return "print-time no;"

        return ""

    def _format_severity(self) -> str:
        if self.severity is None:
            return ""

        if isinstance(self.severity, LogSeverityEnum):
            return f"severity {self.severity.value};"
        return f"severity {self.severity};"

    def model_bind_syntax(self, indent_level: int = 0) -> str:
        lines: list[str] = []
        self._add_comment(lines, indent_level)
        indent = self._indent(indent_level)

        lines.append(f"{indent}channel {self.name} {{")

        inner_indent = self._indent(indent_level + 1)

        if self.file is not None:
            lines.append(f"{inner_indent}{self._format_file_line()}")
        elif self.syslog is not None:
            lines.append(f"{inner_indent}{self._format_syslog_line()}")
        elif self.stderr is not None and self.stderr:
            lines.append(f"{inner_indent}stderr;")
        elif self.null is not None and self.null:
            lines.append(f"{inner_indent}null;")

        if self.buffered is not None:
            lines.append(f"{inner_indent}buffered {self.buffered};")
        if self.print_category is not None:
            lines.append(f"{inner_indent}print-category {self.print_category};")
        if self.print_severity is not None:
            lines.append(f"{inner_indent}print-severity {self.print_severity};")

        print_time_line = self._format_print_time()
        if print_time_line:
            lines.append(f"{inner_indent}{print_time_line}")

        severity_line = self._format_severity()
        if severity_line:
            lines.append(f"{inner_indent}{severity_line}")

        lines.append(f"{indent}}};")
        return "\n".join(lines)


class LogCategory(BindBaseModel):
    """
    Log category definition for BIND9 logging configuration.

    Grammar:
    ```
    category <string> { <string>; ... };
    ```
    """

    name: LogCategoryEnum = Field(..., description="Category name")
    channels: list[string_BIND] = Field(
        default_factory=list,
        description="List of channel names to receive messages from this category",
    )

    _exclude_from_syntax: ClassVar[set[str]] = {"name"}

    @property
    def comparison_attr(self) -> str:
        return str(self.name)

    @field_validator("channels")
    def validate_channels(cls, v: list[string_BIND]) -> list[string_BIND]:
        if not v:
            raise ValueError("Category must have at least one channel")
        return v

    def model_bind_syntax(self, indent_level: int = 0) -> str:
        lines: list[str] = []
        self._add_comment(lines, indent_level)

        indent = self._indent(indent_level)
        inner_indent = self._indent(indent_level + 1)

        lines.append(f"{indent}category {self.name.value} {{")

        for channel in self.channels:
            lines.append(f"{inner_indent}{channel};")

        lines.append(f"{indent}}};")
        return "\n".join(lines)


class LoggingBlock(BindBaseModel):
    """
    Logging block for BIND9 configuration.

    Configures logging options for the name server.

    Block Grammar:
    ```
    logging {
        category <string> { <string>; ... };
        channel <string> {
            buffered <boolean>;
            file <quoted_string> [ versions ( unlimited | <integer> ) ] [ size <size> ] [ suffix ( increment | timestamp ) ];
            null;
            print-category <boolean>;
            print-severity <boolean>;
            print-time ( iso8601 | iso8601-utc | local | <boolean> );
            severity <log_severity>;
            stderr;
            syslog [ <syslog_facility> ];
        };
    };
    ```
    """

    channels: list[LogChannel] = Field(
        default_factory=list, description="List of log channel definitions"
    )
    categories: list[LogCategory] = Field(
        default_factory=list, description="List of log category definitions"
    )

    @model_validator(mode="after")
    def validate_channel_references(self) -> LoggingBlock:
        """Validate that categories reference existing channels or built-in channels."""
        if not self.categories:
            return self

        defined_channels = {channel.name for channel in self.channels}

        builtin_channels = {
            "default_syslog",
            "default_debug",
            "default_stderr",
            "null",
            "default_logfile",
        }

        all_channels = defined_channels.union(builtin_channels)

        for category in self.categories:
            for channel_name in category.channels:
                if channel_name not in all_channels:
                    raise ValueError(
                        f"Category '{category.name.value}' references undefined channel '{channel_name}'. "
                        f"Available channels: {', '.join(sorted(all_channels))}"
                    )

        return self

    def model_bind_syntax(self, indent_level: int = 0) -> str:
        lines: list[str] = []
        self._add_comment(lines, indent_level)

        indent = self._indent(indent_level)

        if not self.channels and not self.categories:
            lines.append(f"{indent}logging {{ }};")
            return "\n".join(lines)

        lines.append(f"{indent}logging {{")

        for channel in sorted(self.channels):
            channel_lines = channel.model_bind_syntax(indent_level + 1).split("\n")
            lines.extend(channel_lines)

        for category in sorted(self.categories):
            category_lines = category.model_bind_syntax(indent_level + 1).split("\n")
            lines.extend(category_lines)

        lines.append(f"{indent}}};")
        return "\n".join(lines)
