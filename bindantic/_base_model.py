from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable
from typing import Any

from pydantic import BaseModel, Field

from ._base_types import string_BIND


class BindBaseModel(ABC, BaseModel):
    """Base class for all BIND blocks."""

    comment: string_BIND | None = Field(
        default=None, description="Optional comment for this block"
    )

    @property
    def comparison_attr(self) -> Any:
        """Attribute used for comparison operations."""
        pass

    @abstractmethod
    def model_bind_syntax(self, indent_level: int = 0) -> str:
        """Convert block to BIND syntax."""
        pass

    def _indent(self, level: int) -> str:
        """Return indentation string."""
        return "    " * level

    def _get_fields_for_syntax(self) -> list[tuple[str, Any]]:
        """Get fields that should be included in BIND syntax output."""
        exclude_fields: set[str] = getattr(self, "_exclude_from_syntax", set())
        exclude_fields = exclude_fields.union({"comment"})

        fields = []
        for field_name in sorted(self.__class__.model_fields):
            if field_name not in exclude_fields:
                value = getattr(self, field_name, None)
                if value is not None:
                    if isinstance(value, list) and len(value) == 0:
                        continue
                    fields.append((field_name, value))
        return fields

    def _add_comment(self, lines: list[str], indent_level: int) -> None:
        if not self.comment:
            return

        indent = self._indent(indent_level)
        comment_lines = self.comment.split("\n")
        formatted_comments = [f"{indent}# {line}" for line in comment_lines]
        lines[0:0] = formatted_comments

    def _format_simple_option(self, name: str, value: Any, indent: str) -> str:
        """Format a simple key-value option."""
        bind_name = name.replace("_", "-")
        if isinstance(value, str) and (" " in value or "\t" in value):
            value = f'"{value}"'

        return f"{indent}{bind_name} {value};"

    def _format_bind_model(self, value: BindBaseModel, indent_level: int) -> str:
        """Format a nested BindBaseModel."""
        return value.model_bind_syntax(indent_level)

    def _format_list_item(self, item: Any, inner_indent: str) -> str:
        """Format a single list item."""
        if isinstance(item, tuple):
            if len(item) == 2 and item[1] is not None:
                return f"{inner_indent}{item[0]} port {item[1]};"
            return f"{inner_indent}{item[0]};"
        if isinstance(item, BindBaseModel):
            return item.model_bind_syntax(0).strip()
        if isinstance(item, str) and (" " in item or "\t" in item):
            item = f'"{item}"'

        return f"{inner_indent}{item};"

    def _format_list_option(self, name: str, value: list[Any], indent_level: int) -> str:
        """Format a list option."""
        bind_name = name.replace("_", "-")
        indent = self._indent(indent_level)
        inner_indent = self._indent(indent_level + 1)
        lines = [f"{indent}{bind_name} {{"]
        for item in sorted(value):
            lines.append(self._format_list_item(item, inner_indent))
        lines.append(f"{indent}}};")
        return "\n".join(lines)

    def _format_option(  # noqa: PLR0911
        self, name: str, value: Any, indent_level: int
    ) -> str | None:
        """Format a single option for BIND syntax."""
        if value is None:
            return None

        custom_formatter = getattr(self, f"_format_{name}", None)
        if custom_formatter:
            formatted = custom_formatter(value, indent_level)
            if formatted is None or isinstance(formatted, str):
                return formatted
            return None

        indent = self._indent(indent_level)
        if isinstance(value, list):
            if len(value) == 0:
                return None
            return self._format_list_option(name, value, indent_level)
        if isinstance(value, BindBaseModel):
            return self._format_bind_model(value, indent_level)
        if hasattr(value, "value"):
            return self._format_simple_option(name, value.value, indent)

        return self._format_simple_option(name, value, indent)

    def auto_format_fields(self, indent_level: int = 0) -> list[str]:
        """Automatically format all fields for BIND syntax."""
        lines = []
        for field_name, value in self._get_fields_for_syntax():
            formatted = self._format_option(field_name, value, indent_level)
            if formatted:
                lines.append(formatted)
        return lines

    def _compare(self, other: object, comparison_func: Callable[[Any, Any], bool]) -> bool | Any:
        """Common comparison logic."""
        if not isinstance(other, self.__class__):
            return NotImplemented

        self_attr = self.comparison_attr
        other_attr = other.comparison_attr

        if self_attr is None and other_attr is None:
            return True
        if self_attr is None:
            return True
        if other_attr is None:
            return False

        return comparison_func(self_attr, other_attr)

    def __lt__(self, other: object) -> bool:
        return self._compare(other, lambda a, b: a < b)

    def __le__(self, other: object) -> bool:
        return self._compare(other, lambda a, b: a <= b)

    def __gt__(self, other: object) -> bool:
        return self._compare(other, lambda a, b: a > b)

    def __ge__(self, other: object) -> bool:
        return self._compare(other, lambda a, b: a >= b)
