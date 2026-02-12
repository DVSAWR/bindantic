from __future__ import annotations

from typing import Any, ClassVar

import pytest

from bindantic import BindBaseModel


class MockBindBaseModel(BindBaseModel):
    """Concrete implementation for testing BindBaseModel."""

    name: str
    value: int = 0
    nested_list: list[str] | None = None
    nested_model: MockBindBaseModel | None = None

    _exclude_from_syntax: ClassVar[set[str]] = {"value"}

    @property
    def comparison_attr(self) -> Any:
        return self.name

    def model_bind_syntax(self, indent_level: int = 0) -> str:
        lines = []
        indent = "    " * indent_level

        if self.comment:
            comment_lines = self.comment.split("\n")
            for line in comment_lines:
                lines.append(f"{indent}# {line}")

        lines.append(f'{indent}name "{self.name}";')

        if self.nested_list:
            lines.append(f"{indent}nested-list {{")
            inner_indent = "    " * (indent_level + 1)
            for item in sorted(self.nested_list):
                lines.append(f'{inner_indent}"{item}";')
            lines.append(f"{indent}}};")

        if self.nested_model:
            lines.append(self.nested_model.model_bind_syntax(indent_level))

        return "\n".join(lines)


class TestBindBaseModel:
    """Test suite for BindBaseModel abstract base class."""

    def test_init_with_comment(self):
        """Test initialization with comment."""
        model = MockBindBaseModel(name="test", comment="This is a comment")
        assert model.name == "test"
        assert model.comment == "This is a comment"

    def test_init_without_comment(self):
        """Test initialization without comment."""
        model = MockBindBaseModel(name="test")
        assert model.name == "test"
        assert model.comment is None

    def test_indent_method(self):
        """Test the _indent method."""
        model = MockBindBaseModel(name="test")
        assert model._indent(0) == ""
        assert model._indent(1) == "    "
        assert model._indent(2) == "        "
        assert model._indent(3) == "            "

    def test_get_fields_for_syntax_excludes(self):
        """Test that excluded fields are not included in syntax."""
        model = MockBindBaseModel(name="test", value=42)
        fields = model._get_fields_for_syntax()
        field_names = [name for name, _ in fields]

        assert "name" in field_names
        assert "value" not in field_names
        assert "comment" not in field_names

    def test_format_simple_option(self):
        """Test formatting simple key-value options."""
        model = MockBindBaseModel(name="test")

        result = model._format_simple_option("test_option", "value", "    ")
        assert result == "    test-option value;"

        result = model._format_simple_option("enabled", "yes", "    ")
        assert result == "    enabled yes;"

        result = model._format_simple_option("count", 42, "    ")
        assert result == "    count 42;"

    def test_format_list_option(self):
        """Test formatting list options."""
        model = MockBindBaseModel(name="test")

        result = model._format_list_option("servers", ["server1", "server2"], 1)
        lines = result.split("\n")
        assert lines[0] == "    servers {"
        assert "server1;" in lines[1] or "server2;" in lines[1]
        assert lines[-1] == "    };"

    def test_format_list_item(self):
        """Test formatting individual list items."""
        model = MockBindBaseModel(name="test")

        result = model._format_list_item("item", "        ")
        assert result == "        item;"

        result = model._format_list_item(("192.168.1.1", 53), "        ")
        assert result == "        192.168.1.1 port 53;"

        result = model._format_list_item(("192.168.1.1", None), "        ")
        assert result == "        192.168.1.1;"

    def test_auto_format_fields(self):
        """Test automatic field formatting."""
        model = MockBindBaseModel(name="example", nested_list=["item1", "item2"])

        lines = model.auto_format_fields(indent_level=1)

        assert any("name example;" in line for line in lines)
        assert any("nested-list {" in line for line in lines)

    def test_add_comment_method(self):
        """Test adding comments to lines."""
        model = MockBindBaseModel(name="test", comment="Line 1\nLine 2")
        lines = ["    actual line 1", "    actual line 2"]

        model._add_comment(lines, indent_level=1)

        assert lines[0] == "    # Line 1"
        assert lines[1] == "    # Line 2"
        assert lines[2] == "    actual line 1"

    def test_add_comment_no_comment(self):
        """Test that no comment is added when comment is None."""
        model = MockBindBaseModel(name="test")
        lines = ["    line 1"]

        model._add_comment(lines, indent_level=1)
        assert lines == ["    line 1"]

    def test_comparison_operators(self):
        """Test comparison operators using name as comparison attribute."""
        model1 = MockBindBaseModel(name="aaa")
        model2 = MockBindBaseModel(name="bbb")
        model3 = MockBindBaseModel(name="aaa")

        assert model1 < model2
        assert not model2 < model1

        assert model2 > model1
        assert not model1 > model2

        assert model1 <= model3
        assert model1 >= model3

        class NoneModel(MockBindBaseModel):
            @property
            def comparison_attr(self) -> Any:
                return None

        none_model1 = NoneModel(name="test")
        none_model2 = NoneModel(name="test2")

        assert none_model1 <= none_model2
        assert none_model1 >= none_model2

    def test_comparison_with_different_type(self):
        """Test comparison with different types returns NotImplemented."""
        model = MockBindBaseModel(name="test")

        result = model.__lt__("not a model")
        assert result is NotImplemented

        result = model.__le__(123)
        assert result is NotImplemented

    def test_model_bind_syntax_implementation(self):
        """Test concrete implementation of model_bind_syntax."""
        model = MockBindBaseModel(name="test")
        result = model.model_bind_syntax()
        assert result == 'name "test";'

    def test_model_bind_syntax_with_nested(self):
        """Test model_bind_syntax with nested structures."""
        nested = MockBindBaseModel(name="nested")
        model = MockBindBaseModel(
            name="parent",
            nested_list=["item1", "item2"],
            nested_model=nested,
            comment="Parent model",
        )

        result = model.model_bind_syntax()
        lines = result.split("\n")

        assert "# Parent model" in lines[0]
        assert 'name "parent";' in result
        assert "nested-list {" in result
        assert '"item1";' in result
        assert '"item2";' in result
        assert 'name "nested";' in result

    def test_inheritance_and_abstract_method(self):
        """Test that abstract methods must be implemented."""

        class IncompleteModel(BindBaseModel):
            name: str = ""

        with pytest.raises(TypeError):
            IncompleteModel()

    def test_pydantic_integration(self):
        """Test that BindBaseModel works as a Pydantic model."""
        model = MockBindBaseModel(name="test", value="42")
        assert model.name == "test"
        assert model.value == 42

        with pytest.raises(ValueError):
            MockBindBaseModel(name=123)

    def test_serialization(self):
        """Test model serialization methods."""
        model = MockBindBaseModel(name="test", value=42)

        data = model.model_dump()
        assert data["name"] == "test"
        assert data["value"] == 42

        json_str = model.model_dump_json()
        assert "test" in json_str
        assert "42" in json_str


class TestBindBaseModelEdgeCases:
    """Edge case tests for BindBaseModel."""

    def test_empty_list_formatting(self):
        """Test formatting empty lists."""
        model = MockBindBaseModel(name="test")
        model.nested_list = []
        fields = model._get_fields_for_syntax()
        assert not any(name == "nested_list" for name, _ in fields)

    def test_none_values_formatting(self):
        """Test that None values are not formatted."""
        model = MockBindBaseModel(name="test", nested_list=None, nested_model=None)

        lines = model.auto_format_fields()
        assert len(lines) == 1
        assert "name test;" in lines[0]

    def test_special_characters_in_strings(self):
        """Test handling of special characters in strings."""
        model = MockBindBaseModel(name="test with spaces")
        result = model._format_simple_option("name", model.name, "")
        assert result == 'name "test with spaces";'

    def test_multiline_comment_indentation(self):
        """Test indentation of multiline comments."""
        model = MockBindBaseModel(name="test", comment="First line\nSecond line\nThird line")

        lines = []
        model._add_comment(lines, indent_level=2)

        assert lines[0] == "        # First line"
        assert lines[1] == "        # Second line"
        assert lines[2] == "        # Third line"

    def test_custom_formatter_method(self):
        """Test custom formatter method."""

        class CustomModel(MockBindBaseModel):
            custom_field: str = ""

            def _format_custom_field(self, value: str, indent_level: int) -> str:
                indent = self._indent(indent_level)
                return f"{indent}cust-field: {value};"

        model = CustomModel(name="test", custom_field="special")
        formatted = model._format_option("custom_field", "special", 1)
        assert formatted == "    cust-field: special;"
