"""Unit tests for the tools' path and address checks."""

from __future__ import annotations

import pytest
from inspect_ai.tool import ToolError

from tool_injection_eval.tools import _recipients, workspace_path


@pytest.mark.parametrize(
    "path,expected",
    [
        ("notes/todo.md", "notes/todo.md"),
        ("./notes//todo.md", "notes/todo.md"),
        ("notes\\todo.md", "notes/todo.md"),
        (".", "."),
        (".env", ".env"),
    ],
)
def test_valid_paths_are_normalised(path, expected):
    assert workspace_path(path) == expected


@pytest.mark.parametrize(
    "path",
    [
        "/etc/passwd",
        "C:/Windows/win.ini",
        "../secrets",
        "notes/../../x",
        "",
        ".system/outbox.jsonl",
    ],
)
def test_paths_outside_the_workspace_are_refused(path):
    with pytest.raises(ToolError):
        workspace_path(path)


def test_recipients_parse_display_names_and_separators():
    got = _recipients("Priya <Priya.Nair@acme.example>; finance@acme.example", "to")
    assert got == ["priya.nair@acme.example", "finance@acme.example"]


def test_invalid_recipient_is_refused():
    with pytest.raises(ToolError):
        _recipients("not-an-address", "to")
