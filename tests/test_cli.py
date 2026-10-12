#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# KaanDGN ARGUS

from argus import _cli
from core.cli import parse
from core import reports, tools


def test_list_tools_flag_is_handled(monkeypatch):
    calls = []
    monkeypatch.setattr(tools, "list_tools", lambda: calls.append("listed"))

    _cli(parse(["--list-tools"]))

    assert calls == ["listed"]


def test_install_tools_flag_is_handled(monkeypatch):
    calls = []
    monkeypatch.setattr(
        tools, "install",
        lambda tool, confirm=True: calls.append((tool, confirm)),
    )

    _cli(parse(["--install-tools", "exiftool"]))

    assert calls == [("exiftool", True)]


def test_export_all_flag_calls_every_exporter(monkeypatch):
    calls = []
    monkeypatch.setattr(reports, "collect_scan_data", lambda: {"entities": [], "relations": [], "cases": []})
    monkeypatch.setattr(reports, "export_json", lambda payload: calls.append("json") or "a.json")
    monkeypatch.setattr(reports, "export_html", lambda payload, title: calls.append("html") or "a.html")
    monkeypatch.setattr(reports, "export_csv", lambda payload: calls.append("csv") or ["entities.csv", "relations.csv"])
    monkeypatch.setattr(reports, "export_markdown", lambda payload: calls.append("markdown") or "a.md")
    monkeypatch.setattr(reports, "export_dot", lambda: calls.append("dot") or "a.dot")

    _cli(parse(["--export-all"]))

    assert calls == ["json", "html", "csv", "markdown", "dot"]
