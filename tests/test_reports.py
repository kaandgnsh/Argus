#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# KaanDGN ARGUS

import csv
from pathlib import Path

from core import reports


def test_collect_scan_data_normalizes_database_rows(monkeypatch):
    monkeypatch.setattr(
        reports.db,
        "get_entities",
        lambda limit: [("domain", "example.com", '{"a": 1}', "rdap", "FOUND", 123.0)],
    )
    monkeypatch.setattr(
        reports.db,
        "get_relations",
        lambda limit: [("example.com", "1.2.3.4", "resolves_to", "DNS", 124.0)],
    )
    monkeypatch.setattr(
        reports.db, "list_cases", lambda: [("case-1", "test note", 125.0)]
    )

    payload = reports.collect_scan_data()

    assert payload["entities"][0]["data"] == {"a": 1}
    assert payload["relations"][0]["relation"] == "resolves_to"
    assert payload["cases"][0]["name"] == "case-1"
    assert payload["generated_at"]


def test_csv_and_markdown_exports_are_created_and_safely_encoded(tmp_path, monkeypatch):
    monkeypatch.setattr(reports, "REPORTS_DIR", str(tmp_path))
    payload = {
        "generated_at": "2026-10-12T12:00:00+03:00",
        "entities": [
            {
                "type": "domain",
                "value": '=HYPERLINK("https://example.com")',
                "data": {"note": "test"},
                "source": "unit-test",
                "confidence": "FOUND",
                "created_at": 1,
            },
            {
                "type": "username",
                "value": "bad|value\nsecond line",
                "data": {},
                "source": "unit-test",
                "confidence": "LIKELY",
                "created_at": 2,
            },
        ],
        "relations": [
            {
                "source": "example.com",
                "target": "1.2.3.4",
                "relation": "resolves_to",
                "evidence": "DNS",
                "created_at": 3,
            }
        ],
        "cases": [],
    }

    csv_paths = reports.export_csv(payload, name="unit-test")
    assert len(csv_paths) == 2
    for path in csv_paths:
        assert Path(path).is_file()

    with open(csv_paths[0], newline="", encoding="utf-8-sig") as file:
        rows = list(csv.DictReader(file))
    assert rows[0]["value"].startswith("'=HYPERLINK")

    md_path = reports.export_markdown(payload, name="unit-test")
    markdown = Path(md_path).read_text(encoding="utf-8")
    assert r"bad\|value<br>second line" in markdown
    assert "## Entities" in markdown
    assert "## Relations" in markdown


def test_dot_export_uses_safe_ids_and_escapes_untrusted_values(tmp_path, monkeypatch):
    monkeypatch.setattr(reports, "REPORTS_DIR", str(tmp_path))
    dangerous = 'target";\n evil'
    monkeypatch.setattr(
        reports.db,
        "get_entities",
        lambda limit: [("domain", dangerous, "{}", "test", "UNKNOWN", 1.0)],
    )
    monkeypatch.setattr(
        reports.db,
        "get_relations",
        lambda limit: [(dangerous, "neighbor", "related_to", "", 2.0)],
    )

    path = reports.export_dot(name="unit-test")
    dot = Path(path).read_text(encoding="utf-8")

    assert "n0 [label=" in dot
    assert "n0 -> n1" in dot
    assert r"target\";\n evil" in dot
    assert '  "target"' not in dot


def test_report_names_cannot_escape_output_directory(tmp_path, monkeypatch):
    monkeypatch.setattr(reports, "REPORTS_DIR", str(tmp_path))
    path = reports.export_json({"ok": True}, name="../../outside")
    assert Path(path).parent == tmp_path
    assert Path(path).name == "outside.json"
