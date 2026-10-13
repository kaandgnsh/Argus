#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# KaanDGN ARGUS

"""Yerel veri deposunu JSON, HTML, CSV, Markdown ve GraphViz DOT'a aktarır."""

import csv
import json
import os
import re
from datetime import datetime

from core import database as db


REPORTS_DIR = "reports"


def _ensure_dir():
    os.makedirs(REPORTS_DIR, exist_ok=True)


def _ts():
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def _safe_stem(name, prefix="report"):
    """Dosya adının rapor dizininin dışına çıkmasını engeller."""
    raw = str(name).strip() if name else f"{prefix}_{_ts()}"
    raw = os.path.basename(raw)
    stem = re.sub(r"[^A-Za-z0-9._-]+", "_", raw).strip("._")
    return stem or f"{prefix}_{_ts()}"


def _escape(value):
    """HTML metnini/öznitelik değerini güvenli biçimde kaçırır."""
    return (str(value).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;").replace("'", "&#x27;"))


def _json_value(value):
    if not isinstance(value, str):
        return value
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return value


def collect_scan_data():
    """SQLite verisini dışa aktarma fonksiyonlarının ortak biçimine dönüştürür."""
    entities = []
    for etype, value, data, source, confidence, created in db.get_entities(limit=5000):
        entities.append({
            "type": etype,
            "value": value,
            "data": _json_value(data),
            "source": source,
            "confidence": confidence,
            "created_at": created,
        })

    relations = []
    for source, target, kind, evidence, created in db.get_relations(limit=10000):
        relations.append({
            "source": source,
            "target": target,
            "relation": kind,
            "evidence": evidence,
            "created_at": created,
        })

    cases = []
    for name, note, created in db.list_cases():
        cases.append({"name": name, "note": note, "created_at": created})

    return {
        "generated_at": datetime.now().astimezone().isoformat(timespec='seconds'),
        "entities": entities,
        "relations": relations,
        "cases": cases,
    }


def export_json(payload, name=None):
    """Payload'ı JSON olarak kaydeder. Yol döner."""
    _ensure_dir()
    stem = _safe_stem(name)
    path = os.path.join(REPORTS_DIR, f"{stem}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, default=str, ensure_ascii=False)
        f.write("\n")
    return path


def export_html(payload, name=None, title="ARGUS Report"):
    """Payload'ı HTML rapor olarak kaydeder. Yol döner."""
    _ensure_dir()
    stem = _safe_stem(name)
    path = os.path.join(REPORTS_DIR, f"{stem}.html")

    body = ""
    if isinstance(payload, dict):
        for section, content in payload.items():
            body += f"<h2>{_escape(section)}</h2>"
            if isinstance(content, list):
                if content and isinstance(content[0], dict):
                    keys = list(dict.fromkeys(
                        key for row in content if isinstance(row, dict)
                        for key in row.keys()
                    ))
                    body += "<table><thead><tr>"
                    for key in keys:
                        body += f"<th>{_escape(key)}</th>"
                    body += "</tr></thead><tbody>"
                    for row in content:
                        if not isinstance(row, dict):
                            continue
                        body += "<tr>"
                        for key in keys:
                            value = row.get(key, "")
                            if isinstance(value, (dict, list)):
                                value = json.dumps(value, ensure_ascii=False, default=str)
                            body += f"<td>{_escape(value)}</td>"
                        body += "</tr>"
                    body += "</tbody></table>"
                else:
                    body += "<ul>"
                    for item in content:
                        body += f"<li>{_escape(item)}</li>"
                    body += "</ul>"
            elif isinstance(content, dict):
                body += "<table>"
                for key, value in content.items():
                    if isinstance(value, (dict, list)):
                        value = json.dumps(value, ensure_ascii=False, default=str)
                    body += f"<tr><th>{_escape(key)}</th><td>{_escape(value)}</td></tr>"
                body += "</table>"
            else:
                body += f"<p>{_escape(content)}</p>"
    else:
        body = f"<pre>{_escape(payload)}</pre>"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_escape(title)}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
         background: #0d1117; color: #c9d1d9; padding: 32px;
         max-width: 1100px; margin: auto; line-height: 1.5; }}
  h1 {{ color: #f85149; border-bottom: 1px solid #30363d; padding-bottom: 12px; }}
  h2 {{ color: #8b949e; margin-top: 32px; border-bottom: 1px solid #21262d;
       padding-bottom: 6px; }}
  table {{ border-collapse: collapse; width: 100%; margin: 16px 0; font-size: 14px; }}
  th, td {{ padding: 8px 12px; border: 1px solid #30363d; text-align: left;
           vertical-align: top; overflow-wrap: anywhere; }}
  th {{ background: #161b22; color: #c9d1d9; font-weight: 600; }}
  tr:hover {{ background: #161b22; }}
  ul {{ padding-left: 24px; }}
  li {{ margin: 4px 0; font-family: monospace; overflow-wrap: anywhere; }}
  pre {{ background: #161b22; padding: 16px; border-radius: 6px;
        overflow-x: auto; font-size: 13px; }}
  .meta {{ color: #6e7681; font-size: 12px; }}
  .footer {{ margin-top: 40px; padding-top: 16px; border-top: 1px solid #30363d;
            color: #6e7681; font-size: 12px; }}
</style>
</head>
<body>
<h1>{_escape(title)}</h1>
<p class="meta">Generated: {_escape(datetime.now().astimezone().isoformat(timespec='seconds'))}</p>
{body}
<div class="footer">
  ARGUS — Public OSINT &amp; Recon Framework — authorized use only.
</div>
</body>
</html>"""

    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
    return path


def _csv_value(value):
    if value is None:
        return ""
    if isinstance(value, (dict, list, tuple)):
        value = json.dumps(value, ensure_ascii=False, default=str)
    text = str(value)
    # Spreadsheet applications can interpret formula-like cells as formulas.
    if text.lstrip(" \t\r\n").startswith(("=", "+", "-", "@")):
        return "'" + text
    return text


def _write_csv(path, fields, rows):
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({field: _csv_value(row.get(field, "")) for field in fields})


def export_csv(payload, name=None):
    """Entity ve ilişki tablolarını ayrı CSV dosyalarına aktarır."""
    _ensure_dir()
    stem = _safe_stem(name)
    entities_path = os.path.join(REPORTS_DIR, f"entities_{stem}.csv")
    relations_path = os.path.join(REPORTS_DIR, f"relations_{stem}.csv")

    entities = payload.get("entities", []) if isinstance(payload, dict) else []
    relations = payload.get("relations", []) if isinstance(payload, dict) else []
    _write_csv(
        entities_path,
        ["type", "value", "data", "source", "confidence", "created_at"],
        [row for row in entities if isinstance(row, dict)],
    )
    _write_csv(
        relations_path,
        ["source", "target", "relation", "evidence", "created_at"],
        [row for row in relations if isinstance(row, dict)],
    )
    return [entities_path, relations_path]


def _md(value):
    if value is None:
        return ""
    if isinstance(value, (dict, list, tuple)):
        value = json.dumps(value, ensure_ascii=False, default=str)
    text = str(value)
    # Escape HTML before adding our own trusted <br> line-break markup.
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    # Prevent untrusted values from creating Markdown links/images or table cells.
    return (
        text.replace("\\", "\\\\")
        .replace("|", "\\|")
        .replace("[", "\\[")
        .replace("]", "\\]")
        .replace("(", "\\(")
        .replace(")", "\\)")
        .replace("!", "\\!")
        .replace("\r", " ")
        .replace("\n", "<br>")
        .replace(chr(96), "\\" + chr(96))
    )


def _markdown_table(headers, rows):
    out = [
        "| " + " | ".join(_md(h) for h in headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    for row in rows:
        if not isinstance(row, dict):
            continue
        out.append("| " + " | ".join(_md(row.get(h, "")) for h in headers) + " |")
    if len(out) == 2:
        out.append("| " + " | ".join("_No data_" if i == 0 else "" for i, _ in enumerate(headers)) + " |")
    return "\n".join(out)


def export_markdown(payload, name=None):
    """Payload'ı GitHub uyumlu Markdown raporu olarak kaydeder."""
    _ensure_dir()
    stem = _safe_stem(name)
    path = os.path.join(REPORTS_DIR, f"{stem}.md")
    payload = payload if isinstance(payload, dict) else {"result": payload}

    sections = [
        "# ARGUS Scan Report",
        "",
        f"**Generated:** {_md(payload.get('generated_at', 'unknown'))}",
        "",
        "## Entities",
        "",
        _markdown_table(
            ["type", "value", "source", "confidence", "created_at"],
            payload.get("entities", []),
        ),
        "",
        "## Relations",
        "",
        _markdown_table(
            ["source", "target", "relation", "evidence", "created_at"],
            payload.get("relations", []),
        ),
        "",
        "## Cases",
        "",
        _markdown_table(["name", "note", "created_at"], payload.get("cases", [])),
        "",
        "> Authorized use only. Validate findings against the original source.",
        "",
    ]

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(sections))
    return path


def _dot_quote(value):
    """DOT string literal'ını kaçırır; verileri DOT sözdizimi olarak yorumlatmaz."""
    text = str(value)
    text = (text.replace("\\", "\\\\").replace('"', '\\"')
            .replace("\r", "\\r").replace("\n", "\\n")
            .replace("\t", "\\t"))
    return '"' + text + '"'


def export_dot(name=None):
    """DB'deki entity ve relation'ları güvenli GraphViz DOT dosyasına aktarır."""
    _ensure_dir()
    stem = _safe_stem(name, prefix="graph")
    path = os.path.join(REPORTS_DIR, f"{stem}.dot")

    colors = {
        "ip": "#f85149", "domain": "#58a6ff", "email": "#a371f7",
        "username": "#3fb950", "phone": "#f0883e", "organization": "#d29922",
        "country": "#8b949e", "city": "#8b949e", "url": "#79c0ff",
        "hash": "#ff7b72", "file": "#ffa657", "repository": "#58a6ff",
        "certificate": "#d2a8ff", "infrastructure": "#ffa657",
    }

    entities = db.get_entities(limit=500)
    relations = db.get_relations(limit=1000)
    node_types = {}
    for etype, value, data, source, confidence, created in entities:
        node_types.setdefault(str(value), etype)
    for source, target, kind, evidence, created in relations:
        node_types.setdefault(str(source), "entity")
        node_types.setdefault(str(target), "entity")

    node_ids = {value: f"n{index}" for index, value in enumerate(node_types)}
    lines = [
        "digraph ARGUS {",
        "  rankdir=LR;",
        '  node [shape=box, style="rounded,filled", fontname="Helvetica", '
        'fillcolor="#161b22", color="#30363d", fontcolor="#c9d1d9"];',
        '  edge [fontname="Helvetica", fontsize=10, color="#8b949e", fontcolor="#8b949e"];',
    ]

    for value, etype in node_types.items():
        label = f"{etype}\\n{value}" if etype != "entity" else value
        color = colors.get(etype, "#8b949e")
        lines.append(
            f"  {node_ids[value]} [label={_dot_quote(label)}, color={_dot_quote(color)}];"
        )

    for source, target, kind, evidence, created in relations:
        lines.append(
            f"  {node_ids[str(source)]} -> {node_ids[str(target)]} "
            f"[label={_dot_quote(kind)}];"
        )

    lines.append("}")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    return path
