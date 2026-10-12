#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# KaanDGN ARGUS

"""Rapor export — JSON, HTML, GraphViz DOT."""

import json
import os
from datetime import datetime

from core import database as db


REPORTS_DIR = "reports"


def _ensure_dir():
    os.makedirs(REPORTS_DIR, exist_ok=True)


def _ts():
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def _escape(s):
    return (str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;"))


def export_json(payload, name=None):
    """Payload'ı JSON olarak kaydeder. Yol döner."""
    _ensure_dir()
    name = name or f"report_{_ts()}"
    path = os.path.join(REPORTS_DIR, f"{name}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, default=str, ensure_ascii=False)
    return path


def export_html(payload, name=None, title="ARGUS Report"):
    """Payload'ı HTML rapor olarak kaydeder. Yol döner."""
    _ensure_dir()
    name = name or f"report_{_ts()}"
    path = os.path.join(REPORTS_DIR, f"{name}.html")

    body = ""
    if isinstance(payload, dict):
        for section, content in payload.items():
            body += f"<h2>{_escape(section)}</h2>"
            if isinstance(content, list):
                if content and isinstance(content[0], dict):
                    keys = list(content[0].keys())
                    body += "<table><thead><tr>"
                    for k in keys:
                        body += f"<th>{_escape(k)}</th>"
                    body += "</tr></thead><tbody>"
                    for row in content:
                        body += "<tr>"
                        for k in keys:
                            body += f"<td>{_escape(row.get(k, ''))}</td>"
                        body += "</tr>"
                    body += "</tbody></table>"
                else:
                    body += "<ul>"
                    for item in content:
                        body += f"<li>{_escape(item)}</li>"
                    body += "</ul>"
            elif isinstance(content, dict):
                body += "<table>"
                for k, v in content.items():
                    body += f"<tr><th>{_escape(k)}</th><td>{_escape(v)}</td></tr>"
                body += "</table>"
            else:
                body += f"<p>{_escape(content)}</p>"
    else:
        body = f"<pre>{_escape(payload)}</pre>"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{_escape(title)}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
         background: #0d1117; color: #c9d1d9; padding: 40px;
         max-width: 960px; margin: auto; line-height: 1.5; }}
  h1 {{ color: #f85149; border-bottom: 1px solid #30363d; padding-bottom: 12px; }}
  h2 {{ color: #58a6ff; margin-top: 32px; border-bottom: 1px solid #21262d;
       padding-bottom: 6px; }}
  table {{ border-collapse: collapse; width: 100%; margin: 16px 0; font-size: 14px; }}
  th, td {{ padding: 8px 12px; border: 1px solid #30363d; text-align: left;
           vertical-align: top; }}
  th {{ background: #161b22; color: #8b949e; font-weight: 600; }}
  tr:hover {{ background: #161b22; }}
  ul {{ padding-left: 24px; }}
  li {{ margin: 4px 0; font-family: monospace; color: #79c0ff; }}
  pre {{ background: #161b22; padding: 16px; border-radius: 6px;
        overflow-x: auto; font-size: 13px; }}
  .meta {{ color: #6e7681; font-size: 12px; }}
  .footer {{ margin-top: 40px; padding-top: 16px; border-top: 1px solid #30363d;
            color: #6e7681; font-size: 12px; }}
</style>
</head>
<body>
<h1>{_escape(title)}</h1>
<p class="meta">Generated: {datetime.now().isoformat(timespec='seconds')}</p>
{body}
<div class="footer">
  ARGUS — Public OSINT &amp; Recon Framework — authorized use only.
</div>
</body>
</html>"""

    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
    return path


def export_dot(name=None):
    """DB'deki entity ve relation'ları GraphViz DOT olarak kaydeder."""
    _ensure_dir()
    name = name or f"graph_{_ts()}"
    path = os.path.join(REPORTS_DIR, f"{name}.dot")

    colors = {
        "ip": "#f85149", "domain": "#58a6ff", "email": "#a371f7",
        "username": "#3fb950", "phone": "#f0883e", "organization": "#d29922",
        "country": "#8b949e", "city": "#8b949e", "url": "#79c0ff",
        "hash": "#ff7b72", "file": "#ffa657", "repository": "#58a6ff",
        "certificate": "#d2a8ff", "infrastructure": "#ffa657",
    }

    lines = [
        "digraph ARGUS {",
        '  rankdir=LR;',
        '  node [shape=box, style="rounded,filled", fontname="Helvetica",'
        ' fillcolor="#161b22", color="#30363d", fontcolor="#c9d1d9"];',
        '  edge [fontname="Helvetica", fontsize=10, color="#8b949e", fontcolor="#8b949e"];',
    ]

    entities = db.get_entities(limit=500)
    seen = set()
    for etype, value, data, source, conf, ts in entities:
        node_id = f'"{value}"'
        if node_id in seen:
            continue
        seen.add(node_id)
        color = colors.get(etype, "#8b949e")
        label = f"{etype}\\n{value}".replace('"', '\\"')
        lines.append(f'  {node_id} [label="{label}", color="{color}"];')

    rels = db.get_relations(limit=1000)
    for src, dst, kind, ev, ts in rels:
        s = str(src).replace('"', '\\"')
        d = str(dst).replace('"', '\\"')
        k = str(kind).replace('"', '\\"')
        lines.append(f'  "{s}" -> "{d}" [label="{k}"];')

    lines.append("}")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    return path