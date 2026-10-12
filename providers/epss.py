#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# KaanDGN ARGUS

"""EPSS — Exploit Prediction Scoring System (FIRST.org).

Endpoint: https://api.first.org/data/v1/epss?cve=CVE-YYYY-XXXX
Ücretsiz, keyless.
Dönen: epss (0-1 arası sömürülme olasılığı), percentile.
"""

from providers.base import Provider, ProviderUnavailable
from providers.registry import register


@register
class EPSS(Provider):
    name = "epss"
    enabled = True
    timeout = 10
    requires_key = False

    URL = "https://api.first.org/data/v1/epss"

    def query(self, cve_id):
        cve = cve_id.upper().strip()
        r = self.get(self.URL, params={"cve": cve})
        if r.status_code != 200:
            raise ProviderUnavailable(f"epss: HTTP {r.status_code}")
        try:
            j = r.json()
        except ValueError as e:
            raise ProviderUnavailable("epss: json error") from e

        data = j.get("data") or []
        if not data:
            return None

        entry = data[0]
        try:
            epss = float(entry.get("epss", 0))
            percentile = float(entry.get("percentile", 0))
        except (TypeError, ValueError):
            return None

        return {
            "cve": entry.get("cve"),
            "epss": epss,
            "percentile": percentile,
            "date": entry.get("date"),
        }