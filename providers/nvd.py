#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# KaanDGN ARGUS

"""NVD — National Vulnerability Database (NIST).

Endpoint: https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-YYYY-XXXX
Ücretsiz, keyless (rate-limited — 5 req/30s key'siz).
Dönen: CVE detayı, CVSS skoru, CWE, referanslar.
"""

from providers.base import Provider, ProviderUnavailable
from providers.registry import register


@register
class NVD(Provider):
    name = "nvd"
    enabled = True
    timeout = 15
    requires_key = False

    URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def query(self, cve_id):
        cve = cve_id.upper().strip()
        r = self.get(self.URL, params={"cveId": cve})
        if r.status_code == 429:
            raise ProviderUnavailable("nvd: rate-limited (5 req/30s)")
        if r.status_code != 200:
            raise ProviderUnavailable(f"nvd: HTTP {r.status_code}")
        try:
            j = r.json()
        except ValueError as e:
            raise ProviderUnavailable("nvd: json error") from e

        vulns = j.get("vulnerabilities") or []
        if not vulns:
            return None

        cve_obj = vulns[0].get("cve") or {}
        cve_id_val = cve_obj.get("id", cve)

        # Açıklama
        desc = ""
        for d in cve_obj.get("descriptions") or []:
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break

        # CVSS skoru (öncelik: v3.1, v3.0, v2)
        cvss = None
        metrics = cve_obj.get("metrics") or {}
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            arr = metrics.get(key)
            if arr:
                m = arr[0]
                cvss_data = m.get("cvssData") or {}
                cvss = {
                    "version": cvss_data.get("version"),
                    "vector": cvss_data.get("vectorString"),
                    "base_score": cvss_data.get("baseScore"),
                    "base_severity": (cvss_data.get("baseSeverity")
                                      or m.get("baseSeverity")),
                    "exploitability": cvss_data.get("exploitabilityScore"),
                    "impact": cvss_data.get("impactScore"),
                }
                break

        # CWE
        cwes = []
        for w in cve_obj.get("weaknesses") or []:
            for d in w.get("description") or []:
                if d.get("lang") == "en":
                    cwes.append(d.get("value"))
        cwes = [c for c in cwes if c and c != "NVD-CWE-noinfo"]

        # Referanslar
        refs = []
        for r_ in (cve_obj.get("references") or [])[:8]:
            url = r_.get("url")
            if url:
                refs.append(url)

        # Yayın tarihleri
        published = cve_obj.get("published")
        modified = cve_obj.get("lastModified")

        return {
            "id": cve_id_val,
            "description": desc,
            "cvss": cvss,
            "cwe": cwes[:5],
            "references": refs,
            "published": published,
            "modified": modified,
        }