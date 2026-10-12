#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# KaanDGN ARGUS

"""CISA KEV — Known Exploited Vulnerabilities kataloğu.

Kaynak: ABD CISA (Cybersecurity and Infrastructure Security Agency)
Endpoint: JSON feed (public, keyless)
URL: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

- Katalog ~1MB. İlk çekilişte indirilir, 24 saat cache'lenir.
- Her CVE için: vendor, product, ransomware_use, due_date.
"""

from providers.base import Provider, ProviderUnavailable
from providers.registry import register
from core import cache


@register
class CISAKEV(Provider):
    name = "cisa_kev"
    enabled = True
    timeout = 20
    requires_key = False

    URL = ("https://www.cisa.gov/sites/default/files/feeds/"
           "known_exploited_vulnerabilities.json")
    CACHE_NS = "cisa_kev_catalog"

    def _load_catalog(self):
        """Kataloğu cache'ten veya CISA'dan yükler."""
        cached = cache.get(self.CACHE_NS, {"v": 1})
        if cached and cached.get("catalog"):
            return cached["catalog"]

        r = self.get(self.URL)
        if r.status_code != 200:
            raise ProviderUnavailable(f"cisa_kev: HTTP {r.status_code}")
        try:
            data = r.json()
        except ValueError as e:
            raise ProviderUnavailable("cisa_kev: json error") from e

        vulns = data.get("vulnerabilities") or []
        # hızlı lookup için CVE -> entry map
        index = {}
        for v in vulns:
            cve = (v.get("cveID") or "").upper()
            if cve:
                index[cve] = {
                    "vendor": v.get("vendorProject", ""),
                    "product": v.get("product", ""),
                    "vulnerabilityName": v.get("vulnerabilityName", ""),
                    "dateAdded": v.get("dateAdded", ""),
                    "dueDate": v.get("dueDate", ""),
                    "ransomware_use": v.get("knownRansomwareCampaignUse", "Unknown"),
                    "shortDescription": v.get("shortDescription", ""),
                    "requiredAction": v.get("requiredAction", ""),
                    "notes": v.get("notes", ""),
                }

        cache.set(self.CACHE_NS, {"v": 1},
                  {"catalog": index, "count": len(index)})
        return index

    def lookup(self, cve_id):
        """CVE KEV kataloğunda mı?"""
        cve = cve_id.upper().strip()
        catalog = self._load_catalog()
        return catalog.get(cve)

    def count(self):
        try:
            return len(self._load_catalog())
        except Exception:
            return 0