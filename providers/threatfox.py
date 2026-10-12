#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# KaanDGN ARGUS

"""ThreatFox (abuse.ch) — IOC bazlı malware / C2 / botnet tespiti.

Endpoint: https://threatfox-api.abuse.ch/api/v1/
Method:   POST {"query": "search_ioc", "search_term": "<ioc>"}
Auth:     Keyless (public API, rate-limited)
Notlar:   URLhaus ile aynı ekip (abuse.ch) tarafından işletilir.
          URLhaus web kötücül URL odaklıdır, ThreatFox IOC odaklıdır.
"""

from providers.base import Provider, ProviderUnavailable
from providers.registry import register


@register
class ThreatFox(Provider):
    name = "threatfox"
    enabled = True
    timeout = 10
    requires_key = False

    API = "https://threatfox-api.abuse.ch/api/v1/"

    def query(self, ioc):
        r = self.post(self.API, json={"query": "search_ioc", "search_term": ioc})
        if r.status_code == 429:
            raise ProviderUnavailable("threatfox: rate-limited")
        if r.status_code != 200:
            raise ProviderUnavailable(f"threatfox: HTTP {r.status_code}")
        try:
            j = r.json()
        except ValueError as e:
            raise ProviderUnavailable("threatfox: json error") from e

        status = j.get("query_status")
        if status == "no_result":
            return {"query_status": "no_result", "data": []}
        if status == "illegal_search_term":
            raise ProviderUnavailable("threatfox: illegal search term")
        if status != "ok":
            raise ProviderUnavailable(f"threatfox: {status}")
        return j