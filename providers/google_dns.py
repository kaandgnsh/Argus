5#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# KaanDGN ARGUS

"""Google Public DNS-over-HTTPS provider."""

from providers.base import Provider, ProviderUnavailable
from providers.registry import register


@register
class GoogleDNS(Provider):
    name = "google_dns"
    enabled = True
    timeout = 6
    URL = "https://dns.google/resolve"

    def query(self, domain, rtype="A"):
        r = self.get(self.URL, params={"name": domain, "type": rtype.upper()},
                     headers={"Accept": "application/dns-json"})
        if r.status_code != 200:
            raise ProviderUnavailable(f"google_dns: HTTP {r.status_code}")
        try:
            j = r.json()
        except ValueError as e:
            raise ProviderUnavailable("google_dns: json error") from e
        answers = j.get("Answer") or []
        return [a.get("data") for a in answers if a.get("data")]