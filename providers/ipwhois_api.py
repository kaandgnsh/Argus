#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# KaanDGN ARGUS

"""ipwho.is — ücretsiz, keyless IP intelligence.

Endpoint: https://ipwho.is/<ip>
Limit: 10,000/month (ücretsiz)
Notlar:
  - HTTPS destekler (ip-api'nin ücretsiz sürümünde yok).
  - VPN/Proxy/Tor tespiti security bloğunda gelir.
  - timezone, currency, flag bilgisi döner.
"""

from providers.base import Provider, ProviderUnavailable
from providers.registry import register


@register
class IPWhoIs(Provider):
    name = "ipwhois_api"
    enabled = True
    timeout = 8
    requires_key = False

    def query(self, ip):
        r = self.get(f"https://ipwho.is/{ip}")
        if r.status_code == 429:
            raise ProviderUnavailable("ipwhois: rate-limited")
        if r.status_code != 200:
            raise ProviderUnavailable(f"ipwhois: HTTP {r.status_code}")
        try:
            j = r.json()
        except ValueError as e:
            raise ProviderUnavailable("ipwhois: json error") from e
        if not j.get("success", True):
            raise ProviderUnavailable(f"ipwhois: {j.get('message', 'unknown')}")
        return j