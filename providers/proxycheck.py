#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# KaanDGN ARGUS

"""proxycheck.io — VPN / Proxy / Tor tespiti (ücretsiz katman, keyless).

Endpoint: https://proxycheck.io/v2/<ip>?vpn=1&asn=1
Limit: 100 sorgu/gün (ücretsiz, key'siz)
Dönen: proxy, type (VPN/TOR/Proxy), provider, asn, country, city, isp
"""

from providers.base import Provider, ProviderUnavailable
from providers.registry import register


@register
class ProxyCheck(Provider):
    name = "proxycheck"
    enabled = True
    timeout = 8
    requires_key = False

    def query(self, ip):
        r = self.get(
            f"https://proxycheck.io/v2/{ip}",
            params={"vpn": 1, "asn": 1},
        )
        if r.status_code == 429:
            raise ProviderUnavailable("proxycheck: rate-limited (100/day free)")
        if r.status_code != 200:
            raise ProviderUnavailable(f"proxycheck: HTTP {r.status_code}")
        try:
            j = r.json()
        except ValueError as e:
            raise ProviderUnavailable("proxycheck: json error") from e
        if j.get("status") != "ok":
            raise ProviderUnavailable(f"proxycheck: {j.get('message', 'unknown')}")
        return j