#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# KaanDGN ARGUS

"""RapidDNS — reverse IP domain lookup (ücretsiz, guest erişim).

Endpoint: https://rapiddns.io/api/search/<ip>?page=1&pagesize=100
Not: API key olmadan guest olarak sınırlı sayıda sonuç döner.
     Pro/Max üyelikte daha fazla sonuç ve export özelliği açılır.
"""

from providers.base import Provider, ProviderUnavailable
from providers.registry import register


@register
class RapidDNS(Provider):
    name = "rapiddns"
    enabled = True
    timeout = 15
    requires_key = False

    def query(self, ip, page=1, pagesize=100):
        r = self.get(
            f"https://rapiddns.io/api/search/{ip}",
            params={"page": page, "pagesize": pagesize},
        )
        if r.status_code == 429:
            raise ProviderUnavailable("rapiddns: rate-limited")
        if r.status_code != 200:
            raise ProviderUnavailable(f"rapiddns: HTTP {r.status_code}")
        try:
            j = r.json()
        except ValueError as e:
            raise ProviderUnavailable("rapiddns: json error") from e
        if j.get("status") != 200:
            raise ProviderUnavailable(f"rapiddns: {j.get('msg', 'unknown')}")
        data = j.get("data") or {}
        return {
            "total": data.get("total", 0),
            "records": data.get("data") or [],
        }