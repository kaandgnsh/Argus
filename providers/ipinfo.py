#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# KaanDGN ARGUS

"""ipinfo.io — ücretsiz katman (50k/ay key'siz, 1000/gün limitsiz).

Endpoint: https://ipinfo.io/<ip>/json
Notlar: Turkiye'de bazi ISP'ler icin sehir duzeyi daha tutarli.
"""

from providers.base import Provider, ProviderUnavailable
from providers.registry import register


@register
class IPInfo(Provider):
    name = "ipinfo"
    enabled = True
    timeout = 8
    requires_key = False

    def query(self, ip):
        r = self.get(f"https://ipinfo.io/{ip}/json")
        if r.status_code == 429:
            raise ProviderUnavailable("ipinfo: rate-limited")
        if r.status_code != 200:
            raise ProviderUnavailable(f"ipinfo: HTTP {r.status_code}")
        try:
            j = r.json()
        except ValueError as e:
            raise ProviderUnavailable("ipinfo: json error") from e
        if j.get("bogon"):
            raise ProviderUnavailable("ipinfo: bogon IP")
        return j