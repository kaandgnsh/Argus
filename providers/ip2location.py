#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# KaanDGN ARGUS

"""ip2location.io — ücretsiz katman, Türkiye'de ilçe düzeyine inebilir.

Endpoint: https://api.ip2location.io/?ip=<ip>
Notlar: Free tier bazen API key ister; key yoksa 401 döner, ARGUS çökmez.
        IP2LOCATION_API_KEY env değişkeni ile key eklenebilir.
"""

import os

from providers.base import Provider, ProviderUnavailable
from providers.registry import register


@register
class IP2Location(Provider):
    name = "ip2location"
    enabled = True
    timeout = 8
    requires_key = False

    def query(self, ip):
        params = {"ip": ip}
        key = os.environ.get("IP2LOCATION_API_KEY")
        if key:
            params["key"] = key
        r = self.get("https://api.ip2location.io/", params=params)
        if r.status_code == 401:
            raise ProviderUnavailable(
                "ip2location: API key gerekli (ücretsiz kayıt). "
                "IP2LOCATION_API_KEY env değişkenine ekle."
            )
        if r.status_code == 429:
            raise ProviderUnavailable("ip2location: rate-limited")
        if r.status_code != 200:
            raise ProviderUnavailable(f"ip2location: HTTP {r.status_code}")
        try:
            j = r.json()
        except ValueError as e:
            raise ProviderUnavailable("ip2location: json error") from e
        if j.get("error"):
            raise ProviderUnavailable(f"ip2location: {j['error']}")
        return j