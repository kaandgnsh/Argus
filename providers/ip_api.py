#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# KaanDGN ARGUS

"""ip-api.com — ücretsiz, keyless IP geolocation + threat flags.

Endpoint: http://ip-api.com/json/<ip>
Limit: 45 req/min (ücretsiz)
Notlar:
  - HTTP ücretsiz, HTTPS ücretli. ARGUS proxy yoksa HTTP kabul edilir.
  - 25+ alan döner: ülke, şehir, ISP, ASN, proxy/hosting/mobile flag, reverse DNS.
"""

from providers.base import Provider, ProviderUnavailable
from providers.registry import register


@register
class IPApi(Provider):
    name = "ip_api"
    enabled = True
    timeout = 8
    requires_key = False

    FIELDS = (
        "status,message,continent,continentCode,country,countryCode,"
        "region,regionName,city,district,zip,lat,lon,timezone,offset,"
        "currency,isp,org,as,asname,reverse,mobile,proxy,hosting,query"
    )

    def query(self, ip):
        r = self.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": self.FIELDS, "lang": "en"},
        )
        if r.status_code == 429:
            raise ProviderUnavailable("ip_api: rate-limited (45/min)")
        if r.status_code != 200:
            raise ProviderUnavailable(f"ip_api: HTTP {r.status_code}")
        try:
            j = r.json()
        except ValueError as e:
            raise ProviderUnavailable("ip_api: json error") from e
        if j.get("status") != "success":
            raise ProviderUnavailable(f"ip_api: {j.get('message', 'unknown')}")
        return j