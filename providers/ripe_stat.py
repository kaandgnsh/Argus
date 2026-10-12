#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# KaanDGN ARGUS

"""RIPE Stat API — BGP prefix ve ASN bilgisi (ücretsiz, keyless).

Endpoint: https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS<asn>
Kaynak: RIPE NCC tarafından işletilir, resmi RIR verisi.
Not: BGPView API (api.bgpview.io) 2026 ortasından beri NXDOMAIN döndüğü için
     bu provider onun yerine yazıldı.
"""

from providers.base import Provider, ProviderUnavailable
from providers.registry import register


@register
class RIPEStat(Provider):
    name = "ripe_stat"
    enabled = True
    timeout = 10
    requires_key = False

    BASE = "https://stat.ripe.net/data"

    def prefixes(self, asn):
        """Belirtilen ASN için duyurulan tüm prefix'leri döndürür."""
        asn = str(asn).replace("AS", "").replace("as", "")
        r = self.get(
            f"{self.BASE}/announced-prefixes/data.json",
            params={"resource": f"AS{asn}"},
        )
        if r.status_code != 200:
            raise ProviderUnavailable(f"ripe_stat: HTTP {r.status_code}")
        try:
            j = r.json()
        except ValueError as e:
            raise ProviderUnavailable("ripe_stat: json error") from e
        data = j.get("data") or {}
        return data.get("prefixes") or []

    def as_overview(self, asn):
        """ASN hakkında özet bilgi (holder, country, type)."""
        asn = str(asn).replace("AS", "").replace("as", "")
        r = self.get(
            f"{self.BASE}/as-overview/data.json",
            params={"resource": f"AS{asn}"},
        )
        if r.status_code != 200:
            raise ProviderUnavailable(f"ripe_stat: HTTP {r.status_code}")
        try:
            j = r.json()
        except ValueError as e:
            raise ProviderUnavailable("ripe_stat: json error") from e
        return j.get("data") or {}