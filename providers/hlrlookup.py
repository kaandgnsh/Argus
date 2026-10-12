#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# KaanDGN ARGUS

"""HLR Lookup — canlı ağ durumu, gerçek operatör, numara taşınmışlık (MNP).

Endpoint: https://api.hlrlookup.com/api/v1/hlr-lookup
Ücretsiz katman: 200 kredi (kayıt sonrası doğrulama ile).
API key: https://www.hlrlookup.com/
Env: HLRLOOKUP_API_KEY, HLRLOOKUP_API_SECRET
     (HLRLOOKUP_API_KEY yoksa ABUSECH_AUTH_KEY fallback)
"""

import os

from providers.base import Provider, ProviderUnavailable
from providers.registry import register


@register
class HLRLookup(Provider):
    name = "hlrlookup"
    enabled = True
    timeout = 12
    requires_key = True
    auth_key = None

    BASE = "https://api.hlrlookup.com/api/v1/hlr-lookup"

    def __init__(self, **opts):
        super().__init__(**opts)
        self.api_key = (
            os.environ.get("HLRLOOKUP_API_KEY")
            or getattr(self, "auth_key", None)
        )
        self.api_secret = os.environ.get("HLRLOOKUP_API_SECRET") or ""

    def query(self, phone_number, msisdn=None):
        if not self.api_key:
            raise ProviderUnavailable(
                "hlrlookup: API key yok. HLRLOOKUP_API_KEY env değişkenine ekle."
            )

        params = {"msisdn": phone_number, "key": self.api_key}
        if self.api_secret:
            params["secret"] = self.api_secret

        r = self.get(self.BASE, params=params)
        if r.status_code == 401:
            raise ProviderUnavailable("hlrlookup: geçersiz API key")
        if r.status_code == 429:
            raise ProviderUnavailable("hlrlookup: rate-limited")
        if r.status_code != 200:
            raise ProviderUnavailable(f"hlrlookup: HTTP {r.status_code}")
        try:
            j = r.json()
        except ValueError as e:
            raise ProviderUnavailable("hlrlookup: json error") from e
        if j.get("error"):
            raise ProviderUnavailable(f"hlrlookup: {j['error']}")
        return j