#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# KaanDGN ARGUS

"""IPQualityScore (IPQS) — telefon doğrulama, fraud skoru, hat tipi.

API key: https://www.ipqualityscore.com/create-account
Env: IPQS_API_KEY
Not: IPQS API biçimi anahtarı URL yolunda gerektirir; HTTP logları bunu maskeler.
"""

import os

from providers.base import Provider, ProviderUnavailable
from providers.registry import register


@register
class IPQualityScore(Provider):
    name = "ipqualityscore"
    enabled = True
    timeout = 10
    requires_key = True
    auth_key = None

    BASE = "https://ipqualityscore.com/api/json/phone"

    def __init__(self, **opts):
        super().__init__(**opts)
        self.api_key = os.environ.get("IPQS_API_KEY") or getattr(self, "auth_key", None)

    def query(self, phone_number, country=None):
        if not self.api_key:
            raise ProviderUnavailable(
                "ipqualityscore: API key yok. IPQS_API_KEY env değişkenine ekle."
            )

        params = {}
        if country:
            params["country"] = country

        url = f"{self.BASE}/{self.api_key}/{phone_number}"
        r = self.get(url, params=params)
        if r.status_code == 401:
            raise ProviderUnavailable("ipqualityscore: geçersiz API key")
        if r.status_code == 429:
            raise ProviderUnavailable("ipqualityscore: rate-limited")
        if r.status_code != 200:
            raise ProviderUnavailable(f"ipqualityscore: HTTP {r.status_code}")
        try:
            j = r.json()
        except ValueError as e:
            raise ProviderUnavailable("ipqualityscore: json error") from e
        if not j.get("success", False):
            # Provider response text may echo sensitive request details.
            raise ProviderUnavailable("ipqualityscore: provider returned an unsuccessful response")
        return j
