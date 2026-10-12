#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# KaanDGN ARGUS

"""NumLookupAPI — operatör ve konum sorgusu.

Endpoint: https://api.numlookupapi.com/v1/validate/{NUMBER}
Ücretsiz katman: 100 sorgu/ay.
API key: https://numlookupapi.com/
Env: NUMLOOKUP_API_KEY (yoksa ABUSECH_AUTH_KEY fallback)
"""

import os

from providers.base import Provider, ProviderUnavailable
from providers.registry import register


@register
class NumLookupAPI(Provider):
    name = "numlookupapi"
    enabled = True
    timeout = 10
    requires_key = True
    auth_key = None

    BASE = "https://api.numlookupapi.com/v1/validate"

    def __init__(self, **opts):
        super().__init__(**opts)
        self.api_key = (
            os.environ.get("NUMLOOKUP_API_KEY")
            or getattr(self, "auth_key", None)
        )

    def query(self, phone_number):
        if not self.api_key:
            raise ProviderUnavailable(
                "numlookupapi: API key yok. NUMLOOKUP_API_KEY env değişkenine ekle."
            )

        url = f"{self.BASE}/{phone_number}"
        r = self.get(url, params={"apikey": self.api_key})
        if r.status_code == 401:
            raise ProviderUnavailable("numlookupapi: geçersiz API key")
        if r.status_code == 429:
            raise ProviderUnavailable("numlookupapi: rate-limited (100/ay)")
        if r.status_code != 200:
            raise ProviderUnavailable(f"numlookupapi: HTTP {r.status_code}")
        try:
            j = r.json()
        except ValueError as e:
            raise ProviderUnavailable("numlookupapi: json error") from e
        if not j.get("valid"):
            raise ProviderUnavailable("numlookupapi: geçersiz numara")
        return j