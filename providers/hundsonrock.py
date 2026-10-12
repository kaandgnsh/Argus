#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# KaanDGN ARGUS

"""Hudson Rock — infostealer veritabanı sorgusu.

Endpoint: https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-username
Ücretsiz, API key gerekmez.
Bir telefon numarası (username olarak) infostealer veritabanında görünüyor mu?
"""

from providers.base import Provider, ProviderUnavailable
from providers.registry import register


@register
class HudsonRock(Provider):
    name = "hudsonrock"
    enabled = True
    timeout = 10
    requires_key = False

    BASE = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-username"

    def query(self, phone_number):
        r = self.get(self.BASE, params={"username": phone_number})
        if r.status_code == 429:
            raise ProviderUnavailable("hudsonrock: rate-limited")
        if r.status_code != 200:
            raise ProviderUnavailable(f"hudsonrock: HTTP {r.status_code}")
        try:
            j = r.json()
        except ValueError as e:
            raise ProviderUnavailable("hudsonrock: json error") from e
        return j