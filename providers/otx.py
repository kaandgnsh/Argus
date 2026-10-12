#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# KaanDGN ARGUS

"""AlienVault OTX — keyless public endpoints (rate-limited)."""

from providers.base import Provider, ProviderUnavailable
from providers.registry import register


@register
class OTX(Provider):
    name = "otx"
    enabled = True
    timeout = 10

    def query(self, ioc_type, ioc):
        url = f"https://otx.alienvault.com/api/v1/indicators/{ioc_type}/{ioc}/general"
        r = self.get(url)
        if r.status_code == 404:
            return {"pulse_count": 0, "reputation": 0, "raw": None}
        if r.status_code == 403:
            raise ProviderUnavailable("otx: rate-limited")
        if r.status_code != 200:
            raise ProviderUnavailable(f"otx: HTTP {r.status_code}")
        try:
            j = r.json()
        except ValueError as e:
            raise ProviderUnavailable("otx: json error") from e
        return {
            "pulse_count": j.get("pulse_info", {}).get("count", 0),
            "reputation": j.get("reputation", 0),
            "raw": j,
        }