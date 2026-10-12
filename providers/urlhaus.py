#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# KaanDGN ARGUS

"""URLhaus (abuse.ch) — keyless, POST lookup."""

from providers.base import Provider, ProviderUnavailable
from providers.registry import register


@register
class URLhaus(Provider):
    name = "urlhaus"
    enabled = True
    timeout = 10

    def query(self, url_or_host):
        r = self.post(
            "https://urlhaus-api.abuse.ch/v1/host/",
            data={"host": url_or_host},
        )
        if r.status_code != 200:
            raise ProviderUnavailable(f"urlhaus: HTTP {r.status_code}")
        try:
            return r.json()
        except ValueError as e:
            raise ProviderUnavailable("urlhaus: json error") from e