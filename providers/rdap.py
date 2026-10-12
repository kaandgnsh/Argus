#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# KaanDGN ARGUS

"""RDAP provider — WHOIS alternatifi (ücretsiz, structured)."""

from urllib.parse import quote

from providers.base import Provider, ProviderUnavailable
from providers.registry import register


@register
class RDAP(Provider):
    name = "rdap"
    enabled = True
    timeout = 10
    URL = "https://rdap.org/domain/{d}"

    def query(self, domain):
        url = self.URL.format(d=quote(domain))
        r = self.get(url, allow_redirects=True,
                     headers={"Accept": "application/rdap+json"})
        if r.status_code == 404:
            raise ProviderUnavailable(f"rdap: {domain} not found")
        if r.status_code != 200:
            raise ProviderUnavailable(f"rdap: HTTP {r.status_code}")
        try:
            return r.json()
        except ValueError as e:
            raise ProviderUnavailable("rdap: json error") from e