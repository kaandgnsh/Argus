#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# KaanDGN ARGUS

"""Cloudflare DNS-over-HTTPS provider."""

from providers.base import Provider, ProviderUnavailable
from providers.registry import register


@register
class CloudflareDNS(Provider):
    name = "cloudflare_dns"
    enabled = True
    timeout = 6

    URL = "https://cloudflare-dns.com/dns-query"

    def query(self, domain, rtype="A"):
        r = self.get(
            self.URL,
            params={"name": domain, "type": rtype.upper()},
            headers={"Accept": "application/dns-json"},
        )
        if r.status_code != 200:
            raise ProviderUnavailable(f"cloudflare_dns: HTTP {r.status_code}")
        try:
            j = r.json()
        except ValueError as e:
            raise ProviderUnavailable("cloudflare_dns: json error") from e
        answers = j.get("Answer") or []
        return [a.get("data") for a in answers if a.get("data")]