#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# KaanDGN ARGUS

"""Shodan InternetDB — açık portlar, CVE'ler, hostname'ler, tag'ler (keyless, ücretsiz).

Endpoint: https://internetdb.shodan.io/<ip>
Limit: Ücretsiz (non-commercial), key gerekmez.
Not: Haftada bir güncellenir. Banner döndürmez, sadece port/CVE/CPE/hostname/tag.
"""

from providers.base import Provider, ProviderUnavailable
from providers.registry import register


@register
class InternetDB(Provider):
    name = "internetdb"
    enabled = True
    timeout = 10
    requires_key = False

    def query(self, ip):
        r = self.get(f"https://internetdb.shodan.io/{ip}")
        if r.status_code == 404:
            return {"ports": [], "cpes": [], "hostnames": [], "tags": [], "vulns": [], "ip": ip}
        if r.status_code != 200:
            raise ProviderUnavailable(f"internetdb: HTTP {r.status_code}")
        try:
            return r.json()
        except ValueError as e:
            raise ProviderUnavailable("internetdb: json error") from e