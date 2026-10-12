#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# KaanDGN ARGUS

"""urlscan.io — keyless public search."""

from providers.base import Provider, ProviderUnavailable
from providers.registry import register


@register
class URLScan(Provider):
    name = "urlscan"
    enabled = True
    timeout = 10

    def query(self, query, size=10):
        r = self.get("https://urlscan.io/api/v1/search/",
                     params={"q": query, "size": size})
        if r.status_code != 200:
            raise ProviderUnavailable(f"urlscan: HTTP {r.status_code}")
        try:
            return r.json()
        except ValueError as e:
            raise ProviderUnavailable("urlscan: json error") from e