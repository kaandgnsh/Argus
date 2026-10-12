#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# KaanDGN ARGUS

"""Wayback Machine — URL/domain arşiv geçmişi (keyless, ücretsiz)."""

from providers.base import Provider, ProviderUnavailable
from providers.registry import register


@register
class Wayback(Provider):
    name = "wayback"
    enabled = True
    timeout = 20
    requires_key = False

    CDX = "http://web.archive.org/cdx/search/cdx"
    AVAIL = "http://archive.org/wayback/available"

    def snapshots(self, url, limit=50):
        r = self.get(
            self.CDX,
            params={
                "url": url,
                "output": "json",
                "limit": limit,
                "fl": "timestamp,original,statuscode,mimetype,digest,length",
                "collapse": "digest",
            },
        )
        if r.status_code != 200:
            raise ProviderUnavailable(f"wayback: HTTP {r.status_code}")
        try:
            data = r.json()
        except ValueError as e:
            raise ProviderUnavailable("wayback: json error") from e
        if not data:
            return []
        header = data[0]
        rows = data[1:]
        return [dict(zip(header, row)) for row in rows]

    def closest(self, url, timestamp=None):
        params = {"url": url}
        if timestamp:
            params["timestamp"] = timestamp
        r = self.get(self.AVAIL, params=params)
        if r.status_code != 200:
            raise ProviderUnavailable(f"wayback: HTTP {r.status_code}")
        try:
            j = r.json()
        except ValueError as e:
            raise ProviderUnavailable("wayback: json error") from e
        return (j.get("archived_snapshots") or {}).get("closest")