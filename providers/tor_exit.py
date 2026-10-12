#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# KaanDGN ARGUS

"""Tor Project — exit node listesi.

Endpoint: https://check.torproject.org/torbulkexitlist
Format:   Plain text, satır başına bir IP
Auth:     Keyless
Cache:    Tor listesi günlük güncellenir, ARGUS içi 24 saat TTL ile cache'lenir.
"""

from providers.base import Provider, ProviderUnavailable
from providers.registry import register
from core import cache


@register
class TorExit(Provider):
    name = "tor_exit"
    enabled = True
    timeout = 15
    requires_key = False

    URL = "https://check.torproject.org/torbulkexitlist"

    def _load_list(self):
        cached = cache.get("tor_exit_list", {"v": 1})
        if cached and cached.get("ips"):
            return set(cached["ips"])

        r = self.get(self.URL)
        if r.status_code != 200:
            raise ProviderUnavailable(f"tor_exit: HTTP {r.status_code}")
        ips = set()
        for line in r.text.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                ips.add(line)

        # 24 saat TTL ile cache'le (config cache ttl zaten var, ekstra flag)
        cache.set("tor_exit_list", {"v": 1}, {"ips": list(ips), "count": len(ips)})
        return ips

    def is_exit(self, ip):
        """Verilen IP bir Tor exit node mu?"""
        ips = self._load_list()
        return ip in ips

    def count(self):
        try:
            return len(self._load_list())
        except Exception:
            return 0