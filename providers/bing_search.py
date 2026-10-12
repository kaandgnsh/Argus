#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# KaanDGN ARGUS

"""Bing search fallback — DDG sonuç vermediğinde devreye girer.

KRİTİK: Bing `site:` sorgularını yok sayıp "benzer aramalar" döndürebiliyor.
Bu yüzden sonuç URL'lerini query ile doğrularız. Uymayanları atarız.

Örnek:
  query = 'site:instagram.com "+90555..."'
  -> yalnızca URL'i instagram.com içeren sonuçlar kabul edilir
"""

import re
from urllib.parse import urlparse

from bs4 import BeautifulSoup

from providers.base import Provider, ProviderUnavailable
from providers.registry import register


@register
class BingSearch(Provider):
    name = "bing_search"
    enabled = True
    timeout = 10
    requires_key = False

    def _extract_site_filter(self, query):
        """Query içindeki 'site:example.com' filtresini çıkarır."""
        m = re.search(r"site:([a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})", query)
        return m.group(1).lower() if m else None

    def _extract_quoted_terms(self, query):
        """Query içindeki tırnaklı terimleri çıkarır (doğrulama için)."""
        return [t.lower() for t in re.findall(r'"([^"]+)"', query)]

    def _validate_url(self, url, site_filter, quoted_terms):
        """URL gerçekten query ile ilgili mi?"""
        if not url or not url.startswith("http"):
            return False
        if "bing.com/ck/a" in url:
            return False

        try:
            host = urlparse(url).netloc.lower()
        except Exception:
            return False

        # site: filtresi varsa host uymak zorunda
        if site_filter:
            # subdomain toleransı: instagram.com -> www.instagram.com ok
            bare = site_filter.lstrip("www.")
            if bare not in host and host not in bare:
                return False

        return True

    def query(self, query, max_results=5):
        r = self.get(
            "https://www.bing.com/search",
            params={"q": query, "count": max_results * 2, "setlang": "en"},
            headers={
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9",
                "Accept-Language": "en-US,en;q=0.9",
                "Cache-Control": "no-cache",
            },
        )
        if r.status_code == 429:
            raise ProviderUnavailable("bing_search: rate-limited")
        if r.status_code != 200:
            raise ProviderUnavailable(f"bing_search: HTTP {r.status_code}")

        site_filter = self._extract_site_filter(query)
        quoted = self._extract_quoted_terms(query)

        soup = BeautifulSoup(r.text, "html.parser")
        results = []
        seen = set()

        for li in soup.select("li.b_algo"):
            href = None

            # 1) cite etiketi (görünen URL)
            cite = li.select_one("cite")
            if cite:
                text = cite.get_text(strip=True)
                text = text.replace(" › ", "/").replace("›", "/").strip()
                if text.startswith("http"):
                    href = text
                elif "." in text and " " not in text:
                    href = "https://" + text

            # 2) <a data-h> veya h2 a
            if not href:
                for sel in ("h2 a", "a[data-h]"):
                    a = li.select_one(sel)
                    if a:
                        raw = a.get("href", "")
                        if raw.startswith("http") and "bing.com/ck/a" not in raw:
                            href = raw
                            break

            if not href or href in seen:
                continue

            # Doğrulama
            if not self._validate_url(href, site_filter, quoted):
                continue

            seen.add(href)
            results.append(href)
            if len(results) >= max_results:
                break

        return results