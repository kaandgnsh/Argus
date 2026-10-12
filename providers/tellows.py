#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# KaanDGN ARGUS

"""Tellows.com — numara spam / şikayet skoru (public, keyless scrape).

Endpoint: https://www.tellows.com/num/<NUMBER>
Çıktı: spam skoru (1-9), şikayet sayısı, kategori.
"""

import re

from bs4 import BeautifulSoup

from providers.base import Provider, ProviderUnavailable
from providers.registry import register


@register
class Tellows(Provider):
    name = "tellows"
    enabled = True
    timeout = 12
    requires_key = False

    def query(self, phone_number):
        # +905551234567 -> 905551234567
        digits = re.sub(r"\D", "", phone_number)
        url = f"https://www.tellows.com/num/{digits}"

        r = self.get(url, headers={
            "Accept": "text/html,application/xhtml+xml",
            "Accept-Language": "en-US,en;q=0.9",
        })
        if r.status_code == 404:
            return {"score": None, "complaints": 0, "categories": []}
        if r.status_code != 200:
            raise ProviderUnavailable(f"tellows: HTTP {r.status_code}")

        soup = BeautifulSoup(r.text, "html.parser")

        # Spam skoru (1-9)
        score = None
        score_el = soup.select_one(".score, .rating, [class*='score']")
        if score_el:
            m = re.search(r"\b([1-9])\b", score_el.get_text())
            if m:
                score = int(m.group(1))

        # Şikayet sayısı
        complaints = 0
        text_all = soup.get_text(" ", strip=True)
        m = re.search(r"(\d+)\s*(?:complaint|report|review)", text_all, re.I)
        if m:
            complaints = int(m.group(1))

        # Kategoriler
        categories = []
        for el in soup.select(".categories a, .category, [class*='categor']"):
            t = el.get_text(strip=True)
            if t and len(t) < 40 and t not in categories:
                categories.append(t)

        return {
            "score": score,
            "complaints": complaints,
            "categories": categories[:5],
        }