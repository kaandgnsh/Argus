#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# KaanDGN ARGUS

"""Arama provider soyutlaması (DuckDuckGo HTML)."""

import requests
from bs4 import BeautifulSoup

from core.config import CONFIG
from core.http import _session


class SearchUnavailable(Exception):
    pass


def _ddg_html(query, max_results, timeout):
    url = "https://html.duckduckgo.com/html/"
    try:
        r = _session().post(url, data={"q": query}, timeout=timeout)
    except requests.RequestException as e:
        raise SearchUnavailable(str(e)) from e
    if r.status_code == 429:
        raise SearchUnavailable("duckduckgo: rate-limited")
    if r.status_code != 200:
        raise SearchUnavailable(f"duckduckgo: HTTP {r.status_code}")
    soup = BeautifulSoup(r.text, "html.parser")
    results = []
    for a in soup.select("a.result__a"):
        href = a.get("href")
        if href and href.startswith("http"):
            results.append(href)
            if len(results) >= max_results:
                break
    return results


_PROVIDERS = {"duckduckgo": _ddg_html}


def search(query, max_results=None, timeout=None):
    max_results = max_results or CONFIG["search"]["max_results"]
    timeout = timeout or CONFIG["app"]["timeout"]
    for name in CONFIG["search"].get("providers") or ["duckduckgo"]:
        fn = _PROVIDERS.get(name)
        if fn is None:
            continue
        try:
            return fn(query, max_results, timeout)
        except SearchUnavailable:
            continue
    return []