#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# KaanDGN ARGUS

"""GitHub public API (keyless, rate-limited)."""

from providers.base import Provider, ProviderUnavailable
from providers.registry import register


@register
class GitHubAPI(Provider):
    name = "github_api"
    enabled = True
    timeout = 10
    requires_key = False
    BASE = "https://api.github.com"

    def query(self, username):
        r = self.get(f"{self.BASE}/users/{username}",
                     headers={"Accept": "application/vnd.github+json"})
        if r.status_code == 404:
            return None
        if r.status_code == 403:
            raise ProviderUnavailable("github_api: rate-limited (403)")
        if r.status_code != 200:
            raise ProviderUnavailable(f"github_api: HTTP {r.status_code}")
        try:
            return r.json()
        except ValueError as e:
            raise ProviderUnavailable("github_api: json error") from e

    def repos(self, username, limit=30):
        r = self.get(f"{self.BASE}/users/{username}/repos",
                     params={"per_page": limit, "sort": "updated"},
                     headers={"Accept": "application/vnd.github+json"})
        if r.status_code != 200:
            raise ProviderUnavailable(f"github_api/repos: HTTP {r.status_code}")
        return r.json()