#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# KaanDGN ARGUS

"""Provider temel sınıfı.

Provider hataları programı çökertmez. `ProviderUnavailable` fırlatabilir.
API anahtarları yalnızca gerekli ortam değişkenleriyle veya yerel config ile
verilmelidir; hata metinlerine ham URL/yanıt gövdesi eklenmemelidir.
"""

import os

from core.http import safe_get, safe_post, UnsafeURL


class ProviderUnavailable(Exception):
    pass


class Provider:
    name = "base"
    enabled = True
    timeout = 8
    requires_key = False
    auth_key = None

    def __init__(self, **opts):
        for k, v in opts.items():
            setattr(self, k, v)
        if not getattr(self, "auth_key", None):
            self.auth_key = os.environ.get("ABUSECH_AUTH_KEY")

    def _headers(self, extra=None):
        h = {}
        if self.auth_key:
            h["Auth-Key"] = self.auth_key
        if extra:
            h.update(extra)
        return h

    def get(self, url, **kwargs):
        kwargs.setdefault("timeout", self.timeout)
        extra = kwargs.pop("headers", None)
        headers = self._headers(extra)
        if headers:
            kwargs["headers"] = headers
        try:
            return safe_get(url, **kwargs)
        except UnsafeURL as e:
            raise ProviderUnavailable(f"{self.name}: {e}") from None
        except Exception as e:
            # requests exceptions can contain full URLs with API keys in path/query.
            raise ProviderUnavailable(
                f"{self.name}: HTTP request failed ({type(e).__name__})"
            ) from None

    def post(self, url, **kwargs):
        kwargs.setdefault("timeout", self.timeout)
        extra = kwargs.pop("headers", None)
        headers = self._headers(extra)
        if headers:
            kwargs["headers"] = headers
        try:
            return safe_post(url, **kwargs)
        except UnsafeURL as e:
            raise ProviderUnavailable(f"{self.name}: {e}") from None
        except Exception as e:
            raise ProviderUnavailable(
                f"{self.name}: HTTP request failed ({type(e).__name__})"
            ) from None

    def query(self, *args, **kwargs):
        raise ProviderUnavailable(f"{self.name}: query not implemented")
