#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# KaanDGN ARGUS

"""Provider temel sınıfı.

Provider hataları programı çökertmez. `ProviderUnavailable` fırlatabilir.

Ortak özellikler:
  - name          : provider adı
  - enabled       : config'den açık/kapalı
  - timeout       : HTTP timeout
  - requires_key  : API key gerekiyor mu?
  - auth_key      : abuse.ch / IPQS / NumLookup / HLR için ortak API key
                    (config/providers.json'dan VEYA ABUSECH_AUTH_KEY env'den
                    otomatik okunur)
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
        # Class seviyesinde auth_key = None tanımlı olmasaydı, alt sınıflar
        # self.auth_key çağırdığında AttributeError verirdi. Aşağıdaki iki
        # satır bunu garantiler.
        if not hasattr(self, "auth_key"):
            self.auth_key = None

        for k, v in opts.items():
            setattr(self, k, v)

        # Ortam değişkeninden ortak key okuma sırası:
        # 1. config/providers.json'da açıkça verilmişse o kullanılır (üstte setattr)
        # 2. yoksa ABUSECH_AUTH_KEY env'i
        if not self.auth_key:
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
            raise ProviderUnavailable(f"{self.name}: unsafe url ({e})") from e
        except Exception as e:
            raise ProviderUnavailable(f"{self.name}: {e}") from e

    def post(self, url, **kwargs):
        kwargs.setdefault("timeout", self.timeout)
        extra = kwargs.pop("headers", None)
        headers = self._headers(extra)
        if headers:
            kwargs["headers"] = headers
        try:
            return safe_post(url, **kwargs)
        except UnsafeURL as e:
            raise ProviderUnavailable(f"{self.name}: unsafe url ({e})") from e
        except Exception as e:
            raise ProviderUnavailable(f"{self.name}: {e}") from e

    def query(self, *args, **kwargs):
        raise ProviderUnavailable(f"{self.name}: query not implemented")