#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# KaanDGN ARGUS

"""crt.sh Certificate Transparency log provider.

crt.sh halka açık, ücretsiz ama yoğun. Sık sık 502/503 verir.
Bu yüzden basit exponential backoff ile 3 kez denenir.
"""

import time
from urllib.parse import quote

from providers.base import Provider, ProviderUnavailable
from providers.registry import register


@register
class CrtSh(Provider):
    name = "crtsh"
    enabled = True
    timeout = 25

    RETRY_STATUSES = {502, 503, 504, 520, 521, 522, 524}
    MAX_ATTEMPTS = 3

    def query(self, domain):
        url = f"https://crt.sh/?q=%25.{quote(domain)}&output=json"

        last_err = None
        for attempt in range(self.MAX_ATTEMPTS):
            try:
                r = self.get(url, headers={"Accept": "application/json"})
            except Exception as e:
                last_err = str(e)
                if attempt < self.MAX_ATTEMPTS - 1:
                    time.sleep(2 ** attempt)
                    continue
                raise ProviderUnavailable(f"crtsh: {last_err}")

            if r.status_code in self.RETRY_STATUSES:
                last_err = f"HTTP {r.status_code}"
                if attempt < self.MAX_ATTEMPTS - 1:
                    time.sleep(2 ** attempt)
                    continue
                raise ProviderUnavailable(
                    f"crtsh: {last_err} (crt.sh yoğun olabilir, birkaç "
                    f"dakika sonra tekrar dene)"
                )

            if r.status_code == 429:
                raise ProviderUnavailable("crtsh: rate-limited (429)")

            if r.status_code != 200:
                raise ProviderUnavailable(f"crtsh: HTTP {r.status_code}")

            # Başarılı — parse et
            try:
                data = r.json()
            except ValueError as e:
                raise ProviderUnavailable("crtsh: json error") from e

            subs = set()
            for entry in data:
                name = entry.get("name_value") or ""
                for line in name.splitlines():
                    line = line.strip().lower()
                    if line and line.endswith(domain.lower()):
                        subs.add(line)
            return sorted(subs)

        raise ProviderUnavailable(f"crtsh: {last_err or 'failed'}")