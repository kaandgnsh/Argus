#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# KaanDGN ARGUS

"""Telegram Phone Number Checker — Bellingcat aracı ile Telegram kayıt kontrolü.

Kaynak: https://github.com/bellingcat/telegram-phone-number-checker
Gereksinim: Telegram API ID ve Hash (my.telegram.org'dan alınır).
Env: TELEGRAM_API_ID, TELEGRAM_API_HASH, TELEGRAM_PHONE

Uyarı: Bu araç, kişisel Telegram hesabınızı kullanır ve çok sayıda sorguda
       hesabınızın banlanmasına neden olabilir. Sorumlu kullanın.
"""

import os
import subprocess
import shutil

from providers.base import Provider, ProviderUnavailable
from providers.registry import register


@register
class TelegramCheck(Provider):
    name = "telegram_check"
    enabled = True
    timeout = 60
    requires_key = True

    def __init__(self, **opts):
        super().__init__(**opts)
        self.api_id = os.environ.get("TELEGRAM_API_ID")
        self.api_hash = os.environ.get("TELEGRAM_API_HASH")
        self.phone = os.environ.get("TELEGRAM_PHONE")

    def _tool_available(self):
        return shutil.which("telegram-phone-number-checker") is not None

    def query(self, phone_number):
        if not all([self.api_id, self.api_hash, self.phone]):
            raise ProviderUnavailable(
                "telegram_check: TELEGRAM_API_ID, TELEGRAM_API_HASH ve "
                "TELEGRAM_PHONE env değişkenlerini ayarla."
            )

        if not self._tool_available():
            raise ProviderUnavailable(
                "telegram_check: 'telegram-phone-number-checker' kurulu değil. "
                "pip install telegram-phone-number-checker"
            )

        try:
            result = subprocess.run(
                [
                    "telegram-phone-number-checker",
                    phone_number,
                    "--api-id", self.api_id,
                    "--api-hash", self.api_hash,
                    "--phone", self.phone,
                ],
                capture_output=True,
                text=True,
                timeout=50,
            )
        except subprocess.TimeoutExpired as e:
            raise ProviderUnavailable("telegram_check: timeout") from e
        except (OSError, subprocess.SubprocessError) as e:
            raise ProviderUnavailable(f"telegram_check: {e}") from e

        if result.returncode != 0:
            stderr = (result.stderr or "").strip()[:200]
            raise ProviderUnavailable(f"telegram_check: {stderr}")

        return {"raw": result.stdout, "returncode": result.returncode}