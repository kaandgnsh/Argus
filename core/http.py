#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# KaanDGN ARGUS

"""Güvenli HTTP istemcisi — SSRF, retry, timeout, proxy."""

import time

import requests

from core.config import CONFIG
from core.security import is_safe_url
from core.logger import get_logger


log = get_logger()


class UnsafeURL(Exception):
    pass


def _proxies():
    p = CONFIG.get("proxy", {})
    if not p.get("enabled"):
        return None
    if p.get("tor"):
        url = p.get("tor_socks5")
        return {"http": url, "https": url}
    proxies = {}
    if p.get("http"):
        proxies["http"] = p["http"]
    if p.get("https"):
        proxies["https"] = p["https"]
    if p.get("socks5"):
        proxies["http"] = p["socks5"]
        proxies["https"] = p["socks5"]
    return proxies or None


def _session():
    s = requests.Session()
    s.headers.update({
        "User-Agent": CONFIG["app"]["user_agent"],
        "Accept-Language": "en-US,en;q=0.9",
    })
    return s


def safe_get(url, timeout=None, max_bytes=None, allow_private=False, **kwargs):
    """SSRF korumalı GET. requests.Response döner."""
    if not allow_private:
        ok, reason = is_safe_url(url)
        if not ok:
            raise UnsafeURL(f"{url} -> {reason}")

    timeout = timeout or CONFIG["app"]["timeout"]
    retries = CONFIG["http"]["retries"]
    backoff = CONFIG["http"]["backoff"]
    verify = CONFIG["http"]["verify_tls"]

    last_exc = None
    for attempt in range(retries + 1):
        try:
            r = _session().get(
                url, timeout=timeout, verify=verify,
                proxies=_proxies(), stream=bool(max_bytes), **kwargs,
            )
            if max_bytes:
                chunks = []
                total = 0
                for chunk in r.iter_content(8192):
                    total += len(chunk)
                    if total > max_bytes:
                        break
                    chunks.append(chunk)
                r._content = b"".join(chunks)
                r._content_consumed = True
            return r
        except (requests.RequestException,) as e:
            last_exc = e
            log.debug("HTTP attempt %d failed for %s: %s", attempt + 1, url, e)
            if attempt < retries:
                time.sleep(backoff ** attempt)
                continue
            raise
    if last_exc:
        raise last_exc


def safe_post(url, timeout=None, allow_private=False, **kwargs):
    if not allow_private:
        ok, reason = is_safe_url(url)
        if not ok:
            raise UnsafeURL(f"{url} -> {reason}")
    timeout = timeout or CONFIG["app"]["timeout"]
    verify = CONFIG["http"]["verify_tls"]
    return _session().post(
        url, timeout=timeout, verify=verify, proxies=_proxies(), **kwargs,
    )


def fetch_text(url, **kwargs):
    r = safe_get(url, **kwargs)
    r.encoding = r.encoding or "utf-8"
    return r.text, r