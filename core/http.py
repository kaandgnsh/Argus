#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# KaanDGN ARGUS

"""Güvenli HTTP istemcisi — SSRF, yönlendirme kontrolü, retry, timeout."""

import re
import time
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

import requests

from core.config import CONFIG
from core.security import is_safe_url
from core.logger import get_logger


log = get_logger()
_REDIRECT_CODES = {301, 302, 303, 307, 308}
_MAX_REDIRECTS = 5
_SECRET_QUERY_KEYS = re.compile(r"(key|token|secret|password|auth|api.?key|access.?token)", re.I)


class UnsafeURL(Exception):
    pass


def _redact_url(url):
    """Mask credentials and common API-key URL patterns before logging."""
    try:
        p = urlsplit(str(url))
        host_path = p.path
        # IPQualityScore's API puts its key in the path: /api/json/phone/<key>/<number>
        host_path = re.sub(
            r"(/api/json/phone/)[^/]+(/)",
            r"\1[REDACTED]\2",
            host_path,
            flags=re.I,
        )
        query = [
            (key, "[REDACTED]" if _SECRET_QUERY_KEYS.search(key) else value)
            for key, value in parse_qsl(p.query, keep_blank_values=True)
        ]
        netloc = p.hostname or ""
        if p.port:
            netloc += f":{p.port}"
        return urlunsplit((p.scheme, netloc, host_path, urlencode(query), ""))
    except Exception:
        return "[URL REDACTED]"


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


def _check_url(url, allow_private):
    if allow_private:
        return
    ok, reason = is_safe_url(url)
    if not ok:
        # Never include the original URL: provider URLs may contain API keys.
        raise UnsafeURL(f"blocked URL ({reason})")


def safe_get(url, timeout=None, max_bytes=None, allow_private=False, **kwargs):
    """SSRF korumalı GET; her redirect hedefi ayrıca doğrulanır."""
    _check_url(url, allow_private)
    timeout = timeout or CONFIG["app"]["timeout"]
    retries = CONFIG["http"]["retries"]
    backoff = CONFIG["http"]["backoff"]
    verify = CONFIG["http"]["verify_tls"]
    follow_redirects = kwargs.pop("allow_redirects", True)

    last_exc = None
    for attempt in range(retries + 1):
        current_url = url
        session = _session()
        try:
            request_kwargs = dict(kwargs)
            for redirect_count in range(_MAX_REDIRECTS + 1):
                _check_url(current_url, allow_private)
                response = session.get(
                    current_url, timeout=timeout, verify=verify,
                    proxies=_proxies(), stream=bool(max_bytes),
                    allow_redirects=False, **request_kwargs,
                )
                # Query parameters apply only to the initial URL, not each redirect.
                request_kwargs.pop("params", None)
                if response.status_code not in _REDIRECT_CODES or not follow_redirects:
                    r = response
                    break
                location = response.headers.get("Location")
                if not location:
                    r = response
                    break
                if redirect_count >= _MAX_REDIRECTS:
                    response.close()
                    raise UnsafeURL("too many redirects")
                next_url = urljoin(current_url, location)
                _check_url(next_url, allow_private)
                # Do not allow HTTPS requests to silently downgrade to HTTP.
                if urlsplit(current_url).scheme.lower() == "https" and urlsplit(next_url).scheme.lower() != "https":
                    response.close()
                    raise UnsafeURL("HTTPS downgrade redirect blocked")
                response.close()
                current_url = next_url
            else:
                raise UnsafeURL("too many redirects")

            if max_bytes:
                chunks = []
                total = 0
                for chunk in r.iter_content(8192):
                    total += len(chunk)
                    if total > max_bytes:
                        r.close()
                        break
                    chunks.append(chunk)
                r._content = b"".join(chunks)
                r._content_consumed = True
            return r
        except requests.RequestException as e:
            last_exc = e
            log.debug(
                "HTTP attempt %d failed for %s (%s)",
                attempt + 1, _redact_url(current_url), type(e).__name__,
            )
            if attempt < retries:
                time.sleep(backoff ** attempt)
                continue
            raise
        finally:
            session.close()
    if last_exc:
        raise last_exc


def safe_post(url, timeout=None, allow_private=False, **kwargs):
    """SSRF korumalı POST; otomatik redirect kapalıdır."""
    _check_url(url, allow_private)
    timeout = timeout or CONFIG["app"]["timeout"]
    verify = CONFIG["http"]["verify_tls"]
    # POST redirects must be handled explicitly by callers after validating Location.
    kwargs.pop("allow_redirects", None)
    session = _session()
    try:
        return session.post(
            url, timeout=timeout, verify=verify, proxies=_proxies(),
            allow_redirects=False, **kwargs,
        )
    finally:
        session.close()


def fetch_text(url, **kwargs):
    r = safe_get(url, **kwargs)
    r.encoding = r.encoding or "utf-8"
    return r.text, r
