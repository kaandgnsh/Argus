#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# KaanDGN ARGUS

"""Secure HTTP client with SSRF, redirect, retry, timeout and size-limit checks."""

import re
import time
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

import requests
from requests.adapters import HTTPAdapter
from urllib3.connection import HTTPConnection as _HTTPConnection
from urllib3.connection import HTTPSConnection as _HTTPSConnection
from urllib3.connectionpool import HTTPConnectionPool, HTTPSConnectionPool
from urllib3.poolmanager import PoolManager

from core.config import CONFIG
from core.security import is_safe_url, resolve_public_ip
from core.logger import get_logger


log = get_logger()
_REDIRECT_CODES = {301, 302, 303, 307, 308}
_MAX_REDIRECTS = 5
DEFAULT_MAX_RESPONSE_BYTES = 10 * 1024 * 1024  # 10 MiB
_SECRET_QUERY_KEYS = re.compile(r"(key|token|secret|password|auth|api.?key|access.?token)", re.I)


class UnsafeURL(Exception):
    pass


class ResponseTooLarge(Exception):
    """Raised when a response body exceeds the caller's configured byte limit."""

    pass


class _PinDNSMixin:
    """Pin direct TCP connections to a public IP without changing Host/TLS identity."""

    def _new_conn(self):
        original_host = self.host
        original_dns_host = getattr(self, "_dns_host", original_host)
        try:
            try:
                pinned_ip = resolve_public_ip(original_host)
            except (OSError, ValueError) as exc:
                raise UnsafeURL(f"blocked connection target ({exc})") from None

            # urllib3 uses _dns_host for the TCP socket and host for TLS SNI/cert checks.
            # Change both only during socket creation; restore the hostname before TLS.
            self.host = pinned_ip
            self._dns_host = pinned_ip
            try:
                return super()._new_conn()
            finally:
                self.host = original_host
                self._dns_host = original_dns_host
        except Exception:
            self.host = original_host
            self._dns_host = original_dns_host
            raise


class _PinnedHTTPConnection(_PinDNSMixin, _HTTPConnection):
    pass


class _PinnedHTTPSConnection(_PinDNSMixin, _HTTPSConnection):
    pass


class _PinnedHTTPConnectionPool(HTTPConnectionPool):
    ConnectionCls = _PinnedHTTPConnection


class _PinnedHTTPSConnectionPool(HTTPSConnectionPool):
    ConnectionCls = _PinnedHTTPSConnection


class _PinnedPoolManager(PoolManager):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.pool_classes_by_scheme = dict(self.pool_classes_by_scheme)
        self.pool_classes_by_scheme.update({
            "http": _PinnedHTTPConnectionPool,
            "https": _PinnedHTTPSConnectionPool,
        })


class _PinnedHTTPAdapter(HTTPAdapter):
    """Requests adapter that pins DNS for direct HTTP(S) connections."""

    def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
        self._pool_connections = connections
        self._pool_maxsize = maxsize
        self._pool_block = block
        self.poolmanager = _PinnedPoolManager(
            num_pools=connections, maxsize=maxsize, block=block, **pool_kwargs
        )


def _redact_url(url):
    """Mask credentials and common API-key URL patterns before logging."""
    try:
        p = urlsplit(str(url))
        host_path = p.path
        # IPQualityScore's API puts its key in the path: /api/json/phone/<key>/<number>
        host_path = re.sub(
            r"(/api/json/phone/)[^/?]+/[^/?]+",
            r"\1[REDACTED]/[REDACTED]",
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


def _request_proxies():
    """Use only explicitly configured proxies; avoid ambient proxy env variables."""
    configured = _proxies() or {}
    return {
        "http": configured.get("http"),
        "https": configured.get("https"),
        "all": None,
    }


def _session(allow_private=False):
    s = requests.Session()
    s.headers.update({
        "User-Agent": CONFIG["app"]["user_agent"],
        "Accept-Language": "en-US,en;q=0.9",
    })
    if not allow_private:
        s.mount("http://", _PinnedHTTPAdapter())
        s.mount("https://", _PinnedHTTPAdapter())
    return s


def _check_url(url, allow_private):
    if allow_private:
        return
    ok, reason = is_safe_url(url)
    if not ok:
        # Never include the original URL: provider URLs may contain API keys.
        raise UnsafeURL(f"blocked URL ({reason})")


def safe_get(url, timeout=None, max_bytes=DEFAULT_MAX_RESPONSE_BYTES, allow_private=False, **kwargs):
    """SSRF-protected GET; validates redirects and fails on oversized bodies.

    Direct connections pin DNS at socket creation. Configured proxies are a
    separate trust boundary: remote proxy DNS cannot be pinned by this client.

    Responses are limited to 10 MiB by default. An oversized response raises
    ResponseTooLarge instead of returning truncated content. Pass max_bytes=None
    only when an intentionally unbounded response is required. allow_private=True
    opts out of URL checks and direct DNS pinning for controlled environments.
    """
    if max_bytes is not None and (
        isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes <= 0
    ):
        raise ValueError("max_bytes must be a positive integer")

    _check_url(url, allow_private)
    timeout = timeout or CONFIG["app"]["timeout"]
    retries = CONFIG["http"]["retries"]
    backoff = CONFIG["http"]["backoff"]
    verify = CONFIG["http"]["verify_tls"]
    follow_redirects = kwargs.pop("allow_redirects", True)

    last_exc = None
    for attempt in range(retries + 1):
        current_url = url
        session = _session(allow_private=allow_private)
        try:
            request_kwargs = dict(kwargs)
            for redirect_count in range(_MAX_REDIRECTS + 1):
                _check_url(current_url, allow_private)
                response = session.get(
                    current_url, timeout=timeout, verify=verify,
                    proxies=_request_proxies(), stream=max_bytes is not None,
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

            if max_bytes is not None:
                chunks = []
                total = 0
                for chunk in r.iter_content(8192):
                    if not chunk:
                        continue
                    total += len(chunk)
                    if total > max_bytes:
                        r.close()
                        raise ResponseTooLarge(
                            f"response body exceeded max_bytes ({max_bytes})"
                        )
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
    """SSRF-protected POST; automatic redirects are disabled."""
    _check_url(url, allow_private)
    timeout = timeout or CONFIG["app"]["timeout"]
    verify = CONFIG["http"]["verify_tls"]
    # POST redirects must be handled explicitly by callers after validating Location.
    kwargs.pop("allow_redirects", None)
    session = _session(allow_private=allow_private)
    try:
        return session.post(
            url, timeout=timeout, verify=verify, proxies=_request_proxies(),
            allow_redirects=False, **kwargs,
        )
    finally:
        session.close()


def fetch_text(url, **kwargs):
    r = safe_get(url, **kwargs)
    r.encoding = r.encoding or "utf-8"
    return r.text, r
