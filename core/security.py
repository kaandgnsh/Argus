#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# KaanDGN ARGUS

"""Security helpers for SSRF, path traversal and archive-bomb checks."""

import ipaddress
import os
import re
import socket
from urllib.parse import urlparse


# ===== SSRF =====

_BLOCKED_HOSTNAMES = {
    "localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback",
    "metadata.google.internal", "metadata.google",
}

MAX_ARCHIVE_MEMBERS = 5000
MAX_ARCHIVE_TOTAL = 500 * 1024 * 1024  # 500 MB
MAX_ARCHIVE_RATIO = 200  # compression ratio limit


def is_private_ip(ip_str):
    """Allow only globally routable IP addresses; also handle IPv4-mapped IPv6."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return not ip.is_global


def _resolve(host):
    infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    return {info[4][0].split("%", 1)[0] for info in infos}


def is_safe_url(url):
    """SSRF check. Returns (allowed, reason)."""
    try:
        p = urlparse(url)
        # Reject credentials in URLs to avoid ambiguous parsing and accidental leaks.
        if p.username is not None or p.password is not None:
            return False, "credentials in URL are not allowed"
        if p.scheme.lower() not in ("http", "https"):
            return False, "scheme not allowed"
        host = (p.hostname or "").strip().lower().rstrip(".")
        if not host:
            return False, "no host"
        if host in _BLOCKED_HOSTNAMES:
            return False, "blocked hostname"
        try:
            literal = ipaddress.ip_address(host)
        except ValueError:
            literal = None
        if literal is not None and is_private_ip(str(literal)):
            return False, "non-public IP literal"
        try:
            addrs = _resolve(host)
        except (socket.gaierror, OSError):
            return False, "DNS resolution failed"
        if not addrs:
            return False, "DNS returned no addresses"
        for addr in addrs:
            if is_private_ip(addr):
                return False, "host resolves to a non-public IP"
        return True, "ok"
    except (TypeError, ValueError, UnicodeError):
        return False, "invalid URL"


# ===== PATH =====

def is_safe_path(path, base_dir=None):
    """Path traversal check. Absolute paths are allowed when base_dir is omitted."""
    try:
        real = os.path.realpath(path)
    except (OSError, TypeError, ValueError):
        return False
    if base_dir:
        base = os.path.realpath(base_dir)
        return real == base or real.startswith(base + os.sep)
    return True


# ===== ARCHIVE BOMB =====

def archive_is_suspicious(members, compressed_size):
    """Check archive member count, sizes, compression ratio and cross-platform paths."""
    if (
        isinstance(compressed_size, bool)
        or not isinstance(compressed_size, int)
        or compressed_size < 0
    ):
        return True, "invalid compressed size"
    if len(members) > MAX_ARCHIVE_MEMBERS:
        return True, f"member count > {MAX_ARCHIVE_MEMBERS}"

    total = 0
    for entry in members:
        if not isinstance(entry, (tuple, list)) or len(entry) != 2:
            return True, "invalid member metadata"
        name, size = entry
        if not isinstance(name, str) or not name or "\x00" in name:
            return True, "invalid archive member path"
        if isinstance(size, bool) or not isinstance(size, int) or size < 0:
            return True, "invalid archive member size"

        normalized = name.replace("\\", "/")
        # Check Windows drive paths as well as POSIX/UNC paths, regardless of host OS.
        if (
            normalized.startswith("/")
            or re.match(r"^[a-zA-Z]:", normalized)
            or any(part == ".." for part in normalized.split("/"))
        ):
            return True, f"unsafe path in archive: {name}"
        total += size

    if total > MAX_ARCHIVE_TOTAL:
        return True, f"uncompressed total > {MAX_ARCHIVE_TOTAL} bytes"
    if total > 0 and compressed_size == 0:
        return True, "non-empty archive has zero compressed size"
    if compressed_size > 0 and total / compressed_size > MAX_ARCHIVE_RATIO:
        return True, f"compression ratio > {MAX_ARCHIVE_RATIO}"
    return False, "ok"
