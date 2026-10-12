#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# KaanDGN ARGUS

"""Güvenlik yardımcıları — SSRF, path traversal, archive bomb."""

import ipaddress
import os
import socket
from urllib.parse import urlparse


# ===== SSRF =====

_BLOCKED_HOSTNAMES = {
    "localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback",
    "metadata.google.internal", "metadata.google",
}

MAX_ARCHIVE_MEMBERS = 5000
MAX_ARCHIVE_TOTAL = 500 * 1024 * 1024  # 500 MB
MAX_ARCHIVE_RATIO = 200  # sıkıştırma oranı üst sınırı


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
    """SSRF kontrolü. Döner: (bool, str_reason)."""
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
    """Path traversal koruması. base_dir verilmezse abs path serbest."""
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
    """members: [(name, size), ...]"""
    if len(members) > MAX_ARCHIVE_MEMBERS:
        return True, f"member count > {MAX_ARCHIVE_MEMBERS}"
    total = sum(s for _, s in members)
    if total > MAX_ARCHIVE_TOTAL:
        return True, f"uncompressed total > {MAX_ARCHIVE_TOTAL} bytes"
    if compressed_size > 0 and total / compressed_size > MAX_ARCHIVE_RATIO:
        return True, f"compression ratio > {MAX_ARCHIVE_RATIO}"
    for name, _ in members:
        normalized = name.replace("\\", "/")
        if normalized.startswith("/") or any(part == ".." for part in normalized.split("/")):
            return True, f"unsafe path in archive: {name}"
    return False, "ok"
