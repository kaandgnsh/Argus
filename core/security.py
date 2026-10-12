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
    "localhost", "ip6-localhost", "ip6-loopback",
    "metadata.google.internal",
}

_BLOCKED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("255.255.255.255/32"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("ff00::/8"),
]


def is_private_ip(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return any(ip in net for net in _BLOCKED_NETWORKS)


def _resolve(host):
    infos = socket.getaddrinfo(host, None)
    return {info[4][0] for info in infos}


def is_safe_url(url):
    """SSRF kontrolü. Döner: (bool, str_reason)."""
    try:
        p = urlparse(url)
    except Exception:
        return False, "invalid url"
    if p.scheme not in ("http", "https"):
        return False, f"scheme not allowed: {p.scheme}"
    host = (p.hostname or "").strip().lower()
    if not host:
        return False, "no host"
    if host in _BLOCKED_HOSTNAMES:
        return False, "blocked hostname"
    if is_private_ip(host):
        return False, "private ip literal"
    try:
        addrs = _resolve(host)
    except socket.gaierror:
        return False, "dns resolution failed"
    for a in addrs:
        if is_private_ip(a):
            return False, f"host resolves to private ip: {a}"
    return True, "ok"


# ===== PATH =====

def is_safe_path(path, base_dir=None):
    """Path traversal koruması. base_dir verilmezse abs path serbest."""
    try:
        real = os.path.realpath(path)
    except OSError:
        return False
    if base_dir:
        base = os.path.realpath(base_dir)
        return real == base or real.startswith(base + os.sep)
    return True


# ===== ARCHIVE BOMB =====

MAX_ARCHIVE_MEMBERS = 5000
MAX_ARCHIVE_TOTAL = 500 * 1024 * 1024  # 500 MB
MAX_ARCHIVE_RATIO = 200  # sıkıştırma oranı üst sınırı


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
        if name.startswith("/") or ".." in name.split("/"):
            return True, f"unsafe path in archive: {name}"
    return False, "ok"