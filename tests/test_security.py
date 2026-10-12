#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# KaanDGN ARGUS

from core.security import is_private_ip, is_safe_url, archive_is_suspicious


def test_private_ip():
    assert is_private_ip("127.0.0.1")
    assert is_private_ip("10.0.0.5")
    assert is_private_ip("192.168.1.1")
    assert is_private_ip("172.16.10.10")
    assert not is_private_ip("8.8.8.8")
    assert not is_private_ip("1.1.1.1")


def test_safe_url_blocks_localhost():
    ok, _ = is_safe_url("http://localhost/admin")
    assert not ok
    ok, _ = is_safe_url("http://127.0.0.1/")
    assert not ok


def test_safe_url_scheme():
    ok, _ = is_safe_url("file:///etc/passwd")
    assert not ok
    ok, _ = is_safe_url("gopher://evil")
    assert not ok


def test_archive_bomb():
    members = [("a" * 100, 10_000_000)] * 10
    bad, _ = archive_is_suspicious(members, 10)
    assert bad


def test_archive_ok():
    members = [("readme.txt", 100), ("docs/", 0)]
    bad, _ = archive_is_suspicious(members, 500)
    assert not bad


def test_path_traversal_detected():
    members = [("../etc/passwd", 10)]
    bad, _ = archive_is_suspicious(members, 50)
    assert bad