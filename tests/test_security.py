#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# KaanDGN ARGUS

import pytest

from core.security import is_private_ip, is_safe_url, archive_is_suspicious


def test_private_ip():
    for address in (
        "127.0.0.1", "10.0.0.5", "192.168.1.1", "172.16.10.10",
        "::1", "fc00::1", "fe80::1", "169.254.169.254",
        "::ffff:127.0.0.1", "192.0.2.1",
    ):
        assert is_private_ip(address)
    assert not is_private_ip("8.8.8.8")
    assert not is_private_ip("1.1.1.1")


def test_safe_url_blocks_localhost():
    ok, _ = is_safe_url("http://localhost/admin")
    assert not ok
    ok, _ = is_safe_url("http://127.0.0.1/")
    assert not ok
    ok, _ = is_safe_url("http://[::ffff:127.0.0.1]/")
    assert not ok


def test_safe_url_scheme():
    ok, _ = is_safe_url("file:///etc/passwd")
    assert not ok
    ok, _ = is_safe_url("gopher://evil")
    assert not ok


def test_safe_url_rejects_credentials():
    ok, _ = is_safe_url("https://user:password@example.com/")
    assert not ok


def test_archive_bomb():
    members = [("a" * 100, 10_000_000)] * 10
    bad, _ = archive_is_suspicious(members, 10)
    assert bad


def test_archive_ok():
    members = [("readme.txt", 100), ("docs/", 0)]
    bad, _ = archive_is_suspicious(members, 500)
    assert not bad


def test_archive_path_traversal_detected():
    assert archive_is_suspicious([("../etc/passwd", 10)], 50)[0]
    assert archive_is_suspicious([("..\\\\etc\\\\passwd", 10)], 50)[0]


@pytest.mark.parametrize(
    "name",
    [
        "C:/Windows/system.ini",
        r"C:\Windows\system.ini",
        "C:drive-relative.txt",
        r"\\server\share\file.txt",
    ],
)
def test_archive_rejects_windows_absolute_or_drive_paths(name):
    bad, _ = archive_is_suspicious([(name, 10)], 100)
    assert bad


@pytest.mark.parametrize(
    "members,compressed_size",
    [
        ([("file.txt", -1)], 100),
        ([("file.txt", True)], 100),
        ([("", 1)], 100),
        ([("bad\x00name", 1)], 100),
        ([("file.txt", 1)], 0),
        ([("file.txt", 1)], -1),
    ],
)
def test_archive_rejects_invalid_metadata(members, compressed_size):
    bad, _ = archive_is_suspicious(members, compressed_size)
    assert bad
