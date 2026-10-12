#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# KaanDGN ARGUS

import pytest

import core.http as http


def test_redact_url_hides_query_secrets():
    value = http._redact_url(
        "https://example.com/check?api_key=abc123&secret=def456&name=kaan"
    )
    assert "abc123" not in value
    assert "def456" not in value
    assert "name=kaan" in value


def test_redact_url_hides_ipqs_path_key():
    value = http._redact_url(
        "https://ipqualityscore.com/api/json/phone/supersecret/+905551112233"
    )
    assert "supersecret" not in value
    assert "[REDACTED]" in value


def test_redirect_target_is_revalidated(monkeypatch):
    class FakeResponse:
        status_code = 302
        headers = {"Location": "http://127.0.0.1/admin"}

        def close(self):
            pass

    class FakeSession:
        calls = 0

        def get(self, *args, **kwargs):
            self.calls += 1
            return FakeResponse()

        def close(self):
            pass

    session = FakeSession()
    monkeypatch.setattr(http, "_session", lambda: session)
    monkeypatch.setattr(
        http, "is_safe_url",
        lambda url: (False, "non-public IP") if "127.0.0.1" in url else (True, "ok"),
    )

    with pytest.raises(http.UnsafeURL):
        http.safe_get("https://public.example/path", retries=0)
    assert session.calls == 1
