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
    assert "+905551112233" not in value
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
    monkeypatch.setattr(http, "_session", lambda **_kwargs: session)
    monkeypatch.setattr(
        http, "is_safe_url",
        lambda url: (False, "non-public IP") if "127.0.0.1" in url else (True, "ok"),
    )

    monkeypatch.setitem(http.CONFIG["http"], "retries", 0)
    with pytest.raises(http.UnsafeURL):
        http.safe_get("https://public.example/path")
    assert session.calls == 1


def _install_fake_successful_response(monkeypatch, chunks):
    class FakeResponse:
        status_code = 200
        headers = {}
        closed = False

        def iter_content(self, chunk_size):
            assert chunk_size == 8192
            yield from chunks

        def close(self):
            self.closed = True

    class FakeSession:
        def __init__(self):
            self.response = FakeResponse()
            self.kwargs = None

        def get(self, *args, **kwargs):
            self.kwargs = kwargs
            return self.response

        def close(self):
            pass

    session = FakeSession()
    monkeypatch.setattr(http, "_session", lambda **_kwargs: session)
    monkeypatch.setattr(http, "_check_url", lambda *_args: None)
    monkeypatch.setitem(http.CONFIG["http"], "retries", 0)
    return session


def test_max_bytes_raises_instead_of_returning_truncated_body(monkeypatch):
    session = _install_fake_successful_response(monkeypatch, [b"1234", b"5678"])

    with pytest.raises(http.ResponseTooLarge, match="max_bytes"):
        http.safe_get("https://public.example/data", max_bytes=5)

    assert session.kwargs["stream"] is True
    assert session.response.closed is True


def test_max_bytes_accepts_body_at_exact_limit(monkeypatch):
    session = _install_fake_successful_response(monkeypatch, [b"123", b"45"])

    response = http.safe_get("https://public.example/data", max_bytes=5)

    assert response._content == b"12345"
    assert response._content_consumed is True
    assert session.response.closed is False


@pytest.mark.parametrize("invalid_limit", [0, -1, 1.5, "100", True, False])
def test_max_bytes_must_be_a_positive_integer(monkeypatch, invalid_limit):
    def unexpected_check(*_args):
        pytest.fail("URL validation should not run for invalid max_bytes")

    monkeypatch.setattr(http, "_check_url", unexpected_check)

    with pytest.raises(ValueError, match="positive integer"):
        http.safe_get("https://public.example/data", max_bytes=invalid_limit)


def test_connection_is_pinned_to_numeric_ip_and_restores_hostname(monkeypatch):
    monkeypatch.setattr(http, "resolve_public_ip", lambda _host: "8.8.8.8")
    monkeypatch.setattr(
        http._HTTPConnection,
        "_new_conn",
        lambda connection: (connection.host, connection._dns_host),
    )
    connection = http._PinnedHTTPConnection("public.example", 80)

    assert connection._new_conn() == ("8.8.8.8", "8.8.8.8")
    assert connection.host == "public.example"
    assert connection._dns_host == "public.example"


def test_session_uses_pinned_adapters():
    session = http._session()
    try:
        assert isinstance(session.get_adapter("http://public.example"), http._PinnedHTTPAdapter)
        assert isinstance(session.get_adapter("https://public.example"), http._PinnedHTTPAdapter)
    finally:
        session.close()


def test_request_proxy_settings_do_not_inherit_environment(monkeypatch):
    monkeypatch.setitem(http.CONFIG["proxy"], "enabled", False)
    assert http._request_proxies() == {"http": None, "https": None, "all": None}


def test_allow_private_uses_standard_adapter_only_when_explicitly_requested():
    session = http._session(allow_private=True)
    try:
        assert not isinstance(session.get_adapter("http://127.0.0.1"), http._PinnedHTTPAdapter)
    finally:
        session.close()


def test_safe_get_defaults_to_bounded_streaming(monkeypatch):
    session = _install_fake_successful_response(monkeypatch, [b"small body"])

    response = http.safe_get("https://public.example/data")

    assert session.kwargs["stream"] is True
    assert response._content == b"small body"
    assert response._content_consumed is True


def test_explicit_none_disables_response_size_limit(monkeypatch):
    session = _install_fake_successful_response(monkeypatch, [b"unbounded"])

    response = http.safe_get("https://public.example/data", max_bytes=None)

    assert session.kwargs["stream"] is False
    assert response is session.response
