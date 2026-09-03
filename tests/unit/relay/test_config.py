from pathlib import Path

from relay.config import Settings


def test_canonical_url_strips_trailing_slash(monkeypatch):
    monkeypatch.setenv("RELAY_PUBLIC_URL", "https://relay.example/")
    monkeypatch.setenv("OAUTH_SIGNING_KEY", "k" * 32)
    monkeypatch.setenv("RELAY_ADMIN_PASSWORD_HASH", "h")
    s = Settings()
    assert s.canonical_url == "https://relay.example"


def test_token_digests_and_extra_redirects_parse_lists(monkeypatch):
    monkeypatch.setenv("RELAY_PUBLIC_URL", "https://relay.example")
    monkeypatch.setenv("OAUTH_SIGNING_KEY", "k" * 32)
    monkeypatch.setenv("RELAY_ADMIN_PASSWORD_HASH", "h")
    monkeypatch.setenv("RELAY_TOKEN_SHA256", " aa , bb ,")
    monkeypatch.setenv("OAUTH_EXTRA_REDIRECT_URIS", "https://a/cb, https://b/cb")
    monkeypatch.setenv("RELAY_DATA_DIR", "/var/relay")
    s = Settings()
    assert s.token_digests == frozenset({"aa", "bb"})
    assert s.extra_redirect_uris == ("https://a/cb", "https://b/cb")
    assert s.db_path == Path("/var/relay/auth.db")


def test_short_signing_key_is_refused(monkeypatch):
    import pytest

    monkeypatch.setenv("RELAY_PUBLIC_URL", "https://relay.example")
    monkeypatch.setenv("OAUTH_SIGNING_KEY", "short")
    monkeypatch.setenv("RELAY_ADMIN_PASSWORD_HASH", "h")
    with pytest.raises(ValueError):
        Settings()
