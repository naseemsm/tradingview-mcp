from relay.auth.redirect_uris import redirect_uri_allowed, redirect_uri_matches

CLAUDE = "https://claude.ai/api/mcp/auth_callback"


def test_allowlist():
    assert redirect_uri_allowed(CLAUDE, [])
    assert redirect_uri_allowed("http://localhost:3118/callback", [])
    assert redirect_uri_allowed("http://127.0.0.1:51234/callback", [])
    assert redirect_uri_allowed("https://extra.example/cb", ["https://extra.example/cb"])
    assert not redirect_uri_allowed("https://evil.example/cb", [])
    assert not redirect_uri_allowed("http://localhost.evil.example/callback", [])
    assert not redirect_uri_allowed("https://claude.ai/api/mcp/auth_callback?x=1", [])
    assert not redirect_uri_allowed("http://claude.ai/api/mcp/auth_callback", [])
    assert not redirect_uri_allowed("javascript:alert(1)", [])


def test_registered_match_is_exact_except_loopback_port():
    assert redirect_uri_matches(CLAUDE, [CLAUDE])
    assert not redirect_uri_matches(CLAUDE + "/", [CLAUDE])
    assert redirect_uri_matches("http://localhost:4444/callback", ["http://localhost/callback"])
    assert redirect_uri_matches("http://127.0.0.1:9/callback", ["http://127.0.0.1:3118/callback"])
    assert not redirect_uri_matches("http://localhost:4444/other", ["http://localhost/callback"])
