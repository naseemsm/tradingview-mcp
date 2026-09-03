from relay.auth.store import AuthStore

CB = "https://claude.ai/api/mcp/auth_callback"


def test_client_roundtrip():
    s = AuthStore(":memory:")
    s.register_client("c1", "Claude", [CB], now=1.0)
    c = s.get_client("c1")
    assert c and c.client_name == "Claude" and c.redirect_uris == (CB,)
    assert s.get_client("nope") is None


def test_code_is_single_use_and_expires():
    s = AuthStore(":memory:")
    s.save_code(
        "h", client_id="c1", redirect_uri="r", code_challenge="ch", scope="s", expires_at=100.0
    )
    got = s.consume_code("h", now=50.0)
    assert got and got.code_challenge == "ch"
    assert s.consume_code("h", now=50.0) is None
    s.save_code(
        "h2", client_id="c1", redirect_uri="r", code_challenge="ch", scope="s", expires_at=100.0
    )
    assert s.consume_code("h2", now=100.0) is None


def test_refresh_rotation_kills_old_token():
    s = AuthStore(":memory:")
    s.save_refresh("old", client_id="c1", scope="s", expires_at=1000.0)
    rec = s.rotate_refresh("old", "new", now=10.0, new_expires_at=2000.0)
    assert rec and rec.client_id == "c1"
    assert s.rotate_refresh("old", "new2", now=10.0, new_expires_at=2000.0) is None
    assert s.rotate_refresh("new", "new3", now=20.0, new_expires_at=3000.0)
    # an expired token is refused and removed, so a later in-window attempt also fails
    assert s.rotate_refresh("new3", "new4", now=3000.0, new_expires_at=4000.0) is None
    assert s.rotate_refresh("new3", "new4", now=30.0, new_expires_at=4000.0) is None
