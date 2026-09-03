import base64
import hashlib
import time

import pytest

from relay.auth.tokens import (
    InvalidToken,
    hash_opaque,
    issue_access_token,
    new_opaque,
    pkce_matches,
    verify_access_token,
)

KW = dict(key="s" * 32, issuer="https://r", audience="https://r")


def test_roundtrip_claims():
    tok = issue_access_token(client_id="c1", scope="tradingview", ttl_s=60, **KW)
    claims = verify_access_token(tok, **KW)
    assert claims["client_id"] == "c1"
    assert claims["aud"] == "https://r"
    assert claims["sub"] == "owner"


def test_rejects_wrong_audience_key_and_expiry():
    tok = issue_access_token(client_id="c1", scope="s", ttl_s=60, **KW)
    with pytest.raises(InvalidToken):
        verify_access_token(tok, key="s" * 32, issuer="https://r", audience="https://other")
    with pytest.raises(InvalidToken):
        verify_access_token(tok, key="w" * 32, issuer="https://r", audience="https://r")
    old = issue_access_token(client_id="c1", scope="s", ttl_s=60, now=time.time() - 120, **KW)
    with pytest.raises(InvalidToken):
        verify_access_token(old, **KW)
    with pytest.raises(InvalidToken):
        verify_access_token("not.a.jwt", **KW)


def test_pkce_s256():
    verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    assert pkce_matches(verifier, challenge)
    assert not pkce_matches(verifier + "x", challenge)


def test_opaque_hash_is_stable_and_distinct():
    a, b = new_opaque(), new_opaque()
    assert a != b
    assert hash_opaque(a) == hash_opaque(a)
    assert hash_opaque(a) != hash_opaque(b)
