from relay.auth.static_tokens import digest, new_token, verify_static_token


def test_verify_matches_one_of_many_digests():
    t = new_token()
    assert verify_static_token(t, ["deadbeef", digest(t)])


def test_verify_rejects_wrong_or_empty():
    t = new_token()
    assert not verify_static_token(t + "x", [digest(t)])
    assert not verify_static_token("", [digest(t)])
    assert not verify_static_token(t, [])


def test_new_token_is_long_and_urlsafe():
    t = new_token()
    assert len(t) >= 43 and all(c.isalnum() or c in "-_" for c in t)
