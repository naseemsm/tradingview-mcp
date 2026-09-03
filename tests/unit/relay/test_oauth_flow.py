import base64
import hashlib
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from argon2 import PasswordHasher

from relay.app import create_app
from relay.auth.store import AuthStore
from relay.config import Settings

PASSWORD = "correct horse"
CLAUDE = "https://claude.ai/api/mcp/auth_callback"


def settings() -> Settings:
    return Settings(
        relay_public_url="https://r.example",
        oauth_signing_key="k" * 32,
        relay_admin_password_hash=PasswordHasher().hash(PASSWORD),
    )


def client():
    app = create_app(settings(), store=AuthStore(":memory:"))
    return httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="https://r.example")


def pkce():
    verifier = "a" * 43
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return verifier, challenge


async def register(c, redirect=CLAUDE):
    r = await c.post(
        "/register",
        json={
            "redirect_uris": [redirect],
            "client_name": "Claude",
            "token_endpoint_auth_method": "none",
        },
    )
    assert r.status_code == 201, r.text
    return r.json()["client_id"]


def auth_params(client_id, challenge, redirect=CLAUDE):
    return {
        "client_id": client_id,
        "redirect_uri": redirect,
        "response_type": "code",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "state": "xyz",
        "scope": "tradingview",
        "resource": "https://r.example",
    }


async def authorize(c, client_id, challenge, password=PASSWORD, redirect=CLAUDE):
    params = auth_params(client_id, challenge, redirect)
    page = await c.get("/authorize", params=params)
    assert page.status_code == 200 and "claude.ai" in page.text
    csrf = page.text.split('name="csrf" value="')[1].split('"')[0]
    return await c.post("/authorize", params=params, data={"password": password, "csrf": csrf})


def code_from(resp):
    return parse_qs(urlsplit(resp.headers["location"]).query)["code"][0]


@pytest.mark.anyio
async def test_discovery_documents():
    async with client() as c:
        prm = (await c.get("/.well-known/oauth-protected-resource")).json()
        assert prm["resource"] == "https://r.example"
        assert prm["authorization_servers"] == ["https://r.example"]
        assert prm["bearer_methods_supported"] == ["header"]
        assert prm["scopes_supported"] == ["tradingview"]
        assert prm["resource_name"] == "TradingView MCP relay"
        suffixed = await c.get("/.well-known/oauth-protected-resource/mcp")
        assert suffixed.status_code == 200
        asm = (await c.get("/.well-known/oauth-authorization-server")).json()
        assert asm["issuer"] == "https://r.example"
        assert asm["code_challenge_methods_supported"] == ["S256"]
        assert asm["token_endpoint_auth_methods_supported"] == ["none"]
        assert asm["registration_endpoint"] == "https://r.example/register"
        assert asm["grant_types_supported"] == ["authorization_code", "refresh_token"]
        assert asm["scopes_supported"] == ["tradingview"]


@pytest.mark.anyio
async def test_register_rejects_bad_redirects():
    async with client() as c:
        r = await c.post("/register", json={"redirect_uris": ["https://evil.example/cb"]})
        assert r.status_code == 400 and r.json()["error"] == "invalid_redirect_uri"
        r = await c.post("/register", json={"client_name": "x"})
        assert r.status_code == 400 and r.json()["error"] == "invalid_client_metadata"
        r = await c.post(
            "/register",
            json={"redirect_uris": [CLAUDE], "token_endpoint_auth_method": "client_secret_basic"},
        )
        assert r.status_code == 400


@pytest.mark.anyio
async def test_full_code_flow_with_pkce_and_refresh_rotation():
    async with client() as c:
        cid = await register(c)
        verifier, challenge = pkce()
        bad = await authorize(c, cid, challenge, password="wrong")
        assert bad.status_code == 401
        ok = await authorize(c, cid, challenge)
        assert ok.status_code == 303
        loc = urlsplit(ok.headers["location"])
        assert loc.scheme == "https" and loc.netloc == "claude.ai"
        assert parse_qs(loc.query)["state"] == ["xyz"]
        code = code_from(ok)

        base = {"grant_type": "authorization_code", "redirect_uri": CLAUDE, "client_id": cid}
        wrong = await c.post("/token", data={**base, "code": code, "code_verifier": "b" * 43})
        assert wrong.status_code == 400 and wrong.json()["error"] == "invalid_grant"
        again = await c.post("/token", data={**base, "code": code, "code_verifier": verifier})
        assert again.json()["error"] == "invalid_grant"  # a failed exchange burns the code

        code = code_from(await authorize(c, cid, challenge))
        tok = await c.post(
            "/token",
            data={**base, "code": code, "code_verifier": verifier, "resource": "https://r.example"},
        )
        assert tok.status_code == 200, tok.text
        body = tok.json()
        assert body["token_type"] == "Bearer" and body["expires_in"] == 3600
        assert tok.headers["cache-control"] == "no-store"

        refresh = {"grant_type": "refresh_token", "client_id": cid}
        r1 = await c.post("/token", data={**refresh, "refresh_token": body["refresh_token"]})
        assert r1.status_code == 200 and r1.json()["refresh_token"] != body["refresh_token"]
        r2 = await c.post("/token", data={**refresh, "refresh_token": body["refresh_token"]})
        assert r2.status_code == 400 and r2.json()["error"] == "invalid_grant"

        me = await c.get("/readyz", headers={"Authorization": f"Bearer {body['access_token']}"})
        assert me.status_code in (200, 503)  # authenticated; upstream is absent in this test


@pytest.mark.anyio
async def test_token_rejects_json_body_and_unknown_client():
    async with client() as c:
        cid = await register(c)
        r = await c.post("/token", json={"grant_type": "refresh_token", "client_id": cid})
        assert r.status_code == 400 and r.json()["error"] == "invalid_request"
        r = await c.post("/token", data={"grant_type": "refresh_token", "client_id": "zzz"})
        assert r.status_code == 401 and r.json()["error"] == "invalid_client"
        r = await c.post("/token", data={"grant_type": "password", "client_id": cid})
        assert r.json()["error"] == "unsupported_grant_type"


@pytest.mark.anyio
async def test_authorize_rejects_missing_pkce_wrong_redirect_and_resource():
    async with client() as c:
        cid = await register(c)
        base = {"client_id": cid, "redirect_uri": CLAUDE, "response_type": "code", "state": "s"}
        r = await c.get("/authorize", params=base)
        assert r.status_code == 400
        pk = {"code_challenge": "x", "code_challenge_method": "S256"}
        r = await c.get("/authorize", params={**base, **pk, "redirect_uri": "https://evil/cb"})
        assert r.status_code == 400
        r = await c.get("/authorize", params={**base, **pk, "resource": "https://other"})
        assert r.status_code == 400
        r = await c.get("/authorize", params={**base, **pk, "client_id": "nope"})
        assert r.status_code == 401


@pytest.mark.anyio
async def test_authorize_post_requires_matching_csrf():
    async with client() as c:
        cid = await register(c)
        _, challenge = pkce()
        params = auth_params(cid, challenge)
        await c.get("/authorize", params=params)
        r = await c.post("/authorize", params=params, data={"password": PASSWORD, "csrf": "bogus"})
        assert r.status_code == 400 and r.json()["error"] == "invalid_request"


@pytest.mark.anyio
async def test_login_lockout_after_repeated_failures():
    async with client() as c:
        cid = await register(c)
        _, challenge = pkce()
        for _ in range(10):
            assert (await authorize(c, cid, challenge, password="wrong")).status_code == 401
        assert (await authorize(c, cid, challenge)).status_code == 429
