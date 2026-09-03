import httpx
import pytest
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route

from relay.auth.middleware import require_auth
from relay.auth.static_tokens import digest
from relay.auth.tokens import issue_access_token
from relay.config import Settings

TOKEN = "static-secret-token"
PRM = 'Bearer resource_metadata="https://r.example/.well-known/oauth-protected-resource"'


def make_settings() -> Settings:
    return Settings(
        relay_public_url="https://r.example/",
        oauth_signing_key="k" * 32,
        relay_admin_password_hash="h",
        relay_token_sha256=digest(TOKEN),
    )


@require_auth
async def whoami(request):
    p = request.state.principal
    return JSONResponse({"kind": p.kind, "client_id": p.client_id})


def make_app():
    app = Starlette(routes=[Route("/p", whoami)])
    app.state.settings = make_settings()
    return app


def client(app=None):
    return httpx.AsyncClient(transport=httpx.ASGITransport(app or make_app()), base_url="http://t")


@pytest.mark.anyio
async def test_missing_token_401_with_resource_metadata():
    async with client() as c:
        r = await c.get("/p")
        assert r.status_code == 401
        assert r.headers["www-authenticate"] == PRM
        assert r.headers["cache-control"] == "no-store"


@pytest.mark.anyio
async def test_query_string_token_is_ignored():
    async with client() as c:
        r = await c.get("/p", params={"access_token": TOKEN})
        assert r.status_code == 401


@pytest.mark.anyio
async def test_static_and_oauth_tokens_accepted_bad_rejected():
    async with client() as c:
        r = await c.get("/p", headers={"Authorization": f"Bearer {TOKEN}"})
        assert r.json() == {"kind": "static", "client_id": "static"}
        jwt_tok = issue_access_token(
            key="k" * 32,
            issuer="https://r.example",
            audience="https://r.example",
            client_id="c9",
            scope="tradingview",
            ttl_s=60,
        )
        r = await c.get("/p", headers={"Authorization": f"Bearer {jwt_tok}"})
        assert r.json() == {"kind": "oauth", "client_id": "c9"}
        r = await c.get("/p", headers={"Authorization": "Bearer nope"})
        assert r.status_code == 401
        assert 'error="invalid_token"' in r.headers["www-authenticate"]
        r = await c.get("/p", headers={"Authorization": f"Basic {TOKEN}"})
        assert r.status_code == 401
