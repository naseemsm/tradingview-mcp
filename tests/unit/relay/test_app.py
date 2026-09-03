import httpx
import pytest
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from relay.app import create_app
from relay.auth.static_tokens import digest
from relay.auth.store import AuthStore
from relay.config import Settings

TOKEN = "tok"


def upstream_app():
    async def any_(request: Request):
        return JSONResponse(
            {
                "path": request.url.path,
                "q": dict(request.query_params),
                "method": request.method,
                "session": request.headers.get("mcp-session-id"),
            }
        )

    return Starlette(routes=[Route("/{p:path}", any_, methods=["GET", "POST", "DELETE"])])


def make(upstream=None):
    s = Settings(
        relay_public_url="https://r.example",
        oauth_signing_key="k" * 32,
        relay_admin_password_hash="h",
        relay_token_sha256=digest(TOKEN),
    )
    up = httpx.AsyncClient(
        transport=httpx.ASGITransport(upstream or upstream_app()), base_url="http://up"
    )
    app = create_app(s, store=AuthStore(":memory:"), upstream=up)
    return httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="https://r.example")


@pytest.mark.anyio
async def test_healthz_open_and_reports_upstream():
    async with make() as c:
        r = await c.get("/healthz")
        assert r.status_code == 200 and r.json() == {"relay": "ok", "upstream": "up"}
        assert r.headers["strict-transport-security"].startswith("max-age=")


@pytest.mark.anyio
async def test_protected_routes_require_token_and_proxy():
    async with make() as c:
        assert (await c.get("/mcp")).status_code == 401
        assert (await c.post("/mcp", content=b"{}")).status_code == 401
        assert (await c.delete("/mcp")).status_code == 401
        assert (await c.get("/mcp/anything")).status_code == 401
        assert (await c.get("/readyz")).status_code == 401
        h = {"Authorization": f"Bearer {TOKEN}", "Mcp-Session-Id": "s1"}
        r = await c.post("/mcp", headers=h, content=b"{}")
        assert r.json() == {"path": "/mcp", "q": {}, "method": "POST", "session": "s1"}
        r = await c.get("/mcp", headers=h)
        assert r.json()["method"] == "GET" and r.json()["session"] == "s1"
        r = await c.delete("/mcp", headers=h)
        assert r.json()["method"] == "DELETE"
        r = await c.get("/mcp/sub", params={"x": "1"}, headers=h)
        assert r.json()["path"] == "/mcp/sub" and r.json()["q"] == {"x": "1"}
        assert (await c.get("/readyz", headers=h)).json() == {"relay": "ok", "upstream": "up"}
        assert (await c.get("/", headers=h)).status_code == 404
        # The MCP server's own open /health is not exposed; only the relay's /healthz is.
        assert (await c.get("/health", headers=h)).status_code == 404
        assert (await c.get("/v3/anything", headers=h)).status_code == 404
