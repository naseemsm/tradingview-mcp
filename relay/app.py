"""Starlette application: health, OAuth server, and the authenticated proxy routes.

The relay is the only listener on the published port. It puts a bearer-token boundary
(static tokens or tokens from the built-in single-user OAuth 2.1 server) in front of the
TradingView MCP server, which runs loopback-only in the same container and speaks
Streamable HTTP on ``/mcp``.
"""

from __future__ import annotations

import contextlib
import logging
from collections.abc import AsyncIterator

import httpx
from argon2 import PasswordHasher
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from relay.auth.middleware import require_auth
from relay.auth.oauth_server import oauth_routes
from relay.auth.ratelimit import SlidingWindowLimiter
from relay.auth.store import AuthStore
from relay.config import Settings
from relay.proxy import proxy_request, upstream_alive

log = logging.getLogger("relay")

# Streamable HTTP: POST carries JSON-RPC, GET opens the server->client SSE stream,
# DELETE ends a session. Everything under /mcp is forwarded verbatim.
_MCP_METHODS = ["GET", "POST", "DELETE"]


class SecurityHeaders(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers.setdefault(
            "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
        )
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        return response


async def _health_payload(request: Request) -> tuple[dict, int]:
    state = request.app.state
    settings = state.settings
    alive = await upstream_alive(
        state.upstream, settings.upstream_url, path=settings.upstream_health_path
    )
    return {"relay": "ok", "upstream": "up" if alive else "starting"}, (200 if alive else 503)


async def healthz(request: Request) -> Response:
    body, status = await _health_payload(request)
    return JSONResponse(body, status_code=status, headers={"Cache-Control": "no-store"})


@require_auth
async def readyz(request: Request) -> Response:
    body, status = await _health_payload(request)
    return JSONResponse(body, status_code=status, headers={"Cache-Control": "no-store"})


@require_auth
async def proxied(request: Request) -> Response:
    state = request.app.state
    return await proxy_request(request, state.upstream, state.settings.upstream_url)


def _install_state(
    app: Starlette, settings: Settings, store: AuthStore | None, upstream: httpx.AsyncClient | None
) -> None:
    app.state.settings = settings
    if store is not None:
        app.state.store = store
    app.state.upstream = upstream or httpx.AsyncClient(
        base_url=settings.upstream_url, timeout=httpx.Timeout(30.0, read=None)
    )
    app.state.password_hasher = PasswordHasher()
    app.state.register_limiter = SlidingWindowLimiter(limit=20, window_s=3600)
    app.state.login_limiter = SlidingWindowLimiter(limit=10, window_s=900)
    app.state.token_limiter = SlidingWindowLimiter(limit=60, window_s=60)


def create_app(
    settings: Settings,
    *,
    store: AuthStore | None = None,
    upstream: httpx.AsyncClient | None = None,
) -> Starlette:
    @contextlib.asynccontextmanager
    async def lifespan(app: Starlette) -> AsyncIterator[None]:
        if getattr(app.state, "store", None) is None:
            settings.db_path.parent.mkdir(parents=True, exist_ok=True)
            app.state.store = AuthStore(settings.db_path)
        log.info(
            "relay up: canonical=%s upstream=%s", settings.canonical_url, settings.upstream_url
        )
        try:
            yield
        finally:
            await app.state.upstream.aclose()
            app.state.store.close()

    routes = [
        Route("/healthz", healthz),
        Route("/readyz", readyz),
        Route("/mcp", proxied, methods=_MCP_METHODS),
        Route("/mcp/{path:path}", proxied, methods=_MCP_METHODS),
        *oauth_routes(),
    ]
    app = Starlette(routes=routes, lifespan=lifespan, middleware=[Middleware(SecurityHeaders)])
    # Set eagerly too: httpx.ASGITransport in tests does not run the lifespan.
    _install_state(app, settings, store, upstream)
    return app
