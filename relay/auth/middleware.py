"""Resolve the bearer credential on protected routes. Static token first, then signed JWT."""

from __future__ import annotations

import functools
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Literal

from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from relay.auth.static_tokens import verify_static_token
from relay.auth.tokens import InvalidToken, verify_access_token
from relay.config import Settings


@dataclass(frozen=True)
class Principal:
    kind: Literal["static", "oauth"]
    client_id: str


def _bearer(request: Request) -> str | None:
    header = request.headers.get("authorization", "")
    scheme, _, value = header.partition(" ")
    if scheme.lower() != "bearer" or not value.strip():
        return None
    return value.strip()


def authenticate(request: Request) -> Principal | None:
    settings: Settings = request.app.state.settings
    token = _bearer(request)
    if token is None:
        return None
    if verify_static_token(token, settings.token_digests):
        return Principal("static", "static")
    try:
        claims = verify_access_token(
            token,
            key=settings.oauth_signing_key,
            issuer=settings.canonical_url,
            audience=settings.canonical_url,
        )
    except InvalidToken:
        return None
    return Principal("oauth", str(claims.get("client_id", "")))


def unauthorized(settings: Settings, *, invalid: bool) -> JSONResponse:
    challenge = (
        f'Bearer resource_metadata="{settings.canonical_url}/.well-known/oauth-protected-resource"'
    )
    if invalid:
        challenge += ', error="invalid_token"'
    return JSONResponse(
        {"error": "invalid_token" if invalid else "unauthorized"},
        status_code=401,
        headers={"WWW-Authenticate": challenge, "Cache-Control": "no-store"},
    )


def require_auth(
    endpoint: Callable[[Request], Awaitable[Response]],
) -> Callable[[Request], Awaitable[Response]]:
    @functools.wraps(endpoint)
    async def wrapper(request: Request) -> Response:
        principal = authenticate(request)
        if principal is None:
            return unauthorized(request.app.state.settings, invalid=_bearer(request) is not None)
        request.state.principal = principal
        return await endpoint(request)

    return wrapper
