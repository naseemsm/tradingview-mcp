"""Single-user OAuth 2.1 authorization server: metadata, DCR, authorize, token."""

from __future__ import annotations

import html
import secrets
import time
from urllib.parse import urlencode, urlsplit

from argon2.exceptions import VerifyMismatchError
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.routing import Route

from relay.auth.redirect_uris import is_loopback, redirect_uri_allowed, redirect_uri_matches
from relay.auth.tokens import hash_opaque, issue_access_token, new_opaque, pkce_matches

_NO_STORE = {"Cache-Control": "no-store", "Pragma": "no-cache"}


def _scope(request: Request) -> str:
    return request.app.state.settings.oauth_scope


def _err(error: str, description: str, status: int = 400) -> JSONResponse:
    return JSONResponse(
        {"error": error, "error_description": description}, status_code=status, headers=_NO_STORE
    )


def _client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for", "")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


async def protected_resource_metadata(request: Request) -> Response:
    base = request.app.state.settings.canonical_url
    return JSONResponse(
        {
            "resource": base,
            "authorization_servers": [base],
            "bearer_methods_supported": ["header"],
            "scopes_supported": [_scope(request)],
            "resource_name": request.app.state.settings.relay_name,
        },
        headers=_NO_STORE,
    )


async def authorization_server_metadata(request: Request) -> Response:
    base = request.app.state.settings.canonical_url
    return JSONResponse(
        {
            "issuer": base,
            "authorization_endpoint": f"{base}/authorize",
            "token_endpoint": f"{base}/token",
            "registration_endpoint": f"{base}/register",
            "response_types_supported": ["code"],
            "response_modes_supported": ["query"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["none"],
            "scopes_supported": [_scope(request)],
        },
        headers=_NO_STORE,
    )


async def register(request: Request) -> Response:
    state = request.app.state
    ip = _client_ip(request)
    if state.register_limiter.is_blocked(ip):
        return _err("too_many_requests", "registration rate limit", 429)
    state.register_limiter.record(ip)
    try:
        body = await request.json()
    except ValueError:
        return _err("invalid_client_metadata", "body must be JSON")
    if not isinstance(body, dict):
        return _err("invalid_client_metadata", "body must be a JSON object")
    uris = body.get("redirect_uris")
    if not isinstance(uris, list) or not uris or not all(isinstance(u, str) for u in uris):
        return _err("invalid_client_metadata", "redirect_uris (non-empty list) is required")
    if body.get("token_endpoint_auth_method", "none") != "none":
        return _err(
            "invalid_client_metadata", "only public clients (token_endpoint_auth_method=none)"
        )
    for uri in uris:
        if not redirect_uri_allowed(uri, state.settings.extra_redirect_uris):
            return _err("invalid_redirect_uri", f"redirect_uri not allowed: {uri}")
    grants = body.get("grant_types", ["authorization_code"])
    if not isinstance(grants, list) or not set(grants) <= {"authorization_code", "refresh_token"}:
        return _err("invalid_client_metadata", "unsupported grant_types")
    client_id = new_opaque()
    name = str(body.get("client_name", "MCP client"))[:100]
    state.store.register_client(client_id, name, uris, now=time.time())
    return JSONResponse(
        {
            "client_id": client_id,
            "client_name": name,
            "redirect_uris": uris,
            "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "client_id_issued_at": int(time.time()),
        },
        status_code=201,
        headers=_NO_STORE,
    )


def _validate_authorize(request: Request) -> tuple[dict, None] | tuple[None, Response]:
    state = request.app.state
    q = request.query_params
    client = state.store.get_client(q.get("client_id", ""))
    if client is None:
        return None, _err("invalid_client", "unknown client_id", 401)
    redirect_uri = q.get("redirect_uri", "")
    if not redirect_uri_matches(redirect_uri, client.redirect_uris):
        return None, _err("invalid_request", "redirect_uri does not match registration")
    if q.get("response_type") != "code":
        return None, _err("unsupported_response_type", "response_type must be code")
    if q.get("code_challenge_method") != "S256" or not q.get("code_challenge"):
        return None, _err("invalid_request", "PKCE S256 code_challenge is required")
    resource = q.get("resource")
    if resource and resource.rstrip("/") != state.settings.canonical_url:
        return None, _err("invalid_target", "resource must be this relay")
    allowed = _scope(request)
    scope = q.get("scope", allowed)
    if scope and set(scope.split()) - {allowed, "offline_access"}:
        return None, _err("invalid_scope", f"only scope '{allowed}' is available")
    return (
        {
            "client": client,
            "redirect_uri": redirect_uri,
            "code_challenge": q["code_challenge"],
            "state": q.get("state", ""),
        },
        None,
    )


def _login_page(
    relay_name: str, client_name: str, redirect_uri: str, csrf: str, error: str = ""
) -> HTMLResponse:
    host = urlsplit(redirect_uri).netloc
    warn = (
        "<p class='warn'>This redirect goes to a program on your own computer (loopback). "
        "Only continue if you started this connection yourself.</p>"
        if is_loopback(redirect_uri)
        else ""
    )
    err_html = f"<p class='err'>{html.escape(error)}</p>" if error else ""
    body = f"""<!doctype html><meta charset=utf-8><title>{html.escape(relay_name)} login</title>
<style>body{{font:16px system-ui;max-width:32rem;margin:4rem auto;padding:0 1rem}}
.warn{{color:#a50}} .err{{color:#b00}} input{{font:inherit;padding:.4rem;width:100%}}
button{{font:inherit;padding:.5rem 1rem;margin-top:1rem}}</style>
<h1>Authorize access to your {html.escape(relay_name)}</h1>
<p><b>{html.escape(client_name)}</b> wants access. After login you will be sent to
<code>{html.escape(host)}</code>.</p>{warn}
{err_html}
<form method=post><input type=hidden name="csrf" value="{csrf}">
<label>Relay admin password<br>
<input type=password name=password autocomplete=current-password autofocus></label>
<button type=submit>Authorize</button></form>"""
    resp = HTMLResponse(body, headers=_NO_STORE)
    resp.set_cookie("relay_csrf", csrf, httponly=True, samesite="lax", secure=True, max_age=600)
    return resp


async def authorize_get(request: Request) -> Response:
    ok, err = _validate_authorize(request)
    if err is not None:
        return err
    assert ok is not None  # noqa: S101 - narrowed by the branch above
    return _login_page(
        request.app.state.settings.relay_name,
        ok["client"].client_name,
        ok["redirect_uri"],
        secrets.token_urlsafe(24),
    )


async def authorize_post(request: Request) -> Response:
    state = request.app.state
    ok, err = _validate_authorize(request)
    if err is not None:
        return err
    assert ok is not None  # noqa: S101 - narrowed by the branch above
    ip = _client_ip(request)
    if state.login_limiter.is_blocked(ip):
        return _err("too_many_requests", "too many failed logins; wait 15 minutes", 429)
    form = await request.form()
    csrf = str(form.get("csrf", ""))
    if not csrf or not secrets.compare_digest(csrf, request.cookies.get("relay_csrf", "")):
        return _err("invalid_request", "bad CSRF token; reload the page")
    try:
        state.password_hasher.verify(
            state.settings.relay_admin_password_hash, str(form.get("password", ""))
        )
    except VerifyMismatchError:
        state.login_limiter.record(ip)
        page = _login_page(
            state.settings.relay_name,
            ok["client"].client_name,
            ok["redirect_uri"],
            csrf,
            "Wrong password.",
        )
        page.status_code = 401
        return page
    code = new_opaque()
    state.store.save_code(
        hash_opaque(code),
        client_id=ok["client"].client_id,
        redirect_uri=ok["redirect_uri"],
        code_challenge=ok["code_challenge"],
        scope=state.settings.oauth_scope,
        expires_at=time.time() + state.settings.auth_code_ttl_s,
    )
    params = {"code": code}
    if ok["state"]:
        params["state"] = ok["state"]
    sep = "&" if urlsplit(ok["redirect_uri"]).query else "?"
    resp = RedirectResponse(f"{ok['redirect_uri']}{sep}{urlencode(params)}", status_code=303)
    resp.headers.update(_NO_STORE)
    resp.delete_cookie("relay_csrf")
    return resp


def _token_response(settings, client_id: str, scope: str, refresh_token: str) -> JSONResponse:
    access = issue_access_token(
        key=settings.oauth_signing_key,
        issuer=settings.canonical_url,
        audience=settings.canonical_url,
        client_id=client_id,
        scope=scope,
        ttl_s=settings.access_token_ttl_s,
    )
    return JSONResponse(
        {
            "access_token": access,
            "token_type": "Bearer",
            "expires_in": settings.access_token_ttl_s,
            "refresh_token": refresh_token,
            "scope": scope,
        },
        headers=_NO_STORE,
    )


async def token(request: Request) -> Response:
    state = request.app.state
    settings = state.settings
    ip = _client_ip(request)
    if state.token_limiter.is_blocked(ip):
        return _err("too_many_requests", "token endpoint rate limit", 429)
    state.token_limiter.record(ip)
    ctype = request.headers.get("content-type", "")
    if not ctype.startswith("application/x-www-form-urlencoded"):
        return _err("invalid_request", "content-type must be application/x-www-form-urlencoded")
    form = await request.form()
    grant = form.get("grant_type")
    client_id = str(form.get("client_id", ""))
    if state.store.get_client(client_id) is None:
        return _err("invalid_client", "unknown client_id", 401)
    resource = str(form.get("resource", ""))
    if resource and resource.rstrip("/") != settings.canonical_url:
        return _err("invalid_target", "resource must be this relay")
    now = time.time()

    if grant == "authorization_code":
        code = str(form.get("code", ""))
        record = state.store.consume_code(hash_opaque(code), now=now) if code else None
        if record is None or record.client_id != client_id:
            return _err("invalid_grant", "code is invalid, expired, or already used")
        if str(form.get("redirect_uri", "")) != record.redirect_uri:
            return _err("invalid_grant", "redirect_uri mismatch")
        verifier = str(form.get("code_verifier", ""))
        if not (43 <= len(verifier) <= 128) or not pkce_matches(verifier, record.code_challenge):
            return _err("invalid_grant", "PKCE verification failed")
        refresh = new_opaque()
        state.store.save_refresh(
            hash_opaque(refresh),
            client_id=client_id,
            scope=record.scope,
            expires_at=now + settings.refresh_token_ttl_s,
        )
        return _token_response(settings, client_id, record.scope, refresh)

    if grant == "refresh_token":
        old = str(form.get("refresh_token", ""))
        new = new_opaque()
        record = (
            state.store.rotate_refresh(
                hash_opaque(old),
                hash_opaque(new),
                now=now,
                new_expires_at=now + settings.refresh_token_ttl_s,
            )
            if old
            else None
        )
        if record is None or record.client_id != client_id:
            return _err("invalid_grant", "refresh token is invalid, expired, or revoked")
        return _token_response(settings, client_id, record.scope, new)

    return _err("unsupported_grant_type", "use authorization_code or refresh_token")


def oauth_routes() -> list[Route]:
    return [
        Route("/.well-known/oauth-protected-resource", protected_resource_metadata),
        Route("/.well-known/oauth-protected-resource/{rest:path}", protected_resource_metadata),
        Route("/.well-known/oauth-authorization-server", authorization_server_metadata),
        Route("/register", register, methods=["POST"]),
        Route("/authorize", authorize_get, methods=["GET"]),
        Route("/authorize", authorize_post, methods=["POST"]),
        Route("/token", token, methods=["POST"]),
    ]
