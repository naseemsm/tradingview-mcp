"""Streaming reverse proxy to the MCP server. Bodies stream both ways; nothing is buffered."""

from __future__ import annotations

import httpx
from starlette.background import BackgroundTask
from starlette.requests import Request
from starlette.responses import JSONResponse, Response, StreamingResponse

_HOP_BY_HOP = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}
_REQUEST_DROP = _HOP_BY_HOP | {"authorization", "host", "cookie", "content-length"}
_RESPONSE_DROP = _HOP_BY_HOP | {
    "access-control-allow-origin",
    "access-control-allow-headers",
    "access-control-allow-methods",
    "content-length",
    "server",
    "date",
}


def _request_headers(request: Request) -> dict[str, str]:
    # Mcp-Session-Id, Accept, MCP-Protocol-Version and Content-Type pass through untouched.
    return {k: v for k, v in request.headers.items() if k.lower() not in _REQUEST_DROP}


def _response_headers(upstream: httpx.Response) -> dict[str, str]:
    out = {k: v for k, v in upstream.headers.items() if k.lower() not in _RESPONSE_DROP}
    out["Cache-Control"] = "no-store"
    return out


async def proxy_request(
    request: Request, client: httpx.AsyncClient, upstream_base: str
) -> Response:
    url = upstream_base.rstrip("/") + request.url.path
    if request.url.query:
        url += "?" + request.url.query
    upstream_req = client.build_request(
        request.method, url, headers=_request_headers(request), content=request.stream()
    )
    try:
        upstream = await client.send(upstream_req, stream=True)
    except httpx.HTTPError:
        return JSONResponse(
            {"error": "upstream_unavailable", "detail": "MCP server is not reachable"},
            status_code=503,
            headers={"Cache-Control": "no-store"},
        )
    return StreamingResponse(
        upstream.aiter_raw(),
        status_code=upstream.status_code,
        headers=_response_headers(upstream),
        background=BackgroundTask(upstream.aclose),
    )


async def upstream_alive(client: httpx.AsyncClient, upstream_base: str, path: str = "/") -> bool:
    """True once the upstream answers HTTP at all (any status); False on connection errors."""
    try:
        await client.get(upstream_base.rstrip("/") + path, timeout=2.0)
    except httpx.HTTPError:
        return False
    return True
