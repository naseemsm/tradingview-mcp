import anyio
import httpx
import pytest
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, StreamingResponse
from starlette.routing import Route

from relay.proxy import proxy_request, upstream_alive
from conftest import live_server


def fake_upstream(release: anyio.Event) -> Starlette:
    async def sse(request: Request):
        async def gen():
            yield b"event: endpoint\ndata: /mcp/message?sessionId=abc\n\n"
            await release.wait()
            yield b"event: message\ndata: {}\n\n"

        return StreamingResponse(
            gen(), media_type="text/event-stream", headers={"Access-Control-Allow-Origin": "*"}
        )

    async def echo(request: Request):
        return JSONResponse(
            {
                "path": request.url.path,
                "query": dict(request.query_params),
                "auth": request.headers.get("authorization"),
                "host": request.headers.get("host"),
                "ctype": request.headers.get("content-type"),
                "body": (await request.body()).decode(),
            },
            headers={"Access-Control-Allow-Origin": "*", "X-Up": "1"},
        )

    return Starlette(
        routes=[
            Route("/mcp/sse", sse),
            Route("/{p:path}", echo, methods=["GET", "POST", "DELETE"]),
        ]
    )


def relay_app(upstream: Starlette | None = None, upstream_url: str = "http://up"):
    if upstream is not None:
        client = httpx.AsyncClient(
            transport=httpx.ASGITransport(upstream),
            base_url=upstream_url,
            timeout=httpx.Timeout(5, read=None),
        )
    else:
        client = httpx.AsyncClient(base_url=upstream_url, timeout=httpx.Timeout(5, read=None))

    async def handler(request: Request):
        return await proxy_request(request, client, upstream_url)

    return Starlette(routes=[Route("/{p:path}", handler, methods=["GET", "POST"])])


@pytest.mark.anyio
async def test_forwards_path_query_body_and_scrubs_headers():
    app = relay_app(fake_upstream(anyio.Event()))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="http://relay") as c:
        r = await c.post(
            "/v3/x/y",
            params={"symbol": "SPXW", "format": "json"},
            content=b'{"a":1}',
            headers={"Authorization": "Bearer t", "Content-Type": "application/json"},
        )
        body = r.json()
        assert body["path"] == "/v3/x/y"
        assert body["query"] == {"symbol": "SPXW", "format": "json"}
        assert body["auth"] is None and body["host"] == "up" and body["body"] == '{"a":1}'
        assert body["ctype"] == "application/json"
        assert "access-control-allow-origin" not in r.headers
        assert r.headers["x-up"] == "1" and r.headers["cache-control"] == "no-store"


@pytest.mark.anyio
async def test_sse_streams_before_upstream_finishes():
    release = anyio.Event()
    async with live_server(fake_upstream(release)) as upstream_url:
        async with live_server(relay_app(upstream_url=upstream_url)) as relay_url:
            async with httpx.AsyncClient(base_url=relay_url, timeout=5) as c:
                async with c.stream("GET", "/mcp/sse") as r:
                    assert r.headers["content-type"].startswith("text/event-stream")
                    it = r.aiter_lines()
                    first = await it.__anext__()
                    assert first == "event: endpoint"  # arrived while upstream is still open
                    release.set()
                    rest = [line async for line in it]
                    assert "event: message" in rest


@pytest.mark.anyio
async def test_upstream_down_gives_503_and_alive_false():
    dead = httpx.AsyncClient(base_url="http://127.0.0.1:9", timeout=1)

    async def handler(request: Request):
        return await proxy_request(request, dead, "http://127.0.0.1:9")

    app = Starlette(routes=[Route("/{p:path}", handler)])
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="http://relay") as c:
        r = await c.get("/v3/anything")
        assert r.status_code == 503 and r.json()["error"] == "upstream_unavailable"
    assert not await upstream_alive(dead, "http://127.0.0.1:9", path="/health")
    live = httpx.AsyncClient(transport=httpx.ASGITransport(fake_upstream(anyio.Event())))
    assert await upstream_alive(live, "http://up", path="/health")
