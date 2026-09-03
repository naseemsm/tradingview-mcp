import asyncio
import contextlib
import socket

import pytest
import uvicorn


@pytest.fixture
def anyio_backend():
    return "asyncio"


@contextlib.asynccontextmanager
async def live_server(app):
    """Serve an ASGI app on a real loopback socket.

    httpx.ASGITransport buffers whole responses, so anything that must prove streaming
    behaviour (SSE) has to cross a real TCP connection.
    """
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning", lifespan="off")
    server = uvicorn.Server(config)
    task = asyncio.create_task(server.serve())
    while not server.started:
        await asyncio.sleep(0.01)
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        await task
