"""`python -m relay`: run the relay with uvicorn behind Railway's TLS edge."""

import logging

import uvicorn

from relay.app import create_app
from relay.config import Settings

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    settings = Settings()
    uvicorn.run(
        create_app(settings),
        host="0.0.0.0",  # noqa: S104 - the container port is the published surface
        port=settings.port,
        proxy_headers=True,
        forwarded_allow_ips="*",
        timeout_keep_alive=75,
    )
