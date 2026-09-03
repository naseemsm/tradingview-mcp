"""Typed settings. Every value comes from the environment; nothing is read from files."""

from __future__ import annotations

from pathlib import Path

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


def _split_csv(raw: str) -> tuple[str, ...]:
    return tuple(part.strip() for part in raw.split(",") if part.strip())


class Settings(BaseSettings):
    model_config = SettingsConfigDict(extra="ignore")

    port: int = 8080
    relay_public_url: str
    relay_name: str = "TradingView MCP relay"
    # The MCP server runs in the same container, loopback-only, on this port.
    upstream_url: str = "http://127.0.0.1:8000"
    upstream_health_path: str = "/health"
    oauth_signing_key: str
    oauth_scope: str = "tradingview"
    relay_admin_password_hash: str
    relay_token_sha256: str = ""
    oauth_extra_redirect_uris: str = ""
    relay_data_dir: Path = Path("/data")
    access_token_ttl_s: int = 3600
    refresh_token_ttl_s: int = 30 * 24 * 3600
    auth_code_ttl_s: int = 300

    @field_validator("oauth_signing_key")
    @classmethod
    def _key_is_long_enough(cls, value: str) -> str:
        # RFC 7518 §3.2: HS256 keys must be at least 256 bits. PyJWT warns; we refuse.
        if len(value.encode("utf-8")) < 32:
            raise ValueError("OAUTH_SIGNING_KEY must be at least 32 bytes")
        return value

    @property
    def canonical_url(self) -> str:
        return self.relay_public_url.rstrip("/")

    @property
    def token_digests(self) -> frozenset[str]:
        return frozenset(d.lower() for d in _split_csv(self.relay_token_sha256))

    @property
    def extra_redirect_uris(self) -> tuple[str, ...]:
        return _split_csv(self.oauth_extra_redirect_uris)

    @property
    def db_path(self) -> Path:
        return self.relay_data_dir / "auth.db"
