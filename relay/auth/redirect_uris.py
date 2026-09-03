"""Redirect URI policy: Claude's hosted callback, RFC 8252 loopback, or an explicit allowlist."""

from __future__ import annotations

from collections.abc import Iterable
from urllib.parse import urlsplit

CLAUDE_HOSTED_CALLBACK = "https://claude.ai/api/mcp/auth_callback"
_LOOPBACK_HOSTS = {"localhost", "127.0.0.1"}


def is_loopback(uri: str) -> bool:
    parts = urlsplit(uri)
    return parts.scheme == "http" and parts.hostname in _LOOPBACK_HOSTS


def _loopback_key(uri: str) -> tuple[str, str, str]:
    parts = urlsplit(uri)
    return (parts.hostname or "", parts.path, parts.query)


def redirect_uri_allowed(uri: str, extra: Iterable[str]) -> bool:
    if uri == CLAUDE_HOSTED_CALLBACK or uri in set(extra):
        return True
    if not is_loopback(uri):
        return False
    parts = urlsplit(uri)
    return not parts.fragment and parts.path != ""


def redirect_uri_matches(presented: str, registered: Iterable[str]) -> bool:
    for reg in registered:
        if presented == reg:
            return True
        if is_loopback(presented) and is_loopback(reg):
            if _loopback_key(presented) == _loopback_key(reg):
                return True
    return False
