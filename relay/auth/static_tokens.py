"""Static bearer tokens: the relay stores only SHA-256 digests; clients hold the plaintext."""

from __future__ import annotations

import hashlib
import hmac
import secrets
from collections.abc import Iterable


def new_token() -> str:
    return secrets.token_urlsafe(32)


def digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def verify_static_token(token: str, digests: Iterable[str]) -> bool:
    if not token:
        return False
    presented = digest(token)
    matched = False
    for candidate in digests:  # always walk the whole list: no early exit on match
        if hmac.compare_digest(presented, candidate.lower()):
            matched = True
    return matched
