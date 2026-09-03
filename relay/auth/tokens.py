"""Signed access tokens (HS256 JWT) and opaque token helpers for codes and refresh tokens."""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import time
import uuid

import jwt


class InvalidToken(Exception):
    """The presented access token is not valid for this relay."""


def issue_access_token(
    *,
    key: str,
    issuer: str,
    audience: str,
    client_id: str,
    scope: str,
    ttl_s: int,
    now: float | None = None,
) -> str:
    iat = int(now if now is not None else time.time())
    payload = {
        "iss": issuer,
        "aud": audience,
        "sub": "owner",
        "client_id": client_id,
        "scope": scope,
        "iat": iat,
        "exp": iat + ttl_s,
        "jti": uuid.uuid4().hex,
    }
    return jwt.encode(payload, key, algorithm="HS256")


def verify_access_token(token: str, *, key: str, issuer: str, audience: str) -> dict:
    try:
        return jwt.decode(
            token,
            key,
            algorithms=["HS256"],
            audience=audience,
            issuer=issuer,
            options={"require": ["exp", "iat", "aud", "iss", "sub"]},
        )
    except jwt.PyJWTError as err:
        raise InvalidToken(str(err)) from err


def new_opaque() -> str:
    return secrets.token_urlsafe(32)


def hash_opaque(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def pkce_matches(verifier: str, challenge: str) -> bool:
    computed = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest())
    return hmac.compare_digest(computed.rstrip(b"=").decode("ascii"), challenge)
