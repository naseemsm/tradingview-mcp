"""Print a fresh static bearer token and its SHA-256 digest.

Give the token to clients (Claude Code ``--header``, curl); put only the digest in the
relay's ``RELAY_TOKEN_SHA256`` (comma-separated to allow several tokens).
"""

import hashlib
import secrets

if __name__ == "__main__":
    token = secrets.token_urlsafe(32)
    print(f"token (give to clients, shown once): {token}")
    print(f"RELAY_TOKEN_SHA256 entry:            {hashlib.sha256(token.encode()).hexdigest()}")
