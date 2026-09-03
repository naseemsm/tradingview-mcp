"""Generate (or hash) the relay admin password; prints the argon2id hash for
RELAY_ADMIN_PASSWORD_HASH. With no argument a random password is generated and shown once.

Run with the relay extra installed: ``uv run --extra relay python tools/hash_password.py``.
"""

import secrets
import sys

from argon2 import PasswordHasher

if __name__ == "__main__":
    password = sys.argv[1] if len(sys.argv) > 1 else secrets.token_urlsafe(24)
    if len(sys.argv) == 1:
        print(f"password (shown once): {password}")
    print(f"RELAY_ADMIN_PASSWORD_HASH: {PasswordHasher().hash(password)}")
