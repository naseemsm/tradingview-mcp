"""SQLite-backed OAuth state. Only hashes of codes and refresh tokens are stored."""

from __future__ import annotations

import json
import sqlite3
import threading
from dataclasses import dataclass
from pathlib import Path

_SCHEMA = """
CREATE TABLE IF NOT EXISTS clients (
  client_id TEXT PRIMARY KEY, client_name TEXT NOT NULL,
  redirect_uris TEXT NOT NULL, created_at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS auth_codes (
  code_hash TEXT PRIMARY KEY, client_id TEXT NOT NULL, redirect_uri TEXT NOT NULL,
  code_challenge TEXT NOT NULL, scope TEXT NOT NULL, expires_at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS refresh_tokens (
  token_hash TEXT PRIMARY KEY, client_id TEXT NOT NULL, scope TEXT NOT NULL,
  expires_at REAL NOT NULL);
"""


@dataclass(frozen=True)
class Client:
    client_id: str
    client_name: str
    redirect_uris: tuple[str, ...]


@dataclass(frozen=True)
class AuthCode:
    client_id: str
    redirect_uri: str
    code_challenge: str
    scope: str


@dataclass(frozen=True)
class RefreshRecord:
    client_id: str
    scope: str


class AuthStore:
    def __init__(self, path: str | Path) -> None:
        self._conn = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None)
        self._lock = threading.Lock()
        with self._lock:
            if str(path) != ":memory:":
                self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.executescript(_SCHEMA)

    def close(self) -> None:
        self._conn.close()

    def register_client(
        self, client_id: str, client_name: str, redirect_uris: list[str], now: float
    ) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO clients VALUES (?,?,?,?)",
                (client_id, client_name, json.dumps(list(redirect_uris)), now),
            )

    def get_client(self, client_id: str) -> Client | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT client_id, client_name, redirect_uris FROM clients WHERE client_id=?",
                (client_id,),
            ).fetchone()
        if row is None:
            return None
        return Client(row[0], row[1], tuple(json.loads(row[2])))

    def save_code(
        self,
        code_hash: str,
        *,
        client_id: str,
        redirect_uri: str,
        code_challenge: str,
        scope: str,
        expires_at: float,
    ) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO auth_codes VALUES (?,?,?,?,?,?)",
                (code_hash, client_id, redirect_uri, code_challenge, scope, expires_at),
            )

    def consume_code(self, code_hash: str, now: float) -> AuthCode | None:
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                row = self._conn.execute(
                    "SELECT client_id, redirect_uri, code_challenge, scope, expires_at "
                    "FROM auth_codes WHERE code_hash=?",
                    (code_hash,),
                ).fetchone()
                self._conn.execute("DELETE FROM auth_codes WHERE code_hash=?", (code_hash,))
                self._conn.execute("COMMIT")
            except Exception:
                self._conn.execute("ROLLBACK")
                raise
        if row is None or row[4] <= now:
            return None
        return AuthCode(row[0], row[1], row[2], row[3])

    def save_refresh(
        self, token_hash: str, *, client_id: str, scope: str, expires_at: float
    ) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO refresh_tokens VALUES (?,?,?,?)",
                (token_hash, client_id, scope, expires_at),
            )

    def rotate_refresh(
        self, old_hash: str, new_hash: str, *, now: float, new_expires_at: float
    ) -> RefreshRecord | None:
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                row = self._conn.execute(
                    "SELECT client_id, scope, expires_at FROM refresh_tokens WHERE token_hash=?",
                    (old_hash,),
                ).fetchone()
                self._conn.execute("DELETE FROM refresh_tokens WHERE token_hash=?", (old_hash,))
                if row is None or row[2] <= now:
                    self._conn.execute("COMMIT")
                    return None
                self._conn.execute(
                    "INSERT INTO refresh_tokens VALUES (?,?,?,?)",
                    (new_hash, row[0], row[1], new_expires_at),
                )
                self._conn.execute("COMMIT")
            except Exception:
                self._conn.execute("ROLLBACK")
                raise
        return RefreshRecord(row[0], row[1])
