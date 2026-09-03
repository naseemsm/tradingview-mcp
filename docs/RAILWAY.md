# Private deployment on Railway (OAuth-gated)

This repo can be deployed to Railway as a **private, authenticated** MCP endpoint, the same
way the ThetaData personal relay is deployed: one container, two processes, and a relay in
front that requires a bearer token before anything reaches the MCP server.

- **TradingView MCP server** (`tradingview-mcp streamable-http`) bound to `127.0.0.1:8000`,
  never published.
- **Relay** (`relay/`, Python/Starlette) on `$PORT`, the only published port. It is a streaming
  reverse proxy that requires `Authorization: Bearer ...` on `/mcp` and `/readyz`, and it hosts
  a single-user OAuth 2.1 authorization server so claude.ai, Claude Desktop, Claude mobile and
  Claude Code can connect without a shared secret.

`entrypoint.sh` supervises both; if either exits the container exits non-zero and Railway's
restart policy restarts it. `railway.toml` selects `Dockerfile.railway` (the plain `Dockerfile`
stays the unauthenticated image published to GHCR).

## Authentication

Two credential types are accepted on `Authorization: Bearer ...` (never in the URL):

| credential | who uses it | how it is issued |
| --- | --- | --- |
| OAuth 2.1 access token | claude.ai, Claude Desktop, Claude mobile, Claude Code via OAuth | Dynamic client registration, PKCE S256, login with the relay admin password, rotating refresh tokens |
| Static bearer token | Claude Code `--header`, curl, scripts | `tools/mint_token.py`; only the SHA-256 digest is stored |

Discovery is spec-shaped: `401` responses carry
`WWW-Authenticate: Bearer resource_metadata="<url>/.well-known/oauth-protected-resource"`, and
`/.well-known/oauth-authorization-server` advertises `code_challenge_methods_supported: ["S256"]`,
`token_endpoint_auth_methods_supported: ["none"]`, and a `registration_endpoint`. Redirect URIs
are restricted to `https://claude.ai/api/mcp/auth_callback`, RFC 8252 loopback
(`http://localhost:<any>/...`, `http://127.0.0.1:<any>/...`), and `OAUTH_EXTRA_REDIRECT_URIS`.

## Variables on the service

| variable | who sets it | purpose |
| --- | --- | --- |
| `PORT` | Railway / `8080` | relay listen port |
| `RELAY_PUBLIC_URL` | deploy | `https://<service-domain>`; OAuth issuer and token audience |
| `OAUTH_SIGNING_KEY` | deploy | HS256 key, at least 32 bytes |
| `RELAY_ADMIN_PASSWORD_HASH` | deploy | argon2id hash from `tools/hash_password.py` |
| `RELAY_TOKEN_SHA256` | deploy | comma-separated digests from `tools/mint_token.py` |
| `RELAY_DATA_DIR` | default `/data` | volume mount for `auth.db` (registered clients, refresh tokens) |
| `RELAY_NAME` | optional | name shown on the login page and in discovery metadata |
| `OAUTH_SCOPE` | optional (`tradingview`) | the single scope the server issues |
| `OAUTH_EXTRA_REDIRECT_URIS` | optional | extra exact redirect URIs |
| `MARKETAUX_API_TOKEN`, `PROXY_*` | optional | passed through to the MCP server (see `.env.example`) |

## Steps

1. Create a Railway project and a service from this GitHub repo. `railway.toml` makes it a
   Dockerfile build using `Dockerfile.railway`.
2. Attach a volume at `/data` (otherwise every redeploy forgets OAuth clients and refresh
   tokens, and every Claude surface has to log in again).
3. Generate a service domain and set `RELAY_PUBLIC_URL=https://<domain>`.
4. Mint secrets locally and set them:

   ```bash
   uv run python tools/mint_token.py                   # RELAY_TOKEN_SHA256 (+ the token to keep)
   uv run --extra relay python tools/hash_password.py  # RELAY_ADMIN_PASSWORD_HASH (+ the password)
   python3 -c 'import secrets; print(secrets.token_urlsafe(48))'   # OAUTH_SIGNING_KEY
   ```

   The container exits with code 64 and a clear message until every required variable is
   present.
5. `GET /healthz` returns `{"relay":"ok","upstream":"up"}` once the MCP server has imported
   pandas and started (a few seconds). The Railway healthcheck waits up to 300 s.

## Connect clients

**claude.ai / Desktop / mobile:** Settings > Connectors > Add custom connector, URL
`https://<domain>/mcp`. Leave the client ID/secret empty. You will be sent to the relay's
login page; enter the relay admin password.

**Claude Code (static token):**

```bash
claude mcp add --transport http tradingview https://<domain>/mcp --header "Authorization: Bearer <token>"
```

**Claude Code (OAuth):** the same command without `--header`; Claude Code registers itself,
opens the login page, and stores a refresh token.

**curl smoke test:**

```bash
curl -i -X POST "https://<domain>/mcp" \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"curl","version":"1"}}}'
```

## Local development

```bash
uv sync --dev
uv run pytest tests/unit/relay -q
export RELAY_PUBLIC_URL=http://localhost:8080 OAUTH_SIGNING_KEY=... RELAY_ADMIN_PASSWORD_HASH=... RELAY_TOKEN_SHA256=...
docker build -f Dockerfile.railway -t tradingview-relay . && docker run --rm -p 8080:8080 \
  -e PORT=8080 -e RELAY_PUBLIC_URL -e OAUTH_SIGNING_KEY -e RELAY_ADMIN_PASSWORD_HASH -e RELAY_TOKEN_SHA256 \
  tradingview-relay
```

## Security notes

- The MCP server is loopback-only inside the container; the relay is the only listener on
  `$PORT`. Its open `/health` route is not exposed; use the relay's `/healthz`.
- Access tokens are HS256 JWTs bound to the relay URL as audience, valid 60 minutes; refresh
  tokens are hashed at rest and rotated on every use; auth codes are single-use, 5 minutes.
- Login is argon2id and rate-limited (10 failures per 15 minutes per IP); `/register` and
  `/token` are rate-limited too.
- Upstream `Access-Control-Allow-Origin: *` is stripped; every response is `Cache-Control: no-store`.
- Nothing sensitive is logged.
