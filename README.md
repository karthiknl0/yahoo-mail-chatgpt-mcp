# Yahoo Mail ChatGPT MCP

A security-first, **read-only** Yahoo Mail MCP server designed for use with ChatGPT and other MCP hosts.

> **Status:** v0.1 foundation. Do not add real Yahoo credentials until CI is green and the deployment has been reviewed.

## Architecture

```text
ChatGPT / MCP host
        |
        | HTTPS + bearer authentication
        v
OAuth 2.1 + Streamable HTTP endpoint: /mcp
        |
        | read-only, bearer-authorized tool calls
        v
Render Key Value (OAuth state only)
        |
        v
Yahoo Mail reader
        |
        | IMAPS / TLS 1.2+ / port 993
        v
imap.mail.yahoo.com
```

The server uses the current Model Context Protocol TypeScript SDK v2 and Streamable HTTP. The MCP endpoint is `/mcp`.

## Security goals

This project treats mailbox data as high-risk. Yahoo mail may contain OTPs, password-reset links, banking alerts, account identifiers and other authentication material.

The design therefore follows four rules:

1. **Read only.** V1 contains no send, delete, move, archive, flag or mark-read tools.
2. **Fail closed.** The server refuses to start if Yahoo credentials or MCP authentication are missing or invalid.
3. **Minimize output.** Tools return bounded summaries; full raw RFC822 messages are never exposed through MCP.
4. **Sanitize before output.** OTPs, verification codes, sensitive login/reset URLs and long card/account-like numbers are redacted before data is returned to the MCP host.

Email body text is treated as **untrusted data, never instructions**. Every mail-returning tool includes a security notice reminding the caller of this boundary.

## Threat model

The main threats considered are:

- compromise of the remote MCP endpoint;
- accidental public deployment without authentication;
- credential leakage through Git, logs, health checks or error responses;
- prompt injection embedded in email content;
- OTP / reset-link exposure to the model;
- excessive email-body disclosure;
- DNS rebinding / hostile Origin or Host headers;
- brute-force access to the MCP endpoint;
- weak or invalid TLS to Yahoo;
- unsafe mailbox modifications.

Current mitigations include OAuth 2.1 authorization-code flow with S256 PKCE, rotating opaque tokens, a single-user passphrase gate, constant-time comparisons, Host/Origin validation provided by the MCP Express integration, rate limiting, request-size checks, security headers, bounded tool inputs, TLS verification, read-only IMAP mailbox opens, deterministic sanitization and secret-free error responses.

## What ChatGPT can access

V1 exposes only these MCP tools:

### `get_morning_brief_emails`

Returns a small set of recent, sanitized emails prioritized for a morning brief.

Inputs:

- `hours`: 1–168, default 24
- `limit`: bounded by `MAX_EMAILS_PER_REQUEST`
- `unreadOnly`: optional

Output includes safe metadata such as UID, folder, sender, subject, timestamp, unread state, attachment presence, sanitized preview, category and importance score.

### `list_emails`

Lists sanitized mail summaries from a selected folder.

### `search_emails`

Performs a read-only Yahoo IMAP text search and returns sanitized summaries.

### `read_email`

Reads one email by UID. The text is sanitized and truncated before MCP output.

### `list_folders`

Lists mailbox folder names.

## What ChatGPT cannot access in V1

There are deliberately **no** MCP tools for:

- sending mail;
- deleting mail;
- archiving mail;
- moving mail;
- marking messages read/unread;
- flagging/unflagging;
- changing Yahoo account settings;
- retrieving the Yahoo app password;
- retrieving environment variables;
- retrieving raw unsanitized RFC822 messages.

## Sensitive-content redaction

The sanitizer attempts to redact:

- 4–8 digit OTP / verification / login / security codes when authentication context is present;
- codes separated with spaces, dashes or punctuation;
- password-reset and account-recovery URLs;
- login / magic-link / authentication URLs and token-bearing URLs;
- long card/account-like digit sequences;
- bearer/JWT-like token strings;
- active HTML tags, scripts and styles.

Example:

```text
Your verification code is 492811
```

becomes:

```text
Your verification code is [REDACTED]
```

Redaction reduces risk but is not a mathematical guarantee. The stronger protection is data minimization: use `get_morning_brief_emails` for normal workflows and reserve `read_email` for explicit requests.

## Yahoo authentication

Use a Yahoo **app-specific password**, not your normal Yahoo account password.

Never paste the password into ChatGPT and never commit it to GitHub.

Copy the environment template:

```bash
cp .env.example .env
```

Then provide values locally or, preferably, through your hosting provider's secret manager:

```env
YAHOO_EMAIL=you@example.com
YAHOO_APP_PASSWORD=your-yahoo-app-specific-password
REDIS_URL=redis://127.0.0.1:6379
PUBLIC_ORIGIN=https://localhost.example.test
MCP_LOGIN_PASSPHRASE_SCRYPT=a-generated-scrypt-digest
OAUTH_COOKIE_KEY=a-random-secret-at-least-32-characters
```

Generate the passphrase digest interactively, after installing dependencies:

```bash
npm run hash-passphrase
```

The command requires a TTY, disables input echo, restores the terminal state even on cancellation, accepts a minimum 16-character passphrase, and writes only a salted `scrypt` digest to standard output. Store that digest as `MCP_LOGIN_PASSPHRASE_SCRYPT`; never store the plaintext passphrase. Generate `OAUTH_COOKIE_KEY` with a cryptographically secure random-value generator and do not reuse another secret.

## Local development

Requirements: Node.js 20+.

```bash
npm install
cp .env.example .env
npm run dev
```

The default bind is `127.0.0.1:3000`.

Health check:

```bash
curl http://127.0.0.1:3000/health
```

Expected response:

```json
{ "status": "ok" }
```

The health endpoint intentionally contains no email address, Yahoo state, token details, IMAP diagnostics or environment information.

## Testing

```bash
npm run lint
npm run typecheck
npm test
npm run build
```

Tests do not require real Yahoo credentials. CI performs these checks for pushes and pull requests.

## Docker

Build:

```bash
docker build -t yahoo-mail-chatgpt-mcp .
```

Run with secrets supplied at runtime:

```bash
docker run --rm \
  -p 127.0.0.1:3000:3000 \
  --env-file .env \
  yahoo-mail-chatgpt-mcp
```

For a public container deployment set:

```env
HOST=0.0.0.0
ALLOWED_HOSTS=mcp.example.com
```

Terminate TLS at a trusted reverse proxy or managed hosting platform and expose **HTTPS only**.

## Render deployment

[`render.yaml`](render.yaml) defines exactly one Node web service and one internal-only Render Key Value instance in the same region. It uses Render's `RENDER_EXTERNAL_URL`, binds the process to `0.0.0.0:$PORT`, wires `REDIS_URL` from the Key Value connection string, and exposes `/health` for process health only.

The Blueprint intentionally leaves these dashboard-managed values unset: `YAHOO_EMAIL`, `YAHOO_APP_PASSWORD`, `MCP_LOGIN_PASSPHRASE_SCRYPT`, `OAUTH_COOKIE_KEY`, and `ALLOWED_HOSTS`. Before creating any deployment, set `ALLOWED_HOSTS` to the exact assigned Render hostname and enter the remaining values through Render's secret controls. Do not add `RENDER_EXTERNAL_URL` manually.

The checked-in plans are free for initial evaluation. The free Key Value plan supports `noeviction`, which makes writes fail rather than silently evict OAuth state, but it has no disk persistence ([Render Key Value documentation](https://render.com/docs/key-value)). A Key Value restart invalidates outstanding OAuth state and requires clients to authorize again. Select and approve a paid, persistent plan before treating this as a production deployment.

Safe smoke-test order:

1. Confirm `/health` returns only `{"status":"ok"}`.
2. Confirm unauthenticated `/mcp` returns `401` and protected-resource metadata.
3. Confirm OAuth discovery, registration, and passphrase + PKCE authorization.
4. Confirm `tools/list` reports exactly the five read-only tools.
5. Run `list_folders`, then one bounded `get_morning_brief_emails` call; record only pass/fail.

Rollback: disable the web service or revert to the last reviewed Blueprint commit. If OAuth state may be compromised, replace or restart Key Value, rotate the passphrase digest and cookie key, then require clients to authorize again.

## Connecting to ChatGPT

ChatGPT custom apps connect to **remote** MCP servers. In ChatGPT developer mode, create a custom app and provide the deployed HTTPS MCP endpoint, for example:

```text
https://mcp.example.com/mcp
```

This service is its own OAuth 2.1 authorization and resource server. It advertises protected-resource metadata for `/mcp`, supports dynamic registration, and requires authorization-code flow with S256 PKCE and a private owner passphrase. Access and refresh tokens are opaque; refresh tokens rotate. The server must never be changed to accept unauthenticated `/mcp` traffic merely to make a client connect.

OAuth endpoints are `/.well-known/oauth-protected-resource/mcp`, `/.well-known/oauth-authorization-server`, `/register`, `/authorize`, and `/token` at the service origin.

## Credential rotation

### Rotate OAuth login material

1. Generate a new `MCP_LOGIN_PASSPHRASE_SCRYPT` with `npm run hash-passphrase`.
2. Generate a new `OAUTH_COOKIE_KEY`.
3. Update both values in Render's secret controls and redeploy.
4. Restart or replace Key Value if all outstanding OAuth state must be revoked.
5. Reauthorize the MCP client/app.

### Rotate Yahoo access

1. Revoke the Yahoo app-specific password in Yahoo account security.
2. Create a new app-specific password.
3. Replace the hosting secret.
4. Restart/redeploy.

Your normal Yahoo password should not need to change solely because an app-specific password was revoked.

## Incident response

If the server, deployment account or Yahoo app password may have been compromised:

1. Disable or scale down the MCP service immediately.
2. Revoke the Yahoo app-specific password.
3. Rotate `MCP_LOGIN_PASSPHRASE_SCRYPT` and `OAUTH_COOKIE_KEY`.
4. Review hosting access/audit logs without copying message bodies into tickets or chat.
5. Review Git history for accidentally committed secrets.
6. Re-deploy from a known-good reviewed commit.
7. Reconnect the MCP client only after authentication and sanitization have been revalidated.

## Logging policy

Application logs intentionally contain operational events only. Do not add logging of:

- email bodies or previews;
- subjects or sender addresses;
- Yahoo credentials;
- bearer tokens;
- Authorization headers;
- MCP request bodies;
- parsed environment variables.

## Project layout

```text
src/
  config.ts            fail-closed environment validation
  index.ts             HTTPS-facing MCP application entry point
  mcp.ts               read-only MCP tool definitions
  yahoo.ts             Yahoo IMAP reader
  oauth/                OAuth discovery, registration, authorization and tokens
  security/
    redact.ts           deterministic secret/content sanitization
tests/
  redact.test.ts
  config-auth.test.ts
.github/workflows/ci.yml
Dockerfile
.env.example
```

## Security note

This repository is public, so assume every committed byte is permanently visible. **Never commit `.env`, credentials, tokens, real email samples, OTPs or Yahoo app passwords.**

See `SECURITY.md` for the security policy.
