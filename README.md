# Yahoo Mail ChatGPT MCP

A security-first, **read-only** Yahoo Mail MCP server designed for use with ChatGPT and other MCP hosts.

> **Status:** v0.1 foundation. Do not add real Yahoo credentials until CI is green and the deployment has been reviewed.

## Architecture

```text
ChatGPT / MCP host
        |
        | HTTPS + bearer authentication
        v
Remote MCP endpoint: /mcp
        |
        | read-only tool calls
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

Current mitigations include bearer authentication, constant-time token comparison, Host/Origin validation provided by the MCP Express integration, rate limiting, request-size checks, security headers, bounded tool inputs, TLS verification, read-only IMAP mailbox opens, deterministic sanitization and secret-free error responses.

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
MCP_API_TOKEN=a-long-random-token-at-least-32-characters
```

Generate `MCP_API_TOKEN` using a cryptographically secure password/token generator. Do not reuse another password.

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
{"status":"ok"}
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

## Managed deployment

The service can run on Render, Railway, Fly.io or a conventional VPS/container host. It does not depend on any specific existing server.

Production checklist:

- deploy from a reviewed commit;
- configure `YAHOO_EMAIL`, `YAHOO_APP_PASSWORD` and `MCP_API_TOKEN` using the platform's secret storage;
- set `HOST=0.0.0.0` only when required by the platform;
- set `ALLOWED_HOSTS` to the exact public MCP hostname;
- keep HTTPS enabled at all times;
- do not enable request/body logging at the proxy;
- rotate the MCP token and Yahoo app password after any suspected compromise;
- keep V1 read-only.

## Connecting to ChatGPT

ChatGPT custom apps connect to **remote** MCP servers. In ChatGPT developer mode, create a custom app and provide the deployed HTTPS MCP endpoint, for example:

```text
https://mcp.example.com/mcp
```

The exact authentication options offered by ChatGPT can evolve. This repository currently implements a static bearer-token gate suitable for private deployments and MCP clients that can send an `Authorization: Bearer ...` header.

If your ChatGPT custom-app setup requires OAuth rather than a static bearer credential, **do not disable authentication**. Add or place a standards-compliant OAuth/OIDC layer in front of `/mcp` instead. OpenAI recommends refresh-token support when OAuth is used so connectivity can be maintained after access-token expiry.

The server must never be changed to accept unauthenticated `/mcp` traffic merely to make a client connect.

## Credential rotation

### Rotate the MCP bearer token

1. Generate a new random token.
2. Update the hosting secret.
3. Restart/redeploy the service.
4. Update the authorized MCP client/app.
5. Invalidate the old token by ensuring it is no longer present anywhere in deployment configuration.

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
3. Rotate `MCP_API_TOKEN`.
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
  security/
    auth.ts             bearer authentication
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
