# Cloudflare Worker Deployment Design

> **Superseded — historical reference only.** Do not follow this document to deploy the service on Cloudflare. The active deployment design is [Render Single-Yahoo MCP Design](2026-08-31-render-single-yahoo-mcp-design.md), which supersedes this proposal and specifies the supported Node/Render architecture.

**Date:** 2026-08-30  
**Status:** Superseded by the 2026-08-31 Render design
**Repository:** `karthiknl0/yahoo-mail-chatgpt-mcp`

## Objective

Deploy the existing security-first Yahoo Mail MCP server as a native Cloudflare Worker so a single authorized ChatGPT user can retrieve bounded, sanitized, read-only mailbox data. The deployment must not expose Yahoo credentials, OTPs, reset links, authentication tokens, or mailbox-write capabilities.

## Scope

The Worker will expose:

- `POST /mcp` using stateless Streamable HTTP;
- the five existing read-only MCP tools: `get_morning_brief_emails`, `list_emails`, `search_emails`, `read_email`, and `list_folders`;
- `GET /health`, returning only `{ "status": "ok" }`;
- OAuth discovery, registration, authorization, callback, and token endpoints required by MCP clients.

The deployment will not expose SMTP, sending, deleting, moving, archiving, flagging, mark-read operations, raw attachments, arbitrary URLs, diagnostics containing environment state, or an unauthenticated MCP mode.

## Selected Architecture

### Runtime and transport

The Express listener will be replaced by a Cloudflare Worker `fetch` handler. The MCP endpoint will use Cloudflare's current stateless `createMcpHandler()` integration and the current MCP server SDK. No deprecated HTTP+SSE route will be added.

The Worker will use a current compatibility date and Cloudflare's Node.js compatibility layer only for APIs that are natively supported. A Wrangler dry run and remote smoke test must prove that the production bundle uses supported runtime APIs.

### Authentication and authorization

The MCP server will implement OAuth 2.1-compatible authorization with `@cloudflare/workers-oauth-provider`. ChatGPT will connect to the public HTTPS `/mcp` URL, discover the OAuth endpoints, and complete an authorization-code flow with PKCE.

Cloudflare Access for SaaS will act as the upstream OIDC identity provider. The Access policy will allow only the owner's chosen email identity. One-time PIN may be used as the initial identity provider; another Cloudflare-supported identity provider can replace it without changing the MCP tool layer.

OAuth client registration, authorization codes, grants, refresh tokens, and access-token state will be stored in a dedicated Workers KV namespace bound as `OAUTH_KV`. The Worker will never use an in-memory token set as production authorization state. Refresh tokens will be enabled only through the supported Cloudflare flow and will remain revocable.

The `/mcp` handler will be unreachable without a valid OAuth access token. Missing bindings, missing OAuth secrets, invalid issuer/audience data, or failed Access validation will fail closed.

### Yahoo IMAP access

Yahoo access will use `imap.mail.yahoo.com:993` over TLS with certificate and hostname verification. Mailboxes will always be opened read-only. The Worker will create an IMAP connection inside the request handler, apply connection and command timeouts, fetch only the bounded data needed for the requested tool, and close the connection in `finally` cleanup.

The existing `YahooReader` interface will remain the boundary between MCP tools and IMAP. `imapflow` may remain only if Wrangler bundling plus a deployed TLS/IMAP smoke test prove compatibility with Cloudflare's native `node:net` and `node:tls` subset. If it fails that proof, only the adapter will be replaced with a Worker-compatible IMAP implementation; MCP schemas and sanitization behavior will not change.

### Sensitive-content handling

All email-derived strings are untrusted data. Tool output construction will continue to sanitize content before it enters an MCP result. Result counts, preview sizes, full-read sizes, and search inputs will remain strictly bounded.

The sanitizer will redact contextual OTPs and verification codes, authentication and reset URLs, URL-embedded tokens, CVV-like values in strong security context, and long account/card-like digit strings. HTML will be converted to inert text before redaction. No remote images, links, scripts, or attachment bodies will be fetched.

Prompt-injection language in email is not treated as instructions. Tool descriptions and returned structured data will explicitly identify mailbox content as untrusted.

## Component Boundaries

- **Worker entry point:** routes health, OAuth, and MCP requests; owns security headers and response-size limits.
- **OAuth handler:** integrates Cloudflare Access OIDC with the Workers OAuth Provider and establishes the authenticated subject.
- **MCP server factory:** registers only the five read-only tools and creates a fresh stateless server per request.
- **Yahoo reader:** validates mailbox/folder/query inputs and performs bounded read-only IMAP operations.
- **Sanitizer:** converts HTML to inert text, redacts sensitive material, and truncates output.
- **Configuration:** validates non-secret configuration and asserts required Worker secret bindings at request/startup boundaries.

No component may return a secret value through an error, health response, tool result, log record, or OAuth response.

## Request and Data Flow

1. ChatGPT requests the Worker MCP endpoint over HTTPS.
2. The OAuth provider redirects an unauthorized client through registration and authorization.
3. Cloudflare Access authenticates the allowed identity and returns to the Worker callback.
4. The Worker issues its own scoped MCP token and stores durable grant state in `OAUTH_KV`.
5. ChatGPT calls `/mcp` with the MCP token.
6. The Worker validates authorization, request size, method, content type, and tool schema.
7. The selected tool opens a TLS-verified, read-only Yahoo IMAP connection.
8. The reader fetches only bounded message metadata or content.
9. The sanitizer strips active HTML, redacts sensitive material, and truncates the result.
10. The Worker returns structured MCP output and closes the IMAP connection.

## Secrets and Configuration

The Cloudflare deployment token and account identifier are infrastructure credentials. They are not Worker runtime secrets and must not be committed, bundled, logged, or uploaded as application variables.

Runtime secrets will be entered through Wrangler's interactive secret command or the Cloudflare dashboard:

- `YAHOO_EMAIL`
- `YAHOO_APP_PASSWORD`
- `ACCESS_CLIENT_ID`
- `ACCESS_CLIENT_SECRET`
- `ACCESS_TOKEN_URL`
- `ACCESS_AUTHORIZATION_URL`
- `ACCESS_JWKS_URL`
- `COOKIE_ENCRYPTION_KEY`

The OAuth KV namespace identifier is non-secret Wrangler configuration. The local `.env` file is not a deployment source of truth and will remain ignored by Git. Real Yahoo credentials will not be added to `.dev.vars`, CI, tests, fixtures, or documentation.

The current local `.env` file contains Cloudflare deployment details in a non-dotenv layout and does not provide parsable `YAHOO_EMAIL` or `YAHOO_APP_PASSWORD` entries. Live mailbox verification is therefore gated on entering those two values interactively as Worker secrets. They must never be pasted into ChatGPT.

## Security Controls

- TLS-only public endpoint provided by Cloudflare.
- OAuth-protected `/mcp`; no public fallback.
- Access policy restricted to one approved identity.
- PKCE, issuer/audience validation, short-lived access tokens, revocable refresh tokens, and durable OAuth state.
- Read-only MCP tool registry and read-only IMAP mailbox opens.
- Zod validation with strict input limits and unknown-field rejection.
- Request/body-size limits and accepted-method/content-type enforcement.
- Per-subject request throttling through a Cloudflare Rate Limiting binding named `MCP_RATE_LIMITER`; binding errors fail closed.
- TLS certificate and hostname verification for Yahoo IMAP.
- Connection, command, and overall tool-execution timeouts.
- Sanitization before MCP output construction.
- Security headers on non-MCP browser responses.
- Sanitized client errors and metadata-only server logs.
- No mailbox content, addresses, subjects, OTPs, URLs, credentials, tokens, or authorization codes in logs.
- Dependency lockfile committed before deployment and automated dependency/security review in CI.

## Logging and Observability

Logs may contain only generated request identifiers, route/tool names, outcome classes, durations, bounded result counts, and sanitized error categories. They must not contain tool arguments when those arguments can contain email queries or identifiers.

`/health` proves only that the Worker can execute. IMAP connectivity and secret-presence checks will not be exposed publicly. Remote smoke tests will report pass/fail without returning mailbox content.

## Error Handling

- Configuration or binding errors: reject the request and emit only a generic configuration category.
- Authentication errors: return standards-compliant OAuth or `401` responses without internal detail.
- Authorization mismatch: return `403` without disclosing the allowlisted identity.
- Invalid MCP input: return a bounded validation error without echoing sensitive payloads.
- Yahoo authentication/TLS/timeout errors: return a generic upstream failure and always close the connection.
- Sanitization failure: suppress the affected message content rather than return unsanitized text.
- KV or rate-limiter failure: fail closed for `/mcp`.

## Testing Strategy

### Local automated tests

- Preserve all existing redaction, configuration, and bearer-auth regression tests until bearer auth is removed.
- Add Worker-native tests for OAuth discovery, unauthorized `/mcp`, invalid token, allowed token context, health response, request-size limits, and security headers.
- Add strict tool-schema and maximum-result tests for every read operation.
- Expand sanitizer bypass tests for spaced/punctuated codes, encoded URLs, HTML entities, malformed HTML, and token-bearing links.
- Mock the Yahoo reader in MCP tests; CI will never require real Yahoo credentials.
- Add secret-leak assertions across errors, logs, health responses, and MCP results.
- Run formatting, linting, type checking, unit tests, Worker integration tests, build, and Wrangler dry run.

### Remote staged verification

1. Deploy without Yahoo secrets and confirm `/health` is minimal and `/mcp` fails closed.
2. Configure KV and Access OAuth secrets; verify discovery and PKCE using MCP Inspector.
3. Add Yahoo credentials interactively as Worker secrets.
4. Run a connectivity-only Yahoo test that returns no mailbox data.
5. Invoke each read-only tool with minimum limits and inspect only sanitized output.
6. Connect ChatGPT through the supported custom MCP/app flow and perform one morning-brief request.
7. Confirm Cloudflare logs contain no mailbox content or secrets.

No production mailbox content will be copied into tests, issue trackers, commits, terminal transcripts, or chat messages.

## Deployment and Rollback

Wrangler configuration will define the Worker name, current compatibility date, entry point, `OAUTH_KV` binding, rate-limit binding, observability settings, and conservative CPU limits. Deployment will use the restricted Cloudflare API token already stored locally, provided it passes token verification and has only the required account permissions.

Before the first live deployment, the implementation must pass all local gates and `wrangler deploy --dry-run`. The first public endpoint will use `workers.dev`; custom DNS is out of scope.

Rollback uses Cloudflare Worker version rollback to the last verified version. A suspected compromise additionally requires revoking OAuth grants, rotating `COOKIE_ENCRYPTION_KEY`, rotating the Yahoo app password, and revoking/replacing the Cloudflare deployment token.

## Threat Model and Residual Risks

- **Unauthorized mailbox access:** mitigated by Access allowlisting, OAuth validation, durable grants, and fail-closed routing.
- **Credential disclosure:** mitigated by Worker secrets, ignored local files, sanitized errors, and content-free logs.
- **OTP/reset-token exposure:** reduced by deterministic sanitization and bounded results, but pattern detection cannot guarantee perfect classification. The system favors redaction and content suppression when uncertain.
- **Prompt injection in email:** reduced by read-only tools, untrusted-data labeling, no URL fetching, and no write actions. The model may still summarize adversarial text, so users must treat summaries as untrusted.
- **Dependency/runtime incompatibility:** controlled by Worker bundle tests and a remote IMAP compatibility gate before mailbox use.
- **Cloudflare/OpenAI data handling:** sanitized email content returned through MCP is processed by Cloudflare and the connected OpenAI product. This is inherent to the requested architecture.
- **Account takeover:** compromise of the allowed identity, Cloudflare account, Yahoo app password, or active OAuth token can expose sanitized mailbox data. Rotation and revocation procedures remain necessary.
- **Redaction false positives:** legitimate numeric or URL content may be removed. This is acceptable because confidentiality takes priority over completeness.

## Acceptance Criteria

Implementation is complete only when:

- all CI and Worker-specific tests pass;
- the Wrangler dry run and deployed Worker bundle succeed;
- `/health` returns only the allowed status object;
- unauthenticated and invalidly authenticated `/mcp` calls fail closed;
- OAuth authorization works for the allowlisted identity and rejects others;
- the deployed Worker connects to Yahoo via verified TLS with a read-only mailbox;
- only the five approved tools are exposed;
- tool outputs are bounded and sanitized before construction;
- no secrets or mailbox content appear in Git, build output, health responses, errors, or Cloudflare logs;
- ChatGPT can connect through OAuth and complete one sanitized, read-only morning-brief request;
- rollback is exercised against a non-production Worker version, and credential-revocation/rotation commands are documented and validated without printing or committing secret values.
