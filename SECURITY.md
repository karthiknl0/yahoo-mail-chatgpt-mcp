# Security Policy

This project handles high-value mailbox data. Security issues involving authentication bypass, secret leakage, OTP exposure, unsafe HTML parsing, excessive email disclosure or unintended mailbox modification should be treated as high severity.

## Supported version

Only the latest commit on `main` is supported during the pre-1.0 development phase.

## Reporting

Do **not** open a public issue containing credentials, tokens, real email content, OTPs, reset links or personal information.

For a vulnerability report, provide only the minimum reproduction details needed to demonstrate the issue and redact all real secrets.

## Security invariants

Changes must preserve these properties:

- `/mcp` fails closed when authentication is absent or invalid.
- Yahoo credentials remain server-side and are never returned by an MCP tool.
- Yahoo is accessed with IMAPS/TLS certificate verification.
- Mailboxes are opened read-only in V1.
- No send/delete/move/archive/mark/flag tools exist in V1.
- Email text is sanitized before it is serialized into MCP output.
- Logs do not contain email bodies, subjects, sender addresses, credentials, bearer tokens or request bodies.
- Tool outputs are bounded in count and size.
- Health responses reveal no mailbox or authentication details.

## Secret handling

Never commit `.env` files or real values for:

- `YAHOO_EMAIL`
- `YAHOO_APP_PASSWORD`
- `MCP_API_TOKEN`

Use hosting-platform secret storage for production values. If a secret is ever committed, assume it is compromised even if the commit is later rewritten; rotate it immediately.

## Dependency and deployment review

Before deployment:

1. Ensure CI passes.
2. Review dependency advisories.
3. Confirm HTTPS termination is configured.
4. Confirm the public hostname exactly matches `ALLOWED_HOSTS`.
5. Confirm request/body logging is disabled at proxies.
6. Confirm no real secrets exist anywhere in Git history.
7. Test unauthorized `/mcp` access returns `401`.
8. Test `/health` returns only `{ "status": "ok" }`.
9. Validate OTP/reset-link redaction with synthetic test messages.

## Incident response

If compromise is suspected, disable the service, revoke the Yahoo app-specific password, rotate the MCP bearer token, review access logs, revalidate the code and deploy from a known-good commit.
