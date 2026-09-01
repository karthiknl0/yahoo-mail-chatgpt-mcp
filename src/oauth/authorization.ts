import {
  Router,
  type NextFunction,
  type Request,
  type Response,
  urlencoded,
} from "express";
import type { AppConfig } from "../config.js";
import {
  randomToken,
  sha256Token,
  signCsrf,
  verifyCsrf,
  verifyPassphrase,
} from "./crypto.js";
import type { OAuthStore } from "./store.js";
import type { AuthorizationTransaction, RegisteredClient } from "./types.js";

const AUTHORIZATION_SCOPE = "mcp:read";
const AUTHORIZATION_TRANSACTION_TTL_SECONDS = 10 * 60;
const AUTHORIZATION_CODE_TTL_SECONDS = 5 * 60;
const AUTHORIZATION_RATE_WINDOW_SECONDS = 15 * 60;
const AUTHORIZATION_ATTEMPT_LIMIT = 5;
const MAX_AUTHORIZATION_FORM_BYTES = 16 * 1_024;
const CSRF_COOKIE_NAME = "__Host-mcp_oauth_csrf";
const PKCE_S256_PATTERN = /^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/;

interface ValidAuthorizationRequest {
  readonly transaction: Omit<AuthorizationTransaction, "csrf">;
}

function oneString(value: unknown, maximum: number): string | null {
  return typeof value === "string" && value.length <= maximum ? value : null;
}

function clientAllowsAuthorization(
  client: RegisteredClient,
  scope: string,
): boolean {
  if (
    client.grantTypes !== undefined &&
    !client.grantTypes.includes("authorization_code")
  ) {
    return false;
  }
  if (
    client.responseTypes !== undefined &&
    !client.responseTypes.includes("code")
  ) {
    return false;
  }
  if (client.scope === undefined) return true;
  return client.scope.split(/\s+/u).includes(scope);
}

async function validateAuthorizationRequest(
  req: Request,
  config: AppConfig,
  store: OAuthStore,
): Promise<ValidAuthorizationRequest | null> {
  const responseType = oneString(req.query.response_type, 32);
  const clientId = oneString(req.query.client_id, 128);
  const redirectUri = oneString(req.query.redirect_uri, 2_048);
  const resource = oneString(req.query.resource, 2_048);
  const state = oneString(req.query.state, 1_024);
  const codeChallenge = oneString(req.query.code_challenge, 128);
  const codeChallengeMethod = oneString(req.query.code_challenge_method, 32);
  const scope = oneString(req.query.scope, 256);

  if (
    responseType !== "code" ||
    clientId === null ||
    clientId.length === 0 ||
    redirectUri === null ||
    resource !== config.resourceUrl ||
    state === null ||
    state.trim().length === 0 ||
    codeChallenge === null ||
    !PKCE_S256_PATTERN.test(codeChallenge) ||
    codeChallengeMethod !== "S256" ||
    scope !== AUTHORIZATION_SCOPE
  ) {
    return null;
  }

  const client = await store.getClient(clientId);
  if (
    client === null ||
    !client.redirectUris.includes(redirectUri) ||
    !clientAllowsAuthorization(client, scope)
  ) {
    return null;
  }

  return {
    transaction: {
      clientId,
      redirectUri,
      resource,
      state,
      codeChallenge,
      scope,
    },
  };
}

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/gu, (character) => {
    switch (character) {
      case "&":
        return "&amp;";
      case "<":
        return "&lt;";
      case ">":
        return "&gt;";
      case '"':
        return "&quot;";
      default:
        return "&#39;";
    }
  });
}

function renderAuthorizationForm(transactionId: string, csrf: string): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Mail MCP authorization</title>
<style>body{font-family:system-ui,sans-serif;max-width:32rem;margin:4rem auto;padding:0 1rem}label,input,button{display:block;margin:.75rem 0}input{box-sizing:border-box;width:100%;padding:.6rem}button{display:inline-block;margin-right:.5rem;padding:.6rem 1rem}</style>
</head>
<body>
<main>
<h1>Mail MCP authorization</h1>
<form method="post" action="/authorize">
<label>Passphrase<input type="password" name="passphrase" autocomplete="current-password" required></label>
<input type="hidden" name="transaction_id" value="${escapeHtml(transactionId)}">
<input type="hidden" name="csrf" value="${escapeHtml(csrf)}">
<button type="submit" name="decision" value="allow">Allow</button>
<button type="submit" name="decision" value="deny" formnovalidate>Deny</button>
</form>
</main>
</body>
</html>`;
}

function enforceAuthorizationBodyLimit(
  req: Request,
  res: Response,
  next: NextFunction,
): void {
  const rawLength = req.get("content-length");
  const length = rawLength === undefined ? NaN : Number(rawLength);
  if (Number.isFinite(length) && length > MAX_AUTHORIZATION_FORM_BYTES) {
    res.status(413).json({ error: "request_too_large" });
    return;
  }
  next();
}

function readCookie(req: Request, name: string): string | null {
  const header = req.get("cookie");
  if (header === undefined) return null;
  const matches = header
    .split(";")
    .map((part) => part.trim())
    .filter((part) => part.startsWith(`${name}=`));
  if (matches.length !== 1) return null;
  return matches[0]!.slice(name.length + 1);
}

function redirectWithParameters(
  res: Response,
  redirectUri: string,
  parameters: Readonly<Record<string, string>>,
): void {
  const target = new URL(redirectUri);
  for (const [key, value] of Object.entries(parameters)) {
    target.searchParams.set(key, value);
  }
  res.redirect(302, target.toString());
}

/** Performs single-user passphrase authorization for registered public clients. */
export function authorizationRouter(
  config: AppConfig,
  store: OAuthStore,
): Router {
  const router = Router();
  router.use("/authorize", (_req, res, next) => {
    res.setHeader("Cache-Control", "no-store");
    res.setHeader(
      "Content-Security-Policy",
      "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'",
    );
    next();
  });

  router.get("/authorize", async (req, res, next) => {
    try {
      const validated = await validateAuthorizationRequest(req, config, store);
      if (validated === null) {
        res.status(400).json({ error: "invalid_request" });
        return;
      }

      const transactionId = randomToken();
      const csrf = randomToken();
      await store.createTransaction(
        transactionId,
        { ...validated.transaction, csrf },
        AUTHORIZATION_TRANSACTION_TTL_SECONDS,
      );
      res.cookie(CSRF_COOKIE_NAME, signCsrf(csrf, config.oauthCookieKey), {
        httpOnly: true,
        secure: true,
        sameSite: "lax",
        path: "/",
      });
      res
        .status(200)
        .type("html")
        .send(renderAuthorizationForm(transactionId, csrf));
    } catch (error) {
      next(error);
    }
  });

  router.post(
    "/authorize",
    enforceAuthorizationBodyLimit,
    urlencoded({ extended: false, limit: "16kb" }),
    async (req, res, next) => {
      try {
        const transactionId = oneString(req.body?.transaction_id, 128);
        const bodyCsrf = oneString(req.body?.csrf, 128);
        const decision = oneString(req.body?.decision, 16);
        const passphrase = oneString(req.body?.passphrase, 16 * 1_024);
        if (
          transactionId === null ||
          transactionId.length === 0 ||
          bodyCsrf === null ||
          bodyCsrf.length === 0 ||
          (decision !== "allow" && decision !== "deny")
        ) {
          res.status(400).json({ error: "invalid_request" });
          return;
        }

        const transaction = await store.consumeTransaction(transactionId);
        if (transaction === null) {
          res.status(400).json({ error: "invalid_request" });
          return;
        }

        const csrfCookie = readCookie(req, CSRF_COOKIE_NAME);
        if (
          csrfCookie === null ||
          !verifyCsrf(csrfCookie, bodyCsrf, config.oauthCookieKey) ||
          !verifyCsrf(csrfCookie, transaction.csrf, config.oauthCookieKey)
        ) {
          res.status(400).json({ error: "invalid_request" });
          return;
        }

        if (decision === "deny") {
          redirectWithParameters(res, transaction.redirectUri, {
            error: "access_denied",
            state: transaction.state,
          });
          return;
        }

        if (passphrase === null) {
          res.status(403).json({ error: "access_denied" });
          return;
        }

        if (!(await verifyPassphrase(passphrase, config.passphraseDigest))) {
          // The transaction is already consumed and cannot be retried. Its
          // bucket records this failed submission; the IP bucket aggregates
          // failures across fresh one-time transactions.
          const ip = req.ip ?? "unknown";
          const [transactionFailures, ipFailures] = await Promise.all([
            store.incrementRateLimit(
              `authorization:transaction:${sha256Token(transactionId)}`,
              AUTHORIZATION_RATE_WINDOW_SECONDS,
            ),
            store.incrementRateLimit(
              `authorization:ip:${sha256Token(ip)}`,
              AUTHORIZATION_RATE_WINDOW_SECONDS,
            ),
          ]);
          if (
            transactionFailures > AUTHORIZATION_ATTEMPT_LIMIT ||
            ipFailures > AUTHORIZATION_ATTEMPT_LIMIT
          ) {
            res.status(429).json({ error: "rate_limited" });
            return;
          }
          res.status(403).json({ error: "access_denied" });
          return;
        }

        const code = randomToken();
        await store.createAuthorizationCode(
          sha256Token(code),
          {
            clientId: transaction.clientId,
            redirectUri: transaction.redirectUri,
            resource: transaction.resource,
            codeChallenge: transaction.codeChallenge,
            scope: transaction.scope,
          },
          AUTHORIZATION_CODE_TTL_SECONDS,
        );
        redirectWithParameters(res, transaction.redirectUri, {
          code,
          state: transaction.state,
        });
      } catch (error) {
        next(error);
      }
    },
  );

  return router;
}
