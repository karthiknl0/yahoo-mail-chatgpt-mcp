import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import type { NextFunction, Request, Response } from 'express';
import { Router, json, urlencoded } from 'express';
import rateLimit from 'express-rate-limit';
import { issueAccessToken, issueRefreshToken, verifyRefreshToken } from './security/token.js';

interface PendingCode {
  redirectUri: string;
  codeChallenge: string;
  codeChallengeMethod: string;
  clientId: string;
  expiresAt: number;
}

const pendingCodes = new Map<string, PendingCode>();

// Prune expired codes without relying on GC timing.
setInterval(() => {
  const now = Date.now();
  for (const [code, entry] of pendingCodes) {
    if (entry.expiresAt < now) pendingCodes.delete(code);
  }
}, 60_000).unref();

function generateCode(): string {
  return randomBytes(24).toString('base64url');
}

function constantTimeEquals(a: string, b: string): boolean {
  const ba = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ba.length !== bb.length) return false;
  return timingSafeEqual(ba, bb);
}

function verifyS256(verifier: string, challenge: string): boolean {
  return createHash('sha256').update(verifier).digest('base64url') === challenge;
}

function esc(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function loginPage(params: Record<string, string | undefined>, error?: string): string {
  const hidden = Object.entries(params)
    .filter(([, v]) => v !== undefined)
    .map(([k, v]) => `<input type="hidden" name="${esc(k)}" value="${esc(v!)}">`)
    .join('');
  const errHtml = error ? `<p class="err">${esc(error)}</p>` : '';
  return `<!doctype html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Yahoo Mail MCP — Authorize</title>
<style>
*{box-sizing:border-box}
body{font-family:system-ui,sans-serif;background:#f0f0f0;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}
.c{background:#fff;border-radius:10px;padding:2rem;width:100%;max-width:340px;box-shadow:0 4px 16px rgba(0,0,0,.12)}
h1{margin:0 0 .5rem;font-size:1.1rem}
p{margin:0 0 1rem;font-size:.85rem;color:#666}
label{display:block;font-size:.85rem;color:#444;margin-bottom:.35rem}
input[type=password]{width:100%;padding:.5rem .6rem;border:1px solid #ccc;border-radius:6px;font-size:1rem}
button{width:100%;margin-top:.9rem;padding:.6rem;border:none;border-radius:6px;background:#6366f1;color:#fff;font-size:1rem;cursor:pointer}
.err{color:#c00;font-size:.85rem;margin-bottom:.75rem}
</style></head><body>
<div class="c">
<h1>Yahoo Mail MCP</h1>
<p>Paste your MCP API token to authorize ChatGPT.</p>
${errHtml}
<form method="POST" autocomplete="off">${hidden}
<label for="tok">MCP API Token</label>
<input type="password" id="tok" name="token" autocomplete="current-password" required>
<button type="submit">Authorize</button>
</form>
</div></body></html>`;
}

// Parses either urlencoded or JSON bodies (token endpoint accepts both).
function flexBody(req: Request, res: Response, next: NextFunction): void {
  const ct = req.get('content-type') ?? '';
  if (ct.includes('application/json')) {
    json({ limit: '4kb' })(req, res, next);
  } else {
    urlencoded({ extended: false, limit: '4kb' })(req, res, next);
  }
}

export interface OAuthOptions {
  redirectOrigins: string[];
  tokenEpoch: number;
  accessTokenTtlSeconds: number;
  refreshTokenTtlSeconds?: number;
}

// An unrestricted redirect_uri turns this endpoint into an open redirector: an attacker
// links a victim to a genuine-looking authorize page on this domain, and the auth code
// (exchangeable for a token) lands on the attacker's host.
function redirectUriAllowed(redirectUri: string, allowedOrigins: string[]): boolean {
  let parsed: URL;
  try {
    parsed = new URL(redirectUri);
  } catch {
    return false;
  }
  if (parsed.protocol !== 'https:') return false;
  return allowedOrigins.includes(parsed.origin);
}

export function createOAuthRouter(
  baseUrl: string,
  mcpApiToken: string,
  options: OAuthOptions,
): ReturnType<typeof Router> {
  const router = Router();
  const refreshTokenTtlSeconds = options.refreshTokenTtlSeconds ?? 31_536_000;

  // Tight rate limit on the authorize form to prevent offline brute-force of the token.
  const authorizeLimiter = rateLimit({
    windowMs: 60_000,
    limit: 10,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'rate_limited' },
  });

  const registerLimiter = rateLimit({
    windowMs: 60_000,
    limit: 10,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'rate_limited' },
  });

  // RFC 8414 — OAuth 2.0 Authorization Server Metadata
  router.get('/.well-known/oauth-authorization-server', (_req, res) => {
    res.json({
      issuer: baseUrl,
      authorization_endpoint: `${baseUrl}/oauth/authorize`,
      token_endpoint: `${baseUrl}/oauth/token`,
      registration_endpoint: `${baseUrl}/register`,
      response_types_supported: ['code'],
      grant_types_supported: ['authorization_code', 'refresh_token'],
      code_challenge_methods_supported: ['S256'],
      token_endpoint_auth_methods_supported: ['none', 'client_secret_post', 'client_secret_basic'],
    });
  });

  // RFC 9728 — OAuth 2.0 Protected Resource Metadata for the /mcp endpoint. Served at both
  // the path-suffixed and root locations because clients probe either.
  // Trailing slashes are trimmed here only; the existing issuer value is left untouched.
  const resourceBase = baseUrl.replace(/\/+$/, '');
  const protectedResourceMetadata = {
    resource: `${resourceBase}/mcp`,
    authorization_servers: [baseUrl],
    bearer_methods_supported: ['header'],
  };
  router.get(
    ['/.well-known/oauth-protected-resource', '/.well-known/oauth-protected-resource/mcp'],
    (_req, res) => {
      res.json(protectedResourceMetadata);
    },
  );

  // RFC 7591 — Dynamic Client Registration (used by Claude custom connectors).
  // Registration is stateless: the authorize step already gates on the MCP API token and
  // the redirect_uri origin allowlist, so a client_id alone grants nothing. Registration
  // still rejects redirect URIs outside the allowlist so misconfiguration fails early.
  router.post('/register', registerLimiter, json({ limit: '8kb' }), (req, res) => {
    const b = (req.body ?? {}) as Record<string, unknown>;
    const redirectUris = b.redirect_uris;
    if (
      !Array.isArray(redirectUris) ||
      redirectUris.length === 0 ||
      redirectUris.length > 10 ||
      !redirectUris.every((u) => typeof u === 'string' && redirectUriAllowed(u, options.redirectOrigins))
    ) {
      res.status(400).json({
        error: 'invalid_redirect_uri',
        error_description: 'redirect_uris must be HTTPS URLs on an allowed origin',
      });
      return;
    }

    const requestedAuth = b.token_endpoint_auth_method;
    const authMethod =
      requestedAuth === 'client_secret_post' || requestedAuth === 'client_secret_basic'
        ? requestedAuth
        : 'none';
    const clientName = typeof b.client_name === 'string' ? b.client_name.slice(0, 100) : undefined;

    res.status(201).json({
      client_id: `dcr_${randomBytes(16).toString('base64url')}`,
      client_id_issued_at: Math.floor(Date.now() / 1000),
      // A secret is issued only for clients that insist on one; the token endpoint relies on
      // PKCE rather than client authentication, so it is not checked.
      ...(authMethod === 'none' ? {} : { client_secret: randomBytes(32).toString('base64url'), client_secret_expires_at: 0 }),
      redirect_uris: redirectUris,
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      token_endpoint_auth_method: authMethod,
      ...(clientName ? { client_name: clientName } : {}),
    });
  });

  // GET /oauth/authorize — render the token-entry form
  router.get('/oauth/authorize', (req, res) => {
    const q = req.query as Record<string, string>;
    if (q.response_type !== 'code') {
      res.status(400).json({ error: 'unsupported_response_type' });
      return;
    }
    if (!q.redirect_uri || !redirectUriAllowed(q.redirect_uri, options.redirectOrigins)) {
      res.status(400).json({ error: 'invalid_request', error_description: 'redirect_uri not allowed' });
      return;
    }
    if (!q.code_challenge || q.code_challenge_method !== 'S256') {
      res.status(400).json({ error: 'invalid_request', error_description: 'PKCE S256 is required' });
      return;
    }
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(
      loginPage({
        redirect_uri: q.redirect_uri,
        state: q.state,
        code_challenge: q.code_challenge,
        code_challenge_method: q.code_challenge_method,
        client_id: q.client_id,
      }),
    );
  });

  // POST /oauth/authorize — validate token and redirect with auth code
  router.post(
    '/oauth/authorize',
    authorizeLimiter,
    urlencoded({ extended: false, limit: '4kb' }),
    (req, res) => {
      const b = req.body as Record<string, string>;
      const { redirect_uri, state, code_challenge, code_challenge_method, client_id, token } = b;

      // Re-validate: these arrive as form fields and are fully attacker-controllable.
      if (!redirect_uri || !redirectUriAllowed(redirect_uri, options.redirectOrigins)) {
        res.status(400).json({ error: 'invalid_request', error_description: 'redirect_uri not allowed' });
        return;
      }
      if (!code_challenge || code_challenge_method !== 'S256') {
        res.status(400).json({ error: 'invalid_request', error_description: 'PKCE S256 is required' });
        return;
      }

      if (!token || !constantTimeEquals(token, mcpApiToken)) {
        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        res.status(401).send(
          loginPage(
            { redirect_uri, state, code_challenge, code_challenge_method, client_id },
            'Invalid token. Please try again.',
          ),
        );
        return;
      }

      const code = generateCode();
      const entry: PendingCode = {
        redirectUri: redirect_uri,
        codeChallenge: code_challenge,
        codeChallengeMethod: 'S256',
        clientId: client_id ?? 'unknown',
        expiresAt: Date.now() + 5 * 60 * 1000,
      };
      pendingCodes.set(code, entry);

      try {
        const cb = new URL(redirect_uri);
        cb.searchParams.set('code', code);
        if (state) cb.searchParams.set('state', state);
        res.redirect(302, cb.toString());
      } catch {
        pendingCodes.delete(code);
        res.status(400).json({ error: 'invalid_request', error_description: 'invalid redirect_uri' });
      }
    },
  );

  // POST /oauth/token — exchange auth code for access token
  router.post('/oauth/token', flexBody, (req, res) => {
    const b = req.body as Record<string, string>;
    const { grant_type, code, redirect_uri, code_verifier } = b;

    if (grant_type === 'refresh_token') {
      const presented = b.refresh_token;
      const verified = presented
        ? verifyRefreshToken(mcpApiToken, options.tokenEpoch, presented)
        : null;
      if (!verified || (b.client_id && b.client_id !== verified.clientId)) {
        res.status(400).json({ error: 'invalid_grant' });
        return;
      }
      const { token, expiresIn } = issueAccessToken(
        mcpApiToken,
        verified.clientId,
        options.tokenEpoch,
        options.accessTokenTtlSeconds,
      );
      res.json({
        access_token: token,
        token_type: 'Bearer',
        expires_in: expiresIn,
        refresh_token: issueRefreshToken(
          mcpApiToken,
          verified.clientId,
          options.tokenEpoch,
          refreshTokenTtlSeconds,
        ),
      });
      return;
    }

    if (grant_type !== 'authorization_code') {
      res.status(400).json({ error: 'unsupported_grant_type' });
      return;
    }
    if (!code) {
      res.status(400).json({ error: 'invalid_request' });
      return;
    }

    const pending = pendingCodes.get(code);
    pendingCodes.delete(code); // single-use: consume before any early return

    if (!pending || pending.expiresAt < Date.now()) {
      res.status(400).json({ error: 'invalid_grant' });
      return;
    }
    if (pending.redirectUri !== redirect_uri) {
      res.status(400).json({ error: 'invalid_grant' });
      return;
    }
    if (!code_verifier || !verifyS256(code_verifier, pending.codeChallenge)) {
      res.status(400).json({ error: 'invalid_grant' });
      return;
    }

    // Issue a scoped, expiring token rather than handing out the master secret.
    const { token, expiresIn } = issueAccessToken(
      mcpApiToken,
      pending.clientId,
      options.tokenEpoch,
      options.accessTokenTtlSeconds,
    );
    res.json({
      access_token: token,
      token_type: 'Bearer',
      expires_in: expiresIn,
      refresh_token: issueRefreshToken(
        mcpApiToken,
        pending.clientId,
        options.tokenEpoch,
        refreshTokenTtlSeconds,
      ),
    });
  });

  return router;
}
