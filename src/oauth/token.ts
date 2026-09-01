import { Router, type Request, type Response, urlencoded } from "express";
import type { AppConfig } from "../config.js";
import { pkceChallenge, randomToken, sha256Token } from "./crypto.js";
import type { OAuthStore } from "./store.js";

const ACCESS_TOKEN_TTL_SECONDS = 15 * 60;
const REFRESH_TOKEN_TTL_SECONDS = 30 * 24 * 60 * 60;
const OPAQUE_TOKEN_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const PKCE_VERIFIER_PATTERN = /^[A-Za-z0-9._~-]{43,128}$/;

type TokenError =
  "invalid_grant" | "invalid_request" | "unsupported_grant_type";

function sendTokenError(res: Response, error: TokenError, status = 400): void {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");
  res.status(status).json({ error });
}

function formValue(req: Request, name: string): string | null {
  if (typeof req.body !== "object" || req.body === null) return null;
  const value = (req.body as Record<string, unknown>)[name];
  return typeof value === "string" && value.length > 0 ? value : null;
}

function sendTokens(
  res: Response,
  accessToken: string,
  refreshToken: string,
  scope: string,
): void {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");
  res.status(200).json({
    token_type: "Bearer",
    expires_in: ACCESS_TOKEN_TTL_SECONDS,
    access_token: accessToken,
    refresh_token: refreshToken,
    scope,
  });
}

async function exchangeAuthorizationCode(
  req: Request,
  res: Response,
  config: AppConfig,
  store: OAuthStore,
): Promise<void> {
  const code = formValue(req, "code");
  if (!code) {
    sendTokenError(res, "invalid_grant");
    return;
  }

  const clientId = formValue(req, "client_id");
  const redirectUri = formValue(req, "redirect_uri");
  const resource = formValue(req, "resource");
  const verifier = formValue(req, "code_verifier");
  const codeChallenge =
    verifier !== null && PKCE_VERIFIER_PATTERN.test(verifier)
      ? await pkceChallenge(verifier)
      : "";

  for (let attempt = 0; attempt < 3; attempt += 1) {
    const accessToken = randomToken();
    const refreshToken = randomToken();
    const exchange = await store.exchangeAuthorizationCode({
      codeDigest: sha256Token(code),
      accessDigest: sha256Token(accessToken),
      refreshDigest: sha256Token(refreshToken),
      familyId: randomToken(),
      clientId: clientId ?? "",
      redirectUri: redirectUri ?? "",
      resource: resource === config.resourceUrl ? resource : "",
      codeChallenge,
      scope: OPAQUE_TOKEN_PATTERN.test(code) ? "mcp:read" : "",
      accessTtlSeconds: ACCESS_TOKEN_TTL_SECONDS,
      refreshTtlSeconds: REFRESH_TOKEN_TTL_SECONDS,
    });
    if (exchange.status === "collision") continue;
    if (exchange.status === "storage_error") {
      throw new Error("OAuth token-pair persistence failed");
    }
    if (exchange.status !== "issued") {
      sendTokenError(res, "invalid_grant");
      return;
    }
    sendTokens(res, accessToken, refreshToken, exchange.record.scope);
    return;
  }
  throw new Error("Unable to allocate OAuth token pair");
}

async function exchangeRefreshToken(
  req: Request,
  res: Response,
  config: AppConfig,
  store: OAuthStore,
): Promise<void> {
  const oldToken = formValue(req, "refresh_token");
  if (!oldToken || !OPAQUE_TOKEN_PATTERN.test(oldToken)) {
    sendTokenError(res, "invalid_grant");
    return;
  }

  const clientId = formValue(req, "client_id");
  const resource = formValue(req, "resource");
  const requestedScope = formValue(req, "scope");
  for (let attempt = 0; attempt < 3; attempt += 1) {
    const newToken = randomToken();
    const accessToken = randomToken();
    const rotation = await store.rotateRefreshToken({
      oldDigest: sha256Token(oldToken),
      newDigest: sha256Token(newToken),
      accessDigest: sha256Token(accessToken),
      clientId: clientId ?? "",
      resource: resource === config.resourceUrl ? resource : "",
      scope:
        requestedScope === null || requestedScope === "mcp:read"
          ? "mcp:read"
          : "",
      accessTtlSeconds: ACCESS_TOKEN_TTL_SECONDS,
    });
    if (rotation.status === "collision") continue;
    if (rotation.status === "storage_error") {
      throw new Error("OAuth token-pair persistence failed");
    }
    if (rotation.status !== "rotated") {
      sendTokenError(res, "invalid_grant");
      return;
    }
    sendTokens(res, accessToken, newToken, rotation.record.scope);
    return;
  }
  throw new Error("Unable to allocate OAuth token pair");
}

export function tokenRouter(config: AppConfig, store: OAuthStore): Router {
  const router = Router();

  router.post(
    "/token",
    (req, res, next) => {
      if (!req.is("application/x-www-form-urlencoded")) {
        sendTokenError(res, "invalid_request", 415);
        return;
      }
      next();
    },
    urlencoded({ extended: false, limit: "16kb" }),
    async (req, res, next) => {
      try {
        const grantType = formValue(req, "grant_type");
        if (!grantType) {
          sendTokenError(res, "invalid_request");
          return;
        }
        if (grantType === "authorization_code") {
          await exchangeAuthorizationCode(req, res, config, store);
          return;
        }
        if (grantType === "refresh_token") {
          await exchangeRefreshToken(req, res, config, store);
          return;
        }
        sendTokenError(res, "unsupported_grant_type");
      } catch (error) {
        next(error);
      }
    },
  );

  return router;
}
