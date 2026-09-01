import { Router, type Request, type Response, urlencoded } from "express";
import type { AppConfig } from "../config.js";
import { randomToken, sha256Token, verifyPkce } from "./crypto.js";
import type { OAuthStore } from "./store.js";
import type { AccessTokenRecord, RefreshTokenRecord } from "./types.js";

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

async function storeAccessToken(
  store: OAuthStore,
  record: Omit<AccessTokenRecord, "expiresAt">,
): Promise<string> {
  const accessToken = randomToken();
  await store.createAccessToken(
    sha256Token(accessToken),
    {
      ...record,
      expiresAt: Date.now() + ACCESS_TOKEN_TTL_SECONDS * 1_000,
    },
    ACCESS_TOKEN_TTL_SECONDS,
  );
  return accessToken;
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

  const record = await store.consumeAuthorizationCode(sha256Token(code));
  const clientId = formValue(req, "client_id");
  const redirectUri = formValue(req, "redirect_uri");
  const resource = formValue(req, "resource");
  const verifier = formValue(req, "code_verifier");
  const validPkce =
    record !== null &&
    verifier !== null &&
    PKCE_VERIFIER_PATTERN.test(verifier) &&
    (await verifyPkce(verifier, record.codeChallenge));

  if (
    !OPAQUE_TOKEN_PATTERN.test(code) ||
    record === null ||
    clientId !== record.clientId ||
    redirectUri !== record.redirectUri ||
    resource !== record.resource ||
    resource !== config.resourceUrl ||
    !validPkce
  ) {
    sendTokenError(res, "invalid_grant");
    return;
  }

  const refreshToken = randomToken();
  const refreshRecord: RefreshTokenRecord = {
    familyId: randomToken(),
    clientId: record.clientId,
    resource: record.resource,
    scope: record.scope,
    expiresAt: Date.now() + REFRESH_TOKEN_TTL_SECONDS * 1_000,
  };
  const created = await store.createRefreshToken(
    sha256Token(refreshToken),
    refreshRecord,
    REFRESH_TOKEN_TTL_SECONDS,
  );
  if (!created) throw new Error("Unable to allocate OAuth refresh token");

  const accessToken = await storeAccessToken(store, {
    clientId: record.clientId,
    resource: record.resource,
    scope: record.scope,
  });
  sendTokens(res, accessToken, refreshToken, record.scope);
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

  const newToken = randomToken();
  const rotation = await store.rotateRefreshToken({
    oldDigest: sha256Token(oldToken),
    newDigest: sha256Token(newToken),
  });
  if (rotation.status !== "rotated") {
    sendTokenError(res, "invalid_grant");
    return;
  }

  const clientId = formValue(req, "client_id");
  const resource = formValue(req, "resource");
  const requestedScope = formValue(req, "scope");
  const record = rotation.record;
  if (
    clientId !== record.clientId ||
    resource !== record.resource ||
    resource !== config.resourceUrl ||
    (requestedScope !== null && requestedScope !== record.scope) ||
    record.expiresAt <= Date.now()
  ) {
    sendTokenError(res, "invalid_grant");
    return;
  }

  const accessToken = await storeAccessToken(store, {
    clientId: record.clientId,
    resource: record.resource,
    scope: record.scope,
  });
  sendTokens(res, accessToken, newToken, record.scope);
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
