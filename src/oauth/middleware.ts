import type { RequestHandler } from "express";
import type { AppConfig } from "../config.js";
import { sha256Token } from "./crypto.js";
import type { OAuthStore } from "./store.js";

const BEARER_PATTERN = /^Bearer ([A-Za-z0-9_-]{43})$/i;

function protectedResourceChallenge(config: AppConfig): string {
  const metadataUrl = new URL(
    "/.well-known/oauth-protected-resource/mcp",
    config.publicOrigin,
  ).toString();
  return `Bearer resource_metadata="${metadataUrl}"`;
}

export function requireMcpBearer(
  config: AppConfig,
  store: OAuthStore,
): RequestHandler {
  return async (req, res, next) => {
    const deny = () => {
      res.setHeader("WWW-Authenticate", protectedResourceChallenge(config));
      res.status(401).json({ error: "unauthorized" });
    };

    if (Object.prototype.hasOwnProperty.call(req.query, "access_token")) {
      deny();
      return;
    }

    const match = BEARER_PATTERN.exec(req.get("authorization") ?? "");
    if (!match?.[1]) {
      deny();
      return;
    }

    try {
      const record = await store.getAccessToken(sha256Token(match[1]));
      if (
        !record ||
        record.expiresAt <= Date.now() ||
        record.resource !== config.resourceUrl ||
        record.scope !== "mcp:read"
      ) {
        deny();
        return;
      }
      res.locals.auth = { clientId: record.clientId, scope: record.scope };
      next();
    } catch (error) {
      next(error);
    }
  };
}
