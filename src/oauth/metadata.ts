import { Router } from "express";
import type { AppConfig } from "../config.js";

function endpoint(origin: string, path: string): string {
  return new URL(path, origin).toString();
}

/** Serves OAuth metadata for the single protected MCP resource. */
export function oauthMetadataRouter(config: AppConfig): Router {
  const router = Router();
  const protectedResource = {
    resource: config.resourceUrl,
    authorization_servers: [config.publicOrigin],
    bearer_methods_supported: ["header"],
    scopes_supported: ["mcp:read"],
  };
  const authorizationServer = {
    issuer: config.publicOrigin,
    authorization_endpoint: endpoint(config.publicOrigin, "/authorize"),
    token_endpoint: endpoint(config.publicOrigin, "/token"),
    registration_endpoint: endpoint(config.publicOrigin, "/register"),
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["none"],
  };

  router.use((_req, res, next) => {
    res.setHeader("Cache-Control", "no-store");
    next();
  });
  router.get("/.well-known/oauth-protected-resource", (_req, res) => {
    res.status(200).json(protectedResource);
  });
  router.get("/.well-known/oauth-protected-resource/mcp", (_req, res) => {
    res.status(200).json(protectedResource);
  });
  router.get("/.well-known/oauth-authorization-server", (_req, res) => {
    res.status(200).json(authorizationServer);
  });

  return router;
}
