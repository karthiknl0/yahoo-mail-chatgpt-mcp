import { createMcpExpressApp } from "@modelcontextprotocol/express";
import { toNodeHandler } from "@modelcontextprotocol/node";
import { createMcpHandler, type McpServer } from "@modelcontextprotocol/server";
import type { Express, NextFunction, Request, Response } from "express";
import rateLimit from "express-rate-limit";
import helmet from "helmet";
import type { AppConfig } from "./config.js";
import { oauthMetadataRouter } from "./oauth/metadata.js";
import { registrationRouter } from "./oauth/registration.js";
import type { OAuthStore } from "./oauth/store.js";

export interface AppDependencies {
  oauthStore: OAuthStore;
  createMcpServer: (config: AppConfig) => McpServer;
}

function enforceBodyLimit(
  req: Request,
  res: Response,
  next: NextFunction,
): void {
  const raw = req.get("content-length");
  if (raw) {
    const length = Number(raw);
    if (Number.isFinite(length) && length > 256 * 1024) {
      res.status(413).json({ error: "request_too_large" });
      return;
    }
  }
  next();
}

/**
 * Fails closed until Task 5 replaces this boundary with OAuth access-token
 * validation backed by the injected OAuth store.
 */
function rejectUntilOAuth(_req: Request, res: Response): void {
  res.setHeader("WWW-Authenticate", "Bearer");
  res.status(401).json({ error: "unauthorized" });
}

export function createApp(
  config: AppConfig,
  dependencies: AppDependencies,
): Express {
  const handler = createMcpHandler(() => dependencies.createMcpServer(config), {
    responseMode: "json",
  });
  const nodeHandler = toNodeHandler(handler);
  const app = createMcpExpressApp({
    host: config.host,
    allowedHosts: config.allowedHosts,
    allowedOrigins: config.allowedOrigins,
    jsonLimit: "32kb",
  });

  app.disable("x-powered-by");
  app.use(
    helmet({
      contentSecurityPolicy: false,
      crossOriginResourcePolicy: false,
    }),
  );

  app.get("/health", (_req, res) => {
    res.status(200).json({ status: "ok" });
  });

  app.use(oauthMetadataRouter(config));
  app.use(registrationRouter(config, dependencies.oauthStore));

  const limiter = rateLimit({
    windowMs: 60_000,
    limit: 60,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: "rate_limited" },
  });

  app.all(
    "/mcp",
    limiter,
    enforceBodyLimit,
    rejectUntilOAuth,
    (req, res) => void nodeHandler(req, res, req.body),
  );

  app.use((_req, res) => {
    res.status(404).json({ error: "not_found" });
  });

  app.use(
    (error: unknown, _req: Request, res: Response, _next: NextFunction) => {
      if (
        typeof error === "object" &&
        error !== null &&
        "status" in error &&
        error.status === 413
      ) {
        res.status(413).json({ error: "request_too_large" });
        return;
      }
      console.error(
        "Request failed",
        error instanceof Error ? error.name : "UnknownError",
      );
      if (!res.headersSent) res.status(500).json({ error: "internal_error" });
    },
  );

  return app;
}
