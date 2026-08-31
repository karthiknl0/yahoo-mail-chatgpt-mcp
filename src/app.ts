import { createMcpExpressApp } from "@modelcontextprotocol/express";
import { toNodeHandler } from "@modelcontextprotocol/node";
import { createMcpHandler, type McpServer } from "@modelcontextprotocol/server";
import type { Express, NextFunction, Request, Response } from "express";
import rateLimit from "express-rate-limit";
import helmet from "helmet";
import type { AppConfig } from "./config.js";

/** OAuth storage is intentionally opaque until its durable implementation is added. */
export type OAuthStore = object;

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
    (req, res) => void nodeHandler(req, res, req.body),
  );

  app.use((_req, res) => {
    res.status(404).json({ error: "not_found" });
  });

  app.use(
    (error: unknown, _req: Request, res: Response, _next: NextFunction) => {
      console.error(
        "Request failed",
        error instanceof Error ? error.name : "UnknownError",
      );
      if (!res.headersSent) res.status(500).json({ error: "internal_error" });
    },
  );

  return app;
}
