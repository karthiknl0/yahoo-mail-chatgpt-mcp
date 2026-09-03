import { createServer } from 'node:http';
import { createMcpExpressApp } from '@modelcontextprotocol/express';
import { toNodeHandler } from '@modelcontextprotocol/node';
import { createMcpHandler } from '@modelcontextprotocol/server';
import type { NextFunction, Request, Response } from 'express';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import { loadConfig } from './config.js';
import { createYahooMcpServer } from './mcp.js';
import { createOAuthRouter } from './oauth.js';
import { bearerAuth } from './security/auth.js';

const config = loadConfig();

const handler = createMcpHandler(() => createYahooMcpServer(config), {
  responseMode: 'json',
});
const nodeHandler = toNodeHandler(handler);

const app = createMcpExpressApp({
  host: config.host,
  allowedHosts: config.allowedHosts,
  allowedOrigins: config.allowedOrigins,
});

app.disable('x-powered-by');
app.set('trust proxy', config.trustProxy);
app.use(
  helmet({
    contentSecurityPolicy: false,
    crossOriginResourcePolicy: false,
  }),
);

app.get('/health', (_req, res) => {
  res.status(200).json({ status: 'ok' });
});

// OAuth 2.0 endpoints — must be before the bearer-gated /mcp route.
app.use(createOAuthRouter(config.publicUrl, config.mcpApiToken));

const limiter = rateLimit({
  windowMs: 60_000,
  limit: 60,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'rate_limited' },
});

const BODY_LIMIT = 256 * 1024;
const BODY_METHODS = new Set(['POST', 'PUT', 'PATCH']);

function enforceBodyLimit(req: Request, res: Response, next: NextFunction): void {
  if (!BODY_METHODS.has(req.method)) {
    next();
    return;
  }
  const raw = req.get('content-length');
  if (!raw) {
    res.status(411).json({ error: 'length_required' });
    return;
  }
  const length = Number(raw);
  if (!Number.isFinite(length) || length < 0) {
    res.status(400).json({ error: 'bad_content_length' });
    return;
  }
  if (length > BODY_LIMIT) {
    res.status(413).json({ error: 'request_too_large' });
    return;
  }
  next();
}

app.all(
  '/mcp',
  limiter,
  enforceBodyLimit,
  bearerAuth(config.mcpApiToken),
  (req, res) => void nodeHandler(req, res, req.body),
);

app.use((_req, res) => {
  res.status(404).json({ error: 'not_found' });
});

app.use((error: unknown, _req: Request, res: Response, _next: NextFunction) => {
  console.error('Request failed', error instanceof Error ? error.name : 'UnknownError');
  if (!res.headersSent) res.status(500).json({ error: 'internal_error' });
});

const httpServer = createServer(app);
httpServer.requestTimeout = 30_000;
httpServer.headersTimeout = 10_000;
httpServer.keepAliveTimeout = 5_000;

httpServer.listen(config.port, config.host, () => {
  console.log(`Yahoo Mail MCP listening on ${config.host}:${config.port}`);
});

let shuttingDown = false;
async function shutdown(signal: string): Promise<void> {
  if (shuttingDown) return;
  shuttingDown = true;
  console.log(`Received ${signal}; shutting down`);

  const forceExit = setTimeout(() => process.exit(1), 10_000);
  forceExit.unref();

  httpServer.close(async () => {
    await handler.close();
    clearTimeout(forceExit);
    process.exit(0);
  });
}

process.on('SIGINT', () => void shutdown('SIGINT'));
process.on('SIGTERM', () => void shutdown('SIGTERM'));
