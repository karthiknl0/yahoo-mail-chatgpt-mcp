import { createServer } from "node:http";
import { createClient } from "redis";
import { createApp, type OAuthStore } from "./app.js";
import { loadConfig } from "./config.js";
import { createYahooMcpServer } from "./mcp.js";

const config = loadConfig();
const redis = createClient({ url: config.redisUrl });

await redis.connect();

// Task 2 extends this lifecycle boundary with the durable OAuth store contract.
const oauthStore: OAuthStore = {
  close: async () => {
    await redis.quit();
  },
};

const app = createApp(config, {
  oauthStore,
  createMcpServer: createYahooMcpServer,
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
    await oauthStore.close();
    clearTimeout(forceExit);
    process.exit(0);
  });
}

process.on("SIGINT", () => void shutdown("SIGINT"));
process.on("SIGTERM", () => void shutdown("SIGTERM"));
