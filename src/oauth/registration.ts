import { randomUUID } from "node:crypto";
import {
  json,
  Router,
  type NextFunction,
  type Request,
  type Response,
} from "express";
import { z } from "zod/v4";
import type { AppConfig } from "../config.js";
import {
  CLIENT_PROVISIONAL_RETENTION_SECONDS,
  MAX_ACTIVE_OAUTH_CLIENTS,
  type OAuthStore,
} from "./store.js";
import type { RegisteredClient } from "./types.js";

const REGISTRATION_WINDOW_SECONDS = 60;
const REGISTRATION_LIMIT = 10;
const MAX_REGISTRATION_BODY_BYTES = 32 * 1024;

function enforceRegistrationBodyLimit(
  req: Request,
  res: Response,
  next: NextFunction,
): void {
  const rawLength = req.get("content-length");
  const length = rawLength === undefined ? NaN : Number(rawLength);
  if (Number.isFinite(length) && length > MAX_REGISTRATION_BODY_BYTES) {
    res.status(413).json({ error: "request_too_large" });
    return;
  }
  next();
}

function isSafeRedirectUri(value: string): boolean {
  if (value.includes("*")) return false;
  try {
    const url = new URL(value);
    if (url.hash !== "" || url.username !== "" || url.password !== "") {
      return false;
    }
    if (url.protocol === "https:") return true;
    return (
      url.protocol === "http:" &&
      (url.hostname === "127.0.0.1" || url.hostname === "localhost")
    );
  } catch {
    return false;
  }
}

const registrationSchema = z
  .object({
    redirect_uris: z
      .array(z.string().min(1).max(2_048).refine(isSafeRedirectUri))
      .min(1)
      .max(10)
      .refine((uris) => new Set(uris).size === uris.length),
    client_name: z.string().min(1).max(128).optional(),
    client_uri: z.string().url().max(2_048).optional(),
    grant_types: z
      .array(z.enum(["authorization_code", "refresh_token"]))
      .min(1)
      .max(2)
      .refine((types) => new Set(types).size === types.length)
      .optional(),
    response_types: z.array(z.literal("code")).min(1).max(1).optional(),
    token_endpoint_auth_method: z.literal("none"),
    scope: z.string().min(1).max(256).optional(),
  })
  .strict();

function toRegisteredClient(
  value: z.infer<typeof registrationSchema>,
): RegisteredClient {
  const clientId = randomUUID();
  return {
    clientId,
    redirectUris: value.redirect_uris,
    tokenEndpointAuthMethod: "none",
    ...(value.client_name === undefined
      ? {}
      : { clientName: value.client_name }),
    ...(value.client_uri === undefined ? {} : { clientUri: value.client_uri }),
    ...(value.grant_types === undefined
      ? {}
      : { grantTypes: value.grant_types }),
    ...(value.response_types === undefined
      ? {}
      : { responseTypes: value.response_types }),
    ...(value.scope === undefined ? {} : { scope: value.scope }),
    createdAt: Date.now(),
  };
}

function toRegistrationResponse(
  client: RegisteredClient,
): Record<string, unknown> {
  return {
    client_id: client.clientId,
    redirect_uris: client.redirectUris,
    token_endpoint_auth_method: "none",
    ...(client.clientName === undefined
      ? {}
      : { client_name: client.clientName }),
    ...(client.clientUri === undefined ? {} : { client_uri: client.clientUri }),
    ...(client.grantTypes === undefined
      ? {}
      : { grant_types: client.grantTypes }),
    ...(client.responseTypes === undefined
      ? {}
      : { response_types: client.responseTypes }),
    ...(client.scope === undefined ? {} : { scope: client.scope }),
  };
}

/** Registers only bounded public OAuth clients. */
export function registrationRouter(
  _config: AppConfig,
  store: OAuthStore,
): Router {
  const router = Router();
  router.use((_req, res, next) => {
    res.setHeader("Cache-Control", "no-store");
    next();
  });
  router.post(
    "/register",
    enforceRegistrationBodyLimit,
    json({ limit: "32kb", type: "application/json" }),
    async (req, res, next) => {
      try {
        const count = await store.incrementRateLimit(
          `registration:${req.ip ?? "unknown"}`,
          REGISTRATION_WINDOW_SECONDS,
        );
        if (count > REGISTRATION_LIMIT) {
          res.status(429).json({ error: "rate_limited" });
          return;
        }

        const parsed = registrationSchema.safeParse(req.body);
        if (!parsed.success) {
          res.status(400).json({ error: "invalid_client_metadata" });
          return;
        }

        const client = toRegisteredClient(parsed.data);
        const registered = await store.registerClient(
          client,
          CLIENT_PROVISIONAL_RETENTION_SECONDS,
          MAX_ACTIVE_OAUTH_CLIENTS,
        );
        if (!registered) {
          res
            .setHeader("Retry-After", "60")
            .status(503)
            .json({ error: "temporarily_unavailable" });
          return;
        }
        res.status(201).json(toRegistrationResponse(client));
      } catch (error) {
        next(error);
      }
    },
  );
  return router;
}
