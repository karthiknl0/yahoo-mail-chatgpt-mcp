import type { RedisClientType } from "redis";
import { describe, expect, it } from "vitest";
import { RedisOAuthStore } from "../src/oauth/redis-store.js";
import type {
  AccessTokenRecord,
  AuthorizationCodeRecord,
  AuthorizationTransaction,
  RefreshTokenRecord,
  RotateRefreshTokenInput,
} from "../src/oauth/types.js";
import { InMemoryOAuthStore } from "./helpers/in-memory-oauth-store.js";

const transaction: AuthorizationTransaction = {
  clientId: "client-1",
  redirectUri: "https://client.example/callback",
  resource: "https://service.example/mcp",
  state: "state-1",
  codeChallenge: "challenge-1",
  scope: "mcp:read",
  csrf: "csrf-1",
};

const authorizationCode: AuthorizationCodeRecord = {
  clientId: transaction.clientId,
  redirectUri: transaction.redirectUri,
  resource: transaction.resource,
  codeChallenge: transaction.codeChallenge,
  scope: transaction.scope,
};

const accessToken: AccessTokenRecord = {
  clientId: transaction.clientId,
  resource: transaction.resource,
  scope: transaction.scope,
  expiresAt: 1_700_000_900_000,
};

const refreshToken: RefreshTokenRecord = {
  familyId: "family-1",
  clientId: transaction.clientId,
  resource: transaction.resource,
  scope: transaction.scope,
  expiresAt: 1_702_592_000_000,
};

const rotation: RotateRefreshTokenInput = {
  oldDigest: "old-digest",
  newDigest: "new-digest",
  familyId: refreshToken.familyId,
  clientId: refreshToken.clientId,
  resource: refreshToken.resource,
  scope: refreshToken.scope,
  refreshTtlSeconds: 30 * 24 * 60 * 60,
  familyTtlSeconds: 30 * 24 * 60 * 60,
};

describe("OAuth store contract", () => {
  it("consumes an authorization transaction exactly once", async () => {
    const store = new InMemoryOAuthStore(1_700_000_000_000);
    await store.createTransaction("tx-1", transaction, 600);

    expect(await store.consumeTransaction("tx-1")).toEqual(transaction);
    expect(await store.consumeTransaction("tx-1")).toBeNull();
  });

  it("consumes an authorization code exactly once", async () => {
    const store = new InMemoryOAuthStore(1_700_000_000_000);
    await store.createAuthorizationCode("code-1", authorizationCode, 300);

    expect(await store.consumeAuthorizationCode("code-1")).toEqual(
      authorizationCode,
    );
    expect(await store.consumeAuthorizationCode("code-1")).toBeNull();
  });

  it("expires access tokens at their store TTL", async () => {
    const store = new InMemoryOAuthStore(1_700_000_000_000);
    await store.createAccessToken("access-1", accessToken, 10);

    store.advanceBy(9_999);
    expect(await store.getAccessToken("access-1")).toEqual(accessToken);
    store.advanceBy(1);
    expect(await store.getAccessToken("access-1")).toBeNull();
  });

  it("increments a shared rate-limit counter atomically", async () => {
    const store = new InMemoryOAuthStore(1_700_000_000_000);

    const values = await Promise.all(
      Array.from({ length: 20 }, () => store.incrementRateLimit("ip-1", 60)),
    );

    expect([...values].sort((left, right) => left - right)).toEqual(
      Array.from({ length: 20 }, (_, index) => index + 1),
    );
  });

  it("marks refresh-token replay and revokes the whole family", async () => {
    const store = new InMemoryOAuthStore(1_700_000_000_000);
    await store.seedRefreshToken(
      rotation.oldDigest,
      refreshToken,
      rotation.refreshTtlSeconds,
    );

    expect(await store.rotateRefreshToken(rotation)).toBe("rotated");
    expect(await store.rotateRefreshToken(rotation)).toBe("replayed");
    expect(
      await store.rotateRefreshToken({
        ...rotation,
        oldDigest: rotation.newDigest,
        newDigest: "third-digest",
      }),
    ).toBe("revoked");
  });
});

type RedisCall =
  | { method: "set"; key: string; value: string; ttl?: number }
  | { method: "get" | "getDel"; key: string }
  | { method: "eval"; keys: string[]; arguments: string[] };

class StrictFakeRedisClient {
  readonly calls: RedisCall[] = [];
  readonly values = new Map<string, string>();
  evalReply: unknown = 1;
  quitCalls = 0;

  async set(
    key: string,
    value: string,
    options?: { EX: number },
  ): Promise<string> {
    if (options && (!Number.isInteger(options.EX) || options.EX <= 0)) {
      throw new Error("invalid SET expiry");
    }
    this.calls.push({
      method: "set",
      key,
      value,
      ...(options ? { ttl: options.EX } : {}),
    });
    this.values.set(key, value);
    return "OK";
  }

  async get(key: string): Promise<string | null> {
    this.calls.push({ method: "get", key });
    return this.values.get(key) ?? null;
  }

  async getDel(key: string): Promise<string | null> {
    this.calls.push({ method: "getDel", key });
    const value = this.values.get(key) ?? null;
    this.values.delete(key);
    return value;
  }

  async eval(
    _script: string,
    options: { keys: string[]; arguments: string[] },
  ): Promise<unknown> {
    if (options.keys.length === 0 || options.arguments.length === 0) {
      throw new Error("invalid EVAL command shape");
    }
    this.calls.push({ method: "eval", ...structuredClone(options) });
    return this.evalReply;
  }

  async quit(): Promise<string> {
    this.quitCalls += 1;
    return "OK";
  }
}

function redisStore(fake: StrictFakeRedisClient): RedisOAuthStore {
  return new RedisOAuthStore(
    fake as unknown as RedisClientType,
    () => 1_700_000_000_000,
  );
}

describe("RedisOAuthStore command boundaries", () => {
  it("uses bounded prefixes, expiry-bearing SET, and GETDEL", async () => {
    const fake = new StrictFakeRedisClient();
    const store = redisStore(fake);

    await store.createTransaction("tx-id", transaction, 600);
    await store.consumeTransaction("tx-id");
    await store.createAuthorizationCode("code-digest", authorizationCode, 300);
    await store.consumeAuthorizationCode("code-digest");
    await store.createAccessToken("access-digest", accessToken, 900);
    await store.getAccessToken("access-digest");

    expect(
      fake.calls
        .filter((call) => call.method !== "eval")
        .map(({ method, key }) => [method, key]),
    ).toEqual([
      ["set", "tx:tx-id"],
      ["getDel", "tx:tx-id"],
      ["set", "code:code-digest"],
      ["getDel", "code:code-digest"],
      ["set", "access:access-digest"],
      ["get", "access:access-digest"],
    ]);
    expect(fake.calls.filter((call) => call.method === "set")).toMatchObject([
      { ttl: 600 },
      { ttl: 300 },
      { ttl: 900 },
    ]);
  });

  it("rotates refresh tokens in one Lua command with family-scoped keys", async () => {
    const fake = new StrictFakeRedisClient();
    fake.evalReply = "rotated";
    const store = redisStore(fake);

    expect(await store.rotateRefreshToken(rotation)).toBe("rotated");
    expect(fake.calls).toEqual([
      {
        method: "eval",
        keys: [
          "refresh:old-digest",
          "refresh-used:old-digest",
          "refresh:new-digest",
          "family-revoked:family-1",
        ],
        arguments: [
          JSON.stringify(refreshToken),
          "2592000",
          "2592000",
          "family-1",
        ],
      },
    ]);
  });

  it("increments rate limits in one Lua command", async () => {
    const fake = new StrictFakeRedisClient();
    fake.evalReply = 7;
    const store = redisStore(fake);

    expect(await store.incrementRateLimit("login:ip-1", 900)).toBe(7);
    expect(fake.calls).toEqual([
      {
        method: "eval",
        keys: ["rate:login:ip-1"],
        arguments: ["900"],
      },
    ]);
  });
});
