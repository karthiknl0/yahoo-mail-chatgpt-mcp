import type { RedisClientType } from "redis";
import { describe, expect, it } from "vitest";
import { RedisOAuthStore } from "../src/oauth/redis-store.js";
import type {
  AccessTokenRecord,
  ExchangeAuthorizationCodeInput,
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
  accessDigest: "old-access-digest",
  clientId: transaction.clientId,
  resource: transaction.resource,
  scope: transaction.scope,
  expiresAt: 1_702_592_000_000,
};

const rotation: RotateRefreshTokenInput = {
  oldDigest: "old-digest",
  newDigest: "new-digest",
  accessDigest: "rotated-access-digest",
  clientId: refreshToken.clientId,
  resource: refreshToken.resource,
  scope: refreshToken.scope,
  accessTtlSeconds: 900,
};

const refreshTtlSeconds = 30 * 24 * 60 * 60;
const codeExchange: ExchangeAuthorizationCodeInput = {
  codeDigest: "code-exchange-digest",
  accessDigest: "code-access-digest",
  refreshDigest: "code-refresh-digest",
  familyId: "code-family-id",
  clientId: authorizationCode.clientId,
  redirectUri: authorizationCode.redirectUri,
  resource: authorizationCode.resource,
  codeChallenge: authorizationCode.codeChallenge,
  scope: authorizationCode.scope,
  accessTtlSeconds: 900,
  refreshTtlSeconds,
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

  it("atomically exchanges a bound code for an access and refresh pair", async () => {
    const store = new InMemoryOAuthStore(1_700_000_000_000);
    await store.createAuthorizationCode(
      codeExchange.codeDigest,
      authorizationCode,
      300,
    );

    expect(await store.exchangeAuthorizationCode(codeExchange)).toEqual({
      status: "issued",
      record: authorizationCode,
    });
    expect(await store.getAccessToken(codeExchange.accessDigest)).toEqual({
      clientId: authorizationCode.clientId,
      resource: authorizationCode.resource,
      scope: authorizationCode.scope,
      expiresAt: 1_700_000_900_000,
    });
    expect(
      await store.rotateRefreshToken({
        ...rotation,
        oldDigest: codeExchange.refreshDigest,
        clientId: authorizationCode.clientId,
        resource: authorizationCode.resource,
        scope: authorizationCode.scope,
      }),
    ).toMatchObject({ status: "rotated" });
  });

  it("consumes a code on binding mismatch without writing either token", async () => {
    const store = new InMemoryOAuthStore(1_700_000_000_000);
    await store.createAuthorizationCode(
      codeExchange.codeDigest,
      authorizationCode,
      300,
    );

    expect(
      await store.exchangeAuthorizationCode({
        ...codeExchange,
        clientId: "wrong-client",
      }),
    ).toEqual({ status: "binding_mismatch" });
    expect(await store.exchangeAuthorizationCode(codeExchange)).toEqual({
      status: "missing",
    });
    expect(await store.getAccessToken(codeExchange.accessDigest)).toBeNull();
  });

  it("keeps a valid code reusable when either successor digest collides", async () => {
    const store = new InMemoryOAuthStore(1_700_000_000_000);
    await store.createAuthorizationCode(
      codeExchange.codeDigest,
      authorizationCode,
      300,
    );
    await store.createAccessToken(codeExchange.accessDigest, accessToken, 900);

    expect(await store.exchangeAuthorizationCode(codeExchange)).toEqual({
      status: "collision",
    });
    expect(
      await store.exchangeAuthorizationCode({
        ...codeExchange,
        accessDigest: "retry-code-access-digest",
        refreshDigest: "retry-code-refresh-digest",
      }),
    ).toMatchObject({ status: "issued" });
  });

  it("allows only one concurrent exchange of the same code", async () => {
    const store = new InMemoryOAuthStore(1_700_000_000_000);
    await store.createAuthorizationCode(
      codeExchange.codeDigest,
      authorizationCode,
      300,
    );

    const results = await Promise.all([
      store.exchangeAuthorizationCode(codeExchange),
      store.exchangeAuthorizationCode({
        ...codeExchange,
        accessDigest: "concurrent-code-access",
        refreshDigest: "concurrent-code-refresh",
      }),
    ]);

    expect(results.map((result) => result.status).sort()).toEqual([
      "issued",
      "missing",
    ]);
    expect(
      await store.getAccessToken(codeExchange.accessDigest),
    ).not.toBeNull();
    expect(await store.getAccessToken("concurrent-code-access")).toBeNull();
  });

  it("preserves authorization and refresh credentials when an atomic write fails", async () => {
    const store = new InMemoryOAuthStore(1_700_000_000_000);
    await store.createAuthorizationCode(
      codeExchange.codeDigest,
      authorizationCode,
      300,
    );
    await store.createRefreshToken(
      rotation.oldDigest,
      refreshToken,
      refreshTtlSeconds,
    );

    store.failNextTokenPairWrite();
    expect(await store.exchangeAuthorizationCode(codeExchange)).toEqual({
      status: "storage_error",
    });
    expect(await store.exchangeAuthorizationCode(codeExchange)).toMatchObject({
      status: "issued",
    });

    store.failNextTokenPairWrite();
    expect(await store.rotateRefreshToken(rotation)).toEqual({
      status: "storage_error",
    });
    expect(await store.rotateRefreshToken(rotation)).toMatchObject({
      status: "rotated",
    });
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

  it("atomically caps concurrent multi-key rate-limit reservations", async () => {
    const store = new InMemoryOAuthStore(1_700_000_000_000);
    const attempts = await Promise.all(
      Array.from({ length: 10 }, (_, index) =>
        store.reserveRateLimit(
          [`transaction-${index}`, "ip-1"],
          `reservation-${index}`,
          5,
          60,
        ),
      ),
    );

    expect(attempts.filter(Boolean)).toHaveLength(5);
    expect(attempts.filter((admitted) => !admitted)).toHaveLength(5);
  });

  it("releases successful reservations while retained failures expire at the original TTL", async () => {
    const store = new InMemoryOAuthStore(1_700_000_000_000);
    expect(
      await store.reserveRateLimit(
        ["transaction-1", "ip-1"],
        "reservation-1",
        1,
        60,
      ),
    ).toBe(true);
    expect(
      await store.reserveRateLimit(
        ["transaction-2", "ip-1"],
        "reservation-2",
        1,
        60,
      ),
    ).toBe(false);

    await store.releaseRateLimit(["transaction-1", "ip-1"], "reservation-1");
    expect(
      await store.reserveRateLimit(
        ["transaction-2", "ip-1"],
        "reservation-2",
        1,
        60,
      ),
    ).toBe(true);
    expect(
      await store.reserveRateLimit(
        ["transaction-3", "ip-1"],
        "reservation-3",
        1,
        60,
      ),
    ).toBe(false);
    store.advanceBy(60_000);
    expect(
      await store.reserveRateLimit(
        ["transaction-3", "ip-1"],
        "reservation-3",
        1,
        60,
      ),
    ).toBe(true);
  });

  it("marks refresh-token replay and revokes the whole family", async () => {
    const store = new InMemoryOAuthStore(1_700_000_000_000);
    expect(
      await store.createRefreshToken(
        rotation.oldDigest,
        refreshToken,
        refreshTtlSeconds,
      ),
    ).toBe(true);
    expect(
      await store.createRefreshToken(
        rotation.oldDigest,
        refreshToken,
        refreshTtlSeconds,
      ),
    ).toBe(false);

    expect(await store.rotateRefreshToken(rotation)).toEqual({
      status: "rotated",
      record: refreshToken,
    });
    expect(await store.rotateRefreshToken(rotation)).toEqual({
      status: "replayed",
      record: refreshToken,
    });
    expect(
      await store.rotateRefreshToken({
        ...rotation,
        oldDigest: rotation.newDigest,
        newDigest: "third-digest",
        accessDigest: "third-access-digest",
      }),
    ).toEqual({
      status: "revoked",
      record: { ...refreshToken, accessDigest: rotation.accessDigest },
    });
  });

  it("rejects mismatched refresh bindings without consuming the token", async () => {
    const store = new InMemoryOAuthStore(1_700_000_000_000);
    await store.createRefreshToken(
      rotation.oldDigest,
      refreshToken,
      refreshTtlSeconds,
    );
    const mismatchedCallerInput: RotateRefreshTokenInput = {
      ...rotation,
      clientId: "wrong-client",
      resource: "https://wrong.example/mcp",
      scope: "wrong:scope",
    };

    expect(await store.rotateRefreshToken(mismatchedCallerInput)).toEqual({
      status: "binding_mismatch",
    });
    expect(await store.rotateRefreshToken(rotation)).toEqual({
      status: "rotated",
      record: refreshToken,
    });
  });

  it("persists the rotated access and refresh pair atomically", async () => {
    const store = new InMemoryOAuthStore(1_700_000_000_000);
    await store.createAccessToken(
      refreshToken.accessDigest,
      accessToken,
      rotation.accessTtlSeconds,
    );
    await store.createRefreshToken(
      rotation.oldDigest,
      refreshToken,
      refreshTtlSeconds,
    );

    expect(await store.rotateRefreshToken(rotation)).toEqual({
      status: "rotated",
      record: refreshToken,
    });
    expect(await store.getAccessToken(rotation.accessDigest)).toEqual({
      clientId: refreshToken.clientId,
      resource: refreshToken.resource,
      scope: refreshToken.scope,
      expiresAt: 1_700_000_900_000,
    });
    expect(await store.getAccessToken(refreshToken.accessDigest)).toBeNull();
  });

  it("leaves the old refresh usable when either successor digest collides", async () => {
    const store = new InMemoryOAuthStore(1_700_000_000_000);
    await store.createRefreshToken(
      rotation.oldDigest,
      refreshToken,
      refreshTtlSeconds,
    );
    await store.createAccessToken(rotation.accessDigest, accessToken, 900);

    expect(await store.rotateRefreshToken(rotation)).toEqual({
      status: "collision",
    });
    expect(
      await store.rotateRefreshToken({
        ...rotation,
        newDigest: "retry-refresh-digest",
        accessDigest: "retry-access-digest",
      }),
    ).toEqual({ status: "rotated", record: refreshToken });
  });

  it("allows only one concurrent refresh rotation and revokes its family on replay", async () => {
    const store = new InMemoryOAuthStore(1_700_000_000_000);
    await store.createRefreshToken(
      rotation.oldDigest,
      refreshToken,
      refreshTtlSeconds,
    );

    const results = await Promise.all([
      store.rotateRefreshToken(rotation),
      store.rotateRefreshToken({
        ...rotation,
        newDigest: "concurrent-refresh-digest",
        accessDigest: "concurrent-access-digest",
      }),
    ]);

    expect(results.map((result) => result.status).sort()).toEqual([
      "replayed",
      "rotated",
    ]);
    expect(await store.getAccessToken(rotation.accessDigest)).toEqual(
      accessToken,
    );
    expect(
      await store.rotateRefreshToken({
        ...rotation,
        oldDigest: rotation.newDigest,
        newDigest: "after-replay-refresh-digest",
        accessDigest: "after-replay-access-digest",
      }),
    ).toMatchObject({ status: "revoked" });
  });

  it("rejects a replacement digest already owned by a different family", async () => {
    const store = new InMemoryOAuthStore(1_700_000_000_000);
    const otherFamily = { ...refreshToken, familyId: "family-2" };
    await store.createRefreshToken(
      rotation.oldDigest,
      refreshToken,
      refreshTtlSeconds,
    );
    await store.createRefreshToken(
      rotation.newDigest,
      otherFamily,
      refreshTtlSeconds,
    );

    expect(await store.rotateRefreshToken(rotation)).toEqual({
      status: "collision",
    });
    expect(
      await store.rotateRefreshToken({
        ...rotation,
        oldDigest: rotation.oldDigest,
        newDigest: "family-1-replacement",
        accessDigest: "family-1-access",
      }),
    ).toEqual({ status: "rotated", record: refreshToken });
    expect(
      await store.rotateRefreshToken({
        ...rotation,
        oldDigest: rotation.newDigest,
        newDigest: "family-2-replacement",
        accessDigest: "family-2-access",
        clientId: otherFamily.clientId,
        resource: otherFamily.resource,
        scope: otherFamily.scope,
      }),
    ).toEqual({ status: "rotated", record: otherFamily });
  });

  it("keeps refresh replacements within the original family lifetime", async () => {
    const store = new InMemoryOAuthStore(1_700_000_000_000);
    await store.createRefreshToken(
      rotation.oldDigest,
      refreshToken,
      refreshTtlSeconds,
    );

    store.advanceBy(29 * 24 * 60 * 60 * 1_000);
    expect(await store.rotateRefreshToken(rotation)).toEqual({
      status: "rotated",
      record: refreshToken,
    });
    store.advanceBy(24 * 60 * 60 * 1_000);
    expect(
      await store.rotateRefreshToken({
        ...rotation,
        oldDigest: rotation.newDigest,
        newDigest: "third-digest",
        accessDigest: "third-access-digest",
      }),
    ).toEqual({ status: "missing" });
  });
});

type RedisCall =
  | { method: "set"; key: string; value: string; ttl?: number; nx?: boolean }
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
    options?: { EX: number; NX?: boolean },
  ): Promise<string | null> {
    if (options && (!Number.isInteger(options.EX) || options.EX <= 0)) {
      throw new Error("invalid SET expiry");
    }
    this.calls.push({
      method: "set",
      key,
      value,
      ...(options ? { ttl: options.EX } : {}),
      ...(options?.NX ? { nx: true } : {}),
    });
    if (options?.NX && this.values.has(key)) return null;
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
    if (options.keys.length === 0) {
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
    fake.evalReply = JSON.stringify({
      status: "rotated",
      record: refreshToken,
    });
    const store = redisStore(fake);

    expect(await store.rotateRefreshToken(rotation)).toEqual({
      status: "rotated",
      record: refreshToken,
    });
    expect(fake.calls).toEqual([
      {
        method: "eval",
        keys: [
          "refresh:old-digest",
          "refresh-used:old-digest",
          "refresh:new-digest",
          "access:rotated-access-digest",
        ],
        arguments: [
          "family-revoked:",
          "client-1",
          "https://service.example/mcp",
          "mcp:read",
          "900",
          "rotated-access-digest",
          "access:",
        ],
      },
    ]);
  });

  it("exchanges an authorization code and token pair in one Lua command", async () => {
    const fake = new StrictFakeRedisClient();
    fake.evalReply = JSON.stringify({
      status: "issued",
      record: authorizationCode,
    });
    const store = redisStore(fake);

    expect(await store.exchangeAuthorizationCode(codeExchange)).toEqual({
      status: "issued",
      record: authorizationCode,
    });
    expect(fake.calls).toEqual([
      {
        method: "eval",
        keys: [
          "code:code-exchange-digest",
          "access:code-access-digest",
          "refresh:code-refresh-digest",
        ],
        arguments: [
          "client-1",
          "https://client.example/callback",
          "https://service.example/mcp",
          "challenge-1",
          "mcp:read",
          "code-family-id",
          "900",
          String(refreshTtlSeconds),
          "code-access-digest",
        ],
      },
    ]);
  });

  it("issues the initial refresh token atomically with its fixed expiry", async () => {
    const fake = new StrictFakeRedisClient();
    const store = redisStore(fake);

    expect(
      await store.createRefreshToken(
        "initial-digest",
        refreshToken,
        refreshTtlSeconds,
      ),
    ).toBe(true);
    expect(
      await store.createRefreshToken(
        "initial-digest",
        refreshToken,
        refreshTtlSeconds,
      ),
    ).toBe(false);
    expect(fake.calls).toEqual([
      {
        method: "set",
        key: "refresh:initial-digest",
        value: JSON.stringify(refreshToken),
        ttl: refreshTtlSeconds,
        nx: true,
      },
      {
        method: "set",
        key: "refresh:initial-digest",
        value: JSON.stringify(refreshToken),
        ttl: refreshTtlSeconds,
        nx: true,
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

  it("reserves and releases multiple rate limits atomically in Lua", async () => {
    const fake = new StrictFakeRedisClient();
    fake.evalReply = 1;
    const store = redisStore(fake);

    expect(
      await store.reserveRateLimit(
        ["login:tx-1", "login:ip-1"],
        "reservation-1",
        5,
        900,
      ),
    ).toBe(true);
    await store.releaseRateLimit(["login:tx-1", "login:ip-1"], "reservation-1");
    expect(fake.calls).toEqual([
      {
        method: "eval",
        keys: ["rate-reservations:login:tx-1", "rate-reservations:login:ip-1"],
        arguments: ["reservation-1", "5", "900"],
      },
      {
        method: "eval",
        keys: ["rate-reservations:login:tx-1", "rate-reservations:login:ip-1"],
        arguments: ["reservation-1"],
      },
    ]);
  });
});
