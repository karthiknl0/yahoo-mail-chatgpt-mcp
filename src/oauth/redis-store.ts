import type { RedisClientType } from "redis";
import type { OAuthStore } from "./store.js";
import type {
  AccessTokenRecord,
  AuthorizationCodeRecord,
  AuthorizationTransaction,
  RefreshTokenRecord,
  RegisteredClient,
  RotateRefreshTokenInput,
  RotateRefreshTokenResult,
} from "./types.js";

const THIRTY_DAYS_SECONDS = 30 * 24 * 60 * 60;

const ROTATE_REFRESH_TOKEN_SCRIPT = `
local function result(status, record)
  if record then
    return cjson.encode({ status = status, record = record })
  end
  return cjson.encode({ status = status })
end

local oldRecordJson = redis.call('GET', KEYS[1])
if not oldRecordJson then
  local usedRecordJson = redis.call('GET', KEYS[2])
  if not usedRecordJson then
    return result('missing')
  end

  local usedRecord = cjson.decode(usedRecordJson)
  local revocationKey = ARGV[1] .. usedRecord.familyId
  if redis.call('EXISTS', revocationKey) == 1 then
    return result('revoked', usedRecord)
  end

  local redisTime = redis.call('TIME')
  local nowMillis = tonumber(redisTime[1]) * 1000 + math.floor(tonumber(redisTime[2]) / 1000)
  local remainingMillis = math.min(
    tonumber(usedRecord.expiresAt) - nowMillis,
    redis.call('PTTL', KEYS[2])
  )
  if remainingMillis <= 0 then
    redis.call('DEL', KEYS[2])
    return result('missing')
  end

  redis.call('SET', revocationKey, '1', 'PX', math.floor(remainingMillis))
  return result('replayed', usedRecord)
end

local oldRecord = cjson.decode(oldRecordJson)
local revocationKey = ARGV[1] .. oldRecord.familyId
if redis.call('EXISTS', revocationKey) == 1 then
  return result('revoked', oldRecord)
end

local redisTime = redis.call('TIME')
local nowMillis = tonumber(redisTime[1]) * 1000 + math.floor(tonumber(redisTime[2]) / 1000)
local remainingMillis = math.min(
  tonumber(oldRecord.expiresAt) - nowMillis,
  redis.call('PTTL', KEYS[1])
)
if remainingMillis <= 0 then
  redis.call('DEL', KEYS[1])
  return result('missing')
end

local created = redis.call(
  'SET',
  KEYS[3],
  oldRecordJson,
  'PX',
  math.floor(remainingMillis),
  'NX'
)
if not created then
  return result('missing')
end

redis.call('DEL', KEYS[1])
redis.call('SET', KEYS[2], oldRecordJson, 'PX', math.floor(remainingMillis))
return result('rotated', oldRecord)
`;

const INCREMENT_RATE_LIMIT_SCRIPT = `
local current = redis.call('INCR', KEYS[1])
if current == 1 then
  redis.call('EXPIRE', KEYS[1], ARGV[1])
end
return current
`;

const IS_RATE_LIMITED_SCRIPT = `
local limit = tonumber(ARGV[1])
for _, key in ipairs(KEYS) do
  local current = tonumber(redis.call('GET', key) or '0')
  if current >= limit then
    return 1
  end
end
return 0
`;

function serialize(value: object): string {
  return JSON.stringify(value);
}

function deserialize<T>(value: string | null): T | null {
  return value === null ? null : (JSON.parse(value) as T);
}

function assertTtl(ttlSeconds: number, maximum = THIRTY_DAYS_SECONDS): void {
  if (
    !Number.isSafeInteger(ttlSeconds) ||
    ttlSeconds <= 0 ||
    ttlSeconds > maximum
  ) {
    throw new RangeError("OAuth store TTL is outside the allowed range");
  }
}

function boundedRefreshRecord(
  value: RefreshTokenRecord,
  ttlSeconds: number,
  now: number,
): { record: RefreshTokenRecord; ttlSeconds: number } | null {
  assertTtl(ttlSeconds);
  if (!Number.isSafeInteger(value.expiresAt)) return null;
  const expiresAt = Math.min(value.expiresAt, now + ttlSeconds * 1_000);
  const remainingSeconds = Math.floor((expiresAt - now) / 1_000);
  if (remainingSeconds <= 0) return null;
  return {
    record: { ...value, expiresAt },
    ttlSeconds: remainingSeconds,
  };
}

function isRefreshTokenRecord(value: unknown): value is RefreshTokenRecord {
  if (typeof value !== "object" || value === null) return false;
  const record = value as Record<string, unknown>;
  return (
    typeof record.familyId === "string" &&
    typeof record.clientId === "string" &&
    typeof record.resource === "string" &&
    typeof record.scope === "string" &&
    typeof record.expiresAt === "number" &&
    Number.isSafeInteger(record.expiresAt)
  );
}

function parseRotationResult(value: unknown): RotateRefreshTokenResult {
  if (typeof value !== "string") {
    throw new Error("Unexpected OAuth refresh rotation result");
  }
  const parsed = JSON.parse(value) as unknown;
  if (typeof parsed !== "object" || parsed === null) {
    throw new Error("Unexpected OAuth refresh rotation result");
  }
  const result = parsed as Record<string, unknown>;
  if (result.status === "missing") return { status: "missing" };
  if (
    (result.status === "rotated" ||
      result.status === "replayed" ||
      result.status === "revoked") &&
    isRefreshTokenRecord(result.record)
  ) {
    return { status: result.status, record: result.record };
  }
  throw new Error("Unexpected OAuth refresh rotation result");
}

export class RedisOAuthStore implements OAuthStore {
  constructor(
    private readonly client: RedisClientType,
    private readonly now: () => number = Date.now,
  ) {}

  async registerClient(client: RegisteredClient): Promise<void> {
    await this.client.set(`client:${client.clientId}`, serialize(client));
  }

  async getClient(clientId: string): Promise<RegisteredClient | null> {
    return deserialize<RegisteredClient>(
      await this.client.get(`client:${clientId}`),
    );
  }

  async createTransaction(
    id: string,
    value: AuthorizationTransaction,
    ttlSeconds: number,
  ): Promise<void> {
    await this.setExpiring(`tx:${id}`, value, ttlSeconds);
  }

  async consumeTransaction(
    id: string,
  ): Promise<AuthorizationTransaction | null> {
    return deserialize<AuthorizationTransaction>(
      await this.client.getDel(`tx:${id}`),
    );
  }

  async createAuthorizationCode(
    digest: string,
    value: AuthorizationCodeRecord,
    ttlSeconds: number,
  ): Promise<void> {
    await this.setExpiring(`code:${digest}`, value, ttlSeconds);
  }

  async consumeAuthorizationCode(
    digest: string,
  ): Promise<AuthorizationCodeRecord | null> {
    return deserialize<AuthorizationCodeRecord>(
      await this.client.getDel(`code:${digest}`),
    );
  }

  async createAccessToken(
    digest: string,
    value: AccessTokenRecord,
    ttlSeconds: number,
  ): Promise<void> {
    await this.setExpiring(`access:${digest}`, value, ttlSeconds);
  }

  async getAccessToken(digest: string): Promise<AccessTokenRecord | null> {
    return deserialize<AccessTokenRecord>(
      await this.client.get(`access:${digest}`),
    );
  }

  async createRefreshToken(
    digest: string,
    value: RefreshTokenRecord,
    ttlSeconds: number,
  ): Promise<boolean> {
    const bounded = boundedRefreshRecord(value, ttlSeconds, this.now());
    if (!bounded) return false;
    const result = await this.client.set(
      `refresh:${digest}`,
      serialize(bounded.record),
      { EX: bounded.ttlSeconds, NX: true },
    );
    return result === "OK";
  }

  async rotateRefreshToken(
    input: RotateRefreshTokenInput,
  ): Promise<RotateRefreshTokenResult> {
    const result = await this.client.eval(ROTATE_REFRESH_TOKEN_SCRIPT, {
      keys: [
        `refresh:${input.oldDigest}`,
        `refresh-used:${input.oldDigest}`,
        `refresh:${input.newDigest}`,
      ],
      arguments: ["family-revoked:"],
    });
    return parseRotationResult(result);
  }

  async incrementRateLimit(key: string, ttlSeconds: number): Promise<number> {
    assertTtl(ttlSeconds);
    const result = await this.client.eval(INCREMENT_RATE_LIMIT_SCRIPT, {
      keys: [`rate:${key}`],
      arguments: [String(ttlSeconds)],
    });
    if (typeof result !== "number" || !Number.isSafeInteger(result)) {
      throw new Error("Unexpected OAuth rate-limit result");
    }
    return result;
  }

  async isRateLimited(
    keys: readonly string[],
    limit: number,
  ): Promise<boolean> {
    if (
      keys.length === 0 ||
      keys.length > 10 ||
      !Number.isSafeInteger(limit) ||
      limit <= 0
    ) {
      throw new RangeError(
        "OAuth rate-limit check is outside the allowed range",
      );
    }
    const result = await this.client.eval(IS_RATE_LIMITED_SCRIPT, {
      keys: keys.map((key) => `rate:${key}`),
      arguments: [String(limit)],
    });
    if (result !== 0 && result !== 1) {
      throw new Error("Unexpected OAuth rate-limit check result");
    }
    return result === 1;
  }

  async close(): Promise<void> {
    await this.client.quit();
  }

  private async setExpiring(
    key: string,
    value: object,
    ttlSeconds: number,
  ): Promise<void> {
    assertTtl(ttlSeconds);
    await this.client.set(key, serialize(value), { EX: ttlSeconds });
  }
}
