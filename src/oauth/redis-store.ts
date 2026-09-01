import type { RedisClientType } from "redis";
import {
  CLIENT_REGISTRATION_RETENTION_SECONDS,
  MAX_ACTIVE_OAUTH_CLIENTS,
  type OAuthStore,
} from "./store.js";
import type {
  AccessTokenRecord,
  AuthorizationCodeRecord,
  AuthorizationTransaction,
  ExchangeAuthorizationCodeInput,
  ExchangeAuthorizationCodeResult,
  PromoteClientAndCreateAuthorizationCodeResult,
  RefreshTokenRecord,
  RegisteredClient,
  RotateRefreshTokenInput,
  RotateRefreshTokenResult,
} from "./types.js";

const THIRTY_DAYS_SECONDS = 30 * 24 * 60 * 60;

const REGISTER_CLIENT_SCRIPT = `
local redisTime = redis.call('TIME')
local nowMillis = tonumber(redisTime[1]) * 1000 + math.floor(tonumber(redisTime[2]) / 1000)
local retentionSeconds = tonumber(ARGV[2])
local retentionMillis = retentionSeconds * 1000

redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', nowMillis)
if redis.call('ZCARD', KEYS[1]) >= tonumber(ARGV[3]) then
  return 0
end

local stored = redis.pcall('SET', KEYS[2], ARGV[1], 'EX', retentionSeconds, 'NX')
if type(stored) == 'table' and stored.err then
  return -1
end
if not stored then
  return 0
end

local indexed = redis.pcall('ZADD', KEYS[1], nowMillis + retentionMillis, ARGV[4])
if type(indexed) == 'table' and indexed.err then
  redis.call('DEL', KEYS[2])
  return -1
end
if redis.call('PTTL', KEYS[1]) < retentionMillis then
  redis.call('PEXPIRE', KEYS[1], retentionMillis)
end
return 1
`;

const PROMOTE_CLIENT_AND_CREATE_CODE_SCRIPT = `
local function result(status)
  return status
end

local clientJson = redis.call('GET', KEYS[2])
if not clientJson then
  return result('missing')
end
if redis.call('EXISTS', KEYS[3]) == 1 then
  return result('collision')
end

local previousTtl = redis.call('PTTL', KEYS[2])
if previousTtl <= 0 then
  redis.call('DEL', KEYS[2])
  redis.call('ZREM', KEYS[1], ARGV[4])
  return result('missing')
end

local codeStored = redis.pcall('SET', KEYS[3], ARGV[1], 'EX', tonumber(ARGV[2]), 'NX')
if type(codeStored) == 'table' and codeStored.err then
  return result('storage_error')
end
if not codeStored then
  return result('collision')
end

local promoted = redis.pcall('SET', KEYS[2], clientJson, 'EX', tonumber(ARGV[3]))
if type(promoted) == 'table' and promoted.err then
  redis.call('DEL', KEYS[3])
  return result('storage_error')
end

local redisTime = redis.call('TIME')
local nowMillis = tonumber(redisTime[1]) * 1000 + math.floor(tonumber(redisTime[2]) / 1000)
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', nowMillis)
local indexed = redis.pcall('ZADD', KEYS[1], nowMillis + tonumber(ARGV[3]) * 1000, ARGV[4])
if type(indexed) == 'table' and indexed.err then
  redis.call('SET', KEYS[2], clientJson, 'PX', previousTtl)
  redis.call('ZADD', KEYS[1], nowMillis + previousTtl, ARGV[4])
  redis.call('DEL', KEYS[3])
  return result('storage_error')
end
if redis.call('PTTL', KEYS[1]) < tonumber(ARGV[3]) * 1000 then
  redis.call('PEXPIRE', KEYS[1], tonumber(ARGV[3]) * 1000)
end
return result('promoted')
`;

const EXCHANGE_AUTHORIZATION_CODE_SCRIPT = `
local function result(status, record)
  if record then
    return cjson.encode({ status = status, record = record })
  end
  return cjson.encode({ status = status })
end

local function fixedTimeChallengeMatch(left, right)
  if type(left) ~= 'string' or type(right) ~= 'string' then
    return false
  end
  local difference = bit.bxor(string.len(left), string.len(right))
  for index = 1, 43 do
    difference = bit.bor(
      difference,
      bit.bxor(string.byte(left, index) or 0, string.byte(right, index) or 0)
    )
  end
  return difference == 0
end

local codeRecordJson = redis.call('GET', KEYS[1])
if not codeRecordJson then
  return result('missing')
end
if redis.call('EXISTS', KEYS[2]) == 1 or redis.call('EXISTS', KEYS[3]) == 1 then
  return result('collision')
end

local codeRecord = cjson.decode(codeRecordJson)
if codeRecord.clientId ~= ARGV[1]
  or codeRecord.redirectUri ~= ARGV[2]
  or codeRecord.resource ~= ARGV[3]
  or not fixedTimeChallengeMatch(codeRecord.codeChallenge, ARGV[4])
  or codeRecord.scope ~= ARGV[5] then
  redis.call('DEL', KEYS[1])
  return result('binding_mismatch')
end

local redisTime = redis.call('TIME')
local nowMillis = tonumber(redisTime[1]) * 1000 + math.floor(tonumber(redisTime[2]) / 1000)
local accessTtlMillis = tonumber(ARGV[7]) * 1000
local refreshTtlMillis = tonumber(ARGV[8]) * 1000
local accessRecordJson = cjson.encode({
  clientId = codeRecord.clientId,
  resource = codeRecord.resource,
  scope = codeRecord.scope,
  expiresAt = nowMillis + accessTtlMillis
})
local refreshRecordJson = cjson.encode({
  familyId = ARGV[6],
  accessDigest = ARGV[9],
  clientId = codeRecord.clientId,
  resource = codeRecord.resource,
  scope = codeRecord.scope,
  expiresAt = nowMillis + refreshTtlMillis
})

local writeResult = redis.pcall('MSET', KEYS[2], accessRecordJson, KEYS[3], refreshRecordJson)
if type(writeResult) == 'table' and writeResult.err then
  return result('storage_error')
end
local accessExpiry = redis.pcall('PEXPIRE', KEYS[2], accessTtlMillis)
local refreshExpiry = redis.pcall('PEXPIRE', KEYS[3], refreshTtlMillis)
if accessExpiry ~= 1 or refreshExpiry ~= 1 then
  redis.call('DEL', KEYS[2], KEYS[3])
  return result('storage_error')
end
redis.call('DEL', KEYS[1])
return result('issued', codeRecord)
`;

const ROTATE_REFRESH_TOKEN_SCRIPT = `
local function result(status, record)
  if record then
    return cjson.encode({ status = status, record = record })
  end
  return cjson.encode({ status = status })
end

local function bindingsMatch(record)
  return record.clientId == ARGV[2]
    and record.resource == ARGV[3]
    and record.scope == ARGV[4]
end

local oldRecordJson = redis.call('GET', KEYS[1])
if not oldRecordJson then
  local usedRecordJson = redis.call('GET', KEYS[2])
  if not usedRecordJson then
    return result('missing')
  end

  local usedRecord = cjson.decode(usedRecordJson)
  if not bindingsMatch(usedRecord) then
    return result('binding_mismatch')
  end
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

  local revoked = redis.pcall('SET', revocationKey, '1', 'PX', math.floor(remainingMillis))
  if type(revoked) == 'table' and revoked.err then
    return result('storage_error')
  end
  return result('replayed', usedRecord)
end

local oldRecord = cjson.decode(oldRecordJson)
if not bindingsMatch(oldRecord) then
  return result('binding_mismatch')
end
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

if redis.call('EXISTS', KEYS[2]) == 1
  or redis.call('EXISTS', KEYS[3]) == 1
  or redis.call('EXISTS', KEYS[4]) == 1 then
  return result('collision')
end

local accessTtlMillis = tonumber(ARGV[5]) * 1000
local accessRecordJson = cjson.encode({
  clientId = oldRecord.clientId,
  resource = oldRecord.resource,
  scope = oldRecord.scope,
  expiresAt = nowMillis + accessTtlMillis
})
local newRefreshRecordJson = cjson.encode({
  familyId = oldRecord.familyId,
  accessDigest = ARGV[6],
  clientId = oldRecord.clientId,
  resource = oldRecord.resource,
  scope = oldRecord.scope,
  expiresAt = oldRecord.expiresAt
})

local writeResult = redis.pcall(
  'MSET',
  KEYS[2], oldRecordJson,
  KEYS[3], newRefreshRecordJson,
  KEYS[4], accessRecordJson
)
if type(writeResult) == 'table' and writeResult.err then
  return result('storage_error')
end
local usedExpiry = redis.pcall('PEXPIRE', KEYS[2], math.floor(remainingMillis))
local refreshExpiry = redis.pcall('PEXPIRE', KEYS[3], math.floor(remainingMillis))
local accessExpiry = redis.pcall('PEXPIRE', KEYS[4], accessTtlMillis)
if usedExpiry ~= 1 or refreshExpiry ~= 1 or accessExpiry ~= 1 then
  redis.call('DEL', KEYS[2], KEYS[3], KEYS[4])
  return result('storage_error')
end
redis.call('DEL', KEYS[1], ARGV[7] .. oldRecord.accessDigest)
return result('rotated', oldRecord)
`;

const INCREMENT_RATE_LIMIT_SCRIPT = `
local current = redis.call('INCR', KEYS[1])
if current == 1 then
  redis.call('EXPIRE', KEYS[1], ARGV[1])
end
return current
`;

const RESERVE_RATE_LIMIT_SCRIPT = `
local redisTime = redis.call('TIME')
local nowMillis = tonumber(redisTime[1]) * 1000 + math.floor(tonumber(redisTime[2]) / 1000)
local reservationId = ARGV[1]
local limit = tonumber(ARGV[2])
local ttlMillis = tonumber(ARGV[3]) * 1000

for _, key in ipairs(KEYS) do
  redis.call('ZREMRANGEBYSCORE', key, '-inf', nowMillis)
  if redis.call('ZCARD', key) >= limit then
    return 0
  end
end

for _, key in ipairs(KEYS) do
  redis.call('ZADD', key, nowMillis + ttlMillis, reservationId)
  redis.call('PEXPIRE', key, ttlMillis)
end
return 1
`;

const RELEASE_RATE_LIMIT_SCRIPT = `
local reservationId = ARGV[1]
for _, key in ipairs(KEYS) do
  redis.call('ZREM', key, reservationId)
  if redis.call('ZCARD', key) == 0 then
    redis.call('DEL', key)
  end
end
return 1
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

function assertClientRegistration(
  retentionSeconds: number,
  maxActiveClients: number,
): void {
  assertTtl(retentionSeconds);
  if (
    !Number.isSafeInteger(maxActiveClients) ||
    maxActiveClients <= 0 ||
    maxActiveClients > MAX_ACTIVE_OAUTH_CLIENTS
  ) {
    throw new RangeError("OAuth client cap is outside the allowed range");
  }
}

function assertRateLimitReservation(
  keys: readonly string[],
  reservationId: string,
  limit?: number,
): void {
  if (
    keys.length === 0 ||
    keys.length > 10 ||
    new Set(keys).size !== keys.length ||
    keys.some((key) => key.length === 0 || key.length > 512) ||
    reservationId.length === 0 ||
    reservationId.length > 128 ||
    (limit !== undefined && (!Number.isSafeInteger(limit) || limit <= 0))
  ) {
    throw new RangeError("OAuth rate-limit reservation is invalid");
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
    typeof record.accessDigest === "string" &&
    typeof record.clientId === "string" &&
    typeof record.resource === "string" &&
    typeof record.scope === "string" &&
    typeof record.expiresAt === "number" &&
    Number.isSafeInteger(record.expiresAt)
  );
}

function isAuthorizationCodeRecord(
  value: unknown,
): value is AuthorizationCodeRecord {
  if (typeof value !== "object" || value === null) return false;
  const record = value as Record<string, unknown>;
  return (
    typeof record.clientId === "string" &&
    typeof record.redirectUri === "string" &&
    typeof record.resource === "string" &&
    typeof record.codeChallenge === "string" &&
    typeof record.scope === "string"
  );
}

function parseCodeExchangeResult(
  value: unknown,
): ExchangeAuthorizationCodeResult {
  if (typeof value !== "string") {
    throw new Error("Unexpected OAuth code exchange result");
  }
  const parsed = JSON.parse(value) as unknown;
  if (typeof parsed !== "object" || parsed === null) {
    throw new Error("Unexpected OAuth code exchange result");
  }
  const result = parsed as Record<string, unknown>;
  if (
    result.status === "missing" ||
    result.status === "binding_mismatch" ||
    result.status === "collision" ||
    result.status === "storage_error"
  ) {
    return { status: result.status };
  }
  if (result.status === "issued" && isAuthorizationCodeRecord(result.record)) {
    return { status: "issued", record: result.record };
  }
  throw new Error("Unexpected OAuth code exchange result");
}

function parsePromotionResult(
  value: unknown,
): PromoteClientAndCreateAuthorizationCodeResult {
  if (
    value === "promoted" ||
    value === "missing" ||
    value === "collision" ||
    value === "storage_error"
  ) {
    return { status: value };
  }
  throw new Error("Unexpected OAuth client promotion result");
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
  if (result.status === "binding_mismatch") {
    return { status: "binding_mismatch" };
  }
  if (result.status === "collision") return { status: "collision" };
  if (result.status === "storage_error") return { status: "storage_error" };
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

  async registerClient(
    client: RegisteredClient,
    retentionSeconds = CLIENT_REGISTRATION_RETENTION_SECONDS,
    maxActiveClients = MAX_ACTIVE_OAUTH_CLIENTS,
  ): Promise<boolean> {
    assertClientRegistration(retentionSeconds, maxActiveClients);
    const result = await this.client.eval(REGISTER_CLIENT_SCRIPT, {
      keys: ["client-active", `client:${client.clientId}`],
      arguments: [
        serialize(client),
        String(retentionSeconds),
        String(maxActiveClients),
        client.clientId,
      ],
    });
    if (result !== 0 && result !== 1) {
      throw new Error("Unexpected OAuth client registration result");
    }
    return result === 1;
  }

  async getClient(clientId: string): Promise<RegisteredClient | null> {
    return deserialize<RegisteredClient>(
      await this.client.get(`client:${clientId}`),
    );
  }

  async promoteClientAndCreateAuthorizationCode(
    digest: string,
    value: AuthorizationCodeRecord,
    codeTtlSeconds: number,
  ): Promise<PromoteClientAndCreateAuthorizationCodeResult> {
    assertTtl(codeTtlSeconds);
    const result = await this.client.eval(
      PROMOTE_CLIENT_AND_CREATE_CODE_SCRIPT,
      {
        keys: ["client-active", `client:${value.clientId}`, `code:${digest}`],
        arguments: [
          serialize(value),
          String(codeTtlSeconds),
          String(CLIENT_REGISTRATION_RETENTION_SECONDS),
          value.clientId,
        ],
      },
    );
    return parsePromotionResult(result);
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

  async exchangeAuthorizationCode(
    input: ExchangeAuthorizationCodeInput,
  ): Promise<ExchangeAuthorizationCodeResult> {
    assertTtl(input.accessTtlSeconds);
    assertTtl(input.refreshTtlSeconds);
    const result = await this.client.eval(EXCHANGE_AUTHORIZATION_CODE_SCRIPT, {
      keys: [
        `code:${input.codeDigest}`,
        `access:${input.accessDigest}`,
        `refresh:${input.refreshDigest}`,
      ],
      arguments: [
        input.clientId,
        input.redirectUri,
        input.resource,
        input.codeChallenge,
        input.scope,
        input.familyId,
        String(input.accessTtlSeconds),
        String(input.refreshTtlSeconds),
        input.accessDigest,
      ],
    });
    return parseCodeExchangeResult(result);
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
    assertTtl(input.accessTtlSeconds);
    const result = await this.client.eval(ROTATE_REFRESH_TOKEN_SCRIPT, {
      keys: [
        `refresh:${input.oldDigest}`,
        `refresh-used:${input.oldDigest}`,
        `refresh:${input.newDigest}`,
        `access:${input.accessDigest}`,
      ],
      arguments: [
        "family-revoked:",
        input.clientId,
        input.resource,
        input.scope,
        String(input.accessTtlSeconds),
        input.accessDigest,
        "access:",
      ],
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

  async reserveRateLimit(
    keys: readonly string[],
    reservationId: string,
    limit: number,
    ttlSeconds: number,
  ): Promise<boolean> {
    assertRateLimitReservation(keys, reservationId, limit);
    assertTtl(ttlSeconds);
    const result = await this.client.eval(RESERVE_RATE_LIMIT_SCRIPT, {
      keys: keys.map((key) => `rate-reservations:${key}`),
      arguments: [reservationId, String(limit), String(ttlSeconds)],
    });
    if (result !== 0 && result !== 1) {
      throw new Error("Unexpected OAuth rate-limit reservation result");
    }
    return result === 1;
  }

  async releaseRateLimit(
    keys: readonly string[],
    reservationId: string,
  ): Promise<void> {
    assertRateLimitReservation(keys, reservationId);
    const result = await this.client.eval(RELEASE_RATE_LIMIT_SCRIPT, {
      keys: keys.map((key) => `rate-reservations:${key}`),
      arguments: [reservationId],
    });
    if (result !== 1) {
      throw new Error("Unexpected OAuth rate-limit release result");
    }
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
