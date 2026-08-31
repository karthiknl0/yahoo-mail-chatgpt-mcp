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
if redis.call('EXISTS', KEYS[4]) == 1 then
  return 'revoked'
end

local oldRecordJson = redis.call('GET', KEYS[1])
if not oldRecordJson then
  local usedFamilyId = redis.call('GET', KEYS[2])
  if not usedFamilyId then
    return 'missing'
  end
  if usedFamilyId ~= ARGV[4] then
    return 'missing'
  end
  redis.call('SET', KEYS[4], '1', 'EX', ARGV[3])
  return 'replayed'
end

local oldRecord = cjson.decode(oldRecordJson)
local newRecord = cjson.decode(ARGV[1])
if oldRecord.familyId ~= newRecord.familyId
  or oldRecord.clientId ~= newRecord.clientId
  or oldRecord.resource ~= newRecord.resource
  or oldRecord.scope ~= newRecord.scope then
  return 'missing'
end

redis.call('DEL', KEYS[1])
redis.call('SET', KEYS[2], ARGV[4], 'EX', ARGV[3])
redis.call('SET', KEYS[3], ARGV[1], 'EX', ARGV[2])
return 'rotated'
`;

const INCREMENT_RATE_LIMIT_SCRIPT = `
local current = redis.call('INCR', KEYS[1])
if current == 1 then
  redis.call('EXPIRE', KEYS[1], ARGV[1])
end
return current
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

function refreshRecord(
  input: RotateRefreshTokenInput,
  now: number,
): RefreshTokenRecord {
  return {
    familyId: input.familyId,
    clientId: input.clientId,
    resource: input.resource,
    scope: input.scope,
    expiresAt: now + input.refreshTtlSeconds * 1_000,
  };
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

  async rotateRefreshToken(
    input: RotateRefreshTokenInput,
  ): Promise<RotateRefreshTokenResult> {
    assertTtl(input.refreshTtlSeconds);
    assertTtl(input.familyTtlSeconds);
    const nextRecord = refreshRecord(input, this.now());
    const result = await this.client.eval(ROTATE_REFRESH_TOKEN_SCRIPT, {
      keys: [
        `refresh:${input.oldDigest}`,
        `refresh-used:${input.oldDigest}`,
        `refresh:${input.newDigest}`,
        `family-revoked:${input.familyId}`,
      ],
      arguments: [
        serialize(nextRecord),
        String(input.refreshTtlSeconds),
        String(input.familyTtlSeconds),
        input.familyId,
      ],
    });

    if (
      result === "rotated" ||
      result === "missing" ||
      result === "replayed" ||
      result === "revoked"
    ) {
      return result;
    }
    throw new Error("Unexpected OAuth refresh rotation result");
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
