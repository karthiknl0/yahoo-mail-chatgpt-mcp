import {
  CLIENT_REGISTRATION_RETENTION_SECONDS,
  MAX_ACTIVE_OAUTH_CLIENTS,
  type OAuthStore,
} from "../../src/oauth/store.js";
import type {
  AccessTokenRecord,
  AuthorizationCodeRecord,
  AuthorizationTransaction,
  ExchangeAuthorizationCodeInput,
  ExchangeAuthorizationCodeResult,
  RefreshTokenRecord,
  RegisteredClient,
  RotateRefreshTokenInput,
  RotateRefreshTokenResult,
} from "../../src/oauth/types.js";

interface ExpiringValue<T> {
  value: T;
  expiresAt: number;
}

export class InMemoryOAuthStore implements OAuthStore {
  private readonly clients = new Map<string, ExpiringValue<RegisteredClient>>();
  private readonly transactions = new Map<
    string,
    ExpiringValue<AuthorizationTransaction>
  >();
  private readonly authorizationCodes = new Map<
    string,
    ExpiringValue<AuthorizationCodeRecord>
  >();
  private readonly accessTokens = new Map<
    string,
    ExpiringValue<AccessTokenRecord>
  >();
  private readonly refreshTokens = new Map<
    string,
    ExpiringValue<RefreshTokenRecord>
  >();
  private readonly usedRefreshTokens = new Map<
    string,
    ExpiringValue<RefreshTokenRecord>
  >();
  private readonly revokedFamilies = new Map<string, number>();
  private readonly rateLimits = new Map<string, ExpiringValue<number>>();
  private readonly rateLimitReservations = new Map<
    string,
    Map<string, number>
  >();
  private currentTime: number;
  private failNextPairWrite = false;

  constructor(now = Date.now()) {
    this.currentTime = now;
  }

  advanceBy(milliseconds: number): void {
    this.currentTime += milliseconds;
  }

  failNextTokenPairWrite(): void {
    this.failNextPairWrite = true;
  }

  async seedRefreshToken(
    digest: string,
    value: RefreshTokenRecord,
    ttlSeconds: number,
  ): Promise<void> {
    await this.createRefreshToken(digest, value, ttlSeconds);
  }

  async registerClient(
    client: RegisteredClient,
    retentionSeconds = CLIENT_REGISTRATION_RETENTION_SECONDS,
    maxActiveClients = MAX_ACTIVE_OAUTH_CLIENTS,
  ): Promise<boolean> {
    if (
      !Number.isSafeInteger(retentionSeconds) ||
      retentionSeconds <= 0 ||
      retentionSeconds > 30 * 24 * 60 * 60 ||
      !Number.isSafeInteger(maxActiveClients) ||
      maxActiveClients <= 0 ||
      maxActiveClients > MAX_ACTIVE_OAUTH_CLIENTS
    ) {
      throw new RangeError("OAuth client registration is invalid");
    }
    if (this.read(this.clients, client.clientId)) return false;
    if (this.activeClientCount() >= maxActiveClients) return false;
    this.clients.set(client.clientId, this.expiring(client, retentionSeconds));
    return true;
  }

  async getClient(clientId: string): Promise<RegisteredClient | null> {
    return this.read(this.clients, clientId);
  }

  async createTransaction(
    id: string,
    value: AuthorizationTransaction,
    ttlSeconds: number,
  ): Promise<void> {
    this.transactions.set(id, this.expiring(value, ttlSeconds));
  }

  async consumeTransaction(
    id: string,
  ): Promise<AuthorizationTransaction | null> {
    return this.consume(this.transactions, id);
  }

  async createAuthorizationCode(
    digest: string,
    value: AuthorizationCodeRecord,
    ttlSeconds: number,
  ): Promise<void> {
    this.authorizationCodes.set(digest, this.expiring(value, ttlSeconds));
  }

  async consumeAuthorizationCode(
    digest: string,
  ): Promise<AuthorizationCodeRecord | null> {
    return this.consume(this.authorizationCodes, digest);
  }

  async exchangeAuthorizationCode(
    input: ExchangeAuthorizationCodeInput,
  ): Promise<ExchangeAuthorizationCodeResult> {
    const record = this.read(this.authorizationCodes, input.codeDigest);
    if (!record) return { status: "missing" };
    if (
      this.read(this.accessTokens, input.accessDigest) ||
      this.read(this.refreshTokens, input.refreshDigest)
    ) {
      return { status: "collision" };
    }

    const bindingMismatch =
      record.clientId !== input.clientId ||
      record.redirectUri !== input.redirectUri ||
      record.resource !== input.resource ||
      record.codeChallenge !== input.codeChallenge ||
      record.scope !== input.scope;
    if (bindingMismatch) {
      this.authorizationCodes.delete(input.codeDigest);
      return { status: "binding_mismatch" };
    }

    if (this.consumePairWriteFailure()) return { status: "storage_error" };
    this.authorizationCodes.delete(input.codeDigest);
    const accessRecord: AccessTokenRecord = {
      clientId: record.clientId,
      resource: record.resource,
      scope: record.scope,
      expiresAt: this.currentTime + input.accessTtlSeconds * 1_000,
    };
    const refreshRecord: RefreshTokenRecord = {
      familyId: input.familyId,
      accessDigest: input.accessDigest,
      clientId: record.clientId,
      resource: record.resource,
      scope: record.scope,
      expiresAt: this.currentTime + input.refreshTtlSeconds * 1_000,
    };
    this.accessTokens.set(input.accessDigest, {
      value: accessRecord,
      expiresAt: accessRecord.expiresAt,
    });
    this.refreshTokens.set(input.refreshDigest, {
      value: refreshRecord,
      expiresAt: refreshRecord.expiresAt,
    });
    return { status: "issued", record };
  }

  async createAccessToken(
    digest: string,
    value: AccessTokenRecord,
    ttlSeconds: number,
  ): Promise<void> {
    this.accessTokens.set(digest, this.expiring(value, ttlSeconds));
  }

  async getAccessToken(digest: string): Promise<AccessTokenRecord | null> {
    return this.read(this.accessTokens, digest);
  }

  async createRefreshToken(
    digest: string,
    value: RefreshTokenRecord,
    ttlSeconds: number,
  ): Promise<boolean> {
    if (this.read(this.refreshTokens, digest)) return false;
    const expiresAt = Math.min(
      value.expiresAt,
      this.currentTime + ttlSeconds * 1_000,
    );
    if (expiresAt <= this.currentTime) return false;
    this.refreshTokens.set(digest, {
      value: structuredClone({ ...value, expiresAt }),
      expiresAt,
    });
    return true;
  }

  async rotateRefreshToken(
    input: RotateRefreshTokenInput,
  ): Promise<RotateRefreshTokenResult> {
    const oldRecord = this.read(this.refreshTokens, input.oldDigest);
    if (!oldRecord) {
      const usedRecord = this.read(this.usedRefreshTokens, input.oldDigest);
      if (!usedRecord) return { status: "missing" };
      if (!this.matchesRefreshBindings(usedRecord, input)) {
        return { status: "binding_mismatch" };
      }
      if (this.isFamilyRevoked(usedRecord.familyId)) {
        return { status: "revoked", record: usedRecord };
      }
      this.revokedFamilies.set(usedRecord.familyId, usedRecord.expiresAt);
      return { status: "replayed", record: usedRecord };
    }

    if (!this.matchesRefreshBindings(oldRecord, input)) {
      return { status: "binding_mismatch" };
    }
    if (this.isFamilyRevoked(oldRecord.familyId)) {
      return { status: "revoked", record: oldRecord };
    }
    if (
      this.read(this.usedRefreshTokens, input.oldDigest) ||
      this.read(this.refreshTokens, input.newDigest) ||
      this.read(this.accessTokens, input.accessDigest)
    ) {
      return { status: "collision" };
    }

    if (this.consumePairWriteFailure()) return { status: "storage_error" };
    const accessRecord: AccessTokenRecord = {
      clientId: oldRecord.clientId,
      resource: oldRecord.resource,
      scope: oldRecord.scope,
      expiresAt: this.currentTime + input.accessTtlSeconds * 1_000,
    };
    const newRefreshRecord: RefreshTokenRecord = {
      ...oldRecord,
      accessDigest: input.accessDigest,
    };
    this.refreshTokens.delete(input.oldDigest);
    this.accessTokens.delete(oldRecord.accessDigest);
    this.usedRefreshTokens.set(input.oldDigest, {
      value: structuredClone(oldRecord),
      expiresAt: oldRecord.expiresAt,
    });
    this.refreshTokens.set(input.newDigest, {
      value: structuredClone(newRefreshRecord),
      expiresAt: oldRecord.expiresAt,
    });
    this.accessTokens.set(input.accessDigest, {
      value: accessRecord,
      expiresAt: accessRecord.expiresAt,
    });
    return { status: "rotated", record: oldRecord };
  }

  async incrementRateLimit(key: string, ttlSeconds: number): Promise<number> {
    const existing = this.read(this.rateLimits, key) ?? 0;
    const next = existing + 1;
    const current = this.rateLimits.get(key);
    const expiresAt =
      current && current.expiresAt > this.currentTime
        ? current.expiresAt
        : this.currentTime + ttlSeconds * 1_000;
    this.rateLimits.set(key, { value: next, expiresAt });
    return next;
  }

  async reserveRateLimit(
    keys: readonly string[],
    reservationId: string,
    limit: number,
    ttlSeconds: number,
  ): Promise<boolean> {
    if (
      keys.length === 0 ||
      keys.length > 10 ||
      new Set(keys).size !== keys.length ||
      keys.some((key) => key.length === 0 || key.length > 512) ||
      reservationId.length === 0 ||
      reservationId.length > 128 ||
      !Number.isSafeInteger(limit) ||
      limit <= 0 ||
      !Number.isSafeInteger(ttlSeconds) ||
      ttlSeconds <= 0 ||
      ttlSeconds > 30 * 24 * 60 * 60
    ) {
      throw new RangeError("OAuth rate-limit reservation is invalid");
    }
    const buckets = keys.map((key) => this.activeReservations(key));
    if (buckets.some((bucket) => bucket.size >= limit)) return false;
    const expiresAt = this.currentTime + ttlSeconds * 1_000;
    for (const [index, bucket] of buckets.entries()) {
      bucket.set(reservationId, expiresAt);
      this.rateLimitReservations.set(keys[index]!, bucket);
    }
    return true;
  }

  async releaseRateLimit(
    keys: readonly string[],
    reservationId: string,
  ): Promise<void> {
    if (
      keys.length === 0 ||
      keys.length > 10 ||
      new Set(keys).size !== keys.length ||
      keys.some((key) => key.length === 0 || key.length > 512) ||
      reservationId.length === 0 ||
      reservationId.length > 128
    ) {
      throw new RangeError("OAuth rate-limit reservation is invalid");
    }
    for (const key of keys) {
      const bucket = this.activeReservations(key);
      bucket.delete(reservationId);
      if (bucket.size === 0) this.rateLimitReservations.delete(key);
    }
  }

  async close(): Promise<void> {}

  private expiring<T>(value: T, ttlSeconds: number): ExpiringValue<T> {
    return {
      value: structuredClone(value),
      expiresAt: this.currentTime + ttlSeconds * 1_000,
    };
  }

  private read<T>(
    values: Map<string, ExpiringValue<T>>,
    key: string,
  ): T | null {
    const entry = values.get(key);
    if (!entry) return null;
    if (entry.expiresAt <= this.currentTime) {
      values.delete(key);
      return null;
    }
    return structuredClone(entry.value);
  }

  private consume<T>(
    values: Map<string, ExpiringValue<T>>,
    key: string,
  ): T | null {
    const value = this.read(values, key);
    values.delete(key);
    return value;
  }

  private activeClientCount(): number {
    for (const clientId of this.clients.keys()) {
      this.read(this.clients, clientId);
    }
    return this.clients.size;
  }

  private isFamilyRevoked(familyId: string): boolean {
    const expiresAt = this.revokedFamilies.get(familyId);
    if (expiresAt === undefined) return false;
    if (expiresAt <= this.currentTime) {
      this.revokedFamilies.delete(familyId);
      return false;
    }
    return true;
  }

  private matchesRefreshBindings(
    record: RefreshTokenRecord,
    input: RotateRefreshTokenInput,
  ): boolean {
    return (
      record.clientId === input.clientId &&
      record.resource === input.resource &&
      record.scope === input.scope
    );
  }

  private consumePairWriteFailure(): boolean {
    if (!this.failNextPairWrite) return false;
    this.failNextPairWrite = false;
    return true;
  }

  private activeReservations(key: string): Map<string, number> {
    const bucket = this.rateLimitReservations.get(key) ?? new Map();
    for (const [reservationId, expiresAt] of bucket) {
      if (expiresAt <= this.currentTime) bucket.delete(reservationId);
    }
    if (bucket.size === 0) {
      this.rateLimitReservations.delete(key);
    }
    return bucket;
  }
}
