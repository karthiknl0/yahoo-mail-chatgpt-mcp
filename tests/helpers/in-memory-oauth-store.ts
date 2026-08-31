import type { OAuthStore } from "../../src/oauth/store.js";
import type {
  AccessTokenRecord,
  AuthorizationCodeRecord,
  AuthorizationTransaction,
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
  private readonly clients = new Map<string, RegisteredClient>();
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
  private readonly usedRefreshTokens = new Map<string, ExpiringValue<string>>();
  private readonly revokedFamilies = new Map<string, number>();
  private readonly rateLimits = new Map<string, ExpiringValue<number>>();
  private currentTime: number;

  constructor(now = Date.now()) {
    this.currentTime = now;
  }

  advanceBy(milliseconds: number): void {
    this.currentTime += milliseconds;
  }

  async seedRefreshToken(
    digest: string,
    value: RefreshTokenRecord,
    ttlSeconds: number,
  ): Promise<void> {
    this.refreshTokens.set(digest, this.expiring(value, ttlSeconds));
  }

  async registerClient(client: RegisteredClient): Promise<void> {
    this.clients.set(client.clientId, structuredClone(client));
  }

  async getClient(clientId: string): Promise<RegisteredClient | null> {
    return this.clone(this.clients.get(clientId));
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

  async rotateRefreshToken(
    input: RotateRefreshTokenInput,
  ): Promise<RotateRefreshTokenResult> {
    if (this.isFamilyRevoked(input.familyId)) return "revoked";

    const oldRecord = this.read(this.refreshTokens, input.oldDigest);
    if (!oldRecord) {
      const usedFamilyId = this.read(this.usedRefreshTokens, input.oldDigest);
      if (!usedFamilyId) return "missing";

      this.revokedFamilies.set(
        usedFamilyId,
        this.currentTime + input.familyTtlSeconds * 1_000,
      );
      return "replayed";
    }

    if (
      oldRecord.familyId !== input.familyId ||
      oldRecord.clientId !== input.clientId ||
      oldRecord.resource !== input.resource ||
      oldRecord.scope !== input.scope
    ) {
      return "missing";
    }

    this.refreshTokens.delete(input.oldDigest);
    this.usedRefreshTokens.set(
      input.oldDigest,
      this.expiring(input.familyId, input.familyTtlSeconds),
    );
    this.refreshTokens.set(
      input.newDigest,
      this.expiring(
        {
          familyId: input.familyId,
          clientId: input.clientId,
          resource: input.resource,
          scope: input.scope,
          expiresAt: this.currentTime + input.refreshTtlSeconds * 1_000,
        },
        input.refreshTtlSeconds,
      ),
    );
    return "rotated";
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

  private clone<T>(value: T | undefined): T | null {
    return value === undefined ? null : structuredClone(value);
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
}
