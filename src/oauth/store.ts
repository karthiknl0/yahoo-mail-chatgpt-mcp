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
} from "./types.js";

/** One refresh-token lifetime keeps stale public registrations bounded. */
export const CLIENT_REGISTRATION_RETENTION_SECONDS = 30 * 24 * 60 * 60;
/** 32 maximum-size public records consume about 1 MiB of Key Value storage. */
export const MAX_ACTIVE_OAUTH_CLIENTS = 32;

export interface OAuthStore {
  registerClient(
    client: RegisteredClient,
    retentionSeconds?: number,
    maxActiveClients?: number,
  ): Promise<boolean>;
  getClient(clientId: string): Promise<RegisteredClient | null>;
  createTransaction(
    id: string,
    value: AuthorizationTransaction,
    ttlSeconds: number,
  ): Promise<void>;
  consumeTransaction(id: string): Promise<AuthorizationTransaction | null>;
  createAuthorizationCode(
    digest: string,
    value: AuthorizationCodeRecord,
    ttlSeconds: number,
  ): Promise<void>;
  consumeAuthorizationCode(
    digest: string,
  ): Promise<AuthorizationCodeRecord | null>;
  exchangeAuthorizationCode(
    input: ExchangeAuthorizationCodeInput,
  ): Promise<ExchangeAuthorizationCodeResult>;
  createAccessToken(
    digest: string,
    value: AccessTokenRecord,
    ttlSeconds: number,
  ): Promise<void>;
  getAccessToken(digest: string): Promise<AccessTokenRecord | null>;
  createRefreshToken(
    digest: string,
    value: RefreshTokenRecord,
    ttlSeconds: number,
  ): Promise<boolean>;
  rotateRefreshToken(
    input: RotateRefreshTokenInput,
  ): Promise<RotateRefreshTokenResult>;
  reserveRateLimit(
    keys: readonly string[],
    reservationId: string,
    limit: number,
    ttlSeconds: number,
  ): Promise<boolean>;
  releaseRateLimit(
    keys: readonly string[],
    reservationId: string,
  ): Promise<void>;
  incrementRateLimit(key: string, ttlSeconds: number): Promise<number>;
  close(): Promise<void>;
}
