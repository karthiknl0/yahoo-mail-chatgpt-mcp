import type {
  AccessTokenRecord,
  AuthorizationCodeRecord,
  AuthorizationTransaction,
  RegisteredClient,
  RotateRefreshTokenInput,
  RotateRefreshTokenResult,
} from "./types.js";

export interface OAuthStore {
  registerClient(client: RegisteredClient): Promise<void>;
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
  createAccessToken(
    digest: string,
    value: AccessTokenRecord,
    ttlSeconds: number,
  ): Promise<void>;
  getAccessToken(digest: string): Promise<AccessTokenRecord | null>;
  rotateRefreshToken(
    input: RotateRefreshTokenInput,
  ): Promise<RotateRefreshTokenResult>;
  incrementRateLimit(key: string, ttlSeconds: number): Promise<number>;
  close(): Promise<void>;
}
