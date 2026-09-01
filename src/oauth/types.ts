export interface RegisteredClient {
  readonly clientId: string;
  readonly redirectUris: readonly string[];
  readonly clientName?: string;
  readonly clientUri?: string;
  readonly grantTypes?: readonly string[];
  readonly responseTypes?: readonly string[];
  readonly tokenEndpointAuthMethod?: "none";
  readonly scope?: string;
  readonly createdAt?: number;
}

export interface AuthorizationTransaction {
  readonly clientId: string;
  readonly redirectUri: string;
  readonly resource: string;
  readonly state: string;
  readonly codeChallenge: string;
  readonly scope: string;
  readonly csrf: string;
}

export interface AuthorizationCodeRecord {
  readonly clientId: string;
  readonly redirectUri: string;
  readonly resource: string;
  readonly codeChallenge: string;
  readonly scope: string;
}

export type PromoteClientAndCreateAuthorizationCodeResult =
  | { readonly status: "promoted" }
  | { readonly status: "missing" }
  | { readonly status: "collision" }
  | { readonly status: "storage_error" };

export interface AccessTokenRecord {
  readonly clientId: string;
  readonly resource: string;
  readonly scope: string;
  readonly expiresAt: number;
}

export interface RefreshTokenRecord {
  readonly familyId: string;
  readonly accessDigest: string;
  readonly clientId: string;
  readonly resource: string;
  readonly scope: string;
  readonly expiresAt: number;
}

export interface ExchangeAuthorizationCodeInput {
  readonly codeDigest: string;
  readonly accessDigest: string;
  readonly refreshDigest: string;
  readonly familyId: string;
  readonly clientId: string;
  readonly redirectUri: string;
  readonly resource: string;
  readonly codeChallenge: string;
  readonly scope: string;
  readonly accessTtlSeconds: number;
  readonly refreshTtlSeconds: number;
}

export type ExchangeAuthorizationCodeResult =
  | { readonly status: "issued"; readonly record: AuthorizationCodeRecord }
  | { readonly status: "binding_mismatch" }
  | { readonly status: "collision" }
  | { readonly status: "storage_error" }
  | { readonly status: "missing" };

export interface RotateRefreshTokenInput {
  readonly oldDigest: string;
  readonly newDigest: string;
  readonly accessDigest: string;
  readonly clientId: string;
  readonly resource: string;
  readonly scope: string;
  readonly accessTtlSeconds: number;
}

export type RotateRefreshTokenResult =
  | { readonly status: "rotated"; readonly record: RefreshTokenRecord }
  | { readonly status: "replayed"; readonly record: RefreshTokenRecord }
  | { readonly status: "revoked"; readonly record: RefreshTokenRecord }
  | { readonly status: "binding_mismatch" }
  | { readonly status: "collision" }
  | { readonly status: "storage_error" }
  | { readonly status: "missing" };
