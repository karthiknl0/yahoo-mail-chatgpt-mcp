import {
  createHash,
  createHmac,
  randomBytes,
  scrypt as nodeScrypt,
  timingSafeEqual,
  type BinaryLike,
  type ScryptOptions,
} from "node:crypto";
import { promisify } from "node:util";

const scrypt = promisify(nodeScrypt) as (
  password: BinaryLike,
  salt: BinaryLike,
  keyLength: number,
  options: ScryptOptions,
) => Promise<Buffer>;
const SCRYPT_MAX_MEMORY = 64 * 1024 * 1024;
const SCRYPT_KEY_LENGTH = 32;
const SCRYPT_PATTERN =
  /^scrypt\$16384\$8\$1\$([A-Za-z0-9_-]+)\$([A-Za-z0-9_-]+)$/;

function equalBuffers(left: Buffer, right: Buffer): boolean {
  return left.length === right.length && timingSafeEqual(left, right);
}

export function randomToken(): string {
  return randomBytes(32).toString("base64url");
}

export function sha256Token(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("base64url");
}

export async function pkceChallenge(verifier: string): Promise<string> {
  return sha256Token(verifier);
}

export async function verifyPkce(
  verifier: string,
  challenge: string,
): Promise<boolean> {
  const calculated = Buffer.from(await pkceChallenge(verifier), "utf8");
  return equalBuffers(calculated, Buffer.from(challenge, "utf8"));
}

export async function verifyPassphrase(
  passphrase: string,
  encoded: string,
): Promise<boolean> {
  const match = SCRYPT_PATTERN.exec(encoded);
  if (!match) return false;

  const saltText = match[1];
  const digestText = match[2];
  if (!saltText || !digestText) return false;

  try {
    const salt = Buffer.from(saltText, "base64url");
    const expected = Buffer.from(digestText, "base64url");
    if (salt.length === 0 || expected.length !== SCRYPT_KEY_LENGTH)
      return false;

    const actual = await scrypt(passphrase, salt, SCRYPT_KEY_LENGTH, {
      N: 16_384,
      r: 8,
      p: 1,
      maxmem: SCRYPT_MAX_MEMORY,
    });

    return equalBuffers(actual, expected);
  } catch {
    return false;
  }
}

export function signCsrf(value: string, key: string): string {
  const signature = createHmac("sha256", key)
    .update(value, "utf8")
    .digest("base64url");
  return `${value}.${signature}`;
}

export function verifyCsrf(
  cookie: string,
  bodyValue: string,
  key: string,
): boolean {
  const separator = cookie.lastIndexOf(".");
  if (separator <= 0 || separator === cookie.length - 1) return false;

  const cookieValue = cookie.slice(0, separator);
  if (!equalBuffers(Buffer.from(cookieValue), Buffer.from(bodyValue)))
    return false;

  const providedSignature = Buffer.from(cookie.slice(separator + 1), "utf8");
  const expectedSignature = Buffer.from(
    createHmac("sha256", key).update(cookieValue, "utf8").digest("base64url"),
    "utf8",
  );
  return equalBuffers(providedSignature, expectedSignature);
}
