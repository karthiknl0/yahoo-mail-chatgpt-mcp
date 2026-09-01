import {
  scrypt as nodeScrypt,
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

export async function encodePassphrase(
  passphrase: string,
  salt: Buffer,
): Promise<string> {
  const digest = await scrypt(passphrase, salt, SCRYPT_KEY_LENGTH, {
    N: 16_384,
    r: 8,
    p: 1,
    maxmem: SCRYPT_MAX_MEMORY,
  });

  return `scrypt$16384$8$1$${salt.toString("base64url")}$${digest.toString("base64url")}`;
}
