import { scryptSync } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  pkceChallenge,
  randomToken,
  sha256Token,
  signCsrf,
  verifyCsrf,
  verifyPassphrase,
  verifyPkce,
} from "../src/oauth/crypto.js";

describe("OAuth cryptography", () => {
  it("produces a deterministic SHA-256 token digest", () => {
    expect(sha256Token("opaque-token")).toBe(
      "hNPyPam19RsyaVZu_wXT-yNgfu74lWf5zSgLkMoNvFw",
    );
    expect(sha256Token("opaque-token")).toBe(sha256Token("opaque-token"));
  });

  it("returns an unpredictable 32-byte base64url token", () => {
    const first = randomToken();
    const second = randomToken();

    expect(first).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(Buffer.from(first, "base64url")).toHaveLength(32);
    expect(second).not.toBe(first);
  });

  it("verifies only the matching S256 PKCE verifier", async () => {
    const verifier = "abcdefghijklmnopqrstuvwxyz0123456789-._~ABCDE";
    const challenge = await pkceChallenge(verifier);

    expect(challenge).toBe("e5A_4YqDBAOkeozejiAzw4Fzm_mqcrVsstgid63knfc");
    expect(await verifyPkce(verifier, challenge)).toBe(true);
    expect(await verifyPkce(`${verifier}x`, challenge)).toBe(false);
  });

  it("rejects a tampered CSRF cookie or mismatched body value", () => {
    const value = "csrf-value";
    const key = "local-cookie-signing-key";
    const cookie = signCsrf(value, key);

    expect(verifyCsrf(cookie, value, key)).toBe(true);
    expect(verifyCsrf(`${cookie}x`, value, key)).toBe(false);
    expect(verifyCsrf(cookie, `${value}x`, key)).toBe(false);
  });

  it("verifies correct scrypt passphrases and rejects incorrect ones", async () => {
    const salt = Buffer.from("salt-for-oauth-tests");
    const derived = scryptSync("correct horse", salt, 32, {
      N: 16_384,
      r: 8,
      p: 1,
      maxmem: 64 * 1024 * 1024,
    });
    const digest = `scrypt$16384$8$1$${salt.toString("base64url")}$${derived.toString("base64url")}`;

    expect(await verifyPassphrase("correct horse", digest)).toBe(true);
    expect(await verifyPassphrase("wrong horse", digest)).toBe(false);
  });

  it("rejects unsupported or malformed passphrase digests", async () => {
    expect(
      await verifyPassphrase(
        "correct horse",
        "scrypt$32768$8$1$c2FsdA$ZGlnaWVzdA",
      ),
    ).toBe(false);
    expect(await verifyPassphrase("correct horse", "not-a-digest")).toBe(false);
  });

  it("rejects non-canonical or unbounded scrypt fields", async () => {
    const derive = (salt: Buffer) =>
      scryptSync("correct horse", salt, 32, {
        N: 16_384,
        r: 8,
        p: 1,
        maxmem: 64 * 1024 * 1024,
      });
    const largeSalt = Buffer.alloc(65, 65);
    const largeDigest = derive(largeSalt).toString("base64url");
    const canonicalSalt = Buffer.from("12345678");
    const canonicalSaltText = canonicalSalt.toString("base64url");
    const canonicalDigest = derive(canonicalSalt).toString("base64url");
    const alphabet =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    const nonCanonicalSalt = `${canonicalSaltText.slice(0, -1)}${alphabet[alphabet.indexOf(canonicalSaltText.at(-1) ?? "") + 1]}`;
    const nonCanonicalDigest = `${canonicalDigest.slice(0, -1)}${alphabet[alphabet.indexOf(canonicalDigest.at(-1) ?? "") + 1]}`;

    expect(largeSalt.toString("base64url")).toHaveLength(87);
    expect(
      await verifyPassphrase(
        "correct horse",
        `scrypt$16384$8$1$${largeSalt.toString("base64url")}$${largeDigest}`,
      ),
    ).toBe(false);
    expect(Buffer.from(nonCanonicalSalt, "base64url")).toEqual(canonicalSalt);
    expect(
      await verifyPassphrase(
        "correct horse",
        `scrypt$16384$8$1$${nonCanonicalSalt}$${canonicalDigest}`,
      ),
    ).toBe(false);
    expect(Buffer.from(nonCanonicalDigest, "base64url")).toEqual(
      Buffer.from(canonicalDigest, "base64url"),
    );
    expect(
      await verifyPassphrase(
        "correct horse",
        `scrypt$16384$8$1$${canonicalSaltText}$${nonCanonicalDigest}`,
      ),
    ).toBe(false);

    const salt = Buffer.from("salt-for-oauth-tests");
    const derived = scryptSync("correct horse", salt, 32, {
      N: 16_384,
      r: 8,
      p: 1,
      maxmem: 64 * 1024 * 1024,
    });
    const saltText = salt.toString("base64url");
    const digestText = derived.toString("base64url");

    expect(
      await verifyPassphrase(
        "correct horse",
        `scrypt$16384$8$1$${saltText}$${digestText.slice(0, 42)}`,
      ),
    ).toBe(false);
    expect(
      await verifyPassphrase(
        "correct horse",
        `scrypt$16384$8$1$${saltText}$${digestText}=`,
      ),
    ).toBe(false);
  });
});
