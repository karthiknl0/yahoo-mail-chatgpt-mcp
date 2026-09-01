import { describe, expect, it } from "vitest";
import { verifyPassphrase } from "../src/oauth/crypto.js";
import { encodePassphrase } from "../src/oauth/passphrase.js";

describe("passphrase encoding", () => {
  it("encodes a passphrase with the fixed scrypt profile and supplied salt", async () => {
    const digest = await encodePassphrase(
      "private phrase",
      Buffer.from("fixed-test-salt!"),
    );

    expect(digest).toMatch(
      /^scrypt\$16384\$8\$1\$[A-Za-z0-9_-]+\$[A-Za-z0-9_-]+$/,
    );
    expect(await verifyPassphrase("private phrase", digest)).toBe(true);
  });
});
