import { EventEmitter } from "node:events";
import { describe, expect, it } from "vitest";
import { vi } from "vitest";
import { verifyPassphrase } from "../src/oauth/crypto.js";
import { encodePassphrase } from "../src/oauth/passphrase.js";
import {
  createTerminalRestorer,
  registerTerminationHandlers,
} from "../src/oauth/terminal.js";

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

  it("restores terminal input once before termination signals exit", () => {
    const terminal = {
      isRaw: false,
      setRawMode: vi.fn(),
      pause: vi.fn(),
    };
    const signals = new EventEmitter();
    const exit = vi.fn();

    const restore = createTerminalRestorer(terminal);
    registerTerminationHandlers(signals, restore, exit);
    signals.emit("SIGTERM");
    signals.emit("SIGHUP");

    expect(terminal.setRawMode).toHaveBeenCalledOnce();
    expect(terminal.setRawMode).toHaveBeenCalledWith(false);
    expect(terminal.pause).toHaveBeenCalledOnce();
    expect(exit).toHaveBeenNthCalledWith(1, 143);
    expect(exit).toHaveBeenNthCalledWith(2, 129);
  });
});
