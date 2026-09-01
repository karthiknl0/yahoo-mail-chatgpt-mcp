import { randomBytes } from "node:crypto";
import process from "node:process";
import { encodePassphrase } from "../dist/src/oauth/passphrase.js";
import {
  createTerminalRestorer,
  registerTerminationHandlers,
} from "../dist/src/oauth/terminal.js";

const minimumPassphraseLength = 16;

async function readHiddenPassphrase() {
  if (!process.stdin.isTTY) {
    throw new Error("Passphrase input requires an interactive TTY");
  }

  const stdin = process.stdin;
  const restoreTerminal = createTerminalRestorer(stdin);
  let passphrase = "";

  registerTerminationHandlers(process, restoreTerminal, (code) => {
    process.exit(code);
  });
  stdin.setEncoding("utf8");
  stdin.setRawMode(true);
  stdin.resume();

  try {
    for await (const chunk of stdin) {
      for (const character of chunk) {
        if (character === "\u0003") {
          throw new Error("Passphrase input cancelled");
        }
        if (character === "\r" || character === "\n") {
          return passphrase;
        }
        if (character === "\u007f" || character === "\b") {
          passphrase = passphrase.slice(0, -1);
          continue;
        }
        if (character >= " ") passphrase += character;
      }
    }
  } finally {
    restoreTerminal();
  }

  throw new Error("Passphrase input ended unexpectedly");
}

try {
  const passphrase = await readHiddenPassphrase();
  if (passphrase.length < minimumPassphraseLength) {
    throw new Error("Passphrase must be at least 16 characters");
  }

  const digest = await encodePassphrase(passphrase, randomBytes(16));
  process.stdout.write(`${digest}\n`);
} catch (error) {
  process.stderr.write(
    `${error instanceof Error ? error.message : "Unable to hash passphrase"}\n`,
  );
  process.exitCode = 1;
}
