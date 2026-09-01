export interface TerminalInput {
  isRaw?: boolean;
  setRawMode(mode: boolean): void;
  pause(): void;
}

export interface SignalEmitter {
  once(signal: "SIGHUP" | "SIGTERM", listener: () => void): unknown;
}

export function createTerminalRestorer(terminal: TerminalInput): () => void {
  const wasRaw = terminal.isRaw ?? false;
  let restored = false;

  return () => {
    if (restored) return;
    restored = true;
    try {
      terminal.setRawMode(wasRaw);
    } finally {
      terminal.pause();
    }
  };
}

export function registerTerminationHandlers(
  signals: SignalEmitter,
  restoreTerminal: () => void,
  exit: (code: number) => void,
): void {
  signals.once("SIGHUP", () => {
    try {
      restoreTerminal();
    } finally {
      exit(129);
    }
  });
  signals.once("SIGTERM", () => {
    try {
      restoreTerminal();
    } finally {
      exit(143);
    }
  });
}
