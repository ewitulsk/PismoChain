export {};

declare global {
  interface Window {
    solana?: {
      isPhantom?: boolean;
      connect: (opts?: { onlyIfTrusted?: boolean }) => Promise<{ publicKey: { toBytes(): Uint8Array; toBase58(): string } }>;
      disconnect: () => Promise<void>;
      signMessage: (message: Uint8Array, display?: 'utf8' | 'hex') => Promise<{ signature: Uint8Array }>; // Phantom supports signMessage
      sign: (tx: unknown) => Promise<unknown>;
      on: (event: string, handler: (...args: any[]) => void) => void;
      off: (event: string, handler: (...args: any[]) => void) => void;
      publicKey?: { toBytes(): Uint8Array; toBase58(): string };
    };
  }
}
