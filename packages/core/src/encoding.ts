export function utf8ToBytes(input: string): Uint8Array {
  return new TextEncoder().encode(input);
}

export function bytesToUtf8(input: Uint8Array): string {
  return new TextDecoder().decode(input);
}

type NodeBuffer = {
  from(data: Uint8Array, offset?: number, length?: number): {
    toString(encoding: "base64"): string;
  };
  from(data: string, encoding: "base64"): Uint8Array;
};

function nodeBuffer(): NodeBuffer | undefined {
  return (globalThis as { Buffer?: NodeBuffer }).Buffer;
}

/** Base64 for small JSON metadata only (keys, IV, salt, signatures). Not for ciphertext. */
export function bytesToBase64(bytes: Uint8Array): string {
  const Buffer = nodeBuffer();
  if (Buffer) {
    return Buffer.from(bytes).toString("base64");
  }
  return btoa(String.fromCharCode(...bytes));
}

/** Decode base64 metadata fields from JSON payloads. */
export function base64ToBytes(base64: string): Uint8Array {
  const Buffer = nodeBuffer();
  if (Buffer) {
    return new Uint8Array(Buffer.from(base64, "base64"));
  }
  const binary = atob(base64);
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

export function bytesToHex(bytes: Uint8Array): string {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}
