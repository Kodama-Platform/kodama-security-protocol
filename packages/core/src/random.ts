let randomOverride: ((length: number) => Uint8Array) | null = null;

/** @internal Test-only hook for deterministic salts and IVs. */
export function setRandomOverride(fn: ((length: number) => Uint8Array) | null): void {
  randomOverride = fn;
}

export function randomBytes(length: number): Uint8Array {
  if (randomOverride) return randomOverride(length);
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
}

export function randomSalt(length = 32): Uint8Array {
  return randomBytes(length);
}

export function randomIv(length = 12): Uint8Array {
  return randomBytes(length);
}
