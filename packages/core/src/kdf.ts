import { argon2id } from "hash-wasm";
import { utf8ToBytes } from "./encoding.js";
import type { KdfAlgorithm } from "./types.js";

/** Argon2id parameters for KSP v1 (OWASP-aligned, browser-feasible). */
export const ARGON2ID_PARAMS = {
  parallelism: 1,
  iterations: 3,
  memorySize: 65_536, // 64 MiB in KiB
  hashLength: 32,
} as const;

export const PBKDF2_ITERATIONS = 310_000;

export async function deriveMasterSecretArgon2id(
  password: string,
  salt: Uint8Array
): Promise<Uint8Array> {
  const hash = await argon2id({
    password,
    salt,
    parallelism: ARGON2ID_PARAMS.parallelism,
    iterations: ARGON2ID_PARAMS.iterations,
    memorySize: ARGON2ID_PARAMS.memorySize,
    hashLength: ARGON2ID_PARAMS.hashLength,
    outputType: "binary",
  });
  return hash as Uint8Array;
}

export async function deriveMasterSecretPbkdf2(
  password: string,
  salt: Uint8Array,
  iterations = PBKDF2_ITERATIONS
): Promise<Uint8Array> {
  const baseKey = await crypto.subtle.importKey(
    "raw",
    utf8ToBytes(password) as unknown as BufferSource,
    "PBKDF2",
    false,
    ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: salt as unknown as BufferSource,
      iterations,
      hash: "SHA-256",
    },
    baseKey,
    256
  );
  return new Uint8Array(bits);
}

export function resolveKdf(kdf?: KdfAlgorithm): KdfAlgorithm {
  return kdf ?? "pbkdf2";
}

export async function deriveMasterSecret(
  password: string,
  salt: Uint8Array,
  kdf: KdfAlgorithm = "argon2id"
): Promise<Uint8Array> {
  switch (kdf) {
    case "argon2id":
      return deriveMasterSecretArgon2id(password, salt);
    case "pbkdf2":
      return deriveMasterSecretPbkdf2(password, salt);
  }
}
