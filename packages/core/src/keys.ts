import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";
import { utf8ToBytes } from "./encoding.js";
import { deriveMasterSecret } from "./kdf.js";
import type { KdfAlgorithm } from "./types.js";

export { deriveMasterSecret, deriveMasterSecretPbkdf2 } from "./kdf.js";
export { ARGON2ID_PARAMS, PBKDF2_ITERATIONS } from "./kdf.js";

export interface KspKeyMaterial {
  masterSecret: Uint8Array;
  readKey: Uint8Array;
  editorSeed: Uint8Array;
  ownerSeed: Uint8Array;
}

export function deriveCapability(
  inputKeyMaterial: Uint8Array,
  info: string,
  length = 32
): Uint8Array {
  return hkdf(sha256, inputKeyMaterial, undefined, utf8ToBytes(info), length);
}

export function deriveKspMaterial(masterSecret: Uint8Array): KspKeyMaterial {
  return {
    masterSecret,
    readKey: deriveCapability(masterSecret, "kodama:v1:read", 32),
    editorSeed: deriveCapability(masterSecret, "kodama:v1:editor", 32),
    ownerSeed: deriveCapability(masterSecret, "kodama:v1:owner", 32),
  };
}

export async function deriveKspMaterialFromPassword(
  password: string,
  salt: Uint8Array,
  kdf: KdfAlgorithm = "argon2id"
): Promise<KspKeyMaterial> {
  const masterSecret = await deriveMasterSecret(password, salt, kdf);
  return deriveKspMaterial(masterSecret);
}
