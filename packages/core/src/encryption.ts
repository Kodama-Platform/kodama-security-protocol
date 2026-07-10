import type { EncryptedBlob } from "./types.js";
import { utf8ToBytes } from "./encoding.js";
import { randomIv } from "./random.js";

async function importAesKey(key: Uint8Array): Promise<CryptoKey> {
  if (key.length !== 32) throw new Error("AES-256-GCM key must be 32 bytes");
  return crypto.subtle.importKey(
    "raw",
    key as unknown as BufferSource,
    { name: "AES-GCM" },
    false,
    ["encrypt", "decrypt"]
  );
}

/** Encrypt a compressed content blob with AES-256-GCM. Returns raw bytes. */
export async function encryptBytes(
  plaintext: Uint8Array,
  key: Uint8Array,
  aad?: string
): Promise<EncryptedBlob> {
  const iv = randomIv();
  const cryptoKey = await importAesKey(key);
  const ciphertext = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: iv as unknown as BufferSource,
      additionalData: aad ? (utf8ToBytes(aad) as unknown as BufferSource) : undefined,
    },
    cryptoKey,
    plaintext as unknown as BufferSource
  );
  return {
    ciphertext: new Uint8Array(ciphertext),
    iv,
  };
}

/** Decrypt to a compressed content blob. Decompress separately before reading as text. */
export async function decryptBytes(
  blob: EncryptedBlob,
  key: Uint8Array,
  aad?: string
): Promise<Uint8Array> {
  const cryptoKey = await importAesKey(key);
  const plaintext = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: blob.iv as unknown as BufferSource,
      additionalData: aad ? (utf8ToBytes(aad) as unknown as BufferSource) : undefined,
    },
    cryptoKey,
    blob.ciphertext as unknown as BufferSource
  );
  return new Uint8Array(plaintext);
}
