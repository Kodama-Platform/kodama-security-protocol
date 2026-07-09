import type { EncryptedPayload } from "./types.js";
import { base64ToBytes, bytesToBase64, utf8ToBytes } from "./encoding.js";
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

/** Encrypt a compressed content blob with AES-256-GCM. */
export async function encryptBytes(
  plaintext: Uint8Array,
  key: Uint8Array,
  aad?: string
): Promise<EncryptedPayload> {
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
    ciphertext: bytesToBase64(new Uint8Array(ciphertext)),
    iv: bytesToBase64(iv),
  };
}

/** Decrypt to a compressed content blob. Decompress separately before reading as text. */
export async function decryptBytes(
  payload: EncryptedPayload,
  key: Uint8Array,
  aad?: string
): Promise<Uint8Array> {
  const cryptoKey = await importAesKey(key);
  const plaintext = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: base64ToBytes(payload.iv) as unknown as BufferSource,
      additionalData: aad ? (utf8ToBytes(aad) as unknown as BufferSource) : undefined,
    },
    cryptoKey,
    base64ToBytes(payload.ciphertext) as unknown as BufferSource
  );
  return new Uint8Array(plaintext);
}
