import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  bytesToHex,
  compressNoteText,
  createNotePayload,
  deriveKspMaterial,
  deriveMasterSecretArgon2id,
  deriveMasterSecretPbkdf2,
  encryptBytes,
  normalizeSlug,
  verifyCreateNotePayload,
} from "../src/index.js";
import { setRandomOverride } from "../src/random.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const vectors = JSON.parse(
  readFileSync(join(__dirname, "../../../test-vectors/v1.json"), "utf8")
);

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

describe("test vectors v1.json", () => {
  it("matches Argon2id derivation", async () => {
    const { password, salt_hex, master_secret_hex } = vectors.kdf.argon2id;
    const salt = hexToBytes(salt_hex);
    const master = await deriveMasterSecretArgon2id(password, salt);
    expect(bytesToHex(master)).toBe(master_secret_hex);
  });

  it("matches PBKDF2 derivation", async () => {
    const { password, salt_hex, master_secret_hex } = vectors.kdf.pbkdf2;
    const salt = hexToBytes(salt_hex);
    const master = await deriveMasterSecretPbkdf2(password, salt);
    expect(bytesToHex(master)).toBe(master_secret_hex);
  });

  it("matches HKDF read key derivation", async () => {
    const { salt_hex, master_secret_hex, read_key_hex } = vectors.kdf.argon2id;
    const master = hexToBytes(master_secret_hex);
    const material = deriveKspMaterial(master);
    expect(bytesToHex(material.readKey)).toBe(read_key_hex);

    // cross-check via full pipeline
    const salt = hexToBytes(salt_hex);
    const derived = await deriveMasterSecretArgon2id(
      vectors.kdf.argon2id.password,
      salt
    );
    expect(bytesToHex(deriveKspMaterial(derived).readKey)).toBe(read_key_hex);
  });

  it("matches gzip compression output", async () => {
    const compressed = await compressNoteText(vectors.compression.plaintext);
    expect(bytesToHex(compressed)).toBe(vectors.compression.compressed_hex);
  });

  it("matches encryption output", async () => {
    const { aad, iv_hex } = vectors.encryption;
    const readKey = hexToBytes(vectors.kdf.argon2id.read_key_hex);
    const iv = hexToBytes(iv_hex);
    const compressed = hexToBytes(vectors.compression.compressed_hex);

    setRandomOverride((length) => (length === 12 ? iv : new Uint8Array(length)));

    const encrypted = await encryptBytes(compressed, readKey, aad);
    expect(encrypted.ciphertext).toBe(vectors.encryption.ciphertext);
    expect(encrypted.iv).toBe(vectors.encryption.iv);

    setRandomOverride(null);
  });

  it("matches create-note signature", async () => {
    const salt = hexToBytes(vectors.kdf.argon2id.salt_hex);
    const iv = hexToBytes(vectors.encryption.iv_hex);

    setRandomOverride((length) => {
      if (length === 32) return salt;
      if (length === 12) return iv;
      return new Uint8Array(length);
    });

    const created = await createNotePayload({
      slug: vectors.create_note.slug,
      password: vectors.kdf.argon2id.password,
      plaintext: vectors.encryption.plaintext,
    });

    expect(created.payload.owner_signature).toBe(vectors.create_note.owner_signature);
    expect(await verifyCreateNotePayload(created.payload)).toBe(true);

    setRandomOverride(null);
  });

  it("validates slug vector cases", () => {
    for (const c of vectors.slug.cases) {
      expect(normalizeSlug(c.input)).toBe(c.normalized);
    }
  });
});
