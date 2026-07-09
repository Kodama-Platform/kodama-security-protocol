import { describe, expect, it } from "vitest";
import {
  buildContentAad,
  bytesToHex,
  createNotePayload,
  deriveMasterSecretArgon2id,
  deriveMasterSecretPbkdf2,
  deriveKspMaterial,
  normalizeSlug,
  readWithCapability,
  readWithPassword,
} from "../src/index.js";
import { setRandomOverride } from "../src/random.js";

const FIXED_SALT = new Uint8Array(32).fill(0x42);
const FIXED_IV = new Uint8Array(12).fill(0x11);

describe("KDF", () => {
  it("derives deterministic Argon2id master secrets", async () => {
    const a = await deriveMasterSecretArgon2id("password", FIXED_SALT);
    const b = await deriveMasterSecretArgon2id("password", FIXED_SALT);
    expect(bytesToHex(a)).toBe(bytesToHex(b));
    expect(a.length).toBe(32);
  });

  it("derives deterministic PBKDF2 master secrets", async () => {
    const a = await deriveMasterSecretPbkdf2("password", FIXED_SALT);
    const b = await deriveMasterSecretPbkdf2("password", FIXED_SALT);
    expect(bytesToHex(a)).toBe(bytesToHex(b));
    expect(a.length).toBe(32);
  });

  it("produces different keys for Argon2id vs PBKDF2", async () => {
    const argon2 = await deriveMasterSecretArgon2id("password", FIXED_SALT);
    const pbkdf2 = await deriveMasterSecretPbkdf2("password", FIXED_SALT);
    expect(bytesToHex(argon2)).not.toBe(bytesToHex(pbkdf2));
  });
});

describe("read helpers", () => {
  it("builds correct AAD", () => {
    expect(buildContentAad("wallet", 1, "note")).toBe("wallet:1:note");
  });

  it("decrypts with capability using AAD from place record", async () => {
    setRandomOverride((length) => (length === 32 ? FIXED_SALT : FIXED_IV));

    const created = await createNotePayload({
      slug: "wallet",
      password: "correct horse battery staple",
      plaintext: "hello kodama",
    });

    const plaintext = await readWithCapability(
      created.readerCapability,
      created.payload
    );
    expect(plaintext).toBe("hello kodama");

    setRandomOverride(null);
  });

  it("defaults missing kdf to pbkdf2 for legacy payloads", async () => {
    setRandomOverride((length) => (length === 32 ? FIXED_SALT : FIXED_IV));

    const created = await createNotePayload({
      slug: "wallet",
      password: "correct horse battery staple",
      plaintext: "hello kodama",
      kdf: "pbkdf2",
    });

    const legacyPlace = { ...created.payload };
    delete (legacyPlace as { kdf?: string }).kdf;

    const plaintext = await readWithPassword(
      "correct horse battery staple",
      legacyPlace
    );
    expect(plaintext).toBe("hello kodama");

    setRandomOverride(null);
  });
});

describe("KSP material derivation", () => {
  it("derives distinct capabilities from master secret", async () => {
    const master = await deriveMasterSecretArgon2id("password", FIXED_SALT);
    const material = deriveKspMaterial(master);
    expect(bytesToHex(material.readKey)).not.toBe(bytesToHex(material.editorSeed));
    expect(bytesToHex(material.editorSeed)).not.toBe(bytesToHex(material.ownerSeed));
  });
});
