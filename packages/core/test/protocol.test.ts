import { describe, expect, it } from "vitest";
import {
  base64ToBytes,
  createEditPayload,
  createNotePayload,
  readWithCapability,
  readWithPassword,
  verifyCreateNotePayload,
  verifyEditPayload,
} from "../src/index.js";

describe("KSP core protocol", () => {
  it("creates, verifies, decrypts, edits, and verifies edit payload", async () => {
    const created = await createNotePayload({
      slug: "Wallet",
      password: "correct horse battery staple",
      plaintext: "hello kodama",
    });

    expect(created.payload.slug).toBe("wallet");
    expect(created.payload.kdf).toBe("argon2id");
    expect(await verifyCreateNotePayload(created.payload)).toBe(true);

    const plaintext = await readWithCapability(
      created.readerCapability,
      created.payload
    );
    expect(plaintext).toBe("hello kodama");

    const edit = await createEditPayload({
      slug: created.payload.slug,
      oldVersion: 1,
      plaintext: "updated note",
      readKey: base64ToBytes(created.readerCapability),
      editorPrivateKey: created.editorPrivateKey,
      editorPublicKey: created.payload.editor_public_keys[0]!,
    });

    expect(await verifyEditPayload(edit, created.payload.editor_public_keys, 1)).toBe(
      true
    );
    expect(await verifyEditPayload(edit, created.payload.editor_public_keys, 2)).toBe(
      false
    );
  });

  it("reads with password via read helper", async () => {
    const created = await createNotePayload({
      slug: "secrets",
      password: "my-password",
      plaintext: "owner read",
    });

    const plaintext = await readWithPassword("my-password", created.payload);
    expect(plaintext).toBe("owner read");
  });

  it("supports pbkdf2 for legacy interop", async () => {
    const created = await createNotePayload({
      slug: "legacy",
      password: "legacy-pass",
      plaintext: "legacy content",
      kdf: "pbkdf2",
    });

    expect(created.payload.kdf).toBe("pbkdf2");
    expect(await verifyCreateNotePayload(created.payload)).toBe(true);
    expect(await readWithPassword("legacy-pass", created.payload)).toBe(
      "legacy content"
    );
  });
});
