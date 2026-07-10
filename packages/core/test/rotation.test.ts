import { describe, expect, it } from "vitest";
import {
  OWNER_ACTIONS,
  createNotePayload,
  createRevokeAction,
  createRotateEditorAction,
  createRotatePasswordAction,
  createRotateReaderAction,
  readWithCapability,
  readWithPassword,
  verifyCreateNotePayload,
  verifyRevokeAction,
  verifyRotateEditorAction,
  verifyRotatePasswordAction,
  verifyRotateReaderAction,
} from "../src/index.js";

describe("rotation and revocation", () => {
  it("rotates reader capability and re-encrypts content", async () => {
    const created = await createNotePayload({
      slug: "rotate-me",
      password: "owner-password",
      plaintext: "secret content",
    });

    const { action, ciphertext, newReaderCapability } = await createRotateReaderAction({
      slug: created.payload.slug,
      version: created.payload.version,
      password: "owner-password",
      place: created.payload,
      ownerPrivateKey: created.ownerPrivateKey,
    });

    expect(action.action).toBe(OWNER_ACTIONS.ROTATE_READER);
    expect(
      await verifyRotateReaderAction(
        action,
        created.payload.owner_public_key,
        created.payload.version,
        ciphertext
      )
    ).toBe(true);

    const updatedPlace = {
      ...created.payload,
      ciphertext,
      iv: action.payload.iv,
    };

    const plaintext = await readWithCapability(newReaderCapability, updatedPlace);
    expect(plaintext).toBe("secret content");

    await expect(
      readWithCapability(created.readerCapability, updatedPlace)
    ).rejects.toThrow();
  });

  it("rotates password and re-encrypts with new derived keys", async () => {
    const created = await createNotePayload({
      slug: "password-rotate",
      password: "old-password",
      plaintext: "secret note",
    });

    const rotated = await createRotatePasswordAction({
      slug: created.payload.slug,
      version: created.payload.version,
      currentPassword: "old-password",
      newPassword: "new-password",
      place: created.payload,
      ownerPrivateKey: created.ownerPrivateKey,
    });

    expect(rotated.action.action).toBe(OWNER_ACTIONS.ROTATE_PASSWORD);
    expect(
      await verifyRotatePasswordAction(
        rotated.action,
        created.payload.owner_public_key,
        created.payload.version,
        rotated.ciphertext
      )
    ).toBe(true);

    const updatedPlace = {
      slug: created.payload.slug,
      product_type: created.payload.product_type,
      version: created.payload.version,
      kdf: rotated.action.payload.kdf,
      salt: rotated.action.payload.salt,
      ciphertext: rotated.ciphertext,
      iv: rotated.action.payload.iv,
    };

    expect(await readWithPassword("new-password", updatedPlace)).toBe(
      "secret note"
    );
    await expect(readWithPassword("old-password", updatedPlace)).rejects.toThrow();
    expect(rotated.ownerPrivateKey).not.toBe(created.ownerPrivateKey);
  });

  it("rotates editor public keys", async () => {
    const created = await createNotePayload({
      slug: "editor-rotate",
      password: "owner-password",
      plaintext: "content",
    });

    const newEditorKey = "dGVzdC1lZGl0b3ItcHVibGljLWtleS1iYXNlNjQ=";
    const action = await createRotateEditorAction({
      slug: created.payload.slug,
      version: created.payload.version,
      editorPublicKeys: [newEditorKey],
      ownerPrivateKey: created.ownerPrivateKey,
    });

    expect(action.action).toBe(OWNER_ACTIONS.ROTATE_EDITOR);
    expect(action.payload.editor_public_keys).toEqual([newEditorKey]);
    expect(
      await verifyRotateEditorAction(
        action,
        created.payload.owner_public_key,
        created.payload.version
      )
    ).toBe(true);
  });

  it("revokes a place", async () => {
    const created = await createNotePayload({
      slug: "revoke-me",
      password: "owner-password",
      plaintext: "content",
    });

    const action = await createRevokeAction({
      slug: created.payload.slug,
      version: created.payload.version,
      status: "revoked",
      reason: "compromised editor key",
      ownerPrivateKey: created.ownerPrivateKey,
    });

    expect(action.action).toBe(OWNER_ACTIONS.REVOKE);
    expect(action.payload.status).toBe("revoked");
    expect(action.payload.reason).toBe("compromised editor key");
    expect(
      await verifyRevokeAction(
        action,
        created.payload.owner_public_key,
        created.payload.version
      )
    ).toBe(true);
  });

  it("rejects owner actions signed for wrong version", async () => {
    const created = await createNotePayload({
      slug: "version-check",
      password: "owner-password",
      plaintext: "content",
    });

    const action = await createRevokeAction({
      slug: created.payload.slug,
      version: created.payload.version,
      status: "archived",
      ownerPrivateKey: created.ownerPrivateKey,
    });

    expect(
      await verifyRevokeAction(
        action,
        created.payload.owner_public_key,
        created.payload.version + 1
      )
    ).toBe(false);
  });
});

describe("create verification edge cases", () => {
  it("rejects tampered create payloads", async () => {
    const created = await createNotePayload({
      slug: "tamper",
      password: "password",
      plaintext: "content",
    });

    const tampered = {
      ...created.payload,
      ciphertext: created.payload.ciphertext.slice(0, -1),
    };

    expect(await verifyCreateNotePayload(tampered)).toBe(false);
  });
});
