import { describe, expect, it } from "vitest";
import {
  createNoteMessage,
  createPlaceBundleMessage,
  editPlaceBundleMessage,
  rotateReaderActionMessage,
  rotateReaderBundleActionMessage,
  rotatePasswordActionMessage,
  revokeActionMessage,
  sha256Hex,
  utf8ToBytes,
} from "../src/index.js";

describe("canonical messages", () => {
  it("formats create-note messages with kdf and raw ciphertext bytes", () => {
    const ciphertext = utf8ToBytes("abc");
    const message = createNoteMessage({
      slug: "wallet",
      productType: "note",
      version: 1,
      kdf: "argon2id",
      ciphertext,
      iv: "iv-value",
      salt: "salt-value",
      ownerPublicKey: "owner-pk",
      editorPublicKeys: ["editor-pk"],
    });

    expect(message).toBe(
      [
        "kodama:v1:create-note",
        "wallet",
        "note",
        "1",
        "argon2id",
        sha256Hex(ciphertext),
        "iv-value",
        "salt-value",
        "owner-pk",
        sha256Hex(JSON.stringify(["editor-pk"])),
      ].join("\n")
    );
  });

  it("formats rotate-reader with raw ciphertext bytes", () => {
    const ciphertext = new Uint8Array([1, 2, 3, 4]);
    expect(
      rotateReaderActionMessage({
        slug: "wallet",
        version: 2,
        ciphertext,
        iv: "iv-b64",
      })
    ).toBe(
      [
        "kodama:v1:owner-action",
        "wallet",
        "rotate-reader",
        "2",
        sha256Hex(ciphertext),
        "iv-b64",
      ].join("\n")
    );
  });

  it("formats rotate-password with raw ciphertext bytes", () => {
    const ciphertext = new Uint8Array([9, 8, 7]);
    expect(
      rotatePasswordActionMessage({
        slug: "wallet",
        version: 2,
        kdf: "argon2id",
        salt: "salt-b64",
        ciphertext,
        iv: "iv-b64",
        ownerPublicKey: "owner-pk",
        editorPublicKeys: ["editor-pk"],
      })
    ).toBe(
      [
        "kodama:v1:owner-action",
        "wallet",
        "rotate-password",
        "2",
        "argon2id",
        "salt-b64",
        sha256Hex(ciphertext),
        "iv-b64",
        "owner-pk",
        sha256Hex(JSON.stringify(["editor-pk"])),
      ].join("\n")
    );
  });

  it("formats revoke with status and reason", () => {
    expect(
      revokeActionMessage({
        slug: "wallet",
        version: 2,
        status: "revoked",
        reason: "compromised",
      })
    ).toBe(
      [
        "kodama:v1:owner-action",
        "wallet",
        "revoke",
        "2",
        "revoked",
        "compromised",
      ].join("\n")
    );
  });

  it("formats create-place-bundle with bundle digest", () => {
    expect(
      createPlaceBundleMessage({
        slug: "wallet",
        productType: "note",
        version: 1,
        kdf: "argon2id",
        bundleDigest: "abc123",
        salt: "salt-value",
        ownerPublicKey: "owner-pk",
        editorPublicKeys: ["editor-pk"],
      })
    ).toBe(
      [
        "kodama:v1:create-place-bundle",
        "wallet",
        "note",
        "1",
        "argon2id",
        "abc123",
        "salt-value",
        "owner-pk",
        sha256Hex(JSON.stringify(["editor-pk"])),
      ].join("\n")
    );
  });

  it("formats edit-place-bundle with bundle digest", () => {
    expect(
      editPlaceBundleMessage({
        slug: "wallet",
        oldVersion: 1,
        newVersion: 2,
        bundleDigest: "digest-hex",
        editorPublicKey: "editor-pk",
      })
    ).toBe(
      [
        "kodama:v1:edit-place-bundle",
        "wallet",
        "1",
        "2",
        "digest-hex",
        "editor-pk",
      ].join("\n")
    );
  });

  it("formats rotate-reader-bundle with bundle digest", () => {
    expect(
      rotateReaderBundleActionMessage({
        slug: "wallet",
        version: 2,
        bundleDigest: "digest-hex",
      })
    ).toBe(
      [
        "kodama:v1:owner-action",
        "wallet",
        "rotate-reader-bundle",
        "2",
        "digest-hex",
      ].join("\n")
    );
  });
});
