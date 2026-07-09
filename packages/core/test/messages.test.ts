import { describe, expect, it } from "vitest";
import { createNoteMessage, sha256Hex } from "../src/index.js";

describe("canonical messages", () => {
  it("formats create-note messages with kdf", () => {
    const message = createNoteMessage({
      slug: "wallet",
      productType: "note",
      version: 1,
      kdf: "argon2id",
      ciphertext: "abc",
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
        sha256Hex("abc"),
        "iv-value",
        "salt-value",
        "owner-pk",
        sha256Hex(JSON.stringify(["editor-pk"])),
      ].join("\n")
    );
  });
});
