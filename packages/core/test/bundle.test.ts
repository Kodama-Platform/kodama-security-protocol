import { describe, expect, it } from "vitest";
import {
  bundleDigest,
  bundleDigestFromPlaceBundle,
  validatePlaceBundle,
} from "../src/bundle.js";
import {
  createEditBundlePayload,
  createPlaceBundlePayload,
  decryptPlaceBundle,
  readPlaceBundleWithCapability,
  verifyCreatePlaceBundlePayload,
  verifyEditBundlePayload,
} from "../src/bundle-protocol.js";
import {
  buildCreateBundleFormData,
  parseBundleFormData,
} from "../src/wire.js";
import { sha256Hex } from "../src/hash.js";

describe("place bundle", () => {
  it("creates, verifies, reads, and edits a multi-note bundle with attachment", async () => {
    const attachmentBytes = new Uint8Array([0x89, 0x50, 0x4e, 0x47]);

    const created = await createPlaceBundlePayload({
      slug: "workbook",
      password: "bundle-password",
      notes: [
        { id: "tab-a", plaintext: "first tab" },
        { id: "tab-b", plaintext: "second tab" },
      ],
      attachments: [{ id: "img-1", bytes: attachmentBytes }],
    });

    expect(created.metadata.storage_mode).toBe("bundle");
    expect(created.metadata.notes).toHaveLength(2);
    expect(created.metadata.attachments).toHaveLength(1);
    expect(await verifyCreatePlaceBundlePayload(created.metadata, created.bundle)).toBe(
      true
    );

    const decrypted = await readPlaceBundleWithCapability(
      created.readerCapability,
      {
        slug: created.metadata.slug,
        product_type: created.metadata.product_type,
        version: created.metadata.version,
        salt: created.metadata.salt,
        kdf: created.metadata.kdf,
        bundle: created.bundle,
      }
    );

    expect(decrypted.notes.get("tab-a")).toBe("first tab");
    expect(decrypted.notes.get("tab-b")).toBe("second tab");
    expect(decrypted.attachments.get("img-1")).toEqual(attachmentBytes);

    const edit = await createEditBundlePayload({
      slug: created.metadata.slug,
      oldVersion: 1,
      productType: created.metadata.product_type,
      notes: [
        { id: "tab-a", plaintext: "first tab updated" },
        { id: "tab-b", plaintext: "second tab" },
      ],
      attachments: [{ id: "img-1", bytes: attachmentBytes }],
      readKey: (await import("../src/encoding.js")).base64ToBytes(
        created.readerCapability
      ),
      editorPrivateKey: created.editorPrivateKey,
      editorPublicKey: created.metadata.editor_public_keys[0]!,
    });

    expect(
      await verifyEditBundlePayload(
        edit.metadata,
        edit.bundle,
        created.metadata.editor_public_keys,
        1
      )
    ).toBe(true);

    const edited = await readPlaceBundleWithCapability(
      created.readerCapability,
      {
        slug: created.metadata.slug,
        product_type: created.metadata.product_type,
        version: edit.metadata.new_version,
        salt: created.metadata.salt,
        kdf: created.metadata.kdf,
        bundle: edit.bundle,
      }
    );
    expect(edited.notes.get("tab-a")).toBe("first tab updated");
  });

  it("round-trips bundle multipart wire format", async () => {
    const created = await createPlaceBundlePayload({
      slug: "wire-bundle",
      password: "password",
      notes: [{ id: "only", plaintext: "content" }],
    });

    const form = buildCreateBundleFormData(created.metadata, created.bundle);
    const parsed = await parseBundleFormData(form);

    expect(parsed.metadata.slug).toBe("wire-bundle");
    expect(parsed.bundle.notes[0]!.ciphertext).toEqual(
      created.bundle.notes[0]!.ciphertext
    );
    expect(
      await verifyCreatePlaceBundlePayload(
        parsed.metadata as typeof created.metadata,
        parsed.bundle
      )
    ).toBe(true);
  });

  it("computes stable bundle digest", () => {
    const digest = bundleDigest(
      [
        { id: "b", iv: "iv-b", ciphertext_sha256: sha256Hex("b") },
        { id: "a", iv: "iv-a", ciphertext_sha256: sha256Hex("a") },
      ],
      [{ id: "z", iv: "iv-z", ciphertext_sha256: sha256Hex("z") }]
    );
    const digestReordered = bundleDigest(
      [
        { id: "a", iv: "iv-a", ciphertext_sha256: sha256Hex("a") },
        { id: "b", iv: "iv-b", ciphertext_sha256: sha256Hex("b") },
      ],
      [{ id: "z", iv: "iv-z", ciphertext_sha256: sha256Hex("z") }]
    );
    expect(digest).toBe(digestReordered);
  });

  it("rejects invalid bundles", () => {
    const result = validatePlaceBundle({ notes: [], attachments: [] });
    expect(result.ok).toBe(false);
    expect(
      bundleDigestFromPlaceBundle({
        notes: [
          {
            id: "a",
            iv: "x",
            ciphertext: new Uint8Array([1]),
          },
        ],
        attachments: [],
      }).length
    ).toBe(64);
  });
});

describe("bundle rotation", () => {
  it("rotates reader capability for a bundle", async () => {
    const {
      createPlaceBundlePayload,
    } = await import("../src/bundle-protocol.js");
    const {
      createRotateReaderBundleAction,
      verifyRotateReaderBundleAction,
    } = await import("../src/rotation.js");

    const created = await createPlaceBundlePayload({
      slug: "rotate-bundle",
      password: "old-password",
      notes: [{ id: "main", plaintext: "secret" }],
    });

    const rotated = await createRotateReaderBundleAction({
      slug: created.metadata.slug,
      version: created.metadata.version,
      password: "old-password",
      place: {
        slug: created.metadata.slug,
        product_type: created.metadata.product_type,
        version: created.metadata.version,
        salt: created.metadata.salt,
        kdf: created.metadata.kdf,
        bundle: created.bundle,
      },
      ownerPrivateKey: created.ownerPrivateKey,
    });

    expect(
      await verifyRotateReaderBundleAction(
        rotated.action,
        created.metadata.owner_public_key,
        created.metadata.version,
        rotated.bundle
      )
    ).toBe(true);

    const plaintext = await readPlaceBundleWithCapability(
      rotated.newReaderCapability,
      {
        slug: created.metadata.slug,
        product_type: created.metadata.product_type,
        version: created.metadata.version,
        salt: created.metadata.salt,
        kdf: created.metadata.kdf,
        bundle: rotated.bundle,
      }
    );
    expect(plaintext.notes.get("main")).toBe("secret");
  });
});
