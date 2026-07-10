import { describe, expect, it } from "vitest";
import {
  buildBinaryUploadFormData,
  mergeCreatePlacePayload,
  parseBinaryUploadFormData,
  splitCreatePlacePayload,
} from "../src/wire.js";
import { createNotePayload, verifyCreateNotePayload } from "../src/index.js";

describe("wire transport", () => {
  it("round-trips multipart metadata + binary ciphertext", async () => {
    const created = await createNotePayload({
      slug: "wire-test",
      password: "password",
      plaintext: "binary upload",
    });

    const { metadata, ciphertext } = splitCreatePlacePayload(created.payload);
    const form = buildBinaryUploadFormData(metadata, ciphertext);
    const parsed = await parseBinaryUploadFormData(form);
    const payload = mergeCreatePlacePayload(
      parsed.metadata as typeof metadata,
      parsed.ciphertext
    );

    expect(payload.ciphertext).toEqual(created.payload.ciphertext);
    expect(await verifyCreateNotePayload(payload)).toBe(true);
  });
});
