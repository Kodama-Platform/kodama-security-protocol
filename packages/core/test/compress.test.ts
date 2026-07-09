import { describe, expect, it } from "vitest";
import {
  compressNoteText,
  decompressNoteText,
  encryptBytes,
  decryptBytes,
} from "../src/index.js";

describe("compression", () => {
  it("round-trips note text through gzip", async () => {
    const text = "hello kodama\n".repeat(50);
    const compressed = await compressNoteText(text);
    expect(compressed.length).toBeLessThan(text.length);
    expect(await decompressNoteText(compressed)).toBe(text);
  });
});

describe("encryption", () => {
  it("encrypts and decrypts blobs without text encoding", async () => {
    const blob = await compressNoteText("blob content");
    const key = new Uint8Array(32).fill(0xab);
    const aad = "wallet:1:note";

    const encrypted = await encryptBytes(blob, key, aad);
    const decrypted = await decryptBytes(encrypted, key, aad);

    expect(decrypted).toEqual(blob);
    expect(await decompressNoteText(decrypted)).toBe("blob content");
  });
});
