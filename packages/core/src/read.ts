import { decompressNoteText } from "./compress.js";
import { base64ToBytes } from "./encoding.js";
import { decryptBytes } from "./encryption.js";
import { deriveKspMaterialFromPassword } from "./keys.js";
import { resolveKdf } from "./kdf.js";
import type { PlaceContent } from "./types.js";

export function buildContentAad(
  slug: string,
  version: number,
  productType: string
): string {
  return `${slug}:${version}:${productType}`;
}

export async function deriveReadKeyFromPassword(
  password: string,
  place: Pick<PlaceContent, "salt" | "kdf">
): Promise<Uint8Array> {
  const saltBytes = base64ToBytes(place.salt);
  const kdf = resolveKdf(place.kdf);
  const material = await deriveKspMaterialFromPassword(password, saltBytes, kdf);
  return material.readKey;
}

export async function readWithPassword(
  password: string,
  place: PlaceContent
): Promise<string> {
  const readKey = await deriveReadKeyFromPassword(password, place);
  return readWithReadKey(readKey, place);
}

export async function readWithCapability(
  readerCapability: string,
  place: PlaceContent
): Promise<string> {
  return readWithReadKey(base64ToBytes(readerCapability), place);
}

export async function readWithReadKey(
  readKey: Uint8Array,
  place: PlaceContent
): Promise<string> {
  const aad = buildContentAad(place.slug, place.version, place.product_type);
  const compressed = await decryptBytes(
    { ciphertext: place.ciphertext, iv: base64ToBytes(place.iv) },
    readKey,
    aad
  );
  return decompressNoteText(compressed);
}
